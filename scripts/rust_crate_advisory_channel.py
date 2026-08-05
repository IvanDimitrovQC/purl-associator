"""Build a small Rust-crate advisory channel from a Pixi lockfile.

The script targets the demo path where a Pixi environment contains conda
packages backed by Rust crates. It writes normal advisory-channel security
artifacts:

* ``<subdir>/<artifact>.sboms/<sha>.conda``
* ``cves/<ID>/<sha>.conda``
* ``<subdir>/<artifact>.matches/<ID>/<sha>.conda``
* ``<subdir>/<artifact>.advisories/<sha>.conda``
* mutable advisory-channel indexes

When exact ``cargo-auditable``/``rust-audit-info`` JSON is available, pass it via
``--cargo-auditable-dir``. Without it, the script emits a conservative demo SBOM
containing only the known root crate for each supported conda package.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import logging
from pathlib import Path
import subprocess
import sys
import tomllib
from typing import Any
from urllib.parse import quote, urlparse
import uuid

from scripts.advisory_index import (
    CHANNEL_INDEX,
    SHARDS_DIR,
    SUBDIR_INDEX,
    AdvisoryIndexState,
    build_indexes,
)
from scripts.cli_logging import add_logging_args, configure_logging, print_log_location
from scripts.correlate_osv import (
    DEFAULT_OSV_BATCH_SIZE,
    DEFAULT_OSV_BATCH_URL,
    correlate_sbom_with_results,
    query_osv_chunked,
    write_advisory_artifacts,
)
from scripts.generate_sbom import (
    DEFAULT_CHANNEL,
    DEFAULT_SBOM_TIMESTAMP,
    SBOM_INPUT_SCHEMA_VERSION,
    conda_artifact_stem,
    conda_purl,
    write_versioned_sbom,
)
from scripts.s3_publish import (
    Runner,
    S3PublishError,
    add_s3_args,
    aws_global_args,
    cleanup_uploaded_files,
    download_file,
    download_files,
    list_s3_relative_paths,
    print_cleanup_summary,
    print_s3_summary,
    upload_files,
)

LOGGER = logging.getLogger("scripts.rust_crate_advisory_channel")
DEFAULT_INPUT_DIR = Path(".tmp/rust-crate-test")
DEFAULT_OUTPUT_ROOT = DEFAULT_INPUT_DIR / "advisory-channel"
RUST_SBOM_INPUT_SCHEMA_VERSION = 1

# This is intentionally small. Exact crate graphs should come from
# cargo-auditable/rust-audit-info JSON whenever possible.
DEFAULT_CONDA_CRATE_ROOTS: dict[str, list[str]] = {
    "rattler": ["rattler"],
    "py-rattler": ["py-rattler"],
    "polars-runtime-32": ["polars"],
}

DEFAULT_DEPENDENCY_CONDA_TARGETS: dict[str, list[str]] = {
    "rattler": ["rattler"],
    "py-rattler": ["py-rattler"],
    "polars": ["polars-runtime-32"],
}


class RustCrateChannelError(RuntimeError):
    """User-facing Rust advisory-channel generation failure."""


@dataclass(frozen=True)
class CondaLockRecord:
    name: str
    version: str
    build: str
    subdir: str
    filename: str
    url: str
    sha256: str | None
    md5: str | None
    license: str | None
    timestamp: int | None


@dataclass(frozen=True)
class CargoGraph:
    components: list[dict[str, Any]]
    dependencies: list[dict[str, Any]]
    subject_depends_on: list[str]
    source: str
    source_path: str | None = None


@dataclass(frozen=True)
class WrittenPackage:
    record: CondaLockRecord
    sbom: dict[str, Any]
    sbom_path: Path
    cargo_source: str


def _canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(data: Any) -> str:
    return hashlib.sha256(_canonical_json(data).encode()).hexdigest()


def _quote_purl_part(value: str) -> str:
    return quote(value, safe="-._~")


def cargo_purl(name: str, version: str) -> str:
    return f"pkg:cargo/{_quote_purl_part(name)}@{_quote_purl_part(version)}"


def _scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return ""
    if value in {"{}", "[]"}:
        return {} if value == "{}" else []
    if value[0:1] in {"'", '"'} and value[-1:] == value[0]:
        return value[1:-1]
    if value.isdigit():
        try:
            return int(value)
        except ValueError:
            return value
    return value


def _load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open() as f:
            data = json.load(f)
    except FileNotFoundError as exc:
        raise RustCrateChannelError(f"{path}: file does not exist") from exc
    except json.JSONDecodeError as exc:
        raise RustCrateChannelError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise RustCrateChannelError(f"{path}: expected a JSON object")
    return data


def load_pixi_dependencies(path: Path) -> list[str]:
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError as exc:
        raise RustCrateChannelError(f"{path}: file does not exist") from exc
    except tomllib.TOMLDecodeError as exc:
        raise RustCrateChannelError(f"{path}: invalid TOML: {exc}") from exc
    dependencies = data.get("dependencies")
    if not isinstance(dependencies, dict):
        return []
    return sorted(key for key in dependencies if isinstance(key, str))


def _parse_package_url(url: str) -> tuple[str, str, str, str]:
    parsed = urlparse(url)
    parts = Path(parsed.path).parts
    if len(parts) < 2:
        raise RustCrateChannelError(f"could not determine subdir from URL {url!r}")
    subdir = parts[-2]
    filename = parts[-1]
    stem = conda_artifact_stem(filename)
    try:
        name, version, build = stem.rsplit("-", 2)
    except ValueError as exc:
        raise RustCrateChannelError(
            f"could not parse conda artifact filename {filename!r}"
        ) from exc
    return subdir, filename, name, version, build


def _lock_records_without_yaml(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text().splitlines()
    except FileNotFoundError as exc:
        raise RustCrateChannelError(f"{path}: file does not exist") from exc
    records: list[dict[str, Any]] = []
    in_packages = False
    current: dict[str, Any] | None = None
    for line in lines:
        if line == "packages:":
            in_packages = True
            continue
        if not in_packages:
            continue
        if line.startswith("- conda: "):
            if current is not None:
                records.append(current)
            current = {"conda": _scalar(line.split(": ", 1)[1])}
            continue
        if current is None:
            continue
        if line and not line.startswith(" "):
            break
        if not line.startswith("  ") or line.startswith("  - "):
            continue
        stripped = line.strip()
        if ": " not in stripped:
            continue
        key, value = stripped.split(": ", 1)
        if key in {"sha256", "md5", "license", "timestamp"}:
            current[key] = _scalar(value)
    if current is not None:
        records.append(current)
    return records


def load_lock_records(path: Path) -> list[CondaLockRecord]:
    raw_records: list[dict[str, Any]]
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError:
        raw_records = _lock_records_without_yaml(path)
    else:
        try:
            with path.open() as f:
                data = yaml.safe_load(f)
        except FileNotFoundError as exc:
            raise RustCrateChannelError(f"{path}: file does not exist") from exc
        if not isinstance(data, dict):
            raise RustCrateChannelError(f"{path}: expected lockfile mapping")
        packages = data.get("packages")
        raw_records = [r for r in packages if isinstance(r, dict)] if isinstance(packages, list) else []

    records: list[CondaLockRecord] = []
    for raw in raw_records:
        url = raw.get("conda")
        if not isinstance(url, str) or not url:
            continue
        subdir, filename, name, version, build = _parse_package_url(url)
        timestamp = raw.get("timestamp")
        records.append(
            CondaLockRecord(
                name=name,
                version=version,
                build=build,
                subdir=subdir,
                filename=filename,
                url=url,
                sha256=raw.get("sha256") if isinstance(raw.get("sha256"), str) else None,
                md5=raw.get("md5") if isinstance(raw.get("md5"), str) else None,
                license=raw.get("license") if isinstance(raw.get("license"), str) else None,
                timestamp=timestamp if isinstance(timestamp, int) else None,
            )
        )
    return records


def _record_timestamp(record: CondaLockRecord) -> str:
    if record.timestamp is None:
        return DEFAULT_SBOM_TIMESTAMP
    timestamp = record.timestamp / 1000 if record.timestamp >= 10_000_000_000 else record.timestamp
    try:
        return datetime.fromtimestamp(timestamp, UTC).isoformat(timespec="seconds")
    except (OSError, OverflowError, ValueError):
        return DEFAULT_SBOM_TIMESTAMP


def _hashes(record: CondaLockRecord) -> list[dict[str, str]]:
    hashes: list[dict[str, str]] = []
    if record.sha256:
        hashes.append({"alg": "SHA-256", "content": record.sha256})
    if record.md5:
        hashes.append({"alg": "MD5", "content": record.md5})
    return hashes


def _licenses(record: CondaLockRecord) -> list[dict[str, dict[str, str]]] | None:
    if not record.license:
        return None
    return [{"license": {"name": record.license}}]


def _property(name: str, value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    return {"name": name, "value": str(value)}


def _properties(*items: tuple[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for name, value in items:
        prop = _property(name, value)
        if prop is not None:
            out.append(prop)
    return out


def _audit_info_keys(record: CondaLockRecord) -> list[str]:
    stem = conda_artifact_stem(record.filename)
    return [
        record.filename,
        stem,
        f"{record.subdir}-{record.filename}",
        f"{record.subdir}-{stem}",
        record.name,
    ]


def load_audit_info_dir(path: Path | None) -> dict[str, tuple[Path, dict[str, Any]]]:
    if path is None:
        return {}
    if not path.exists():
        raise RustCrateChannelError(f"{path}: cargo-auditable dir does not exist")
    out: dict[str, tuple[Path, dict[str, Any]]] = {}
    for candidate in sorted(path.rglob("*.json")):
        payload = _load_json(candidate)
        out[candidate.name] = (candidate, payload)
        out[candidate.stem] = (candidate, payload)
    return out


def audit_info_for_record(
    record: CondaLockRecord,
    audit_info: dict[str, tuple[Path, dict[str, Any]]],
) -> tuple[Path, dict[str, Any]] | None:
    for key in _audit_info_keys(record):
        if key in audit_info:
            return audit_info[key]
        json_key = f"{key}.json"
        if json_key in audit_info:
            return audit_info[json_key]
    return None


def cargo_graph_from_audit_info(path: Path, payload: dict[str, Any]) -> CargoGraph:
    packages = payload.get("packages")
    if not isinstance(packages, list):
        raise RustCrateChannelError(f"{path}: expected packages[]")

    purls_by_index: dict[int, str] = {}
    components_by_purl: dict[str, dict[str, Any]] = {}
    raw_dependencies: dict[str, list[int]] = {}
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not name:
            continue
        if not isinstance(version, str) or not version:
            continue
        purl = cargo_purl(name, version)
        purls_by_index[index] = purl
        component = components_by_purl.setdefault(
            purl,
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": purl,
                "bom-ref": purl,
                "properties": _properties(
                    ("cargo:source", package.get("source")),
                    ("rust-crate-sbom:source", "cargo-auditable"),
                ),
            },
        )
        kind = package.get("kind")
        if isinstance(kind, str):
            component["scope"] = "optional" if kind == "build" else "required"
        dependencies = package.get("dependencies")
        raw_dependencies[purl] = [
            dep for dep in dependencies if isinstance(dep, int)
        ] if isinstance(dependencies, list) else []

    dependencies: list[dict[str, Any]] = []
    referenced: set[str] = set()
    for purl, indexes in sorted(raw_dependencies.items()):
        depends_on = sorted(
            dep_purl
            for index in indexes
            if (dep_purl := purls_by_index.get(index)) is not None
        )
        referenced.update(depends_on)
        dependencies.append({"ref": purl, "dependsOn": depends_on})
    roots = sorted(set(components_by_purl) - referenced) or sorted(components_by_purl)
    return CargoGraph(
        components=[components_by_purl[purl] for purl in sorted(components_by_purl)],
        dependencies=dependencies,
        subject_depends_on=roots,
        source="cargo-auditable",
        source_path=path.as_posix(),
    )


def fallback_cargo_graph(record: CondaLockRecord) -> CargoGraph | None:
    crate_names = DEFAULT_CONDA_CRATE_ROOTS.get(record.name)
    if not crate_names:
        return None
    components: list[dict[str, Any]] = []
    for crate_name in crate_names:
        purl = cargo_purl(crate_name, record.version)
        components.append(
            {
                "type": "library",
                "name": crate_name,
                "version": record.version,
                "purl": purl,
                "bom-ref": purl,
                "properties": _properties(
                    ("rust-crate-sbom:source", "fallback-root-crate"),
                    (
                        "rust-crate-sbom:note",
                        "root crate only; pass --cargo-auditable-dir for full dependency graph",
                    ),
                ),
            }
        )
    purls = [str(component["purl"]) for component in components]
    return CargoGraph(
        components=components,
        dependencies=[{"ref": purl, "dependsOn": []} for purl in purls],
        subject_depends_on=purls,
        source="fallback-root-crate",
    )


def _record_input(record: CondaLockRecord) -> dict[str, Any]:
    return {
        "name": record.name,
        "version": record.version,
        "build": record.build,
        "subdir": record.subdir,
        "filename": record.filename,
        "url": record.url,
        "sha256": record.sha256,
        "md5": record.md5,
        "license": record.license,
        "timestamp": record.timestamp,
    }


def build_rust_crate_sbom(
    *,
    record: CondaLockRecord,
    cargo_graph: CargoGraph,
    channel: str,
) -> dict[str, Any]:
    subject_ref = conda_purl(
        channel=channel,
        name=record.name,
        version=record.version,
        subdir=record.subdir,
        build=record.build,
    )
    inputs = {
        "schema_version": RUST_SBOM_INPUT_SCHEMA_VERSION,
        "kind": "rust-crate-sbom",
        "channel": channel,
        "record": _record_input(record),
        "cargo_source": cargo_graph.source,
        "cargo_components": [
            {
                "purl": component.get("purl"),
                "name": component.get("name"),
                "version": component.get("version"),
            }
            for component in cargo_graph.components
        ],
        "cargo_dependencies": cargo_graph.dependencies,
    }
    inputs_hash = _sha256(inputs)
    version_id = inputs_hash
    subject: dict[str, Any] = {
        "type": "library",
        "name": record.name,
        "version": record.version,
        "purl": subject_ref,
        "bom-ref": subject_ref,
        "externalReferences": [{"type": "distribution", "url": record.url}],
        "properties": _properties(
            ("sbom-generator:name", "purl-associator-rust-crate"),
            ("sbom-generator:input-schema-version", SBOM_INPUT_SCHEMA_VERSION),
            ("sbom-generator:version", version_id),
            ("sbom-generator:input-sha256", inputs_hash),
            ("purl-associator:mapping-sha256", _sha256(cargo_graph.components)),
            ("conda:channel", channel),
            ("conda:subdir", record.subdir),
            ("conda:filename", record.filename),
            ("conda:build", record.build),
            ("rust-crate-sbom:source", cargo_graph.source),
            ("rust-crate-sbom:audit-info", cargo_graph.source_path),
        ),
    }
    hashes = _hashes(record)
    if hashes:
        subject["hashes"] = hashes
    licenses = _licenses(record)
    if licenses:
        subject["licenses"] = licenses

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, subject_ref + '#' + version_id)}",
        "version": 1,
        "metadata": {
            "timestamp": _record_timestamp(record),
            "component": subject,
        },
        "components": cargo_graph.components,
        "dependencies": [
            {"ref": subject_ref, "dependsOn": cargo_graph.subject_depends_on},
            *cargo_graph.dependencies,
        ],
    }


def target_package_names(dependencies: list[str]) -> set[str]:
    targets: set[str] = set()
    for dependency in dependencies:
        targets.update(DEFAULT_DEPENDENCY_CONDA_TARGETS.get(dependency, []))
        if dependency in DEFAULT_CONDA_CRATE_ROOTS:
            targets.add(dependency)
    return targets


def select_records(
    records: list[CondaLockRecord],
    *,
    dependencies: list[str],
    include_packages: list[str],
    include_subdirs: list[str],
    audit_info: dict[str, tuple[Path, dict[str, Any]]],
) -> list[CondaLockRecord]:
    requested = set(include_packages) or target_package_names(dependencies)
    requested_subdirs = set(include_subdirs)
    selected: list[CondaLockRecord] = []
    seen: set[tuple[str, str, str]] = set()
    for record in sorted(records, key=lambda r: (r.subdir, r.name, r.version, r.build)):
        if requested_subdirs and record.subdir not in requested_subdirs:
            continue
        include = record.name in requested
        include = include or audit_info_for_record(record, audit_info) is not None
        if not include:
            continue
        key = (record.subdir, record.filename, record.url)
        if key in seen:
            continue
        seen.add(key)
        selected.append(record)
    return selected


def write_sboms(
    *,
    records: list[CondaLockRecord],
    audit_info: dict[str, tuple[Path, dict[str, Any]]],
    output_root: Path,
    channel: str,
    require_cargo_auditable: bool,
) -> list[WrittenPackage]:
    written: list[WrittenPackage] = []
    for record in records:
        match = audit_info_for_record(record, audit_info)
        if match is not None:
            audit_path, payload = match
            cargo_graph = cargo_graph_from_audit_info(audit_path, payload)
        else:
            if require_cargo_auditable:
                raise RustCrateChannelError(
                    "missing cargo-auditable JSON for "
                    f"{record.subdir}/{record.filename}; pass "
                    "--cargo-auditable-dir or --cargo-auditable-s3-uri"
                )
            cargo_graph = fallback_cargo_graph(record)
        if cargo_graph is None:
            LOGGER.warning(
                "skipping package without cargo graph package=%s artifact=%s",
                record.name,
                record.filename,
            )
            continue
        sbom = build_rust_crate_sbom(
            record=record,
            cargo_graph=cargo_graph,
            channel=channel,
        )
        path, created = write_versioned_sbom(
            sbom=sbom,
            root=output_root,
            subdir=record.subdir,
            filename=record.filename,
        )
        LOGGER.info(
            "SBOM %s path=%s package=%s cargo_source=%s",
            "created" if created else "exists",
            path,
            record.name,
            cargo_graph.source,
        )
        written.append(
            WrittenPackage(
                record=record,
                sbom=sbom,
                sbom_path=path,
                cargo_source=cargo_graph.source,
            )
        )
    return written


def _component_purls(sbom: dict[str, Any]) -> list[str]:
    components = sbom.get("components")
    if not isinstance(components, list):
        return []
    purls: list[str] = []
    for component in components:
        if not isinstance(component, dict):
            continue
        purl = component.get("purl")
        if isinstance(purl, str) and "@" in purl.rsplit("/", 1)[-1]:
            purls.append(purl)
    return purls


def write_osv_artifacts(
    *,
    packages: list[WrittenPackage],
    output_root: Path,
    api_url: str,
    batch_size: int,
    skip_osv: bool,
) -> list[Path]:
    all_purls = sorted({purl for package in packages for purl in _component_purls(package.sbom)})
    LOGGER.info("prepared Cargo PURLs for OSV query count=%d", len(all_purls))
    if skip_osv:
        osv_results: dict[str, list[dict[str, Any]]] = {purl: [] for purl in all_purls}
    else:
        osv_results = query_osv_chunked(
            all_purls,
            api_url=api_url,
            batch_size=batch_size,
            hydrate_details=True,
        )

    output_paths: list[Path] = []
    for package in packages:
        source_sbom = package.sbom_path.relative_to(output_root).as_posix()
        advisory = correlate_sbom_with_results(
            package.sbom,
            source_sbom=source_sbom,
            osv_results=osv_results,
            api_url=api_url,
        )
        results = write_advisory_artifacts(advisory, sbom_path=package.sbom_path)
        output_paths.extend(result.path for result in results)
        LOGGER.info(
            "wrote OSV artifacts package=%s artifact=%s outputs=%d findings=%d",
            package.record.name,
            package.record.filename,
            len(results),
            advisory.get("vulnerability_count", 0),
        )
    return output_paths


def _is_sbom_artifact_path(path: Path) -> bool:
    return path.name.endswith(".conda") and path.parent.name.endswith(".sboms")


def _is_advisories_artifact_path(path: Path) -> bool:
    return path.name.endswith(".conda") and path.parent.name.endswith(".advisories")


def update_indexes_for_paths(
    *,
    channel_root: Path,
    channel: str,
    artifact_paths: list[Path],
) -> list[Path]:
    state = AdvisoryIndexState.load(channel_root=channel_root, channel=channel)
    for path in sorted(artifact_paths):
        if _is_sbom_artifact_path(path):
            state.update_sbom(path)
        elif _is_advisories_artifact_path(path):
            state.update_advisory(path)
    return state.write()


def _is_index_relative_path(relative_path: str) -> bool:
    parts = Path(relative_path).parts
    if parts == (CHANNEL_INDEX,):
        return True
    if len(parts) >= 2 and parts[-1] == SUBDIR_INDEX:
        return True
    return SHARDS_DIR in parts


def _is_missing_s3_object_error(exc: S3PublishError) -> bool:
    message = str(exc)
    return any(marker in message for marker in ("404", "NoSuchKey", "Not Found"))


def _download_optional_relative_s3_file(
    *,
    relative_path: str,
    root: Path,
    s3_uri: str,
    profile: str | None,
    region: str | None,
    runner: Runner,
) -> Path | None:
    try:
        return download_file(
            relative_path=relative_path,
            root=root,
            s3_uri=s3_uri,
            profile=profile,
            region=region,
            runner=runner,
        ).local_path
    except S3PublishError as exc:
        if _is_missing_s3_object_error(exc):
            LOGGER.info(
                "optional S3 object is absent source=%s relative_path=%s",
                s3_uri,
                relative_path,
            )
            return None
        raise


def _load_local_json(path: Path) -> dict[str, Any]:
    try:
        with path.open() as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise RustCrateChannelError(f"{path}: could not load JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise RustCrateChannelError(f"{path}: expected JSON object")
    return data


def _subdir_index_paths_from_channel_index(channel_index: dict[str, Any]) -> list[str]:
    subdirs = channel_index.get("subdirs")
    if not isinstance(subdirs, dict):
        return []
    out: list[str] = []
    for subdir, entry in sorted(subdirs.items()):
        if not isinstance(subdir, str):
            continue
        if isinstance(entry, dict) and isinstance(entry.get("index"), str):
            out.append(entry["index"].lstrip("/"))
        else:
            out.append(f"{subdir}/{SUBDIR_INDEX}")
    return out


def _shard_relative_path_from_entry(
    *, subdir_index: dict[str, Any], entry: Any
) -> str | None:
    if isinstance(entry, dict):
        path = entry.get("path")
        if isinstance(path, str) and path:
            return path.lstrip("/")
        digest = entry.get("sha256")
    elif isinstance(entry, str):
        digest = entry
    else:
        return None
    if not isinstance(digest, str) or not digest:
        return None
    base_url = subdir_index.get("shards_base_url")
    if not isinstance(base_url, str) or not base_url:
        base_url = f"{SHARDS_DIR}/"
    return f"{base_url.rstrip('/')}/{digest}.json"


def _shard_paths_from_subdir_index(
    *, subdir_index_path: str, subdir_index: dict[str, Any]
) -> list[str]:
    subdir = Path(subdir_index_path).parent.as_posix()
    shards = subdir_index.get("shards")
    if not isinstance(shards, dict):
        return []
    out: list[str] = []
    for entry in shards.values():
        shard_path = _shard_relative_path_from_entry(
            subdir_index=subdir_index,
            entry=entry,
        )
        if not shard_path:
            continue
        shard_parts = Path(shard_path).parts
        if shard_parts and shard_parts[0] == subdir:
            out.append(shard_path)
        else:
            out.append(f"{subdir}/{shard_path}".lstrip("/"))
    return sorted(dict.fromkeys(out))


def _stage_existing_indexes_from_channel_index(
    *,
    s3_uri: str,
    root: Path,
    profile: str | None,
    region: str | None,
    workers: int,
    runner: Runner,
) -> list[Path] | None:
    channel_index_path = _download_optional_relative_s3_file(
        relative_path=CHANNEL_INDEX,
        root=root,
        s3_uri=s3_uri,
        profile=profile,
        region=region,
        runner=runner,
    )
    if channel_index_path is None:
        return None

    paths = [channel_index_path]
    channel_index = _load_local_json(channel_index_path)
    subdir_index_paths = _subdir_index_paths_from_channel_index(channel_index)
    if subdir_index_paths:
        subdir_summary = download_files(
            relative_paths=subdir_index_paths,
            root=root,
            s3_uri=s3_uri,
            profile=profile,
            region=region,
            workers=workers,
            runner=runner,
        )
        paths.extend(subdir_summary.local_paths)
    shard_paths: list[str] = []
    for relative_path in subdir_index_paths:
        local_path = root / relative_path
        if not local_path.exists():
            continue
        shard_paths.extend(
            _shard_paths_from_subdir_index(
                subdir_index_path=relative_path,
                subdir_index=_load_local_json(local_path),
            )
        )
    if shard_paths:
        shard_summary = download_files(
            relative_paths=sorted(dict.fromkeys(shard_paths)),
            root=root,
            s3_uri=s3_uri,
            profile=profile,
            region=region,
            workers=workers,
            runner=runner,
        )
        paths.extend(shard_summary.local_paths)
    return paths


def stage_existing_indexes_from_s3(
    *,
    s3_uri: str,
    root: Path,
    profile: str | None,
    region: str | None,
    workers: int,
    runner: Runner = subprocess.run,
) -> list[Path]:
    staged_from_channel_index = _stage_existing_indexes_from_channel_index(
        s3_uri=s3_uri,
        root=root,
        profile=profile,
        region=region,
        workers=workers,
        runner=runner,
    )
    if staged_from_channel_index is not None:
        LOGGER.info(
            "staged existing advisory indexes from channel-index source=%s count=%d",
            s3_uri,
            len(staged_from_channel_index),
        )
        return staged_from_channel_index

    LOGGER.info(
        "falling back to S3 listing for existing advisory indexes source=%s",
        s3_uri,
    )
    relative_paths = [
        path
        for path in list_s3_relative_paths(
            s3_uri=s3_uri,
            profile=profile,
            region=region,
            runner=runner,
        )
        if _is_index_relative_path(path)
    ]
    if not relative_paths:
        LOGGER.info("no existing advisory indexes found in S3 source=%s", s3_uri)
        return []
    summary = download_files(
        relative_paths=relative_paths,
        root=root,
        s3_uri=s3_uri,
        profile=profile,
        region=region,
        workers=workers,
        runner=runner,
    )
    LOGGER.info(
        "staged existing advisory indexes from S3 source=%s count=%d",
        s3_uri,
        summary.downloaded,
    )
    return summary.local_paths


def _download_s3_object(
    *,
    s3_uri: str,
    out: Path,
    profile: str | None,
    region: str | None,
    runner: Runner = subprocess.run,
) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    aws_args = aws_global_args(profile=profile, region=region)
    LOGGER.info("downloading S3 object source=%s local=%s", s3_uri, out)
    result = runner(
        [
            "aws",
            *aws_args,
            "s3",
            "cp",
            s3_uri,
            str(out),
            "--only-show-errors",
            "--no-progress",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise S3PublishError(
            f"could not download {s3_uri}: {(result.stderr or '').strip()}"
        )
    return out


def stage_cargo_auditable_from_s3(
    *,
    s3_uri: str,
    root: Path,
    profile: str | None,
    region: str | None,
    workers: int,
    runner: Runner = subprocess.run,
) -> Path:
    relative_paths = [
        path
        for path in list_s3_relative_paths(
            s3_uri=s3_uri,
            profile=profile,
            region=region,
            runner=runner,
        )
        if path.endswith(".json")
    ]
    if not relative_paths:
        raise RustCrateChannelError(f"{s3_uri}: no cargo-auditable JSON files found")
    summary = download_files(
        relative_paths=relative_paths,
        root=root,
        s3_uri=s3_uri,
        profile=profile,
        region=region,
        workers=workers,
        runner=runner,
    )
    LOGGER.info(
        "staged cargo-auditable JSON files from S3 source=%s count=%d",
        s3_uri,
        summary.downloaded,
    )
    return root


def build_channel(
    *,
    pixi_toml: Path,
    pixi_lock: Path,
    output_root: Path,
    cargo_auditable_dir: Path | None,
    channel: str,
    include_packages: list[str],
    include_subdirs: list[str],
    api_url: str,
    batch_size: int,
    skip_osv: bool,
    update_index: bool,
    incremental_index: bool = False,
    require_cargo_auditable: bool = False,
) -> dict[str, Any]:
    dependencies = load_pixi_dependencies(pixi_toml)
    records = load_lock_records(pixi_lock)
    audit_info = load_audit_info_dir(cargo_auditable_dir)
    selected = select_records(
        records,
        dependencies=dependencies,
        include_packages=include_packages,
        include_subdirs=include_subdirs,
        audit_info=audit_info,
    )
    LOGGER.info(
        "selected Rust-backed conda artifacts count=%d dependencies=%s",
        len(selected),
        ",".join(dependencies),
    )
    packages = write_sboms(
        records=selected,
        audit_info=audit_info,
        output_root=output_root,
        channel=channel,
        require_cargo_auditable=require_cargo_auditable,
    )
    osv_paths = write_osv_artifacts(
        packages=packages,
        output_root=output_root,
        api_url=api_url,
        batch_size=batch_size,
        skip_osv=skip_osv,
    )
    artifact_paths = [package.sbom_path for package in packages]
    artifact_paths.extend(osv_paths)
    if not update_index:
        index_paths: list[Path] = []
    elif incremental_index:
        index_paths = update_indexes_for_paths(
            channel_root=output_root,
            channel=channel,
            artifact_paths=artifact_paths,
        )
    else:
        index_paths = build_indexes(channel_root=output_root, channel=channel)
    return {
        "dependencies": dependencies,
        "selected_artifacts": len(selected),
        "sboms": len(packages),
        "artifact_paths": [path.as_posix() for path in artifact_paths],
        "indexes": len(index_paths),
        "index_paths": [path.as_posix() for path in index_paths],
        "output_root": output_root.as_posix(),
    }


def _include_packages(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return out


def _include_subdirs(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return out


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create Rust crate SBOM and OSV advisory artifacts from pixi.toml and pixi.lock"
        )
    )
    parser.add_argument(
        "--pixi-toml",
        type=Path,
        default=DEFAULT_INPUT_DIR / "pixi.toml",
        help="pixi.toml containing the requested top-level dependencies",
    )
    parser.add_argument(
        "--pixi-toml-s3-uri",
        help="s3:// URI for pixi.toml; overrides --pixi-toml after staging",
    )
    parser.add_argument(
        "--pixi-lock",
        type=Path,
        default=DEFAULT_INPUT_DIR / "pixi.lock",
        help="pixi.lock containing resolved conda artifacts",
    )
    parser.add_argument(
        "--pixi-lock-s3-uri",
        help="s3:// URI for pixi.lock; overrides --pixi-lock after staging",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=DEFAULT_OUTPUT_ROOT,
        help="output advisory-channel root",
    )
    parser.add_argument(
        "--cargo-auditable-dir",
        type=Path,
        help=(
            "optional directory of rust-audit-info/cargo-auditable JSON files; "
            "filenames may be package names or conda artifact stems"
        ),
    )
    parser.add_argument(
        "--cargo-auditable-s3-uri",
        help=(
            "optional s3://bucket/prefix containing rust-audit-info/"
            "cargo-auditable JSON files"
        ),
    )
    parser.add_argument(
        "--require-cargo-auditable",
        action="store_true",
        help="fail when a selected Rust artifact has no cargo-auditable JSON",
    )
    parser.add_argument(
        "--include-package",
        action="append",
        default=[],
        help="comma-separated conda package name(s) to include instead of inferred targets",
    )
    parser.add_argument(
        "--include-subdir",
        action="append",
        default=[],
        help="comma-separated conda subdir(s) to include, e.g. osx-arm64 or linux-64",
    )
    parser.add_argument("--channel", default=DEFAULT_CHANNEL)
    parser.add_argument("--api-url", default=DEFAULT_OSV_BATCH_URL)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_OSV_BATCH_SIZE)
    parser.add_argument(
        "--s3-source-uri",
        help=(
            "existing advisory-channel S3 prefix to reconcile against before "
            "writing mutable indexes; defaults to --s3-uri when omitted"
        ),
    )
    parser.add_argument(
        "--s3-stage-dir",
        type=Path,
        default=DEFAULT_INPUT_DIR / "s3-stage",
        help="local staging directory for S3 input files",
    )
    parser.add_argument(
        "--skip-osv",
        action="store_true",
        help="write no-finding advisory artifacts without calling OSV",
    )
    parser.add_argument(
        "--no-index",
        action="store_true",
        help="do not rebuild advisory-channel indexes after writing artifacts",
    )
    add_s3_args(parser)
    add_logging_args(parser, command_name="rust-crate-advisory-channel")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    log_path = configure_logging(
        command_name="rust-crate-advisory-channel",
        log_level=args.log_level,
        log_file=args.log_file,
    )
    try:
        if args.cargo_auditable_dir and args.cargo_auditable_s3_uri:
            raise RustCrateChannelError(
                "pass only one of --cargo-auditable-dir or --cargo-auditable-s3-uri"
            )

        pixi_toml = args.pixi_toml
        pixi_lock = args.pixi_lock
        cargo_auditable_dir = args.cargo_auditable_dir
        if args.pixi_toml_s3_uri:
            pixi_toml = _download_s3_object(
                s3_uri=args.pixi_toml_s3_uri,
                out=args.s3_stage_dir / "inputs" / "pixi.toml",
                profile=args.s3_profile,
                region=args.s3_region,
            )
        if args.pixi_lock_s3_uri:
            pixi_lock = _download_s3_object(
                s3_uri=args.pixi_lock_s3_uri,
                out=args.s3_stage_dir / "inputs" / "pixi.lock",
                profile=args.s3_profile,
                region=args.s3_region,
            )
        if args.cargo_auditable_s3_uri:
            cargo_auditable_dir = stage_cargo_auditable_from_s3(
                s3_uri=args.cargo_auditable_s3_uri,
                root=args.s3_stage_dir / "cargo-auditable",
                profile=args.s3_profile,
                region=args.s3_region,
                workers=args.s3_workers,
            )

        s3_source_uri = args.s3_source_uri or args.s3_uri
        incremental_index = False
        if s3_source_uri and not args.no_index:
            stage_existing_indexes_from_s3(
                s3_uri=s3_source_uri,
                root=args.out_dir,
                profile=args.s3_profile,
                region=args.s3_region,
                workers=args.s3_workers,
            )
            incremental_index = True

        summary = build_channel(
            pixi_toml=pixi_toml,
            pixi_lock=pixi_lock,
            output_root=args.out_dir,
            cargo_auditable_dir=cargo_auditable_dir,
            channel=args.channel,
            include_packages=_include_packages(args.include_package),
            include_subdirs=_include_subdirs(args.include_subdir),
            api_url=args.api_url,
            batch_size=args.batch_size,
            skip_osv=args.skip_osv,
            update_index=not args.no_index,
            incremental_index=incremental_index,
            require_cargo_auditable=args.require_cargo_auditable,
        )
        if args.s3_uri:
            artifact_paths = [Path(path) for path in summary["artifact_paths"]]
            index_paths = [Path(path) for path in summary["index_paths"]]
            if artifact_paths:
                LOGGER.info(
                    "publishing immutable Rust security artifacts to S3 count=%d",
                    len(artifact_paths),
                )
                artifact_summary = upload_files(
                    local_paths=artifact_paths,
                    root=args.out_dir,
                    s3_uri=args.s3_uri,
                    profile=args.s3_profile,
                    region=args.s3_region,
                    dry_run=args.s3_dry_run,
                    workers=args.s3_workers,
                )
                print_s3_summary(artifact_summary, dry_run=args.s3_dry_run)
                if args.cleanup_uploaded and not args.s3_dry_run:
                    print_cleanup_summary(
                        cleanup_uploaded_files(artifact_summary, root=args.out_dir)
                    )
            if index_paths:
                LOGGER.info(
                    "publishing mutable advisory indexes to S3 count=%d",
                    len(index_paths),
                )
                index_summary = upload_files(
                    local_paths=index_paths,
                    root=args.out_dir,
                    s3_uri=args.s3_uri,
                    profile=args.s3_profile,
                    region=args.s3_region,
                    dry_run=args.s3_dry_run,
                    overwrite=True,
                    workers=args.s3_workers,
                )
                print_s3_summary(index_summary, dry_run=args.s3_dry_run)
                if args.cleanup_uploaded and not args.s3_dry_run:
                    print_cleanup_summary(
                        cleanup_uploaded_files(index_summary, root=args.out_dir)
                    )
    except (RustCrateChannelError, S3PublishError, OSError) as exc:
        LOGGER.error("Rust crate advisory channel generation failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        raise SystemExit(1) from exc
    print(json.dumps(summary, indent=2, sort_keys=True))
    print_log_location(log_path)


if __name__ == "__main__":
    main()
