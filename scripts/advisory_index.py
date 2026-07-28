"""Build mutable advisory-channel indexes from SBOM and OSV artifacts."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import io
import json
import logging
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.cli_logging import add_logging_args, configure_logging, print_log_location
from scripts.generate_sbom import (
    DEFAULT_CHANNEL,
    DEFAULT_LOCAL_CHANNEL,
    SECURITY_ADVISORIES_PAYLOAD_NAME,
    SECURITY_METADATA_NAME,
    SECURITY_SBOM_PAYLOAD_NAME,
)
from scripts.osv_vulnerability_summary import vulnerabilities_from_advisory_payload
from scripts.s3_osv_inventory import filter_osv_inventory_paths
from scripts.s3_publish import (
    Runner,
    S3PublishError,
    add_s3_args,
    aws_global_args,
    list_s3_relative_paths,
    s3_uri_for_relative_path,
    upload_files,
)
from scripts.s3_sbom_inventory import is_sbom_artifact_path

INDEX_SCHEMA_VERSION = 1
SHARD_SCHEMA_VERSION = 1
CHANNEL_INDEX = "channel-index.json"
SUBDIR_INDEX = "advisory-channel.json"
SHARDS_DIR = "advisory-channel-shards"
SHARD_FORMAT = "advisory-channel-shards-v1"
DEFAULT_WORKERS = 8
LOGGER = logging.getLogger("scripts.advisory_index")


class AdvisoryIndexError(RuntimeError):
    """User-facing advisory index failure."""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _load_json_path(path: Path) -> dict[str, Any]:
    try:
        with path.open() as f:
            data = json.load(f)
    except FileNotFoundError as exc:
        raise AdvisoryIndexError(f"{path}: file does not exist") from exc
    except json.JSONDecodeError as exc:
        raise AdvisoryIndexError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise AdvisoryIndexError(f"{path}: expected a JSON object")
    return data


def _write_json(path: Path, data: dict[str, Any]) -> None:
    LOGGER.info("writing advisory index path=%s", path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def _canonical_json_bytes(data: dict[str, Any]) -> bytes:
    return (
        json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()


def _canonical_sha256(data: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json_bytes(data)).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_canonical_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp")
    tmp.write_bytes(_canonical_json_bytes(data))
    tmp.replace(path)


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise AdvisoryIndexError(f"{path} is not under channel root {root}") from exc


def _component_property(component: dict[str, Any], name: str) -> str | None:
    for prop in component.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == name:
            value = prop.get("value")
            return value if isinstance(value, str) else None
    return None


def _security_artifact_name_hash(path: Path) -> str | None:
    if not path.name.endswith(".conda"):
        return None
    stem = path.name.removesuffix(".conda")
    if len(stem) != 64 or any(char not in "0123456789abcdef" for char in stem):
        return None
    return stem


def _is_security_sbom_relative_path(path: str) -> bool:
    parts = Path(path).parts
    return (
        len(parts) >= 3
        and parts[-2].endswith(".sboms")
        and _security_artifact_name_hash(Path(parts[-1])) is not None
    )


def _is_security_advisories_relative_path(path: str) -> bool:
    parts = Path(path).parts
    return (
        len(parts) >= 3
        and parts[-2].endswith(".advisories")
        and _security_artifact_name_hash(Path(parts[-1])) is not None
    )


def _load_security_artifact_bytes(
    data: bytes,
    *,
    relative_path: str,
    expected_kind: str,
    expected_schema: str,
    payload_name: str,
) -> tuple[dict[str, Any], dict[str, Any], str, int]:
    path = Path(relative_path)
    actual_sha256 = _sha256_bytes(data)
    expected_sha256 = _security_artifact_name_hash(path)
    if expected_sha256 and expected_sha256 != actual_sha256:
        raise AdvisoryIndexError(
            f"{relative_path}: filename hash does not match artifact bytes "
            f"({expected_sha256} != {actual_sha256})"
        )
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            security = json.loads(archive.read(SECURITY_METADATA_NAME))
            payload_bytes = archive.read(payload_name)
            payload = json.loads(payload_bytes)
    except (KeyError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        raise AdvisoryIndexError(
            f"{relative_path}: invalid security artifact: {exc}"
        ) from exc
    if not isinstance(security, dict):
        raise AdvisoryIndexError(f"{relative_path}: info/security.json must be object")
    if not isinstance(payload, dict):
        raise AdvisoryIndexError(f"{relative_path}: {payload_name} must be object")

    metadata = security.get("metadata")
    if not isinstance(metadata, dict):
        raise AdvisoryIndexError(f"{relative_path}: security metadata is missing")
    if metadata.get("kind") != expected_kind:
        raise AdvisoryIndexError(
            f"{relative_path}: security kind must be {expected_kind}"
        )
    if metadata.get("data_schema") != expected_schema:
        raise AdvisoryIndexError(
            f"{relative_path}: data_schema must be {expected_schema}"
        )

    artifacts = security.get("artifacts")
    sbom_artifact = (
        artifacts.get(payload_name)
        if isinstance(artifacts, dict)
        else None
    )
    if not isinstance(sbom_artifact, dict):
        raise AdvisoryIndexError(
            f"{relative_path}: missing artifact metadata for {payload_name}"
        )
    expected_payload_sha256 = sbom_artifact.get("sha256")
    if expected_payload_sha256 != _sha256_bytes(payload_bytes):
        raise AdvisoryIndexError(f"{relative_path}: {payload_name} hash mismatch")
    expected_payload_size = sbom_artifact.get("size")
    if isinstance(expected_payload_size, int) and expected_payload_size != len(
        payload_bytes
    ):
        raise AdvisoryIndexError(f"{relative_path}: {payload_name} size mismatch")
    return payload, security, actual_sha256, len(data)


def _load_security_sbom_artifact_bytes(
    data: bytes, *, relative_path: str
) -> tuple[dict[str, Any], dict[str, Any], str, int]:
    return _load_security_artifact_bytes(
        data,
        relative_path=relative_path,
        expected_kind="SBOM",
        expected_schema="sbom.v1",
        payload_name=SECURITY_SBOM_PAYLOAD_NAME,
    )


def _load_security_advisories_artifact_bytes(
    data: bytes, *, relative_path: str
) -> tuple[dict[str, Any], dict[str, Any], str, int]:
    return _load_security_artifact_bytes(
        data,
        relative_path=relative_path,
        expected_kind="ADVISORIES",
        expected_schema="advisories.v1",
        payload_name=SECURITY_ADVISORIES_PAYLOAD_NAME,
    )


def _load_security_sbom_artifact_path(
    path: Path, *, channel_root: Path
) -> tuple[dict[str, Any], dict[str, Any], str, int]:
    relative_path = _relative(path, channel_root)
    try:
        data = path.read_bytes()
    except FileNotFoundError as exc:
        raise AdvisoryIndexError(f"{path}: file does not exist") from exc
    return _load_security_sbom_artifact_bytes(data, relative_path=relative_path)


def _load_security_advisories_artifact_path(
    path: Path, *, channel_root: Path
) -> tuple[dict[str, Any], dict[str, Any], str, int]:
    relative_path = _relative(path, channel_root)
    try:
        data = path.read_bytes()
    except FileNotFoundError as exc:
        raise AdvisoryIndexError(f"{path}: file does not exist") from exc
    return _load_security_advisories_artifact_bytes(data, relative_path=relative_path)


def _subject(sbom: dict[str, Any]) -> dict[str, Any]:
    metadata = sbom.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(component, dict):
        raise AdvisoryIndexError("SBOM metadata.component is missing")
    return component


def _artifact_filename(path: Path) -> str:
    parts = path.parts
    if len(parts) >= 3 and parts[-2].endswith((".sboms", ".advisories")):
        suffix = ".sboms" if parts[-2].endswith(".sboms") else ".advisories"
        return f"{parts[-2].removesuffix(suffix)}.conda"
    if len(parts) >= 4 and parts[-3].endswith(".matches"):
        return f"{parts[-3].removesuffix('.matches')}.conda"
    if path.parent.parent.name in {"sboms", "advisories"}:
        return path.parent.name
    return path.name.removesuffix(".cdx.json").removesuffix(".osv.json")


def _artifact_subdir(path: Path) -> str:
    parts = path.parts
    if len(parts) >= 3 and parts[-2].endswith((".sboms", ".advisories")):
        return parts[-3]
    if len(parts) >= 4 and parts[-3].endswith(".matches"):
        return parts[-4]
    if path.parent.parent.name in {"sboms", "advisories"}:
        return path.parent.parent.parent.name
    return path.parent.parent.name


def _finding_ids(advisory: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for finding in advisory.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        value = finding.get("vulnerability_id")
        if isinstance(value, str) and value not in ids:
            ids.append(value)
    return ids


def _osv_status(advisory: dict[str, Any]) -> str:
    vulnerability_count = advisory.get("vulnerability_count")
    query_count = advisory.get("query_count")
    if isinstance(vulnerability_count, int) and vulnerability_count > 0:
        return "vulnerabilities_found"
    if query_count == 0:
        return "not_queryable"
    return "no_known_vulnerabilities"


def _sbom_version_from_filename(path: Path) -> str | None:
    if path.name.startswith("sbom-") and path.name.endswith(".cdx.json"):
        return path.name.removeprefix("sbom-").removesuffix(".cdx.json")
    return None


def _record_from_subject(subject: dict[str, Any], *, subdir: str) -> dict[str, Any]:
    return {
        "name": subject.get("name"),
        "version": subject.get("version"),
        "build": _component_property(subject, "conda:build"),
        "subdir": subdir,
        "conda_purl": subject.get("purl"),
        "flags": [],
    }


def _sbom_generated_at(sbom: dict[str, Any]) -> str | None:
    metadata = sbom.get("metadata")
    timestamp = metadata.get("timestamp") if isinstance(metadata, dict) else None
    return timestamp if isinstance(timestamp, str) else None


def _replace_current_reference(
    *, existing: dict[str, Any] | None, update: dict[str, Any] | None
) -> bool:
    if not isinstance(existing, dict) or not isinstance(update, dict):
        return True
    existing_generated_at = existing.get("generated_at")
    update_generated_at = update.get("generated_at")
    if isinstance(existing_generated_at, str):
        if not isinstance(update_generated_at, str):
            return False
        return update_generated_at >= existing_generated_at
    return True


def _current_sbom_record(record: dict[str, Any]) -> dict[str, Any] | None:
    sboms = record.get("sboms")
    if isinstance(sboms, dict):
        preferred = sboms.get("sbom.v1")
        if isinstance(preferred, dict):
            return preferred
        for value in sboms.values():
            if isinstance(value, dict):
                return value
    legacy = record.get("sbom")
    return legacy if isinstance(legacy, dict) else None


def _sbom_version_from_record(record: dict[str, Any]) -> str | None:
    sbom = _current_sbom_record(record)
    if not isinstance(sbom, dict):
        return None
    for key in ("version", "sbom_input_sha256", "input_sha256"):
        value = sbom.get(key)
        if isinstance(value, str):
            return value
    return None


def _same_source_sbom(*, sbom_current: Any, source_sbom: Any) -> bool:
    if not isinstance(sbom_current, str) or not isinstance(source_sbom, str):
        return False
    return source_sbom == sbom_current or source_sbom.endswith(f"/{sbom_current}")


def sbom_index_update_from_data(
    sbom: dict[str, Any], *, relative_path: str
) -> tuple[str, str, dict]:
    return sbom_index_update_from_artifact(
        sbom,
        security=None,
        artifact_sha256=None,
        artifact_size=None,
        relative_path=relative_path,
    )


def sbom_index_update_from_artifact(
    sbom: dict[str, Any],
    *,
    security: dict[str, Any] | None,
    artifact_sha256: str | None,
    artifact_size: int | None,
    relative_path: str,
) -> tuple[str, str, dict]:
    subject = _subject(sbom)
    path = Path(relative_path)
    subdir = _artifact_subdir(path)
    filename = _component_property(subject, "conda:filename") or _artifact_filename(path)
    version = _component_property(subject, "sbom-generator:version")
    version = version or _sbom_version_from_filename(path)
    component_purls = [
        component["purl"]
        for component in sbom.get("components") or []
        if isinstance(component, dict) and isinstance(component.get("purl"), str)
    ]
    record = _record_from_subject(subject, subdir=subdir)
    sbom_record = {
        "current": relative_path,
        "sha256": artifact_sha256,
        "size": artifact_size,
        "sbom_input_sha256": _component_property(
            subject, "sbom-generator:input-sha256"
        ),
        "mapping_sha256": _component_property(
            subject, "purl-associator:mapping-sha256"
        ),
        "component_purls": component_purls,
    }
    if version:
        sbom_record["version"] = version
    generated_at = _sbom_generated_at(sbom)
    if generated_at:
        sbom_record["generated_at"] = generated_at
    metadata = security.get("metadata") if isinstance(security, dict) else None
    schema = (
        metadata.get("data_schema")
        if isinstance(metadata, dict) and isinstance(metadata.get("data_schema"), str)
        else "sbom.v1"
    )
    created_on = metadata.get("created_on") if isinstance(metadata, dict) else None
    if isinstance(created_on, int):
        sbom_record["created_on"] = created_on
    parent_sha256 = metadata.get("parent_sha256") if isinstance(metadata, dict) else None
    if isinstance(parent_sha256, str):
        sbom_record["parent_sha256"] = parent_sha256
    record["sboms"] = {schema: sbom_record}
    return subdir, filename, record


def sbom_index_update(sbom_path: Path, *, channel_root: Path) -> tuple[str, str, dict]:
    relative_path = _relative(sbom_path, channel_root)
    if _is_security_sbom_relative_path(relative_path):
        sbom, security, artifact_sha256, artifact_size = (
            _load_security_sbom_artifact_path(sbom_path, channel_root=channel_root)
        )
        return sbom_index_update_from_artifact(
            sbom,
            security=security,
            artifact_sha256=artifact_sha256,
            artifact_size=artifact_size,
            relative_path=relative_path,
        )
    return sbom_index_update_from_data(_load_json_path(sbom_path), relative_path=relative_path)


def advisory_index_update_from_data(
    advisory: dict[str, Any], *, relative_path: str
) -> tuple[str, str, dict]:
    path = Path(relative_path)
    subdir = _artifact_subdir(path)
    filename = _artifact_filename(path)
    finding_ids = _finding_ids(advisory)
    vulnerabilities = vulnerabilities_from_advisory_payload(
        advisory,
        path=relative_path,
    )
    osv = {
        "current": relative_path,
        "source_sbom": advisory.get("source_sbom"),
        "correlation_version": advisory.get("correlation_version"),
        "query_count": advisory.get("query_count", 0),
        "vulnerability_count": advisory.get("vulnerability_count", 0),
        "finding_ids": finding_ids,
        "status": _osv_status(advisory),
    }
    if vulnerabilities:
        osv["vulnerabilities"] = vulnerabilities
    generated_at = advisory.get("generated_at")
    if isinstance(generated_at, str):
        osv["generated_at"] = generated_at
    subject = advisory.get("subject")
    record = (
        _record_from_subject(subject, subdir=subdir)
        if isinstance(subject, dict)
        else {"subdir": subdir, "flags": []}
    )
    record["osv"] = osv
    return subdir, filename, record


def advisory_index_update(
    advisory_path: Path, *, channel_root: Path
) -> tuple[str, str, dict]:
    relative_path = _relative(advisory_path, channel_root)
    if _is_security_advisories_relative_path(relative_path):
        advisory, _security, _artifact_sha256, _artifact_size = (
            _load_security_advisories_artifact_path(
                advisory_path,
                channel_root=channel_root,
            )
        )
        return advisory_index_update_from_data(advisory, relative_path=relative_path)
    return advisory_index_update_from_data(
        _load_json_path(advisory_path),
        relative_path=relative_path,
    )


def iter_sbom_paths(channel_root: Path) -> list[Path]:
    security = channel_root.glob("*/*.sboms/*.conda")
    versioned = channel_root.glob("*/sboms/*/sbom-*.cdx.json")
    legacy = channel_root.glob("*/sboms/*.cdx.json")
    return sorted([*security, *versioned, *legacy])


def iter_advisory_paths(channel_root: Path) -> list[Path]:
    security = channel_root.glob("*/*.advisories/*.conda")
    versioned = channel_root.glob("*/advisories/*/osv-*.json")
    legacy = channel_root.glob("*/advisories/*.osv*.json")
    return sorted([*security, *versioned, *legacy])


def _shard_name(*, filename: str, record: dict[str, Any]) -> str:
    name = record.get("name")
    return name if isinstance(name, str) and name else filename


def _sorted_packages(packages: dict[str, Any]) -> dict[str, Any]:
    return dict(sorted(packages.items()))


def _shard_payload(
    *,
    channel: str,
    subdir: str,
    name: str,
    packages: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": SHARD_SCHEMA_VERSION,
        "shard_format": SHARD_FORMAT,
        "channel": channel,
        "subdir": subdir,
        "package": name,
        "artifact_count": len(packages),
        "packages.conda": _sorted_packages(packages),
    }


def _shard_index_entry(
    *,
    shard_base_url: str,
    digest: str,
    size: int,
    artifact_count: int,
) -> dict[str, Any]:
    return {
        "sha256": digest,
        "path": f"{shard_base_url}{digest}.json",
        "size": size,
        "artifact_count": artifact_count,
    }


def _shard_relative_path(
    *,
    subdir_index: dict[str, Any],
    entry: Any,
) -> str | None:
    if isinstance(entry, str) and entry:
        digest = entry
        path = None
    elif isinstance(entry, dict):
        path = entry.get("path")
        digest = entry.get("sha256")
    else:
        return None
    if isinstance(path, str) and path:
        return path.lstrip("/")
    if not isinstance(digest, str) or not digest:
        return None
    base_url = subdir_index.get("shards_base_url")
    if not isinstance(base_url, str) or not base_url:
        base_url = f"{SHARDS_DIR}/"
    return f"{base_url.rstrip('/')}/{digest}.json"


def _load_packages_from_shards(
    *, subdir_index_path: Path, subdir_index: dict[str, Any]
) -> dict[str, Any]:
    shards = subdir_index.get("shards")
    if not isinstance(shards, dict):
        return {}
    packages: dict[str, Any] = {}
    for name, entry in sorted(shards.items()):
        shard_relative = _shard_relative_path(subdir_index=subdir_index, entry=entry)
        if not shard_relative:
            raise AdvisoryIndexError(
                f"{subdir_index_path}: invalid shard entry for package {name!r}"
            )
        shard_path = subdir_index_path.parent / shard_relative
        shard = _load_json_path(shard_path)
        shard_packages = shard.get("packages.conda")
        if not isinstance(shard_packages, dict):
            shard_packages = shard.get("packages")
        if not isinstance(shard_packages, dict):
            raise AdvisoryIndexError(f"{shard_path}: expected packages.conda object")
        packages.update(shard_packages)
    return packages


def _packages_from_subdir_index(
    *, subdir_index_path: Path, subdir_index: dict[str, Any]
) -> dict[str, Any]:
    packages = subdir_index.get("packages")
    if isinstance(packages, dict):
        return packages
    packages_conda = subdir_index.get("packages.conda")
    if isinstance(packages_conda, dict):
        return packages_conda
    return _load_packages_from_shards(
        subdir_index_path=subdir_index_path,
        subdir_index=subdir_index,
    )


@dataclass
class AdvisoryIndexState:
    channel_root: Path
    channel: str = DEFAULT_CHANNEL
    subdirs: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def load(
        cls, *, channel_root: Path, channel: str = DEFAULT_CHANNEL
    ) -> "AdvisoryIndexState":
        state = cls(channel_root=channel_root, channel=channel)
        for path in sorted(channel_root.glob(f"*/{SUBDIR_INDEX}")):
            data = _load_json_path(path)
            subdir = data.get("subdir")
            packages = _packages_from_subdir_index(
                subdir_index_path=path,
                subdir_index=data,
            )
            if isinstance(subdir, str) and isinstance(packages, dict):
                state.subdirs[subdir] = {
                    "schema_version": INDEX_SCHEMA_VERSION,
                    "generated_at": data.get("generated_at"),
                    "channel": data.get("channel") or channel,
                    "subdir": subdir,
                    "packages": packages,
                }
        return state

    def _subdir_index(self, subdir: str) -> dict[str, Any]:
        if subdir not in self.subdirs:
            self.subdirs[subdir] = {
                "schema_version": INDEX_SCHEMA_VERSION,
                "generated_at": _now(),
                "channel": self.channel,
                "subdir": subdir,
                "packages": {},
            }
        return self.subdirs[subdir]

    def update_sbom(self, path: Path) -> None:
        subdir, filename, update = sbom_index_update(
            path, channel_root=self.channel_root
        )
        self.update_sbom_record(subdir=subdir, filename=filename, update=update)

    def update_sbom_data(self, sbom: dict[str, Any], *, relative_path: str) -> None:
        subdir, filename, update = sbom_index_update_from_data(
            sbom, relative_path=relative_path
        )
        self.update_sbom_record(subdir=subdir, filename=filename, update=update)

    def update_sbom_record(
        self, *, subdir: str, filename: str, update: dict[str, Any]
    ) -> None:
        packages = self._subdir_index(subdir)["packages"]
        existing = (
            packages.get(filename) if isinstance(packages.get(filename), dict) else {}
        )
        record = {**existing, **update}
        merged_sboms = (
            dict(existing.get("sboms"))
            if isinstance(existing, dict) and isinstance(existing.get("sboms"), dict)
            else {}
        )
        update_sboms = update.get("sboms")
        if isinstance(update_sboms, dict):
            for schema, update_sbom in update_sboms.items():
                if not isinstance(schema, str) or not isinstance(update_sbom, dict):
                    continue
                existing_sbom = merged_sboms.get(schema)
                if not _replace_current_reference(
                    existing=existing_sbom if isinstance(existing_sbom, dict) else None,
                    update=update_sbom,
                ):
                    continue
                merged_sboms[schema] = update_sbom
        if merged_sboms:
            record["sboms"] = merged_sboms
        osv = record.get("osv")
        sbom_version = _sbom_version_from_record(record)
        sbom_current = (_current_sbom_record(record) or {}).get("current")
        osv_current = osv.get("current") if isinstance(osv, dict) else None
        source_sbom = osv.get("source_sbom") if isinstance(osv, dict) else None
        if isinstance(osv_current, str) and isinstance(sbom_version, str):
            if sbom_version not in Path(osv_current).name and not _same_source_sbom(
                sbom_current=sbom_current,
                source_sbom=source_sbom,
            ):
                record.pop("osv", None)
        packages[filename] = record

    def update_advisory(self, path: Path) -> None:
        subdir, filename, update = advisory_index_update(
            path, channel_root=self.channel_root
        )
        self.update_advisory_record(subdir=subdir, filename=filename, update=update)

    def update_advisory_data(
        self, advisory: dict[str, Any], *, relative_path: str
    ) -> None:
        subdir, filename, update = advisory_index_update_from_data(
            advisory, relative_path=relative_path
        )
        self.update_advisory_record(subdir=subdir, filename=filename, update=update)

    def update_advisory_record(
        self, *, subdir: str, filename: str, update: dict[str, Any]
    ) -> None:
        packages = self._subdir_index(subdir)["packages"]
        existing = (
            packages.get(filename) if isinstance(packages.get(filename), dict) else {}
        )
        sbom_version = _sbom_version_from_record(existing)
        sbom_current = (_current_sbom_record(existing) or {}).get("current")
        update_osv = update.get("osv")
        update_osv_current = (
            update_osv.get("current") if isinstance(update_osv, dict) else None
        )
        update_source_sbom = (
            update_osv.get("source_sbom") if isinstance(update_osv, dict) else None
        )
        if isinstance(sbom_version, str) and isinstance(update_osv_current, str):
            if sbom_version not in Path(update_osv_current).name and not _same_source_sbom(
                sbom_current=sbom_current,
                source_sbom=update_source_sbom,
            ):
                return
        existing_osv = existing.get("osv") if isinstance(existing, dict) else None
        if not _replace_current_reference(
            existing=existing_osv if isinstance(existing_osv, dict) else None,
            update=update_osv if isinstance(update_osv, dict) else None,
        ):
            return
        record = {**update, **existing}
        record["osv"] = update["osv"]
        packages[filename] = record

    def write(self) -> list[Path]:
        generated_at = _now()
        paths: list[Path] = []
        channel_index = {
            "schema_version": INDEX_SCHEMA_VERSION,
            "generated_at": generated_at,
            "channel": self.channel,
            "subdirs": {},
        }
        for subdir, index in sorted(self.subdirs.items()):
            packages = index.get("packages")
            if not isinstance(packages, dict):
                packages = {}
            shard_base_url = f"{SHARDS_DIR}/"
            shards: dict[str, dict[str, Any]] = {}
            packages_by_name: dict[str, dict[str, Any]] = {}
            for filename, record in _sorted_packages(packages).items():
                if not isinstance(record, dict):
                    continue
                name = _shard_name(filename=filename, record=record)
                packages_by_name.setdefault(name, {})[filename] = record
            for name, shard_packages in sorted(packages_by_name.items()):
                shard = _shard_payload(
                    channel=self.channel,
                    subdir=subdir,
                    name=name,
                    packages=shard_packages,
                )
                digest = _canonical_sha256(shard)
                shard_path = self.channel_root / subdir / SHARDS_DIR / f"{digest}.json"
                _write_canonical_json(shard_path, shard)
                paths.append(shard_path)
                shard_size = shard_path.stat().st_size
                shards[name] = _shard_index_entry(
                    shard_base_url=shard_base_url,
                    digest=digest,
                    size=shard_size,
                    artifact_count=len(shard_packages),
                )
            index = {
                "schema_version": INDEX_SCHEMA_VERSION,
                "generated_at": generated_at,
                "channel": self.channel,
                "info": {
                    "subdir": subdir,
                    "advisory_channel_version": INDEX_SCHEMA_VERSION,
                    "sharded": True,
                },
                "subdir": subdir,
                "advisory_base_urls": {
                    "sboms": "",
                    "shards": shard_base_url,
                },
                "shard_format": SHARD_FORMAT,
                "shards_base_url": shard_base_url,
                "package_count": len(packages),
                "package_name_count": len(shards),
                "shards": shards,
            }
            path = self.channel_root / subdir / SUBDIR_INDEX
            _write_json(path, index)
            paths.append(path)
            channel_index["subdirs"][subdir] = {
                "index": f"{subdir}/{SUBDIR_INDEX}",
                "package_count": len(packages),
                "package_name_count": len(shards),
                "sharded": True,
            }
        channel_path = self.channel_root / CHANNEL_INDEX
        _write_json(channel_path, channel_index)
        paths.append(channel_path)
        return paths


def build_indexes(*, channel_root: Path, channel: str) -> list[Path]:
    state = AdvisoryIndexState(channel_root=channel_root, channel=channel)
    sbom_paths = iter_sbom_paths(channel_root)
    advisory_paths = iter_advisory_paths(channel_root)
    LOGGER.info(
        "building advisory indexes channel_root=%s sboms=%d advisories=%d",
        channel_root,
        len(sbom_paths),
        len(advisory_paths),
    )
    for path in sbom_paths:
        LOGGER.debug("updating index from SBOM path=%s", path)
        state.update_sbom(path)
    for path in advisory_paths:
        LOGGER.debug("updating index from OSV advisory path=%s", path)
        state.update_advisory(path)
    return state.write()


def _load_inventory_objects(path: Path) -> list[str]:
    data = _load_json_path(path)
    objects = data.get("objects")
    if not isinstance(objects, list):
        raise AdvisoryIndexError(f"{path}: expected objects array")
    return sorted(path for path in objects if isinstance(path, str))


def _s3_source_paths(
    *,
    s3_uri: str,
    profile: str | None,
    region: str | None,
    sbom_inventory: Path | None,
    osv_inventory: Path | None,
    runner: Runner,
) -> tuple[list[str], list[str]]:
    all_paths: list[str] | None = None
    if sbom_inventory:
        sbom_paths = sorted(
            path
            for path in _load_inventory_objects(sbom_inventory)
            if is_sbom_artifact_path(path)
        )
    else:
        all_paths = list_s3_relative_paths(
            s3_uri=s3_uri,
            profile=profile,
            region=region,
            runner=runner,
        )
        sbom_paths = sorted(path for path in all_paths if is_sbom_artifact_path(path))

    if osv_inventory:
        advisory_paths = filter_osv_inventory_paths(
            _load_inventory_objects(osv_inventory)
        )
    else:
        if all_paths is None:
            all_paths = list_s3_relative_paths(
                s3_uri=s3_uri,
                profile=profile,
                region=region,
                runner=runner,
            )
        advisory_paths = filter_osv_inventory_paths(all_paths)
    return sbom_paths, advisory_paths


def read_s3_json(
    *,
    relative_path: str,
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    source = s3_uri_for_relative_path(relative_path=relative_path, s3_uri=s3_uri)
    aws_args = aws_global_args(profile=profile, region=region)
    LOGGER.info("reading S3 JSON source=%s", source)
    result = runner(
        [
            "aws",
            *aws_args,
            "s3",
            "cp",
            source,
            "-",
            "--only-show-errors",
            "--no-progress",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AdvisoryIndexError(
            f"could not read {source}: {(result.stderr or '').strip()}"
        )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AdvisoryIndexError(f"{source}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise AdvisoryIndexError(f"{source}: expected a JSON object")
    return data


def read_s3_bytes(
    *,
    relative_path: str,
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    runner: Runner = subprocess.run,
) -> bytes:
    source = s3_uri_for_relative_path(relative_path=relative_path, s3_uri=s3_uri)
    aws_args = aws_global_args(profile=profile, region=region)
    LOGGER.info("reading S3 bytes source=%s", source)
    result = runner(
        [
            "aws",
            *aws_args,
            "s3",
            "cp",
            source,
            "-",
            "--only-show-errors",
            "--no-progress",
        ],
        capture_output=True,
    )
    if result.returncode != 0:
        stderr = result.stderr
        if isinstance(stderr, bytes):
            stderr_text = stderr.decode(errors="replace")
        else:
            stderr_text = str(stderr or "")
        raise AdvisoryIndexError(f"could not read {source}: {stderr_text.strip()}")
    stdout = result.stdout
    if isinstance(stdout, bytes):
        return stdout
    return str(stdout or "").encode()


def read_s3_sbom(
    *,
    relative_path: str,
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    runner: Runner = subprocess.run,
) -> tuple[str, dict[str, Any], dict[str, Any] | None, str | None, int | None]:
    if _is_security_sbom_relative_path(relative_path):
        data = read_s3_bytes(
            relative_path=relative_path,
            s3_uri=s3_uri,
            profile=profile,
            region=region,
            runner=runner,
        )
        sbom, security, artifact_sha256, artifact_size = (
            _load_security_sbom_artifact_bytes(data, relative_path=relative_path)
        )
        return relative_path, sbom, security, artifact_sha256, artifact_size
    return (
        relative_path,
        read_s3_json(
            relative_path=relative_path,
            s3_uri=s3_uri,
            profile=profile,
            region=region,
            runner=runner,
        ),
        None,
        None,
        None,
    )


def read_s3_advisory(
    *,
    relative_path: str,
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    runner: Runner = subprocess.run,
) -> tuple[str, dict[str, Any]]:
    if _is_security_advisories_relative_path(relative_path):
        data = read_s3_bytes(
            relative_path=relative_path,
            s3_uri=s3_uri,
            profile=profile,
            region=region,
            runner=runner,
        )
        advisory, _security, _artifact_sha256, _artifact_size = (
            _load_security_advisories_artifact_bytes(
                data,
                relative_path=relative_path,
            )
        )
        return relative_path, advisory
    return (
        relative_path,
        read_s3_json(
            relative_path=relative_path,
            s3_uri=s3_uri,
            profile=profile,
            region=region,
            runner=runner,
        ),
    )


def read_s3_json_many(
    *,
    relative_paths: list[str],
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    workers: int = DEFAULT_WORKERS,
    runner: Runner = subprocess.run,
) -> list[tuple[str, dict[str, Any]]]:
    if workers < 1:
        raise AdvisoryIndexError("--workers must be at least 1")
    if workers == 1 or len(relative_paths) <= 1:
        return [
            (
                path,
                read_s3_json(
                    relative_path=path,
                    s3_uri=s3_uri,
                    profile=profile,
                    region=region,
                    runner=runner,
                ),
            )
            for path in relative_paths
        ]

    results: list[tuple[str, dict[str, Any]] | None] = [None] * len(relative_paths)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                read_s3_json,
                relative_path=path,
                s3_uri=s3_uri,
                profile=profile,
                region=region,
                runner=runner,
            ): index
            for index, path in enumerate(relative_paths)
        }
        for future in as_completed(futures):
            index = futures[future]
            results[index] = (relative_paths[index], future.result())
    return [result for result in results if result is not None]


def read_s3_advisory_many(
    *,
    relative_paths: list[str],
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    workers: int = DEFAULT_WORKERS,
    runner: Runner = subprocess.run,
) -> list[tuple[str, dict[str, Any]]]:
    if workers < 1:
        raise AdvisoryIndexError("--workers must be at least 1")
    if workers == 1 or len(relative_paths) <= 1:
        return [
            read_s3_advisory(
                relative_path=path,
                s3_uri=s3_uri,
                profile=profile,
                region=region,
                runner=runner,
            )
            for path in relative_paths
        ]

    results: list[tuple[str, dict[str, Any]] | None] = [None] * len(relative_paths)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                read_s3_advisory,
                relative_path=path,
                s3_uri=s3_uri,
                profile=profile,
                region=region,
                runner=runner,
            ): index
            for index, path in enumerate(relative_paths)
        }
        for future in as_completed(futures):
            index = futures[future]
            results[index] = future.result()
    return [result for result in results if result is not None]


def read_s3_sbom_many(
    *,
    relative_paths: list[str],
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    workers: int = DEFAULT_WORKERS,
    runner: Runner = subprocess.run,
) -> list[tuple[str, dict[str, Any], dict[str, Any] | None, str | None, int | None]]:
    if workers < 1:
        raise AdvisoryIndexError("--workers must be at least 1")
    if workers == 1 or len(relative_paths) <= 1:
        return [
            read_s3_sbom(
                relative_path=path,
                s3_uri=s3_uri,
                profile=profile,
                region=region,
                runner=runner,
            )
            for path in relative_paths
        ]

    results: list[
        tuple[str, dict[str, Any], dict[str, Any] | None, str | None, int | None]
        | None
    ] = [None] * len(relative_paths)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                read_s3_sbom,
                relative_path=path,
                s3_uri=s3_uri,
                profile=profile,
                region=region,
                runner=runner,
            ): index
            for index, path in enumerate(relative_paths)
        }
        for future in as_completed(futures):
            index = futures[future]
            results[index] = future.result()
    return [result for result in results if result is not None]


def build_indexes_from_s3(
    *,
    channel_root: Path,
    channel: str,
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    sbom_inventory: Path | None = None,
    osv_inventory: Path | None = None,
    workers: int = DEFAULT_WORKERS,
    runner: Runner = subprocess.run,
) -> list[Path]:
    sbom_paths, advisory_paths = _s3_source_paths(
        s3_uri=s3_uri,
        profile=profile,
        region=region,
        sbom_inventory=sbom_inventory,
        osv_inventory=osv_inventory,
        runner=runner,
    )
    LOGGER.info(
        "building advisory indexes from S3 s3_uri=%s sboms=%d advisories=%d",
        s3_uri,
        len(sbom_paths),
        len(advisory_paths),
    )
    state = AdvisoryIndexState(channel_root=channel_root, channel=channel)
    for relative_path, sbom, security, artifact_sha256, artifact_size in read_s3_sbom_many(
        relative_paths=sbom_paths,
        s3_uri=s3_uri,
        profile=profile,
        region=region,
        workers=workers,
        runner=runner,
    ):
        if security is None:
            state.update_sbom_data(sbom, relative_path=relative_path)
        else:
            subdir, filename, update = sbom_index_update_from_artifact(
                sbom,
                security=security,
                artifact_sha256=artifact_sha256,
                artifact_size=artifact_size,
                relative_path=relative_path,
            )
            state.update_sbom_record(subdir=subdir, filename=filename, update=update)
    for relative_path, advisory in read_s3_advisory_many(
        relative_paths=advisory_paths,
        s3_uri=s3_uri,
        profile=profile,
        region=region,
        workers=workers,
        runner=runner,
    ):
        state.update_advisory_data(advisory, relative_path=relative_path)
    return state.write()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--channel-root",
        type=Path,
        default=DEFAULT_LOCAL_CHANNEL,
        help="local advisory-channel root",
    )
    parser.add_argument("--channel", default=DEFAULT_CHANNEL, help="conda channel")
    parser.add_argument(
        "--s3-source-uri",
        help=(
            "optional s3://bucket/prefix advisory-channel source to rebuild indexes "
            "from current storage state"
        ),
    )
    parser.add_argument(
        "--s3-sbom-inventory",
        type=Path,
        help="local inventory from sbom:s3-inventory for --s3-source-uri",
    )
    parser.add_argument(
        "--s3-osv-inventory",
        type=Path,
        help="local inventory from osv:s3-inventory for --s3-source-uri",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="parallel S3 artifact reads when --s3-source-uri is set",
    )
    add_s3_args(parser, include_cleanup=False)
    add_logging_args(parser, command_name="advisory-index")
    args = parser.parse_args()
    log_path = configure_logging(
        command_name="advisory-index",
        log_level=args.log_level,
        log_file=args.log_file,
    )
    LOGGER.info(
        "starting advisory index build channel_root=%s channel=%s s3_source_uri=%s "
        "s3_uri=%s s3_dry_run=%s workers=%d",
        args.channel_root,
        args.channel,
        args.s3_source_uri,
        args.s3_uri,
        args.s3_dry_run,
        args.workers,
    )

    try:
        if (args.s3_sbom_inventory or args.s3_osv_inventory) and not args.s3_source_uri:
            raise AdvisoryIndexError(
                "--s3-sbom-inventory and --s3-osv-inventory require --s3-source-uri"
            )
        if args.s3_source_uri:
            index_paths = build_indexes_from_s3(
                channel_root=args.channel_root,
                channel=args.channel,
                s3_uri=args.s3_source_uri,
                profile=args.s3_profile,
                region=args.s3_region,
                sbom_inventory=args.s3_sbom_inventory,
                osv_inventory=args.s3_osv_inventory,
                workers=args.workers,
            )
        else:
            index_paths = build_indexes(
                channel_root=args.channel_root, channel=args.channel
            )
        if args.s3_uri:
            LOGGER.info(
                "publishing mutable advisory indexes/shards to S3 count=%d",
                len(index_paths),
            )
            summary = upload_files(
                local_paths=index_paths,
                root=args.channel_root,
                s3_uri=args.s3_uri,
                profile=args.s3_profile,
                region=args.s3_region,
                dry_run=args.s3_dry_run,
                overwrite=True,
                workers=args.s3_workers,
            )
            action = "would upload" if args.s3_dry_run else "uploaded"
            print(
                f"{action} {summary.uploaded} mutable index/shard file(s)",
                file=sys.stderr,
            )
    except (AdvisoryIndexError, S3PublishError) as exc:
        LOGGER.error("advisory index build failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)

    for path in index_paths:
        print(path)
    print(f"wrote {len(index_paths)} index/shard file(s)", file=sys.stderr)
    LOGGER.info("completed advisory index build count=%d", len(index_paths))
    print_log_location(log_path)


if __name__ == "__main__":
    main()
