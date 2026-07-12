"""Build mutable advisory-channel indexes from SBOM and OSV artifacts."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import logging
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.cli_logging import add_logging_args, configure_logging, print_log_location
from scripts.generate_sbom import DEFAULT_CHANNEL, DEFAULT_LOCAL_CHANNEL
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

INDEX_SCHEMA_VERSION = 2
SHARD_SCHEMA_VERSION = 1
CHANNEL_INDEX = "channel-index.json"
SUBDIR_INDEX = "advisory-repodata.json"
SHARDS_DIR = "advisory-repodata-shards"
SHARD_FORMAT = "advisory-repodata-shards-v1"
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


def _subject(sbom: dict[str, Any]) -> dict[str, Any]:
    metadata = sbom.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(component, dict):
        raise AdvisoryIndexError("SBOM metadata.component is missing")
    return component


def _artifact_filename(path: Path) -> str:
    if path.parent.parent.name in {"sboms", "advisories"}:
        return path.parent.name
    return path.name.removesuffix(".cdx.json").removesuffix(".osv.json")


def _artifact_subdir(path: Path) -> str:
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


def sbom_index_update_from_data(
    sbom: dict[str, Any], *, relative_path: str
) -> tuple[str, str, dict]:
    subject = _subject(sbom)
    path = Path(relative_path)
    subdir = _artifact_subdir(path)
    filename = _artifact_filename(path)
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
        "version": version,
        "input_sha256": _component_property(subject, "sbom-generator:input-sha256"),
        "mapping_sha256": _component_property(
            subject, "purl-associator:mapping-sha256"
        ),
        "component_purls": component_purls,
    }
    generated_at = _sbom_generated_at(sbom)
    if generated_at:
        sbom_record["generated_at"] = generated_at
    record["sbom"] = sbom_record
    return subdir, filename, record


def sbom_index_update(sbom_path: Path, *, channel_root: Path) -> tuple[str, str, dict]:
    return sbom_index_update_from_data(
        _load_json_path(sbom_path),
        relative_path=_relative(sbom_path, channel_root),
    )


def advisory_index_update_from_data(
    advisory: dict[str, Any], *, relative_path: str
) -> tuple[str, str, dict]:
    path = Path(relative_path)
    subdir = _artifact_subdir(path)
    filename = _artifact_filename(path)
    finding_ids = _finding_ids(advisory)
    osv = {
        "current": relative_path,
        "correlation_version": advisory.get("correlation_version"),
        "query_count": advisory.get("query_count", 0),
        "vulnerability_count": advisory.get("vulnerability_count", 0),
        "finding_ids": finding_ids,
        "status": _osv_status(advisory),
    }
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
    return advisory_index_update_from_data(
        _load_json_path(advisory_path),
        relative_path=_relative(advisory_path, channel_root),
    )


def iter_sbom_paths(channel_root: Path) -> list[Path]:
    versioned = channel_root.glob("*/sboms/*/sbom-*.cdx.json")
    legacy = channel_root.glob("*/sboms/*.cdx.json")
    return sorted([*versioned, *legacy])


def iter_advisory_paths(channel_root: Path) -> list[Path]:
    versioned = channel_root.glob("*/advisories/*/osv-*.json")
    legacy = channel_root.glob("*/advisories/*.osv*.json")
    return sorted([*versioned, *legacy])


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
        "name": name,
        "artifact_count": len(packages),
        "packages": _sorted_packages(packages),
    }


def _shard_index_entry(
    *,
    shard_base_url: str,
    digest: str,
    artifact_count: int,
) -> dict[str, Any]:
    return {
        "sha256": digest,
        "path": f"{shard_base_url}{digest}.json",
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
        shard_packages = shard.get("packages")
        if not isinstance(shard_packages, dict):
            raise AdvisoryIndexError(f"{shard_path}: expected packages object")
        packages.update(shard_packages)
    return packages


def _packages_from_subdir_index(
    *, subdir_index_path: Path, subdir_index: dict[str, Any]
) -> dict[str, Any]:
    packages = subdir_index.get("packages")
    if isinstance(packages, dict):
        return packages
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
        existing_sbom = existing.get("sbom") if isinstance(existing, dict) else None
        update_sbom = update.get("sbom")
        if not _replace_current_reference(
            existing=existing_sbom if isinstance(existing_sbom, dict) else None,
            update=update_sbom if isinstance(update_sbom, dict) else None,
        ):
            return
        record = {**existing, **update}
        osv = record.get("osv")
        sbom_version = (record.get("sbom") or {}).get("version")
        osv_current = osv.get("current") if isinstance(osv, dict) else None
        if isinstance(osv_current, str) and isinstance(sbom_version, str):
            if sbom_version not in Path(osv_current).name:
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
        sbom = existing.get("sbom") if isinstance(existing, dict) else None
        sbom_version = sbom.get("version") if isinstance(sbom, dict) else None
        update_osv = update.get("osv")
        update_osv_current = (
            update_osv.get("current") if isinstance(update_osv, dict) else None
        )
        if isinstance(sbom_version, str) and isinstance(update_osv_current, str):
            if sbom_version not in Path(update_osv_current).name:
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
                shards[name] = _shard_index_entry(
                    shard_base_url=shard_base_url,
                    digest=digest,
                    artifact_count=len(shard_packages),
                )
            index = {
                "schema_version": INDEX_SCHEMA_VERSION,
                "generated_at": generated_at,
                "channel": self.channel,
                "subdir": subdir,
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
    for relative_path, sbom in read_s3_json_many(
        relative_paths=sbom_paths,
        s3_uri=s3_uri,
        profile=profile,
        region=region,
        workers=workers,
        runner=runner,
    ):
        state.update_sbom_data(sbom, relative_path=relative_path)
    for relative_path, advisory in read_s3_json_many(
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
