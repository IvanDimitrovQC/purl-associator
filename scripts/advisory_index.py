"""Build mutable advisory-channel indexes from SBOM and OSV artifacts."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.cli_logging import add_logging_args, configure_logging, print_log_location
from scripts.generate_sbom import DEFAULT_CHANNEL, DEFAULT_LOCAL_CHANNEL
from scripts.s3_publish import (
    S3PublishError,
    add_s3_args,
    upload_files,
)

INDEX_SCHEMA_VERSION = 1
CHANNEL_INDEX = "channel-index.json"
SUBDIR_INDEX = "advisory-repodata.json"
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


def sbom_index_update(sbom_path: Path, *, channel_root: Path) -> tuple[str, str, dict]:
    sbom = _load_json_path(sbom_path)
    subject = _subject(sbom)
    subdir = _artifact_subdir(sbom_path)
    filename = _artifact_filename(sbom_path)
    version = _component_property(subject, "sbom-generator:version")
    version = version or _sbom_version_from_filename(sbom_path)
    component_purls = [
        component["purl"]
        for component in sbom.get("components") or []
        if isinstance(component, dict) and isinstance(component.get("purl"), str)
    ]
    record = _record_from_subject(subject, subdir=subdir)
    record["sbom"] = {
        "current": _relative(sbom_path, channel_root),
        "version": version,
        "input_sha256": _component_property(subject, "sbom-generator:input-sha256"),
        "mapping_sha256": _component_property(
            subject, "purl-associator:mapping-sha256"
        ),
        "component_purls": component_purls,
    }
    return subdir, filename, record


def advisory_index_update(
    advisory_path: Path, *, channel_root: Path
) -> tuple[str, str, dict]:
    advisory = _load_json_path(advisory_path)
    subdir = _artifact_subdir(advisory_path)
    filename = _artifact_filename(advisory_path)
    finding_ids = _finding_ids(advisory)
    osv = {
        "current": _relative(advisory_path, channel_root),
        "correlation_version": advisory.get("correlation_version"),
        "query_count": advisory.get("query_count", 0),
        "vulnerability_count": advisory.get("vulnerability_count", 0),
        "finding_ids": finding_ids,
        "status": _osv_status(advisory),
    }
    subject = advisory.get("subject")
    record = (
        _record_from_subject(subject, subdir=subdir)
        if isinstance(subject, dict)
        else {"subdir": subdir, "flags": []}
    )
    record["osv"] = osv
    return subdir, filename, record


def iter_sbom_paths(channel_root: Path) -> list[Path]:
    versioned = channel_root.glob("*/sboms/*/sbom-*.cdx.json")
    legacy = channel_root.glob("*/sboms/*.cdx.json")
    return sorted([*versioned, *legacy])


def iter_advisory_paths(channel_root: Path) -> list[Path]:
    versioned = channel_root.glob("*/advisories/*/osv-*.json")
    legacy = channel_root.glob("*/advisories/*.osv*.json")
    return sorted([*versioned, *legacy])


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
            packages = data.get("packages")
            if isinstance(subdir, str) and isinstance(packages, dict):
                state.subdirs[subdir] = data
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
        packages = self._subdir_index(subdir)["packages"]
        existing = (
            packages.get(filename) if isinstance(packages.get(filename), dict) else {}
        )
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
        packages = self._subdir_index(subdir)["packages"]
        existing = (
            packages.get(filename) if isinstance(packages.get(filename), dict) else {}
        )
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
            index.update(
                {
                    "schema_version": INDEX_SCHEMA_VERSION,
                    "generated_at": generated_at,
                    "channel": self.channel,
                    "subdir": subdir,
                    "package_count": len(packages),
                    "packages": dict(sorted(packages.items())),
                }
            )
            path = self.channel_root / subdir / SUBDIR_INDEX
            _write_json(path, index)
            paths.append(path)
            channel_index["subdirs"][subdir] = {
                "index": f"{subdir}/{SUBDIR_INDEX}",
                "package_count": len(packages),
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--channel-root",
        type=Path,
        default=DEFAULT_LOCAL_CHANNEL,
        help="local advisory-channel root",
    )
    parser.add_argument("--channel", default=DEFAULT_CHANNEL, help="conda channel")
    add_s3_args(parser, include_cleanup=False)
    add_logging_args(parser, command_name="advisory-index")
    args = parser.parse_args()
    log_path = configure_logging(
        command_name="advisory-index",
        log_level=args.log_level,
        log_file=args.log_file,
    )
    LOGGER.info(
        "starting advisory index build channel_root=%s channel=%s s3_uri=%s "
        "s3_dry_run=%s",
        args.channel_root,
        args.channel,
        args.s3_uri,
        args.s3_dry_run,
    )

    try:
        index_paths = build_indexes(
            channel_root=args.channel_root, channel=args.channel
        )
        if args.s3_uri:
            LOGGER.info(
                "publishing mutable advisory indexes to S3 count=%d",
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
                f"{action} {summary.uploaded} mutable index file(s)",
                file=sys.stderr,
            )
    except (AdvisoryIndexError, S3PublishError) as exc:
        LOGGER.error("advisory index build failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)

    for path in index_paths:
        print(path)
    print(f"wrote {len(index_paths)} index file(s)", file=sys.stderr)
    LOGGER.info("completed advisory index build count=%d", len(index_paths))
    print_log_location(log_path)


if __name__ == "__main__":
    main()
