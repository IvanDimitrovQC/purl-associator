"""Summarize SBOM artifacts in a local or S3 advisory channel."""

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
from scripts.s3_publish import (
    S3PublishError,
    add_s3_args,
    list_s3_relative_paths,
    load_s3_object_inventory,
)
from scripts.s3_sbom_inventory import (
    filter_sbom_inventory_paths,
    is_sbom_artifact_path,
)

DEFAULT_CHANNEL_ROOT = Path("local-advisory-channel")
DEFAULT_OUTPUT_PATH = Path(".tmp") / "sbom-summary.json"
LOGGER = logging.getLogger("scripts.sbom_summary")


class SbomSummaryError(RuntimeError):
    """User-facing SBOM summary failure."""


@dataclass(frozen=True)
class CondaArtifactName:
    package: str
    version: str
    build: str


@dataclass
class ArtifactSummary:
    subdir: str
    filename: str
    package: str | None
    version: str | None
    build: str | None
    sbom_versions: set[str] = field(default_factory=set)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _write_json(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)
    return path


def parse_conda_artifact_filename(filename: str) -> CondaArtifactName | None:
    stem = filename
    if stem.endswith(".tar.bz2"):
        stem = stem[: -len(".tar.bz2")]
    elif stem.endswith(".conda"):
        stem = stem[: -len(".conda")]
    else:
        return None

    parts = stem.rsplit("-", 2)
    if len(parts) != 3 or not all(parts):
        return None
    package, version, build = parts
    return CondaArtifactName(package=package, version=version, build=build)


def _sbom_version_from_path(path: str) -> str | None:
    name = Path(path).name
    if name.startswith("sbom-") and name.endswith(".cdx.json"):
        return name.removeprefix("sbom-").removesuffix(".cdx.json")
    stem = name.removesuffix(".conda")
    if (
        name.endswith(".conda")
        and len(stem) == 64
        and all(char in "0123456789abcdef" for char in stem)
    ):
        return stem
    return None


def _artifact_key(path: str) -> tuple[str, str] | None:
    parts = Path(path).parts
    if len(parts) >= 3 and parts[1].endswith(".sboms"):
        filename = f"{parts[1].removesuffix('.sboms')}.conda"
        return parts[0], filename
    if len(parts) >= 4 and parts[1] == "sboms":
        return parts[0], parts[2]
    return None


def local_sbom_paths(channel_root: Path) -> list[str]:
    if not channel_root.exists():
        return []
    paths = [
        *channel_root.glob("*/*.sboms/*.conda"),
        *channel_root.glob("*/sboms/*/sbom-*.cdx.json"),
    ]
    out: list[str] = []
    for path in paths:
        try:
            out.append(path.resolve().relative_to(channel_root.resolve()).as_posix())
        except ValueError:
            continue
    return sorted(dict.fromkeys(out))


def s3_sbom_paths(
    *,
    s3_uri: str,
    profile: str | None,
    region: str | None,
    inventory_path: Path | None,
) -> list[str]:
    if inventory_path:
        try:
            paths = sorted(load_s3_object_inventory(inventory_path))
        except S3PublishError as exc:
            raise SbomSummaryError(str(exc)) from exc
        LOGGER.info(
            "loaded S3 SBOM inventory path=%s objects=%d", inventory_path, len(paths)
        )
    else:
        try:
            paths = list_s3_relative_paths(
                s3_uri=s3_uri,
                profile=profile,
                region=region,
            )
        except S3PublishError as exc:
            raise SbomSummaryError(str(exc)) from exc
    return filter_sbom_inventory_paths(paths)


def _artifact_summary(subdir: str, filename: str) -> ArtifactSummary:
    parsed = parse_conda_artifact_filename(filename)
    return ArtifactSummary(
        subdir=subdir,
        filename=filename,
        package=parsed.package if parsed else None,
        version=parsed.version if parsed else None,
        build=parsed.build if parsed else None,
    )


def _sorted_list(values: set[str]) -> list[str]:
    return sorted(values)


def _artifact_payload(artifact: ArtifactSummary) -> dict[str, Any]:
    return {
        "subdir": artifact.subdir,
        "filename": artifact.filename,
        "package": artifact.package,
        "version": artifact.version,
        "build": artifact.build,
        "sbom_count": len(artifact.sbom_versions),
        "sbom_versions": _sorted_list(artifact.sbom_versions),
    }


def _empty_package_summary() -> dict[str, Any]:
    return {
        "artifact_count": 0,
        "sbom_count": 0,
        "subdirs": set(),
        "versions": {},
    }


def _empty_version_summary() -> dict[str, Any]:
    return {
        "artifact_count": 0,
        "sbom_count": 0,
        "subdirs": set(),
    }


def _add_artifact_to_package(
    packages: dict[str, dict[str, Any]], artifact: ArtifactSummary
) -> None:
    if not artifact.package or not artifact.version:
        return
    package = packages.setdefault(artifact.package, _empty_package_summary())
    version = package["versions"].setdefault(artifact.version, _empty_version_summary())

    package["artifact_count"] += 1 if artifact.sbom_versions else 0
    package["sbom_count"] += len(artifact.sbom_versions)
    package["subdirs"].add(artifact.subdir)

    version["artifact_count"] += 1 if artifact.sbom_versions else 0
    version["sbom_count"] += len(artifact.sbom_versions)
    version["subdirs"].add(artifact.subdir)


def _finalize_packages(packages: dict[str, dict[str, Any]]) -> dict[str, Any]:
    finalized: dict[str, Any] = {}
    for package_name, package in sorted(packages.items()):
        versions = {}
        for version, data in sorted(package["versions"].items()):
            versions[version] = {
                **{k: v for k, v in data.items() if k != "subdirs"},
                "subdirs": sorted(data["subdirs"]),
            }
        finalized[package_name] = {
            **{k: v for k, v in package.items() if k not in {"subdirs", "versions"}},
            "subdir_count": len(package["subdirs"]),
            "subdirs": sorted(package["subdirs"]),
            "version_count": len(versions),
            "versions": versions,
        }
    return finalized


def _subdir_counts(artifacts: list[ArtifactSummary]) -> dict[str, dict[str, int]]:
    subdirs: dict[str, dict[str, int]] = {}
    for artifact in artifacts:
        item = subdirs.setdefault(
            artifact.subdir,
            {
                "artifact_count": 0,
                "sbom_count": 0,
            },
        )
        item["artifact_count"] += 1 if artifact.sbom_versions else 0
        item["sbom_count"] += len(artifact.sbom_versions)
    return dict(sorted(subdirs.items()))


def sbom_summary_payload(
    *,
    paths: list[str],
    source: dict[str, Any],
    include_artifacts: bool = False,
) -> dict[str, Any]:
    groups: dict[tuple[str, str], ArtifactSummary] = {}
    ignored = 0
    for path in filter_sbom_inventory_paths(paths):
        key = _artifact_key(path)
        if key is None:
            ignored += 1
            continue
        subdir, filename = key
        artifact = groups.setdefault(key, _artifact_summary(subdir, filename))
        if is_sbom_artifact_path(path):
            version = _sbom_version_from_path(path)
            if version:
                artifact.sbom_versions.add(version)

    artifacts = sorted(groups.values(), key=lambda item: (item.subdir, item.filename))
    packages: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        _add_artifact_to_package(packages, artifact)

    sbom_count = sum(len(artifact.sbom_versions) for artifact in artifacts)
    artifact_count = sum(1 for artifact in artifacts if artifact.sbom_versions)
    unparsed_artifact_count = sum(
        1 for artifact in artifacts if artifact.sbom_versions and not artifact.package
    )

    payload: dict[str, Any] = {
        "schema_version": 2,
        "generated_at": _now(),
        "source": source,
        "object_count": sbom_count,
        "sbom_count": sbom_count,
        "artifact_count": artifact_count,
        "package_count": len(packages),
        "unparsed_artifact_count": unparsed_artifact_count,
        "ignored_path_count": ignored,
        "subdirs": _subdir_counts(artifacts),
        "packages": _finalize_packages(packages),
    }
    if include_artifacts:
        payload["artifacts"] = [
            _artifact_payload(artifact)
            for artifact in artifacts
            if artifact.sbom_versions
        ]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help="local SBOM summary JSON output path",
    )
    parser.add_argument(
        "--channel-root",
        type=Path,
        default=DEFAULT_CHANNEL_ROOT,
        help="local advisory channel root when --s3-uri is not provided",
    )
    parser.add_argument(
        "--s3-sbom-inventory",
        type=Path,
        help="optional local inventory from sbom:s3-inventory",
    )
    parser.add_argument(
        "--include-artifacts",
        action="store_true",
        help="include per-artifact details; default summary is package-level",
    )
    add_s3_args(parser, include_cleanup=False, include_dry_run=False)
    add_logging_args(parser, command_name="sbom-summary")
    args = parser.parse_args()
    log_path = configure_logging(
        command_name="sbom-summary",
        log_level=args.log_level,
        log_file=args.log_file,
    )

    try:
        if args.s3_sbom_inventory and not args.s3_uri:
            raise SbomSummaryError("--s3-sbom-inventory requires --s3-uri")
        if args.s3_uri:
            LOGGER.info(
                "building S3 SBOM summary s3_uri=%s inventory=%s out=%s",
                args.s3_uri,
                args.s3_sbom_inventory,
                args.out,
            )
            paths = s3_sbom_paths(
                s3_uri=args.s3_uri,
                profile=args.s3_profile,
                region=args.s3_region,
                inventory_path=args.s3_sbom_inventory,
            )
            source = {
                "type": "s3",
                "s3_uri": args.s3_uri,
                "inventory": str(args.s3_sbom_inventory)
                if args.s3_sbom_inventory
                else None,
            }
        else:
            LOGGER.info(
                "building local SBOM summary channel_root=%s out=%s",
                args.channel_root,
                args.out,
            )
            paths = local_sbom_paths(args.channel_root)
            source = {"type": "local", "channel_root": str(args.channel_root)}

        payload = sbom_summary_payload(
            paths=paths,
            source=source,
            include_artifacts=args.include_artifacts,
        )
        out = _write_json(args.out, payload)
    except (SbomSummaryError, S3PublishError) as exc:
        LOGGER.error("SBOM summary failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)

    print(out)
    print(
        "wrote SBOM summary "
        f"with {payload['sbom_count']} SBOM(s), "
        f"{payload['artifact_count']} artifact(s), "
        f"{payload['package_count']} package(s)",
        file=sys.stderr,
    )
    LOGGER.info(
        "completed SBOM summary out=%s sboms=%d artifacts=%d packages=%d",
        out,
        payload["sbom_count"],
        payload["artifact_count"],
        payload["package_count"],
    )
    print_log_location(log_path)


if __name__ == "__main__":
    main()
