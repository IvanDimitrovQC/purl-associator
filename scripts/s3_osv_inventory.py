"""Write a local inventory of OSV advisory artifacts already present in S3."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import io
import json
import logging
import subprocess
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from scripts.cli_logging import add_logging_args, configure_logging, print_log_location
from scripts.correlate_osv import (
    SECURITY_ADVISORIES_SCHEMA,
    SECURITY_CVE_SCHEMA,
    SECURITY_MATCH_SCHEMA,
    security_payload_semantic_hash,
)
from scripts.generate_sbom import (
    SECURITY_ADVISORIES_PAYLOAD_NAME,
    SECURITY_CVE_PAYLOAD_NAME,
    SECURITY_MATCH_PAYLOAD_NAME,
    SECURITY_METADATA_NAME,
)
from scripts.s3_publish import S3PublishError, add_s3_args, list_s3_relative_paths
from scripts.s3_publish import aws_global_args, s3_uri_for_relative_path

DEFAULT_INVENTORY_PATH = Path(".tmp") / "s3-osv-inventory.json"
DEFAULT_WORKERS = 8
LOGGER = logging.getLogger("scripts.s3_osv_inventory")
Runner = Callable[..., subprocess.CompletedProcess[str]]

PAYLOAD_BY_KIND = {
    "CVE": (SECURITY_CVE_SCHEMA, SECURITY_CVE_PAYLOAD_NAME),
    "MATCH": (SECURITY_MATCH_SCHEMA, SECURITY_MATCH_PAYLOAD_NAME),
    "ADVISORIES": (SECURITY_ADVISORIES_SCHEMA, SECURITY_ADVISORIES_PAYLOAD_NAME),
}


def is_osv_advisory_path(path: str) -> bool:
    name = Path(path).name
    parts = Path(path).parts
    if "/advisories/" in path and name.startswith("osv-") and name.endswith(".json"):
        return True
    return (
        len(parts) >= 3
        and parts[-2].endswith(".advisories")
        and name.endswith(".conda")
        and len(name.removesuffix(".conda")) == 64
        and all(char in "0123456789abcdef" for char in name.removesuffix(".conda"))
    )


def is_cve_artifact_path(path: str) -> bool:
    name = Path(path).name
    parts = Path(path).parts
    return (
        len(parts) >= 3
        and parts[0] == "cves"
        and name.endswith(".conda")
        and len(name.removesuffix(".conda")) == 64
        and all(char in "0123456789abcdef" for char in name.removesuffix(".conda"))
    )


def is_match_artifact_path(path: str) -> bool:
    name = Path(path).name
    parts = Path(path).parts
    return (
        len(parts) >= 4
        and parts[-3].endswith(".matches")
        and name.endswith(".conda")
        and len(name.removesuffix(".conda")) == 64
        and all(char in "0123456789abcdef" for char in name.removesuffix(".conda"))
    )


def is_osv_related_artifact_path(path: str) -> bool:
    if is_osv_advisory_path(path):
        return True
    return is_cve_artifact_path(path) or is_match_artifact_path(path)


def filter_osv_inventory_paths(paths: list[str]) -> list[str]:
    return sorted(path for path in dict.fromkeys(paths) if is_osv_advisory_path(path))


def filter_osv_related_inventory_paths(paths: list[str]) -> list[str]:
    return sorted(
        path for path in dict.fromkeys(paths) if is_osv_related_artifact_path(path)
    )


def _artifact_dir(path: str) -> str:
    return str(Path(path).parent).replace("\\", "/")


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
    LOGGER.info("reading S3 OSV metadata source=%s", source)
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
        raise S3PublishError(f"could not read {source}: {stderr_text.strip()}")
    stdout = result.stdout
    if isinstance(stdout, bytes):
        return stdout
    return str(stdout or "").encode()


def read_s3_osv_metadata(
    *,
    relative_path: str,
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    runner: Runner = subprocess.run,
) -> tuple[str, dict[str, Any]]:
    data = read_s3_bytes(
        relative_path=relative_path,
        s3_uri=s3_uri,
        profile=profile,
        region=region,
        runner=runner,
    )
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            security = json.loads(archive.read(SECURITY_METADATA_NAME))
            metadata = security.get("metadata") if isinstance(security, dict) else None
            kind = metadata.get("kind") if isinstance(metadata, dict) else None
            if not isinstance(kind, str) or kind not in PAYLOAD_BY_KIND:
                raise S3PublishError(f"{relative_path}: unsupported security kind")
            expected_schema, payload_name = PAYLOAD_BY_KIND[kind]
            data_schema = metadata.get("data_schema")
            if data_schema != expected_schema:
                raise S3PublishError(
                    f"{relative_path}: data_schema must be {expected_schema}"
                )
            payload = json.loads(archive.read(payload_name))
    except (KeyError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        raise S3PublishError(f"{relative_path}: invalid OSV artifact: {exc}") from exc
    if not isinstance(payload, dict):
        raise S3PublishError(f"{relative_path}: payload must be an object")
    semantic_version = security_payload_semantic_hash(
        payload,
        kind=kind,
        data_schema=expected_schema,
    )
    return (
        relative_path,
        {
            "path": relative_path,
            "artifact_dir": _artifact_dir(relative_path),
            "kind": kind,
            "data_schema": expected_schema,
            "semantic_version": semantic_version,
        },
    )


def read_s3_osv_metadata_many(
    *,
    relative_paths: list[str],
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    workers: int = DEFAULT_WORKERS,
    runner: Runner = subprocess.run,
) -> dict[str, dict[str, Any]]:
    if workers < 1:
        raise S3PublishError("--workers must be at least 1")
    artifact_paths = [
        path for path in relative_paths if Path(path).name.endswith(".conda")
    ]
    if workers == 1 or len(artifact_paths) <= 1:
        return dict(
            read_s3_osv_metadata(
                relative_path=path,
                s3_uri=s3_uri,
                profile=profile,
                region=region,
                runner=runner,
            )
            for path in artifact_paths
        )
    out: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                read_s3_osv_metadata,
                relative_path=path,
                s3_uri=s3_uri,
                profile=profile,
                region=region,
                runner=runner,
            ): path
            for path in artifact_paths
        }
        for future in as_completed(futures):
            path, metadata = future.result()
            out[path] = metadata
    return out


def _logical_osv_index(
    osv_metadata: dict[str, dict[str, Any]] | None,
) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    if not osv_metadata:
        return index
    for path, metadata in sorted(osv_metadata.items()):
        artifact_dir = metadata.get("artifact_dir")
        semantic_version = metadata.get("semantic_version")
        if not isinstance(artifact_dir, str) or not isinstance(semantic_version, str):
            continue
        index.setdefault(artifact_dir, {}).setdefault(semantic_version, path)
    return index


def osv_inventory_payload(
    *,
    s3_uri: str,
    object_paths: list[str],
    osv_metadata: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    advisory_count = sum(1 for path in object_paths if is_osv_advisory_path(path))
    cve_count = sum(1 for path in object_paths if is_cve_artifact_path(path))
    match_count = sum(1 for path in object_paths if is_match_artifact_path(path))
    payload = {
        "schema_version": 3 if osv_metadata is not None else 2,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "s3_uri": s3_uri,
        "object_count": len(object_paths),
        "cve_count": cve_count,
        "match_count": match_count,
        "advisory_count": advisory_count,
        "objects": object_paths,
    }
    if osv_metadata is not None:
        payload["artifacts"] = osv_metadata
        payload["logical_artifacts"] = _logical_osv_index(osv_metadata)
    return payload


def write_inventory(*, payload: dict[str, Any], out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(f"{out.name}.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    tmp.replace(out)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_INVENTORY_PATH,
        help="local JSON inventory output path",
    )
    parser.add_argument(
        "--include-metadata",
        action="store_true",
        help=(
            "read each security .conda artifact and include a stable semantic "
            "version for logical duplicate detection"
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="parallel S3 object reads when --include-metadata is set",
    )
    add_s3_args(parser, include_cleanup=False, include_dry_run=False)
    add_logging_args(parser, command_name="osv-s3-inventory")
    args = parser.parse_args()
    log_path = configure_logging(
        command_name="osv-s3-inventory",
        log_level=args.log_level,
        log_file=args.log_file,
    )

    try:
        if not args.s3_uri:
            raise S3PublishError("--s3-uri is required")
        LOGGER.info("building S3 OSV inventory s3_uri=%s out=%s", args.s3_uri, args.out)
        all_paths = list_s3_relative_paths(
            s3_uri=args.s3_uri,
            profile=args.s3_profile,
            region=args.s3_region,
        )
        object_paths = filter_osv_related_inventory_paths(all_paths)
        osv_metadata = (
            read_s3_osv_metadata_many(
                relative_paths=object_paths,
                s3_uri=args.s3_uri,
                profile=args.s3_profile,
                region=args.s3_region,
                workers=args.workers,
            )
            if args.include_metadata
            else None
        )
        payload = osv_inventory_payload(
            s3_uri=args.s3_uri,
            object_paths=object_paths,
            osv_metadata=osv_metadata,
        )
        out = write_inventory(payload=payload, out=args.out)
    except S3PublishError as exc:
        LOGGER.error("S3 OSV inventory failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)

    print(out)
    print(
        "wrote S3 OSV inventory with "
        f"{payload['cve_count']} CVE file(s), "
        f"{payload['match_count']} match file(s), and "
        f"{payload['advisory_count']} advisory file(s)",
        file=sys.stderr,
    )
    LOGGER.info(
        "completed S3 OSV inventory out=%s cves=%d matches=%d advisories=%d objects=%d",
        out,
        payload["cve_count"],
        payload["match_count"],
        payload["advisory_count"],
        payload["object_count"],
    )
    print_log_location(log_path)


if __name__ == "__main__":
    main()
