"""Write a local inventory of SBOM artifacts already present in S3."""

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
from scripts.generate_sbom import SECURITY_SBOM_PAYLOAD_NAME, SbomError, get_sbom_version
from scripts.s3_publish import (
    S3PublishError,
    add_s3_args,
    aws_global_args,
    list_s3_relative_paths,
    s3_uri_for_relative_path,
)

DEFAULT_INVENTORY_PATH = Path(".tmp") / "s3-sbom-inventory.json"
DEFAULT_WORKERS = 8
LOGGER = logging.getLogger("scripts.s3_sbom_inventory")
Runner = Callable[..., subprocess.CompletedProcess[str]]


def is_sbom_artifact_path(path: str) -> bool:
    name = Path(path).name
    if "/sboms/" in path and name.startswith("sbom-") and name.endswith(".cdx.json"):
        return True
    parts = Path(path).parts
    return (
        len(parts) >= 3
        and parts[-2].endswith(".sboms")
        and len(name.removesuffix(".conda")) == 64
        and name.endswith(".conda")
        and all(char in "0123456789abcdef" for char in name.removesuffix(".conda"))
    )


def filter_sbom_inventory_paths(paths: list[str]) -> list[str]:
    return sorted(path for path in dict.fromkeys(paths) if is_sbom_artifact_path(path))


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
    LOGGER.info("reading S3 SBOM metadata source=%s", source)
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


def read_s3_sbom_metadata(
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
            sbom = json.loads(archive.read(SECURITY_SBOM_PAYLOAD_NAME))
    except (KeyError, json.JSONDecodeError, zipfile.BadZipFile, SbomError) as exc:
        raise S3PublishError(f"{relative_path}: invalid SBOM artifact: {exc}") from exc
    if not isinstance(sbom, dict):
        raise S3PublishError(f"{relative_path}: SBOM payload must be an object")
    return (
        relative_path,
        {
            "path": relative_path,
            "artifact_dir": _artifact_dir(relative_path),
            "sbom_version": get_sbom_version(sbom),
        },
    )


def read_s3_sbom_metadata_many(
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
    if workers == 1 or len(relative_paths) <= 1:
        return dict(
            read_s3_sbom_metadata(
                relative_path=path,
                s3_uri=s3_uri,
                profile=profile,
                region=region,
                runner=runner,
            )
            for path in relative_paths
        )
    out: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                read_s3_sbom_metadata,
                relative_path=path,
                s3_uri=s3_uri,
                profile=profile,
                region=region,
                runner=runner,
            ): path
            for path in relative_paths
        }
        for future in as_completed(futures):
            path, metadata = future.result()
            out[path] = metadata
    return out


def _logical_sbom_index(
    sbom_metadata: dict[str, dict[str, Any]] | None,
) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    if not sbom_metadata:
        return index
    for path, metadata in sorted(sbom_metadata.items()):
        artifact_dir = metadata.get("artifact_dir")
        sbom_version = metadata.get("sbom_version")
        if not isinstance(artifact_dir, str) or not isinstance(sbom_version, str):
            continue
        index.setdefault(artifact_dir, {}).setdefault(sbom_version, path)
    return index


def sbom_inventory_payload(
    *,
    s3_uri: str,
    object_paths: list[str],
    sbom_metadata: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    sbom_count = sum(1 for path in object_paths if is_sbom_artifact_path(path))
    payload = {
        "schema_version": 3 if sbom_metadata is not None else 2,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "s3_uri": s3_uri,
        "object_count": len(object_paths),
        "sbom_count": sbom_count,
        "objects": object_paths,
    }
    if sbom_metadata is not None:
        payload["sboms"] = sbom_metadata
        payload["logical_sboms"] = _logical_sbom_index(sbom_metadata)
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
            "read each SBOM artifact and include its stable sbom-generator "
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
    add_logging_args(parser, command_name="sbom-s3-inventory")
    args = parser.parse_args()
    log_path = configure_logging(
        command_name="sbom-s3-inventory",
        log_level=args.log_level,
        log_file=args.log_file,
    )

    try:
        if not args.s3_uri:
            raise S3PublishError("--s3-uri is required")
        LOGGER.info(
            "building S3 SBOM inventory s3_uri=%s out=%s", args.s3_uri, args.out
        )
        all_paths = list_s3_relative_paths(
            s3_uri=args.s3_uri,
            profile=args.s3_profile,
            region=args.s3_region,
        )
        object_paths = filter_sbom_inventory_paths(all_paths)
        sbom_metadata = (
            read_s3_sbom_metadata_many(
                relative_paths=object_paths,
                s3_uri=args.s3_uri,
                profile=args.s3_profile,
                region=args.s3_region,
                workers=args.workers,
            )
            if args.include_metadata
            else None
        )
        payload = sbom_inventory_payload(
            s3_uri=args.s3_uri,
            object_paths=object_paths,
            sbom_metadata=sbom_metadata,
        )
        out = write_inventory(payload=payload, out=args.out)
    except S3PublishError as exc:
        LOGGER.error("S3 SBOM inventory failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)

    print(out)
    print(
        f"wrote S3 SBOM inventory with {payload['sbom_count']} SBOM(s)",
        file=sys.stderr,
    )
    LOGGER.info(
        "completed S3 SBOM inventory out=%s sboms=%d objects=%d",
        out,
        payload["sbom_count"],
        payload["object_count"],
    )
    print_log_location(log_path)


if __name__ == "__main__":
    main()
