"""Write a local inventory of OSV advisory artifacts already present in S3."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.cli_logging import add_logging_args, configure_logging, print_log_location
from scripts.s3_publish import S3PublishError, add_s3_args, list_s3_relative_paths

DEFAULT_INVENTORY_PATH = Path(".tmp") / "s3-osv-inventory.json"
LOGGER = logging.getLogger("scripts.s3_osv_inventory")


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


def is_osv_related_artifact_path(path: str) -> bool:
    if is_osv_advisory_path(path):
        return True
    name = Path(path).name
    parts = Path(path).parts
    if not (
        name.endswith(".conda")
        and len(name.removesuffix(".conda")) == 64
        and all(char in "0123456789abcdef" for char in name.removesuffix(".conda"))
    ):
        return False
    return (
        (len(parts) >= 3 and parts[0] == "cves")
        or (len(parts) >= 4 and parts[-3].endswith(".matches"))
    )


def filter_osv_inventory_paths(paths: list[str]) -> list[str]:
    return sorted(path for path in dict.fromkeys(paths) if is_osv_advisory_path(path))


def filter_osv_related_inventory_paths(paths: list[str]) -> list[str]:
    return sorted(
        path for path in dict.fromkeys(paths) if is_osv_related_artifact_path(path)
    )


def osv_inventory_payload(*, s3_uri: str, object_paths: list[str]) -> dict[str, Any]:
    advisory_count = sum(1 for path in object_paths if is_osv_advisory_path(path))
    return {
        "schema_version": 2,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "s3_uri": s3_uri,
        "object_count": len(object_paths),
        "advisory_count": advisory_count,
        "objects": object_paths,
    }


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
        payload = osv_inventory_payload(s3_uri=args.s3_uri, object_paths=object_paths)
        out = write_inventory(payload=payload, out=args.out)
    except S3PublishError as exc:
        LOGGER.error("S3 OSV inventory failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)

    print(out)
    print(
        f"wrote S3 OSV inventory with {payload['advisory_count']} advisory file(s)",
        file=sys.stderr,
    )
    LOGGER.info(
        "completed S3 OSV inventory out=%s advisories=%d objects=%d",
        out,
        payload["advisory_count"],
        payload["object_count"],
    )
    print_log_location(log_path)


if __name__ == "__main__":
    main()
