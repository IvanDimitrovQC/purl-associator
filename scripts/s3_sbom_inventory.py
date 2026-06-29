"""Write a local inventory of SBOM artifacts already present in S3."""

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

DEFAULT_INVENTORY_PATH = Path(".tmp") / "s3-sbom-inventory.json"
LOGGER = logging.getLogger("scripts.s3_sbom_inventory")


def is_sbom_artifact_path(path: str) -> bool:
    name = Path(path).name
    return "/sboms/" in path and name.startswith("sbom-") and name.endswith(".cdx.json")


def is_sbom_event_path(path: str) -> bool:
    name = Path(path).name
    return "/sboms/" in path and name.startswith("event-") and name.endswith(".json")


def filter_sbom_inventory_paths(paths: list[str]) -> list[str]:
    return sorted(
        path
        for path in dict.fromkeys(paths)
        if is_sbom_artifact_path(path) or is_sbom_event_path(path)
    )


def sbom_inventory_payload(*, s3_uri: str, object_paths: list[str]) -> dict[str, Any]:
    sbom_count = sum(1 for path in object_paths if is_sbom_artifact_path(path))
    event_count = sum(1 for path in object_paths if is_sbom_event_path(path))
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "s3_uri": s3_uri,
        "object_count": len(object_paths),
        "sbom_count": sbom_count,
        "event_count": event_count,
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
        payload = sbom_inventory_payload(s3_uri=args.s3_uri, object_paths=object_paths)
        out = write_inventory(payload=payload, out=args.out)
    except S3PublishError as exc:
        LOGGER.error("S3 SBOM inventory failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)

    print(out)
    print(
        "wrote S3 SBOM inventory "
        f"with {payload['sbom_count']} SBOM(s), "
        f"{payload['event_count']} event file(s)",
        file=sys.stderr,
    )
    LOGGER.info(
        "completed S3 SBOM inventory out=%s sboms=%d events=%d objects=%d",
        out,
        payload["sbom_count"],
        payload["event_count"],
        payload["object_count"],
    )
    print_log_location(log_path)


if __name__ == "__main__":
    main()
