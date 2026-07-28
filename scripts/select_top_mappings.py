"""Select a top-N mapping payload ranked by hydrated download counts.

The output is intentionally compatible with ``scripts.generate_sboms``: it is
still a purl-associator mapping JSON payload with a top-level ``packages``
object. Extra selection metadata is included for auditability but ignored by the
SBOM generator.
"""

from __future__ import annotations

import argparse
import copy
import json
import logging
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.cli_logging import add_logging_args, configure_logging, print_log_location
from scripts.generate_sbom import DEFAULT_MAPPING_PAYLOAD, purl_type
from scripts.s3_publish import (
    S3PublishError,
    add_s3_args,
    print_s3_summary,
    upload_files,
)

DEFAULT_OUT = Path(".tmp") / "top-1000-mappings.json"
DEFAULT_LIMIT = 1000
LOGGER = logging.getLogger("scripts.select_top_mappings")


class TopMappingsError(RuntimeError):
    """User-facing top mapping selection failure."""


@dataclass(frozen=True)
class SelectedPackage:
    rank: int
    name: str
    download_count: int
    entry: dict[str, Any]


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def load_mapping_payload(path: Path) -> dict[str, Any]:
    try:
        with path.open() as f:
            data = json.load(f)
    except FileNotFoundError as exc:
        raise TopMappingsError(f"{path}: file does not exist") from exc
    except json.JSONDecodeError as exc:
        raise TopMappingsError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise TopMappingsError(f"{path}: expected a JSON object")
    packages = data.get("packages")
    if not isinstance(packages, dict):
        raise TopMappingsError(f"{path}: expected packages object")
    return data


def _download_count(entry: dict[str, Any], *, include_missing: bool) -> int | None:
    value = entry.get("download_count")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return 0 if include_missing and value is None else None


def _has_usable_purl(entry: dict[str, Any]) -> bool:
    return isinstance(entry.get("purl"), str) and bool(entry.get("purl"))


def _purl_type_matches(entry: dict[str, Any], expected: str) -> bool:
    if expected == "any":
        return True
    purl = entry.get("purl")
    if not isinstance(purl, str) or not purl:
        return False
    return purl_type(purl) == expected


def select_top_packages(
    payload: dict[str, Any],
    *,
    limit: int = DEFAULT_LIMIT,
    purl_type_filter: str = "pypi",
    require_purl: bool = True,
    include_missing_downloads: bool = False,
) -> list[SelectedPackage]:
    if limit < 1:
        raise TopMappingsError("--limit must be at least 1")
    packages = payload.get("packages")
    if not isinstance(packages, dict):
        raise TopMappingsError("mapping payload must contain packages object")

    candidates: list[tuple[str, int, dict[str, Any]]] = []
    for name, raw_entry in packages.items():
        if not isinstance(name, str) or not isinstance(raw_entry, dict):
            continue
        entry = copy.deepcopy(raw_entry)
        if require_purl and not _has_usable_purl(entry):
            continue
        if not _purl_type_matches(entry, purl_type_filter):
            continue
        count = _download_count(entry, include_missing=include_missing_downloads)
        if count is None:
            continue
        candidates.append((name, count, entry))

    candidates.sort(key=lambda item: (-item[1], item[0]))
    return [
        SelectedPackage(rank=index, name=name, download_count=count, entry=entry)
        for index, (name, count, entry) in enumerate(candidates[:limit], start=1)
    ]


def build_top_mapping_payload(
    *,
    source_path: Path,
    source_payload: dict[str, Any],
    selected: list[SelectedPackage],
    limit: int,
    purl_type_filter: str,
    require_purl: bool,
    include_missing_downloads: bool,
) -> dict[str, Any]:
    packages: dict[str, dict[str, Any]] = {}
    selection: list[dict[str, Any]] = []
    for item in selected:
        entry = copy.deepcopy(item.entry)
        entry["selection_rank"] = item.rank
        entry["selection_download_count"] = item.download_count
        packages[item.name] = entry
        selection.append(
            {
                "rank": item.rank,
                "name": item.name,
                "download_count": item.download_count,
                "purl": entry.get("purl"),
            }
        )

    return {
        "schema_version": 1,
        "generated_at": _now(),
        "channel": source_payload.get("channel"),
        "package_count": len(packages),
        "packages": packages,
        "selection": {
            "source": str(source_path),
            "source_schema_version": source_payload.get("schema_version"),
            "ranking": "download_count_desc_name_asc",
            "requested_limit": limit,
            "selected_count": len(selected),
            "purl_type": purl_type_filter,
            "require_purl": require_purl,
            "include_missing_downloads": include_missing_downloads,
            "packages": selection,
        },
    }


def write_top_mapping_payload(payload: dict[str, Any], *, out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(f".{out.name}.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    tmp.replace(out)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mapping-json",
        type=Path,
        default=DEFAULT_MAPPING_PAYLOAD,
        help="input purl-associator mapping payload",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help="output reduced mapping payload",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help="number of packages to select",
    )
    parser.add_argument(
        "--purl-type",
        default="pypi",
        help="required mapped PURL type, or 'any'",
    )
    parser.add_argument(
        "--allow-missing-purl",
        action="store_true",
        help="include entries without a usable PURL",
    )
    parser.add_argument(
        "--include-missing-downloads",
        action="store_true",
        help="rank entries with missing/null download_count as zero",
    )
    add_s3_args(parser, include_cleanup=False)
    add_logging_args(parser, command_name="mappings-select-top")
    args = parser.parse_args()
    log_path = configure_logging(
        command_name="mappings-select-top",
        log_level=args.log_level,
        log_file=args.log_file,
    )
    LOGGER.info(
        "selecting top mappings mapping_json=%s out=%s limit=%d purl_type=%s "
        "allow_missing_purl=%s include_missing_downloads=%s s3_uri=%s",
        args.mapping_json,
        args.out,
        args.limit,
        args.purl_type,
        args.allow_missing_purl,
        args.include_missing_downloads,
        args.s3_uri,
    )
    try:
        source_payload = load_mapping_payload(args.mapping_json)
        selected = select_top_packages(
            source_payload,
            limit=args.limit,
            purl_type_filter=args.purl_type,
            require_purl=not args.allow_missing_purl,
            include_missing_downloads=args.include_missing_downloads,
        )
        if not selected:
            raise TopMappingsError("selection produced no packages")
        payload = build_top_mapping_payload(
            source_path=args.mapping_json,
            source_payload=source_payload,
            selected=selected,
            limit=args.limit,
            purl_type_filter=args.purl_type,
            require_purl=not args.allow_missing_purl,
            include_missing_downloads=args.include_missing_downloads,
        )
        out = write_top_mapping_payload(payload, out=args.out)
        if args.s3_uri:
            summary = upload_files(
                local_paths=[out],
                root=out.parent,
                s3_uri=args.s3_uri,
                profile=args.s3_profile,
                region=args.s3_region,
                dry_run=args.s3_dry_run,
                overwrite=True,
                workers=args.s3_workers,
            )
            print_s3_summary(summary, dry_run=args.s3_dry_run)
    except (TopMappingsError, S3PublishError) as exc:
        LOGGER.error("top mapping selection failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)

    first = selected[0]
    last = selected[-1]
    print(out)
    print(
        f"selected {len(selected)} package(s); "
        f"#1 {first.name}={first.download_count}; "
        f"#{len(selected)} {last.name}={last.download_count}",
        file=sys.stderr,
    )
    print_log_location(log_path)
    LOGGER.info(
        "completed top mapping selection out=%s selected=%d first=%s last=%s",
        out,
        len(selected),
        first.name,
        last.name,
    )


if __name__ == "__main__":
    main()
