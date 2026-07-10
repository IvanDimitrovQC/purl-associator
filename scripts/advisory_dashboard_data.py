"""Build a static JSON payload for the advisory dashboard."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.cli_logging import add_logging_args, configure_logging, print_log_location
from scripts.correlate_osv import osv_vulnerability_url
from scripts.generate_sboms import load_mapping_entries
from scripts.s3_publish import (
    Runner,
    S3PublishError,
    add_s3_args,
    aws_global_args,
    s3_uri_for_relative_path,
    upload_file,
)

DEFAULT_OUTPUT_PATH = Path("web") / "public" / "advisory-dashboard-data.json"
DEFAULT_MAPPING_JSON = Path("mappings") / "auto.json"
DEFAULT_OSV_SUMMARY = Path(".tmp") / "osv-vulnerability-summary.json"
DEFAULT_WORKERS = 8
ADVISORY_DASHBOARD_SCHEMA_VERSION = 2
LOGGER = logging.getLogger("scripts.advisory_dashboard_data")


class DashboardDataError(RuntimeError):
    """User-facing dashboard data generation failure."""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _load_json_path(path: Path) -> dict[str, Any]:
    try:
        with path.open() as f:
            data = json.load(f)
    except FileNotFoundError as exc:
        raise DashboardDataError(f"{path}: file does not exist") from exc
    except json.JSONDecodeError as exc:
        raise DashboardDataError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise DashboardDataError(f"{path}: expected a JSON object")
    return data


def _validate_workers(workers: int) -> None:
    if workers < 1:
        raise DashboardDataError("--workers must be at least 1")


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
        raise DashboardDataError(
            f"could not read {source}: {(result.stderr or '').strip()}"
        )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DashboardDataError(f"{source}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise DashboardDataError(f"{source}: expected a JSON object")
    return data


def load_s3_advisory_indexes(
    *,
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    workers: int = DEFAULT_WORKERS,
    runner: Runner = subprocess.run,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    _validate_workers(workers)
    channel_index = read_s3_json(
        relative_path="channel-index.json",
        s3_uri=s3_uri,
        profile=profile,
        region=region,
        runner=runner,
    )
    subdirs = channel_index.get("subdirs")
    if not isinstance(subdirs, dict):
        raise DashboardDataError("channel-index.json is missing subdirs object")

    index_paths: list[str] = []
    for value in subdirs.values():
        if isinstance(value, dict) and isinstance(value.get("index"), str):
            index_paths.append(value["index"])
    index_paths = sorted(dict.fromkeys(index_paths))
    LOGGER.info("loading subdir advisory indexes count=%d", len(index_paths))

    if workers == 1 or len(index_paths) <= 1:
        return channel_index, [
            read_s3_json(
                relative_path=path,
                s3_uri=s3_uri,
                profile=profile,
                region=region,
                runner=runner,
            )
            for path in index_paths
        ]

    indexes: list[dict[str, Any] | None] = [None] * len(index_paths)
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
            for index, path in enumerate(index_paths)
        }
        for future in as_completed(futures):
            indexes[futures[future]] = future.result()
    return channel_index, [index for index in indexes if index is not None]


def load_mapping_by_name(path: Path) -> dict[str, dict[str, Any]]:
    try:
        entries = load_mapping_entries(path)
    except Exception as exc:
        raise DashboardDataError(f"could not load mapping JSON {path}: {exc}") from exc
    return {name: mapping for name, mapping in entries}


def load_osv_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        LOGGER.warning("OSV vulnerability summary does not exist path=%s", path)
        return {
            "schema_version": 1,
            "packages": {},
            "vulnerability_count": 0,
            "package_count": 0,
        }
    data = _load_json_path(path)
    packages = data.get("packages")
    if not isinstance(packages, dict):
        raise DashboardDataError(f"{path}: expected packages object")
    return data


def _version_sort_key(version: str | None) -> tuple:
    if not version:
        return ()
    parts: list[tuple[int, int | str]] = []
    for part in re.split(r"([0-9]+)", version):
        if not part:
            continue
        if part.isdigit():
            parts.append((1, int(part)))
        else:
            parts.append((0, part.lower()))
    return tuple(parts)


def _unique_sorted(values: list[str]) -> list[str]:
    return sorted(dict.fromkeys(values))


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _bool_exists(path: Any) -> bool:
    return isinstance(path, str) and bool(path)


def _url_for_vulnerability(vulnerability_id: Any, explicit_url: Any) -> str | None:
    if isinstance(explicit_url, str) and explicit_url:
        return explicit_url
    if isinstance(vulnerability_id, str) and vulnerability_id:
        return osv_vulnerability_url(vulnerability_id)
    return None


def _vulnerability_id(vulnerability: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(vulnerability.get("id") or ""),
        str(vulnerability.get("component_purl") or ""),
        str(vulnerability.get("component_version") or ""),
    )


def vulnerability_indexes(
    osv_summary: dict[str, Any],
) -> tuple[
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
]:
    by_package: dict[str, list[dict[str, Any]]] = {}
    by_advisory: dict[str, list[dict[str, Any]]] = {}
    packages = osv_summary.get("packages")
    if not isinstance(packages, dict):
        return by_package, by_advisory
    for package, vulnerabilities in packages.items():
        if not isinstance(package, str) or not isinstance(vulnerabilities, list):
            continue
        cleaned: list[dict[str, Any]] = []
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue
            vuln_id = vulnerability.get("id")
            item = {
                "id": vuln_id,
                "component_purl": vulnerability.get("component_purl"),
                "component_name": vulnerability.get("component_name"),
                "component_version": vulnerability.get("component_version"),
                "modified": vulnerability.get("modified"),
                "url": _url_for_vulnerability(vuln_id, vulnerability.get("url")),
                "source_advisory": vulnerability.get("source_advisory"),
            }
            cleaned.append(item)
            source_advisory = item["source_advisory"]
            if isinstance(source_advisory, str):
                by_advisory.setdefault(source_advisory, []).append(item)
        by_package[package] = cleaned
    return by_package, by_advisory


def _placeholder_vulnerabilities(osv: dict[str, Any]) -> list[dict[str, Any]]:
    current = _string_or_none(osv.get("current"))
    out: list[dict[str, Any]] = []
    for finding_id in _as_list(osv.get("finding_ids")):
        if isinstance(finding_id, str):
            out.append(
                {
                    "id": finding_id,
                    "url": osv_vulnerability_url(finding_id),
                    "source_advisory": current,
                }
            )
    return out


def artifact_from_record(
    *,
    filename: str,
    record: dict[str, Any],
    vulnerabilities_by_advisory: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    sbom = _as_dict(record.get("sbom"))
    osv = _as_dict(record.get("osv"))
    sbom_current = _string_or_none(sbom.get("current"))
    osv_current = _string_or_none(osv.get("current"))
    vulnerabilities = (
        vulnerabilities_by_advisory.get(osv_current, []) if osv_current else []
    )
    if not vulnerabilities and int(osv.get("vulnerability_count") or 0) > 0:
        vulnerabilities = _placeholder_vulnerabilities(osv)
    vulnerability_count = int(osv.get("vulnerability_count") or len(vulnerabilities))
    return {
        "filename": filename,
        "name": record.get("name"),
        "version": record.get("version"),
        "subdir": record.get("subdir"),
        "build": record.get("build"),
        "conda_purl": record.get("conda_purl"),
        "component_purls": _as_list(sbom.get("component_purls")),
        "sbom": {
            "exists": _bool_exists(sbom_current),
            "path": sbom_current,
            "version": sbom.get("version"),
            "input_sha256": sbom.get("input_sha256"),
            "mapping_sha256": sbom.get("mapping_sha256"),
        },
        "osv": {
            "exists": _bool_exists(osv_current),
            "path": osv_current,
            "status": osv.get("status"),
            "correlation_version": osv.get("correlation_version"),
            "query_count": osv.get("query_count", 0),
            "vulnerability_count": vulnerability_count,
            "finding_ids": _as_list(osv.get("finding_ids")),
        },
        "vulnerabilities": sorted(vulnerabilities, key=_vulnerability_id),
    }


def artifacts_from_indexes(
    subdir_indexes: list[dict[str, Any]],
    *,
    vulnerabilities_by_advisory: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for index in subdir_indexes:
        packages = index.get("packages")
        if not isinstance(packages, dict):
            continue
        for filename, record in packages.items():
            if not isinstance(filename, str) or not isinstance(record, dict):
                continue
            artifacts.append(
                artifact_from_record(
                    filename=filename,
                    record=record,
                    vulnerabilities_by_advisory=vulnerabilities_by_advisory,
                )
            )
    artifacts.sort(
        key=lambda item: (
            str(item.get("name") or ""),
            _version_sort_key(_string_or_none(item.get("version"))),
            str(item.get("subdir") or ""),
            str(item.get("build") or ""),
            str(item.get("filename") or ""),
        )
    )
    return artifacts


def _dedupe_vulnerabilities(
    vulnerabilities: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for vulnerability in vulnerabilities:
        vuln_id = vulnerability.get("id")
        normalized = {
            **vulnerability,
            "url": _url_for_vulnerability(vuln_id, vulnerability.get("url")),
        }
        by_key.setdefault(_vulnerability_id(normalized), normalized)
    return [by_key[key] for key in sorted(by_key)]


def package_flags(
    *,
    has_purl: bool,
    artifact_count: int,
    sbom_existing: int,
    osv_existing: int,
    total_vulnerability_findings: int,
    latest_artifact_count: int,
    latest_osv_existing: int,
    latest_vulnerability_findings: int,
) -> list[str]:
    flags = ["has_purl" if has_purl else "missing_purl"]
    if artifact_count == 0 or sbom_existing == 0:
        flags.append("missing_sbom")
    elif sbom_existing < artifact_count:
        flags.append("partial_sbom")
    else:
        flags.append("has_sbom")

    if artifact_count == 0 or osv_existing == 0:
        flags.append("missing_osv")
    elif osv_existing < artifact_count:
        flags.append("partial_osv")
    else:
        flags.append("osv_checked")

    if total_vulnerability_findings > 0:
        flags.append("vulnerabilities_found")
    elif artifact_count > 0 and osv_existing == artifact_count:
        flags.append("no_known_vulnerabilities")

    if latest_artifact_count > 0:
        if latest_osv_existing == 0:
            flags.append("latest_version_missing_osv")
        elif latest_osv_existing < latest_artifact_count:
            flags.append("latest_version_partial_osv")
        elif latest_vulnerability_findings > 0:
            flags.append("latest_version_vulnerabilities_found")
        else:
            flags.append("latest_version_no_known_vulnerabilities")
    return flags


def build_package_payload(
    *,
    name: str,
    mapping: dict[str, Any] | None,
    artifacts: list[dict[str, Any]],
    summary_vulnerabilities: list[dict[str, Any]],
) -> dict[str, Any]:
    mapping = mapping or {}
    has_purl = isinstance(mapping.get("purl"), str) and bool(mapping.get("purl"))
    versions = _unique_sorted(
        [
            str(artifact.get("version"))
            for artifact in artifacts
            if artifact.get("version")
        ]
    )
    latest_version = max(versions, key=_version_sort_key) if versions else None
    latest_artifacts = [
        artifact for artifact in artifacts if artifact.get("version") == latest_version
    ]
    artifact_vulnerabilities = [
        vulnerability
        for artifact in artifacts
        for vulnerability in _as_list(artifact.get("vulnerabilities"))
        if isinstance(vulnerability, dict)
    ]
    vulnerabilities = _dedupe_vulnerabilities(
        [
            *artifact_vulnerabilities,
            *[
                vulnerability
                for vulnerability in summary_vulnerabilities
                if isinstance(vulnerability, dict)
            ],
        ]
    )

    artifact_count = len(artifacts)
    sbom_existing = sum(1 for artifact in artifacts if artifact["sbom"]["exists"])
    osv_existing = sum(1 for artifact in artifacts if artifact["osv"]["exists"])
    total_vulnerability_findings = sum(
        int(artifact["osv"].get("vulnerability_count") or 0) for artifact in artifacts
    )
    if total_vulnerability_findings == 0:
        total_vulnerability_findings = len(vulnerabilities)

    latest_osv_existing = sum(
        1 for artifact in latest_artifacts if artifact["osv"]["exists"]
    )
    latest_vulnerability_findings = sum(
        int(artifact["osv"].get("vulnerability_count") or 0)
        for artifact in latest_artifacts
    )
    return {
        "name": name,
        "mapped_purl": mapping.get("purl"),
        "purl_type": mapping.get("type"),
        "purl_confidence": mapping.get("confidence"),
        "has_purl": has_purl,
        "artifact_count": artifact_count,
        "version_count": len(versions),
        "subdir_count": len(
            _unique_sorted(
                [
                    str(artifact.get("subdir"))
                    for artifact in artifacts
                    if artifact.get("subdir")
                ]
            )
        ),
        "latest_version": latest_version,
        "latest_version_basis": "advisory_index" if latest_version else None,
        "sbom": {
            "any_exists": sbom_existing > 0,
            "all_artifacts_have_sbom": artifact_count > 0
            and sbom_existing == artifact_count,
            "missing_count": max(artifact_count - sbom_existing, 0),
        },
        "osv": {
            "any_artifact_checked": osv_existing > 0,
            "all_artifacts_checked": artifact_count > 0
            and osv_existing == artifact_count,
            "missing_count": max(artifact_count - osv_existing, 0),
            "any_vulnerabilities_found": total_vulnerability_findings > 0,
            "total_vulnerability_findings": total_vulnerability_findings,
            "unique_vulnerability_count": len(vulnerabilities),
            "no_vulnerabilities_found_for_any_artifact": (
                artifact_count > 0
                and osv_existing == artifact_count
                and total_vulnerability_findings == 0
            ),
            "vulnerabilities_found_in_any_artifact": total_vulnerability_findings > 0,
            "latest_version": latest_version,
            "latest_version_basis": "advisory_index" if latest_version else None,
            "latest_version_artifact_count": len(latest_artifacts),
            "latest_version_any_checked": latest_osv_existing > 0,
            "latest_version_all_checked": (
                bool(latest_artifacts) and latest_osv_existing == len(latest_artifacts)
            ),
            "latest_version_any_vulnerabilities_found": latest_vulnerability_findings
            > 0,
            "latest_version_total_vulnerability_findings": latest_vulnerability_findings,
        },
        "flags": package_flags(
            has_purl=has_purl,
            artifact_count=artifact_count,
            sbom_existing=sbom_existing,
            osv_existing=osv_existing,
            total_vulnerability_findings=total_vulnerability_findings,
            latest_artifact_count=len(latest_artifacts),
            latest_osv_existing=latest_osv_existing,
            latest_vulnerability_findings=latest_vulnerability_findings,
        ),
        "vulnerabilities": vulnerabilities,
        "artifacts": artifacts,
    }


def dashboard_payload(
    *,
    s3_uri: str,
    mapping_json: Path,
    osv_summary_path: Path,
    channel_index: dict[str, Any],
    subdir_indexes: list[dict[str, Any]],
    mappings: dict[str, dict[str, Any]],
    osv_summary: dict[str, Any],
) -> dict[str, Any]:
    vulnerabilities_by_package, vulnerabilities_by_advisory = vulnerability_indexes(
        osv_summary
    )
    artifacts = artifacts_from_indexes(
        subdir_indexes,
        vulnerabilities_by_advisory=vulnerabilities_by_advisory,
    )
    artifacts_by_package: dict[str, list[dict[str, Any]]] = {}
    for artifact in artifacts:
        name = artifact.get("name")
        if isinstance(name, str) and name:
            artifacts_by_package.setdefault(name, []).append(artifact)

    package_names = sorted(
        set(mappings) | set(artifacts_by_package) | set(vulnerabilities_by_package)
    )
    packages = {
        name: build_package_payload(
            name=name,
            mapping=mappings.get(name),
            artifacts=artifacts_by_package.get(name, []),
            summary_vulnerabilities=vulnerabilities_by_package.get(name, []),
        )
        for name in package_names
    }
    return {
        "schema_version": ADVISORY_DASHBOARD_SCHEMA_VERSION,
        "generated_at": _now(),
        "sources": {
            "s3_uri": s3_uri,
            "mapping_json": str(mapping_json),
            "osv_summary": str(osv_summary_path),
            "channel_index_generated_at": channel_index.get("generated_at"),
            "osv_summary_generated_at": osv_summary.get("generated_at"),
        },
        "counts": {
            "packages": len(packages),
            "artifacts": len(artifacts),
            "packages_with_purl": sum(
                1 for package in packages.values() if package["has_purl"]
            ),
            "packages_with_sbom": sum(
                1 for package in packages.values() if package["sbom"]["any_exists"]
            ),
            "packages_with_osv": sum(
                1
                for package in packages.values()
                if package["osv"]["any_artifact_checked"]
            ),
            "packages_with_vulnerabilities": sum(
                1
                for package in packages.values()
                if package["osv"]["any_vulnerabilities_found"]
            ),
            "vulnerability_findings": sum(
                int(package["osv"]["total_vulnerability_findings"])
                for package in packages.values()
            ),
        },
        "packages": packages,
    }


def write_dashboard_payload(*, payload: dict[str, Any], out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(f"{out.name}.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    tmp.replace(out)
    return out


def upload_dashboard_payload(
    *,
    out: Path,
    s3_output_uri: str,
    profile: str | None = None,
    region: str | None = None,
    runner: Runner = subprocess.run,
) -> str:
    result = upload_file(
        local_path=out,
        root=out.parent,
        s3_uri=s3_output_uri,
        profile=profile,
        region=region,
        overwrite=True,
        runner=runner,
    )
    return result.s3_uri


def build_dashboard_data(
    *,
    s3_uri: str,
    mapping_json: Path,
    osv_summary_path: Path,
    workers: int = DEFAULT_WORKERS,
    profile: str | None = None,
    region: str | None = None,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    channel_index, subdir_indexes = load_s3_advisory_indexes(
        s3_uri=s3_uri,
        profile=profile,
        region=region,
        workers=workers,
        runner=runner,
    )
    mappings = load_mapping_by_name(mapping_json)
    osv_summary = load_osv_summary(osv_summary_path)
    return dashboard_payload(
        s3_uri=s3_uri,
        mapping_json=mapping_json,
        osv_summary_path=osv_summary_path,
        channel_index=channel_index,
        subdir_indexes=subdir_indexes,
        mappings=mappings,
        osv_summary=osv_summary,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mapping-json",
        type=Path,
        default=DEFAULT_MAPPING_JSON,
        help="purl-associator mapping JSON",
    )
    parser.add_argument(
        "--osv-summary",
        type=Path,
        default=DEFAULT_OSV_SUMMARY,
        help="local OSV vulnerability summary JSON",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help="dashboard data JSON output path",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="parallel S3 advisory-index reads",
    )
    parser.add_argument(
        "--s3-output-uri",
        help=(
            "optional s3://bucket/prefix destination for the generated dashboard "
            "JSON; the output filename is written below this prefix"
        ),
    )
    add_s3_args(parser, include_cleanup=False, include_dry_run=False)
    add_logging_args(parser, command_name="advisory-dashboard-data")
    args = parser.parse_args()
    log_path = configure_logging(
        command_name="advisory-dashboard-data",
        log_level=args.log_level,
        log_file=args.log_file,
    )

    try:
        if not args.s3_uri:
            raise DashboardDataError("--s3-uri is required")
        LOGGER.info(
            "starting dashboard data build s3_uri=%s mapping_json=%s "
            "osv_summary=%s out=%s workers=%d s3_output_uri=%s",
            args.s3_uri,
            args.mapping_json,
            args.osv_summary,
            args.out,
            args.workers,
            args.s3_output_uri,
        )
        payload = build_dashboard_data(
            s3_uri=args.s3_uri,
            mapping_json=args.mapping_json,
            osv_summary_path=args.osv_summary,
            workers=args.workers,
            profile=args.s3_profile,
            region=args.s3_region,
        )
        out = write_dashboard_payload(payload=payload, out=args.out)
        uploaded_uri = (
            upload_dashboard_payload(
                out=out,
                s3_output_uri=args.s3_output_uri,
                profile=args.s3_profile,
                region=args.s3_region,
            )
            if args.s3_output_uri
            else None
        )
    except (DashboardDataError, S3PublishError) as exc:
        LOGGER.error("dashboard data build failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)

    print(out)
    print(
        "wrote advisory dashboard data "
        f"for {payload['counts']['packages']} package(s), "
        f"{payload['counts']['artifacts']} artifact(s)",
        file=sys.stderr,
    )
    if uploaded_uri:
        print(f"uploaded advisory dashboard data to {uploaded_uri}", file=sys.stderr)
    LOGGER.info(
        "completed dashboard data build out=%s packages=%d artifacts=%d "
        "vulnerability_findings=%d s3_output=%s",
        out,
        payload["counts"]["packages"],
        payload["counts"]["artifacts"],
        payload["counts"]["vulnerability_findings"],
        uploaded_uri,
    )
    print_log_location(log_path)


if __name__ == "__main__":
    main()
