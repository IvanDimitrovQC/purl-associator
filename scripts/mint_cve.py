"""Mint a manual vulnerability record for one conda package artifact."""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from scripts.advisory_index import AdvisoryIndexState
from scripts.cli_logging import add_logging_args, configure_logging, print_log_location
from scripts.correlate_osv import write_advisory_artifacts
from scripts.generate_sbom import (
    DEFAULT_CHANNEL,
    DEFAULT_LOCAL_CHANNEL,
    read_security_sbom_payload,
)
from scripts.rust_crate_advisory_channel import (
    stage_existing_indexes_from_s3,
    update_indexes_for_paths,
)
from scripts.s3_publish import (
    S3PublishError,
    add_s3_args,
    cleanup_uploaded_files,
    download_file,
    list_s3_relative_paths,
    print_cleanup_summary,
    print_s3_summary,
    upload_files,
)

LOGGER = logging.getLogger("scripts.mint_cve")
DEFAULT_OUTPUT_ROOT = DEFAULT_LOCAL_CHANNEL
DEFAULT_ID_PREFIX = "CONDA"
CUSTOM_ID_RE = re.compile(r"^CONDA-(?P<year>[0-9]{4})-(?P<number>[0-9]{5})$")
SEVERITIES = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")


class MintCveError(RuntimeError):
    """User-facing custom CVE minting failure."""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _artifact_stem(filename: str) -> str:
    if filename.endswith(".tar.bz2"):
        return filename.removesuffix(".tar.bz2")
    if filename.endswith(".conda"):
        return filename.removesuffix(".conda")
    return Path(filename).stem


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise MintCveError(f"{path} is not under channel root {root}") from exc


def _load_json_path(path: Path) -> dict[str, Any]:
    try:
        with path.open() as f:
            data = json.load(f)
    except FileNotFoundError as exc:
        raise MintCveError(f"{path}: file does not exist") from exc
    except json.JSONDecodeError as exc:
        raise MintCveError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise MintCveError(f"{path}: expected a JSON object")
    return data


def _load_sbom(path: Path) -> dict[str, Any]:
    if path.name.endswith(".conda") and path.parent.name.endswith(".sboms"):
        try:
            return read_security_sbom_payload(path)
        except Exception as exc:
            raise MintCveError(str(exc)) from exc
    return _load_json_path(path)


def _subject(sbom: dict[str, Any]) -> dict[str, Any]:
    metadata = sbom.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(component, dict):
        raise MintCveError("SBOM metadata.component is missing")
    return component


def _property(component: dict[str, Any], name: str) -> str | None:
    for prop in component.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == name:
            value = prop.get("value")
            return value if isinstance(value, str) else None
    return None


def _identity(component: dict[str, Any]) -> dict[str, str | None]:
    return {
        "bom_ref": component.get("bom-ref")
        if isinstance(component.get("bom-ref"), str)
        else None,
        "name": component.get("name")
        if isinstance(component.get("name"), str)
        else None,
        "version": component.get("version")
        if isinstance(component.get("version"), str)
        else None,
        "purl": component.get("purl")
        if isinstance(component.get("purl"), str)
        else None,
    }


def _component_from_purl(sbom: dict[str, Any], purl: str) -> dict[str, Any] | None:
    subject = _subject(sbom)
    if subject.get("purl") == purl:
        return subject
    for component in sbom.get("components") or []:
        if isinstance(component, dict) and component.get("purl") == purl:
            return component
    return None


def _parse_purl_name_version(purl: str) -> tuple[str | None, str | None]:
    path = urlparse(purl).path
    leaf = unquote(path.rsplit("/", 1)[-1])
    if "@" not in leaf:
        return leaf or None, None
    name, version = leaf.rsplit("@", 1)
    return name or None, version or None


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


def _record_from_index(
    *, channel_root: Path, subdir: str, artifact: str
) -> dict[str, Any]:
    state = AdvisoryIndexState.load(channel_root=channel_root)
    packages = state.subdirs.get(subdir, {}).get("packages")
    if not isinstance(packages, dict):
        raise MintCveError(f"{channel_root}: no advisory index for subdir {subdir!r}")
    record = packages.get(artifact)
    if not isinstance(record, dict):
        raise MintCveError(f"{artifact!r} is not present in {subdir}/advisory-channel.json")
    return record


def _sbom_path_from_record(*, channel_root: Path, record: dict[str, Any]) -> Path:
    sbom = _current_sbom_record(record)
    current = sbom.get("current") if isinstance(sbom, dict) else None
    if not isinstance(current, str) or not current:
        raise MintCveError("selected package has no indexed SBOM")
    return channel_root / current


def resolve_sbom_path(
    *,
    channel_root: Path,
    sbom_path: Path | None,
    s3_source_uri: str | None,
    subdir: str | None,
    artifact: str | None,
    profile: str | None,
    region: str | None,
    s3_workers: int,
) -> Path:
    if sbom_path is not None:
        if not sbom_path.exists():
            raise MintCveError(f"{sbom_path}: file does not exist")
        return sbom_path

    if not subdir or not artifact:
        raise MintCveError("pass either --sbom-path or both --subdir and --artifact")

    if s3_source_uri:
        stage_existing_indexes_from_s3(
            s3_uri=s3_source_uri,
            root=channel_root,
            profile=profile,
            region=region,
            workers=s3_workers,
        )
    record = _record_from_index(
        channel_root=channel_root,
        subdir=subdir,
        artifact=artifact,
    )
    resolved = _sbom_path_from_record(channel_root=channel_root, record=record)
    if s3_source_uri and not resolved.exists():
        download_file(
            relative_path=_relative(resolved, channel_root),
            root=channel_root,
            s3_uri=s3_source_uri,
            profile=profile,
            region=region,
        )
    if not resolved.exists():
        raise MintCveError(
            f"{resolved}: indexed SBOM is not present locally; "
            "pass --s3-source-uri or --sbom-path"
        )
    return resolved


def _existing_custom_ids_from_paths(paths: list[str], *, year: int) -> set[int]:
    numbers: set[int] = set()
    for path in paths:
        parts = Path(path).parts
        if len(parts) < 3 or parts[0] != "cves":
            continue
        match = CUSTOM_ID_RE.match(unquote(parts[1]))
        if match and int(match.group("year")) == year:
            numbers.add(int(match.group("number")))
    return numbers


def next_custom_id(
    *,
    channel_root: Path,
    s3_source_uri: str | None,
    year: int,
    profile: str | None,
    region: str | None,
) -> str:
    paths = [
        path.relative_to(channel_root).as_posix()
        for path in (channel_root / "cves").glob("CONDA-*/*.conda")
    ]
    if s3_source_uri:
        paths.extend(
            f"cves/{path}"
            for path in list_s3_relative_paths(
                s3_uri=f"{s3_source_uri.rstrip('/')}/cves",
                profile=profile,
                region=region,
            )
            if path.startswith("CONDA-")
        )
    used = _existing_custom_ids_from_paths(paths, year=year)
    number = 1
    while number in used:
        number += 1
    return f"{DEFAULT_ID_PREFIX}-{year}-{number:05d}"


def _normalize_severity(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().upper()
    if normalized == "MODERATE":
        normalized = "MEDIUM"
    if normalized not in SEVERITIES:
        raise MintCveError(f"--severity must be one of: {', '.join(SEVERITIES)}")
    return normalized


def build_manual_vulnerability(
    *,
    vulnerability_id: str,
    summary: str,
    details: str | None,
    severity: str | None,
    severity_score: float | None,
    severity_vector: str | None,
    severity_source: str,
    aliases: list[str],
    references: list[str],
    url: str | None,
    published: str | None,
    modified: str,
    author: str | None,
) -> dict[str, Any]:
    vulnerability: dict[str, Any] = {
        "id": vulnerability_id,
        "modified": modified,
        "summary": summary,
        "source": {
            "name": "manual",
        },
    }
    if author:
        vulnerability["source"]["author"] = author
    if url:
        vulnerability["url"] = url
    if details:
        vulnerability["details"] = details
    if published:
        vulnerability["published"] = published
    if aliases:
        vulnerability["aliases"] = aliases
    if references:
        vulnerability["references"] = [
            {"type": "WEB", "url": reference} for reference in references
        ]
    if severity:
        vulnerability["database_specific"] = {
            "severity": severity,
            "source": "manual",
        }
    if severity_score is not None:
        vulnerability["severity"] = [
            {
                "type": severity_source,
                "score": (
                    severity_vector
                    if severity_vector is not None
                    else f"{severity_score:g}"
                ),
            }
        ]
    elif severity_vector is not None:
        vulnerability["severity"] = [
            {
                "type": severity_source,
                "score": severity_vector,
            }
        ]
    return vulnerability


def build_manual_advisory(
    *,
    sbom: dict[str, Any],
    source_sbom: str,
    vulnerability: dict[str, Any],
    component_purl: str | None,
    component_name: str | None,
    component_version: str | None,
    affected_range: str | None,
) -> dict[str, Any]:
    subject = _subject(sbom)
    component = _component_from_purl(sbom, component_purl) if component_purl else subject
    if component is None:
        parsed_name, parsed_version = _parse_purl_name_version(component_purl or "")
        component = {
            "name": component_name or parsed_name,
            "version": component_version or parsed_version,
            "purl": component_purl,
        }
    identity = _identity(component)
    if component_purl:
        identity["purl"] = component_purl
    if component_name:
        identity["name"] = component_name
    if component_version:
        identity["version"] = component_version

    vuln_id = vulnerability["id"]
    finding: dict[str, Any] = {
        "component_purl": identity.get("purl"),
        "component_name": identity.get("name"),
        "component_version": identity.get("version"),
        "vulnerability_id": vuln_id,
        "url": vulnerability.get("url"),
        "modified": vulnerability.get("modified"),
        "source": "manual",
    }
    if affected_range:
        finding["affected_range"] = affected_range

    component_entry = {
        **identity,
        "vulnerability_count": 1,
        "vulnerabilities": [vulnerability],
    }
    return {
        "schema_version": 2,
        "generated_at": vulnerability["modified"],
        "source": {
            "name": "manual",
            "kind": "custom-vulnerability",
        },
        "source_sbom": source_sbom,
        "subject": _identity(subject),
        "query_count": 0,
        "vulnerability_count": 1,
        "components": [component_entry],
        "skipped_components": [],
        "findings": [finding],
    }


def _infer_security_sbom_root(path: Path) -> Path:
    if path.name.endswith(".conda") and path.parent.name.endswith(".sboms"):
        return path.parent.parent.parent
    raise MintCveError(
        f"{path}: --sbom-path must point at a security SBOM artifact under "
        "<channel-root>/<subdir>/<artifact>.sboms/<sha>.conda"
    )


def mint_custom_cve(
    *,
    channel_root: Path,
    channel: str,
    sbom_path: Path,
    vulnerability_id: str,
    summary: str,
    details: str | None,
    severity: str | None,
    severity_score: float | None,
    severity_vector: str | None,
    severity_source: str,
    aliases: list[str],
    references: list[str],
    url: str | None,
    published: str | None,
    modified: str,
    author: str | None,
    component_purl: str | None,
    component_name: str | None,
    component_version: str | None,
    affected_range: str | None,
    update_index: bool,
) -> dict[str, Any]:
    sbom = _load_sbom(sbom_path)
    source_sbom = _relative(sbom_path, channel_root)
    vulnerability = build_manual_vulnerability(
        vulnerability_id=vulnerability_id,
        summary=summary,
        details=details,
        severity=severity,
        severity_score=severity_score,
        severity_vector=severity_vector,
        severity_source=severity_source,
        aliases=aliases,
        references=references,
        url=url,
        published=published,
        modified=modified,
        author=author,
    )
    advisory = build_manual_advisory(
        sbom=sbom,
        source_sbom=source_sbom,
        vulnerability=vulnerability,
        component_purl=component_purl,
        component_name=component_name,
        component_version=component_version,
        affected_range=affected_range,
    )
    results = write_advisory_artifacts(advisory, sbom_path=sbom_path)
    artifact_paths = [result.path for result in results]
    index_paths = (
        update_indexes_for_paths(
            channel_root=channel_root,
            channel=channel,
            artifact_paths=[sbom_path, *artifact_paths],
        )
        if update_index
        else []
    )
    return {
        "id": vulnerability_id,
        "source_sbom": source_sbom,
        "artifacts": [
            {
                "kind": result.kind,
                "path": _relative(result.path, channel_root),
                "created": result.created,
                "size": result.size,
                "semantic_version": result.semantic_version,
            }
            for result in results
        ],
        "indexes": [_relative(path, channel_root) for path in index_paths],
    }


def _split_csv(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return list(dict.fromkeys(out))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channel-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--channel", default=DEFAULT_CHANNEL)
    parser.add_argument(
        "--s3-source-uri",
        help=(
            "existing advisory-channel S3 prefix used to locate the package SBOM "
            "and reconcile mutable indexes; defaults to --s3-uri"
        ),
    )
    parser.add_argument("--sbom-path", type=Path)
    parser.add_argument("--subdir", help="package subdir, e.g. linux-64")
    parser.add_argument("--artifact", help="conda artifact filename")
    parser.add_argument(
        "--id",
        dest="vulnerability_id",
        help="explicit vulnerability ID; defaults to the next CONDA-YYYY-NNNNN",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=datetime.now(UTC).year,
        help="year used when auto-minting CONDA-YYYY-NNNNN IDs",
    )
    parser.add_argument("--summary", required=True)
    parser.add_argument("--details")
    parser.add_argument("--component-purl")
    parser.add_argument("--component-name")
    parser.add_argument("--component-version")
    parser.add_argument(
        "--affected-range",
        help="free-form affected range note for this package/component match",
    )
    parser.add_argument("--severity", choices=(*SEVERITIES, "MODERATE"))
    parser.add_argument("--severity-score", type=float)
    parser.add_argument("--severity-vector")
    parser.add_argument("--severity-source", default="manual")
    parser.add_argument("--alias", action="append", default=[])
    parser.add_argument("--reference", action="append", default=[])
    parser.add_argument("--url", help="canonical URL for this custom advisory")
    parser.add_argument("--published")
    parser.add_argument("--modified", default=_now())
    parser.add_argument("--author")
    parser.add_argument("--no-index", action="store_true")
    add_s3_args(parser)
    add_logging_args(parser, command_name="advisory-mint-cve")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    log_path = configure_logging(
        command_name="advisory-mint-cve",
        log_level=args.log_level,
        log_file=args.log_file,
    )
    try:
        s3_source_uri = args.s3_source_uri or args.s3_uri
        sbom_path = resolve_sbom_path(
            channel_root=args.channel_root,
            sbom_path=args.sbom_path,
            s3_source_uri=s3_source_uri,
            subdir=args.subdir,
            artifact=args.artifact,
            profile=args.s3_profile,
            region=args.s3_region,
            s3_workers=args.s3_workers,
        )
        channel_root = args.channel_root
        if args.sbom_path is not None:
            channel_root = _infer_security_sbom_root(sbom_path)

        vulnerability_id = args.vulnerability_id or next_custom_id(
            channel_root=channel_root,
            s3_source_uri=s3_source_uri,
            year=args.year,
            profile=args.s3_profile,
            region=args.s3_region,
        )
        severity = _normalize_severity(args.severity)
        LOGGER.info(
            "minting custom vulnerability id=%s sbom=%s s3_uri=%s",
            vulnerability_id,
            sbom_path,
            args.s3_uri,
        )
        summary = mint_custom_cve(
            channel_root=channel_root,
            channel=args.channel,
            sbom_path=sbom_path,
            vulnerability_id=vulnerability_id,
            summary=args.summary,
            details=args.details,
            severity=severity,
            severity_score=args.severity_score,
            severity_vector=args.severity_vector,
            severity_source=args.severity_source,
            aliases=_split_csv(args.alias),
            references=_split_csv(args.reference),
            url=args.url,
            published=args.published,
            modified=args.modified,
            author=args.author,
            component_purl=args.component_purl,
            component_name=args.component_name,
            component_version=args.component_version,
            affected_range=args.affected_range,
            update_index=not args.no_index,
        )

        if args.s3_uri:
            artifact_paths = [
                channel_root / artifact["path"] for artifact in summary["artifacts"]
            ]
            LOGGER.info(
                "publishing custom vulnerability artifacts to S3 count=%d",
                len(artifact_paths),
            )
            artifact_summary = upload_files(
                local_paths=artifact_paths,
                root=channel_root,
                s3_uri=args.s3_uri,
                profile=args.s3_profile,
                region=args.s3_region,
                dry_run=args.s3_dry_run,
                workers=args.s3_workers,
            )
            print_s3_summary(artifact_summary, dry_run=args.s3_dry_run)

            index_paths = [channel_root / path for path in summary["indexes"]]
            if index_paths:
                LOGGER.info(
                    "publishing custom vulnerability indexes to S3 count=%d",
                    len(index_paths),
                )
                index_summary = upload_files(
                    local_paths=index_paths,
                    root=channel_root,
                    s3_uri=args.s3_uri,
                    profile=args.s3_profile,
                    region=args.s3_region,
                    dry_run=args.s3_dry_run,
                    overwrite=True,
                    workers=args.s3_workers,
                )
                print_s3_summary(index_summary, dry_run=args.s3_dry_run)
                if args.cleanup_uploaded and not args.s3_dry_run:
                    print_cleanup_summary(
                        cleanup_uploaded_files(artifact_summary, root=channel_root)
                    )
                    print_cleanup_summary(
                        cleanup_uploaded_files(index_summary, root=channel_root)
                    )

        print(json.dumps(summary, indent=2, sort_keys=True))
        print_log_location(log_path)
    except (MintCveError, S3PublishError, OSError) as exc:
        LOGGER.error("custom CVE minting failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
