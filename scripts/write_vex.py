"""Write a manual OpenVEX-style statement into an advisory channel."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from scripts.cli_logging import add_logging_args, configure_logging, print_log_location
from scripts.generate_sbom import DEFAULT_CHANNEL, DEFAULT_LOCAL_CHANNEL, conda_purl
from scripts.s3_publish import (
    S3PublishError,
    add_s3_args,
    cleanup_uploaded_files,
    print_s3_summary,
    upload_files,
)

LOGGER = logging.getLogger("scripts.write_vex")

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
VEX_SCHEMA_VERSION = 1
VEX_ARTIFACT_DIR = "vex"
VEX_STATUSES = ("not_affected", "affected", "fixed", "under_investigation")
VEX_JUSTIFICATIONS = (
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)


class VexError(RuntimeError):
    """User-facing VEX authoring failure."""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _canonical_json_bytes(data: Any) -> bytes:
    return (
        json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()


def _sha256(data: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(data)).hexdigest()


def _artifact_stem(filename: str) -> str:
    if filename.endswith(".tar.bz2"):
        return filename.removesuffix(".tar.bz2")
    if filename.endswith(".conda"):
        return filename.removesuffix(".conda")
    return Path(filename).stem


def artifact_identity(filename: str) -> tuple[str, str, str]:
    parts = _artifact_stem(filename).rsplit("-", 2)
    if len(parts) != 3 or not all(parts):
        raise VexError(
            f"could not parse conda artifact filename {filename!r}; "
            "pass --product-purl explicitly"
        )
    name, version, build = parts
    return name, version, build


def default_product_purl(*, channel: str, subdir: str, artifact: str) -> str:
    name, version, build = artifact_identity(artifact)
    return conda_purl(
        channel=channel,
        name=name,
        version=version,
        subdir=subdir,
        build=build,
    )


def _safe_filename_part(value: str) -> str:
    return quote(value, safe="-._~")


def normalized_vex_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    normalized.pop("@id", None)
    normalized.pop("metadata", None)
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        normalized["metadata"] = {
            key: value for key, value in metadata.items() if key != "content_sha256"
        }
    return normalized


def vex_content_hash(payload: dict[str, Any]) -> str:
    return _sha256(normalized_vex_payload(payload))


def vex_output_path(
    *,
    channel_root: Path,
    subdir: str,
    artifact: str,
    vulnerability: str,
    content_hash: str,
) -> Path:
    return (
        channel_root
        / subdir
        / VEX_ARTIFACT_DIR
        / artifact
        / f"vex-{_safe_filename_part(vulnerability)}-{content_hash}.json"
    )


def build_vex_payload(
    *,
    channel: str,
    subdir: str,
    artifact: str,
    vulnerability: str,
    status: str,
    author: str,
    product_purl: str | None = None,
    justification: str | None = None,
    impact_statement: str | None = None,
    action_statement: str | None = None,
    timestamp: str | None = None,
    source_advisory: str | None = None,
    source: str = "manual",
) -> dict[str, Any]:
    if status not in VEX_STATUSES:
        raise VexError(f"--status must be one of: {', '.join(VEX_STATUSES)}")
    if status == "not_affected" and not justification:
        raise VexError("--justification is required for --status not_affected")
    if justification and justification not in VEX_JUSTIFICATIONS:
        raise VexError(
            f"--justification must be one of: {', '.join(VEX_JUSTIFICATIONS)}"
        )

    product = product_purl or default_product_purl(
        channel=channel,
        subdir=subdir,
        artifact=artifact,
    )
    statement: dict[str, Any] = {
        "vulnerability": {"name": vulnerability},
        "products": [{"@id": product}],
        "status": status,
    }
    if justification:
        statement["justification"] = justification
    if impact_statement:
        statement["impact_statement"] = impact_statement
    if action_statement:
        statement["action_statement"] = action_statement

    payload: dict[str, Any] = {
        "@context": OPENVEX_CONTEXT,
        "author": author,
        "timestamp": timestamp or _now(),
        "version": 1,
        "statements": [statement],
        "metadata": {
            "schema_version": VEX_SCHEMA_VERSION,
            "channel": channel,
            "subdir": subdir,
            "artifact": artifact,
            "vulnerability": vulnerability,
            "product_purl": product,
            "source": source,
        },
    }
    if source_advisory:
        payload["metadata"]["source_advisory"] = source_advisory

    content_hash = vex_content_hash(payload)
    payload["@id"] = f"urn:conda-forge:vex:{content_hash}"
    payload["metadata"]["content_sha256"] = content_hash
    return payload


def write_vex_artifact(
    *,
    payload: dict[str, Any],
    channel_root: Path,
    subdir: str,
    artifact: str,
    vulnerability: str,
) -> tuple[Path, bool]:
    content_hash = payload["metadata"]["content_sha256"]
    out = vex_output_path(
        channel_root=channel_root,
        subdir=subdir,
        artifact=artifact,
        vulnerability=vulnerability,
        content_hash=content_hash,
    )
    if out.exists():
        LOGGER.info("VEX artifact already exists path=%s", out)
        return out, False
    LOGGER.info("writing VEX artifact path=%s", out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return out, True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--channel-root",
        type=Path,
        default=DEFAULT_LOCAL_CHANNEL,
        help="local advisory-channel root",
    )
    parser.add_argument("--channel", default=DEFAULT_CHANNEL, help="conda channel")
    parser.add_argument("--subdir", required=True, help="conda subdir")
    parser.add_argument(
        "--artifact",
        required=True,
        help="conda artifact filename, including .conda or .tar.bz2",
    )
    parser.add_argument("--vulnerability", required=True, help="CVE/GHSA/CONDA ID")
    parser.add_argument("--status", required=True, choices=VEX_STATUSES)
    parser.add_argument(
        "--justification",
        choices=VEX_JUSTIFICATIONS,
        help="OpenVEX justification; required for not_affected",
    )
    parser.add_argument("--impact-statement", help="human-readable impact statement")
    parser.add_argument("--action-statement", help="human-readable action statement")
    parser.add_argument("--author", required=True, help="VEX author identity")
    parser.add_argument(
        "--product-purl",
        help="explicit product PURL; defaults to the parsed conda artifact PURL",
    )
    parser.add_argument(
        "--source-advisory",
        help="optional source OSV/SA artifact path that this VEX responds to",
    )
    parser.add_argument(
        "--timestamp",
        help="override timestamp, mainly for deterministic tests and demos",
    )
    add_s3_args(parser)
    add_logging_args(parser, command_name="vex-write")
    args = parser.parse_args()
    log_path = configure_logging(
        command_name="vex-write",
        log_level=args.log_level,
        log_file=args.log_file,
    )
    LOGGER.info(
        "starting VEX write channel_root=%s channel=%s subdir=%s artifact=%s "
        "vulnerability=%s status=%s s3_uri=%s s3_dry_run=%s cleanup_uploaded=%s",
        args.channel_root,
        args.channel,
        args.subdir,
        args.artifact,
        args.vulnerability,
        args.status,
        args.s3_uri,
        args.s3_dry_run,
        args.cleanup_uploaded,
    )

    try:
        payload = build_vex_payload(
            channel=args.channel,
            subdir=args.subdir,
            artifact=args.artifact,
            vulnerability=args.vulnerability,
            status=args.status,
            justification=args.justification,
            impact_statement=args.impact_statement,
            action_statement=args.action_statement,
            author=args.author,
            product_purl=args.product_purl,
            timestamp=args.timestamp,
            source_advisory=args.source_advisory,
        )
        out, created = write_vex_artifact(
            payload=payload,
            channel_root=args.channel_root,
            subdir=args.subdir,
            artifact=args.artifact,
            vulnerability=args.vulnerability,
        )
        if args.s3_uri:
            summary = upload_files(
                local_paths=[out],
                root=args.channel_root,
                s3_uri=args.s3_uri,
                profile=args.s3_profile,
                region=args.s3_region,
                dry_run=args.s3_dry_run,
                workers=args.s3_workers,
            )
            print_s3_summary(summary, dry_run=args.s3_dry_run)
            if args.cleanup_uploaded and not args.s3_dry_run:
                cleanup_uploaded_files(summary, root=args.channel_root)
    except (VexError, S3PublishError) as exc:
        LOGGER.error("VEX write failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)

    print(out)
    action = "created" if created else "already exists"
    print(f"{action} VEX artifact {out}", file=sys.stderr)
    print_log_location(log_path)


if __name__ == "__main__":
    main()
