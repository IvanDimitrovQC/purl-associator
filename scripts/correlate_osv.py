"""Correlate CycloneDX component PURLs against OSV.

This local/demo downstream step reads one generated CycloneDX SBOM, queries OSV
for versioned component PURLs, and writes a small advisory sidecar next to the
local SBOM channel.
"""

from __future__ import annotations

import argparse
import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import logging
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from scripts.cli_logging import add_logging_args, configure_logging, print_log_location
from scripts.generate_sbom import read_security_sbom_payload
from scripts.s3_publish import (
    S3PublishError,
    add_s3_args,
    cleanup_uploaded_files,
    print_cleanup_summary,
    print_s3_summary,
    upload_files,
)

DEFAULT_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
DEFAULT_OSV_BATCH_SIZE = 250
DEFAULT_OSV_DETAIL_WORKERS = 8
DEFAULT_OSV_RETRIES = 3
DEFAULT_OSV_RETRY_DELAY_SECONDS = 1.0
OSV_ADVISORY_SCHEMA_VERSION = 2
OSV_VULNERABILITY_URL_BASE = "https://osv.dev/vulnerability"
LOGGER = logging.getLogger("scripts.correlate_osv")


class OsvError(RuntimeError):
    """User-facing OSV correlation failure."""


def _load_json_path(path: Path) -> dict[str, Any]:
    try:
        with path.open() as f:
            data = json.load(f)
    except FileNotFoundError as exc:
        raise OsvError(f"{path}: file does not exist") from exc
    except json.JSONDecodeError as exc:
        raise OsvError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise OsvError(f"{path}: expected a JSON object")
    return data


def _is_security_sbom_path(path: Path) -> bool:
    return path.name.endswith(".conda") and path.parent.name.endswith(".sboms")


def _load_sbom_path(path: Path) -> dict[str, Any]:
    if _is_security_sbom_path(path):
        try:
            return read_security_sbom_payload(path)
        except Exception as exc:
            raise OsvError(str(exc)) from exc
    return _load_json_path(path)


def _canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(data: Any) -> str:
    return hashlib.sha256(_canonical_json(data).encode()).hexdigest()


def _has_version(purl: str) -> bool:
    base = purl.split("#", 1)[0].split("?", 1)[0]
    return "@" in base.rsplit("/", 1)[-1]


def _component_identity(component: dict[str, Any]) -> dict[str, str | None]:
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


def extract_component_purls(sbom: dict[str, Any]) -> list[dict[str, Any]]:
    components = sbom.get("components")
    if not isinstance(components, list):
        return []

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for component in components:
        if not isinstance(component, dict):
            continue
        identity = _component_identity(component)
        purl = identity.get("purl")
        if purl is None:
            continue
        if purl in seen:
            continue
        seen.add(purl)
        out.append({**identity, "queryable": _has_version(purl)})
    return out


def _retry_after_seconds(exc: HTTPError, fallback: float) -> float:
    retry_after = exc.headers.get("Retry-After")
    if retry_after is None:
        return fallback
    try:
        return max(float(retry_after), 0.0)
    except ValueError:
        return fallback


def _post_json(
    url: str,
    payload: dict[str, Any],
    *,
    retries: int = DEFAULT_OSV_RETRIES,
    retry_delay_seconds: float = DEFAULT_OSV_RETRY_DELAY_SECONDS,
) -> dict[str, Any]:
    body = json.dumps(payload).encode()
    request = Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "purl-associator-osv-correlator",
        },
        method="POST",
    )
    for attempt in range(retries + 1):
        try:
            LOGGER.info(
                "posting OSV request url=%s query_count=%d attempt=%d",
                url,
                len(payload.get("queries") or []),
                attempt + 1,
            )
            with urlopen(request, timeout=60) as response:
                data = json.load(response)
            break
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            retryable = exc.code == 429 or 500 <= exc.code <= 599
            if retryable and attempt < retries:
                fallback = retry_delay_seconds * (2**attempt)
                delay = _retry_after_seconds(exc, fallback)
                LOGGER.warning(
                    "OSV request retry http_status=%s attempt=%d delay_seconds=%.2f",
                    exc.code,
                    attempt + 1,
                    delay,
                )
                time.sleep(delay)
                continue
            LOGGER.error("OSV request failed http_status=%s error=%s", exc.code, detail)
            raise OsvError(
                f"OSV request failed with HTTP {exc.code}: {detail}"
            ) from exc
        except URLError as exc:
            if attempt < retries:
                delay = retry_delay_seconds * (2**attempt)
                LOGGER.warning(
                    "OSV request retry error=%s attempt=%d delay_seconds=%.2f",
                    exc.reason,
                    attempt + 1,
                    delay,
                )
                time.sleep(delay)
                continue
            LOGGER.error("OSV request failed error=%s", exc.reason)
            raise OsvError(f"OSV request failed: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise OsvError(f"OSV returned invalid JSON: {exc}") from exc
    else:
        raise OsvError("OSV request failed after retries")
    if not isinstance(data, dict):
        raise OsvError("OSV returned a non-object JSON payload")
    return data


def _get_json(
    url: str,
    *,
    retries: int = DEFAULT_OSV_RETRIES,
    retry_delay_seconds: float = DEFAULT_OSV_RETRY_DELAY_SECONDS,
) -> dict[str, Any]:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "purl-associator-osv-correlator",
        },
        method="GET",
    )
    for attempt in range(retries + 1):
        try:
            LOGGER.info("getting OSV detail url=%s attempt=%d", url, attempt + 1)
            with urlopen(request, timeout=60) as response:
                data = json.load(response)
            break
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            retryable = exc.code == 429 or 500 <= exc.code <= 599
            if retryable and attempt < retries:
                fallback = retry_delay_seconds * (2**attempt)
                delay = _retry_after_seconds(exc, fallback)
                LOGGER.warning(
                    "OSV detail retry http_status=%s attempt=%d delay_seconds=%.2f",
                    exc.code,
                    attempt + 1,
                    delay,
                )
                time.sleep(delay)
                continue
            LOGGER.error(
                "OSV detail request failed http_status=%s error=%s",
                exc.code,
                detail,
            )
            raise OsvError(
                f"OSV detail request failed with HTTP {exc.code}: {detail}"
            ) from exc
        except URLError as exc:
            if attempt < retries:
                delay = retry_delay_seconds * (2**attempt)
                LOGGER.warning(
                    "OSV detail retry error=%s attempt=%d delay_seconds=%.2f",
                    exc.reason,
                    attempt + 1,
                    delay,
                )
                time.sleep(delay)
                continue
            LOGGER.error("OSV detail request failed error=%s", exc.reason)
            raise OsvError(f"OSV detail request failed: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise OsvError(f"OSV detail returned invalid JSON: {exc}") from exc
    else:
        raise OsvError("OSV detail request failed after retries")
    if not isinstance(data, dict):
        raise OsvError("OSV detail returned a non-object JSON payload")
    return data


def _vuln_detail_url(*, api_url: str, vulnerability_id: str) -> str:
    return f"{api_url.rsplit('/', 1)[0]}/vulns/{quote(vulnerability_id, safe='')}"


def _vulnerability_ids(
    osv_results: dict[str, list[dict[str, Any]]],
) -> list[str]:
    ids: list[str] = []
    for vulnerabilities in osv_results.values():
        for vulnerability in vulnerabilities:
            vuln_id = vulnerability.get("id")
            if isinstance(vuln_id, str) and vuln_id:
                ids.append(vuln_id)
    return list(dict.fromkeys(ids))


def query_osv_vulnerability(
    vulnerability_id: str,
    *,
    api_url: str = DEFAULT_OSV_BATCH_URL,
    retries: int = DEFAULT_OSV_RETRIES,
    retry_delay_seconds: float = DEFAULT_OSV_RETRY_DELAY_SECONDS,
) -> dict[str, Any]:
    detail = _get_json(
        _vuln_detail_url(api_url=api_url, vulnerability_id=vulnerability_id),
        retries=retries,
        retry_delay_seconds=retry_delay_seconds,
    )
    compact = {
        key: detail[key]
        for key in ("id", "modified", "severity", "database_specific")
        if key in detail
    }
    if not isinstance(compact.get("id"), str):
        compact["id"] = vulnerability_id
    return compact


def query_osv_vulnerabilities(
    vulnerability_ids: list[str],
    *,
    api_url: str = DEFAULT_OSV_BATCH_URL,
    workers: int = DEFAULT_OSV_DETAIL_WORKERS,
    retries: int = DEFAULT_OSV_RETRIES,
    retry_delay_seconds: float = DEFAULT_OSV_RETRY_DELAY_SECONDS,
) -> dict[str, dict[str, Any]]:
    unique_ids = list(dict.fromkeys(vulnerability_ids))
    if not unique_ids:
        return {}
    if workers < 1:
        raise OsvError("--workers must be at least 1")
    LOGGER.info("hydrating OSV vulnerability details count=%d", len(unique_ids))
    if workers == 1 or len(unique_ids) <= 1:
        return {
            vulnerability_id: query_osv_vulnerability(
                vulnerability_id,
                api_url=api_url,
                retries=retries,
                retry_delay_seconds=retry_delay_seconds,
            )
            for vulnerability_id in unique_ids
        }

    details: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                query_osv_vulnerability,
                vulnerability_id,
                api_url=api_url,
                retries=retries,
                retry_delay_seconds=retry_delay_seconds,
            ): vulnerability_id
            for vulnerability_id in unique_ids
        }
        for future in as_completed(futures):
            vulnerability_id = futures[future]
            details[vulnerability_id] = future.result()
    return details


def hydrate_osv_details(
    osv_results: dict[str, list[dict[str, Any]]],
    *,
    api_url: str = DEFAULT_OSV_BATCH_URL,
    workers: int = DEFAULT_OSV_DETAIL_WORKERS,
    retries: int = DEFAULT_OSV_RETRIES,
    retry_delay_seconds: float = DEFAULT_OSV_RETRY_DELAY_SECONDS,
) -> dict[str, list[dict[str, Any]]]:
    details = query_osv_vulnerabilities(
        _vulnerability_ids(osv_results),
        api_url=api_url,
        workers=workers,
        retries=retries,
        retry_delay_seconds=retry_delay_seconds,
    )
    if not details:
        return osv_results
    hydrated: dict[str, list[dict[str, Any]]] = {}
    for purl, vulnerabilities in osv_results.items():
        hydrated[purl] = [
            {**vulnerability, **details.get(str(vulnerability.get("id")), {})}
            if isinstance(vulnerability.get("id"), str)
            else vulnerability
            for vulnerability in vulnerabilities
        ]
    return hydrated


def query_osv_batch(
    purls: list[str],
    *,
    api_url: str = DEFAULT_OSV_BATCH_URL,
    hydrate_details: bool = True,
    detail_workers: int = DEFAULT_OSV_DETAIL_WORKERS,
    retries: int = DEFAULT_OSV_RETRIES,
    retry_delay_seconds: float = DEFAULT_OSV_RETRY_DELAY_SECONDS,
) -> dict[str, list[dict[str, Any]]]:
    """Return ``{purl: vulns}``, following OSV querybatch pagination."""

    results: dict[str, list[dict[str, Any]]] = {purl: [] for purl in purls}
    pending = [{"purl": purl, "page_token": None} for purl in purls]

    while pending:
        LOGGER.info(
            "querying OSV batch api_url=%s query_count=%d",
            api_url,
            len(pending),
        )
        payload = {
            "queries": [
                {
                    "package": {"purl": item["purl"]},
                    **(
                        {"page_token": item["page_token"]}
                        if item.get("page_token")
                        else {}
                    ),
                }
                for item in pending
            ]
        }
        response = _post_json(
            api_url,
            payload,
            retries=retries,
            retry_delay_seconds=retry_delay_seconds,
        )
        batch_results = response.get("results")
        if not isinstance(batch_results, list):
            raise OsvError("OSV response is missing results[]")
        if len(batch_results) != len(pending):
            raise OsvError(
                "OSV response result count does not match request query count"
            )

        next_pending: list[dict[str, str | None]] = []
        vulnerability_count = 0
        for item, result in zip(pending, batch_results, strict=True):
            if not isinstance(result, dict):
                raise OsvError("OSV result entry must be an object")
            vulns = result.get("vulns") or []
            if not isinstance(vulns, list):
                raise OsvError("OSV result vulns must be an array")
            purl = str(item["purl"])
            results[purl].extend(v for v in vulns if isinstance(v, dict))
            vulnerability_count += len([v for v in vulns if isinstance(v, dict)])
            token = result.get("next_page_token")
            if isinstance(token, str) and token:
                next_pending.append({"purl": purl, "page_token": token})
        LOGGER.info(
            "OSV batch complete query_count=%d vulnerability_count=%d next_pages=%d",
            len(pending),
            vulnerability_count,
            len(next_pending),
        )
        pending = next_pending

    if not hydrate_details:
        return results
    return hydrate_osv_details(
        results,
        api_url=api_url,
        workers=detail_workers,
        retries=retries,
        retry_delay_seconds=retry_delay_seconds,
    )


def query_osv_chunked(
    purls: list[str],
    *,
    api_url: str = DEFAULT_OSV_BATCH_URL,
    batch_size: int = DEFAULT_OSV_BATCH_SIZE,
    hydrate_details: bool = True,
    detail_workers: int = DEFAULT_OSV_DETAIL_WORKERS,
    delay_seconds: float = 0.0,
    retries: int = DEFAULT_OSV_RETRIES,
    retry_delay_seconds: float = DEFAULT_OSV_RETRY_DELAY_SECONDS,
) -> dict[str, list[dict[str, Any]]]:
    if batch_size < 1:
        raise OsvError("--batch-size must be at least 1")

    unique_purls = list(dict.fromkeys(purls))
    LOGGER.info(
        "querying OSV in chunks unique_purls=%d batch_size=%d api_url=%s",
        len(unique_purls),
        batch_size,
        api_url,
    )
    results: dict[str, list[dict[str, Any]]] = {}
    for index in range(0, len(unique_purls), batch_size):
        if delay_seconds > 0 and index > 0:
            time.sleep(delay_seconds)
        chunk = unique_purls[index : index + batch_size]
        LOGGER.info(
            "querying OSV chunk start=%d end=%d total=%d",
            index + 1,
            index + len(chunk),
            len(unique_purls),
        )
        results.update(
            query_osv_batch(
                chunk,
                api_url=api_url,
                hydrate_details=False,
                retries=retries,
                retry_delay_seconds=retry_delay_seconds,
            )
        )
        LOGGER.info(
            "OSV chunk complete start=%d end=%d total=%d",
            index + 1,
            index + len(chunk),
            len(unique_purls),
        )
    if not hydrate_details:
        return results
    return hydrate_osv_details(
        results,
        api_url=api_url,
        workers=detail_workers,
        retries=retries,
        retry_delay_seconds=retry_delay_seconds,
    )


def _subject(sbom: dict[str, Any]) -> dict[str, Any] | None:
    metadata = sbom.get("metadata")
    if not isinstance(metadata, dict):
        return None
    component = metadata.get("component")
    if not isinstance(component, dict):
        return None
    return _component_identity(component)


def osv_vulnerability_url(vulnerability_id: str) -> str:
    return f"{OSV_VULNERABILITY_URL_BASE}/{quote(vulnerability_id, safe='')}"


def _vulnerability_with_url(vulnerability: dict[str, Any]) -> dict[str, Any]:
    vuln_id = vulnerability.get("id")
    if not isinstance(vuln_id, str):
        return vulnerability
    return {
        **vulnerability,
        "url": vulnerability.get("url") or osv_vulnerability_url(vuln_id),
    }


def _flatten_findings(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for component in components:
        for vuln in component.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            vuln_id = vuln.get("id")
            if not isinstance(vuln_id, str):
                continue
            findings.append(
                {
                    "component_purl": component.get("purl"),
                    "component_name": component.get("name"),
                    "component_version": component.get("version"),
                    "vulnerability_id": vuln_id,
                    "url": vuln.get("url") or osv_vulnerability_url(vuln_id),
                    "modified": vuln.get("modified"),
                }
            )
    return findings


def correlate_sbom_with_results(
    sbom: dict[str, Any],
    *,
    source_sbom: str,
    osv_results: dict[str, list[dict[str, Any]]],
    api_url: str = DEFAULT_OSV_BATCH_URL,
) -> dict[str, Any]:
    components = extract_component_purls(sbom)
    queryable = [c for c in components if c.get("queryable")]
    skipped = [
        {**c, "reason": "component PURL is not versioned"}
        for c in components
        if not c.get("queryable")
    ]
    purls = [str(c["purl"]) for c in queryable]
    LOGGER.info(
        "correlating SBOM with OSV results source_sbom=%s queryable=%d skipped=%d",
        source_sbom,
        len(queryable),
        len(skipped),
    )

    correlated: list[dict[str, Any]] = []
    for component in queryable:
        purl = str(component["purl"])
        vulnerabilities = [
            _vulnerability_with_url(vulnerability)
            for vulnerability in osv_results.get(purl, [])
            if isinstance(vulnerability, dict)
        ]
        correlated.append(
            {
                **component,
                "vulnerability_count": len(vulnerabilities),
                "vulnerabilities": vulnerabilities,
            }
        )

    findings = _flatten_findings(correlated)
    return {
        "schema_version": OSV_ADVISORY_SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "source": {
            "name": "osv.dev",
            "api": api_url,
            "endpoint": "/v1/querybatch",
        },
        "source_sbom": source_sbom,
        "subject": _subject(sbom),
        "query_count": len(purls),
        "vulnerability_count": len(findings),
        "components": correlated,
        "skipped_components": skipped,
        "findings": findings,
    }


def correlate_sbom(
    sbom: dict[str, Any],
    *,
    source_sbom: str,
    api_url: str = DEFAULT_OSV_BATCH_URL,
) -> dict[str, Any]:
    purls = [
        str(component["purl"])
        for component in extract_component_purls(sbom)
        if component.get("queryable")
    ]
    LOGGER.info(
        "querying OSV for SBOM source_sbom=%s query_count=%d",
        source_sbom,
        len(purls),
    )
    osv_results = query_osv_batch(purls, api_url=api_url) if purls else {}
    return correlate_sbom_with_results(
        sbom,
        source_sbom=source_sbom,
        osv_results=osv_results,
        api_url=api_url,
    )


def normalized_advisory(advisory: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(advisory)
    normalized.pop("generated_at", None)
    normalized.pop("correlation_version", None)
    return normalized


def advisory_content_hash(advisory: dict[str, Any]) -> str:
    return _sha256(normalized_advisory(advisory))


def finalized_advisory(advisory: dict[str, Any]) -> dict[str, Any]:
    finalized = copy.deepcopy(advisory)
    finalized["correlation_version"] = advisory_content_hash(advisory)
    return finalized


def default_output_path(sbom_path: Path) -> Path:
    if sbom_path.name.endswith(".conda") and sbom_path.parent.name.endswith(".sboms"):
        sbom_version = sbom_path.name.removesuffix(".conda")
        artifact_filename = f"{sbom_path.parent.name.removesuffix('.sboms')}.conda"
        return (
            sbom_path.parent.parent
            / "advisories"
            / artifact_filename
            / f"osv-{sbom_version}.json"
        )
    if (
        sbom_path.name.startswith("sbom-")
        and sbom_path.name.endswith(".cdx.json")
        and sbom_path.parent.parent.name == "sboms"
    ):
        version = sbom_path.name.removeprefix("sbom-").removesuffix(".cdx.json")
        return (
            sbom_path.parent.parent.parent
            / "advisories"
            / sbom_path.parent.name
            / f"osv-{version}.json"
        )
    if sbom_path.parent.name == "sboms":
        stem = sbom_path.name.removesuffix(".cdx.json")
        return sbom_path.parent.parent / "advisories" / f"{stem}.osv.json"
    return sbom_path.with_suffix(".osv.json")


def versioned_output_path(sbom_path: Path, advisory: dict[str, Any]) -> Path:
    correlation_hash = advisory_content_hash(advisory)
    if sbom_path.name.endswith(".conda") and sbom_path.parent.name.endswith(".sboms"):
        sbom_version = sbom_path.name.removesuffix(".conda")
        artifact_filename = f"{sbom_path.parent.name.removesuffix('.sboms')}.conda"
        return (
            sbom_path.parent.parent
            / "advisories"
            / artifact_filename
            / f"osv-{sbom_version}-{correlation_hash}.json"
        )
    if (
        sbom_path.name.startswith("sbom-")
        and sbom_path.name.endswith(".cdx.json")
        and sbom_path.parent.parent.name == "sboms"
    ):
        sbom_version = sbom_path.name.removeprefix("sbom-").removesuffix(".cdx.json")
        return (
            sbom_path.parent.parent.parent
            / "advisories"
            / sbom_path.parent.name
            / f"osv-{sbom_version}-{correlation_hash}.json"
        )
    return default_output_path(sbom_path).with_name(
        f"{default_output_path(sbom_path).stem}-{correlation_hash}.json"
    )


def write_advisory(advisory: dict[str, Any], out: Path) -> tuple[Path, bool]:
    if out.exists():
        LOGGER.info("OSV advisory artifact already exists path=%s", out)
        return out, False
    LOGGER.info("writing OSV advisory artifact path=%s", out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(finalized_advisory(advisory), indent=2) + "\n")
    return out, True


def advisory_channel_root(advisory_path: Path) -> Path:
    if advisory_path.parent.parent.name == "advisories":
        return advisory_path.parent.parent.parent.parent
    if advisory_path.parent.name == "advisories":
        return advisory_path.parent.parent.parent
    return advisory_path.parent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sbom", type=Path, help="CycloneDX SBOM JSON file")
    parser.add_argument("--out", type=Path, help="explicit advisory output file")
    parser.add_argument(
        "--api-url",
        default=DEFAULT_OSV_BATCH_URL,
        help="OSV querybatch endpoint",
    )
    add_s3_args(parser)
    add_logging_args(parser, command_name="osv-correlate")
    args = parser.parse_args()
    log_path = configure_logging(
        command_name="osv-correlate",
        log_level=args.log_level,
        log_file=args.log_file,
    )
    LOGGER.info(
        "starting OSV correlation sbom=%s api_url=%s s3_uri=%s s3_dry_run=%s "
        "cleanup_uploaded=%s",
        args.sbom,
        args.api_url,
        args.s3_uri,
        args.s3_dry_run,
        args.cleanup_uploaded,
    )

    try:
        if args.out and args.s3_uri:
            raise OsvError("--s3-uri cannot be used together with --out")
        sbom = _load_sbom_path(args.sbom)
        advisory = correlate_sbom(
            sbom, source_sbom=str(args.sbom), api_url=args.api_url
        )
        if args.out:
            out = args.out
            out.parent.mkdir(parents=True, exist_ok=True)
            LOGGER.info("writing explicit OSV advisory path=%s", out)
            out.write_text(json.dumps(finalized_advisory(advisory), indent=2) + "\n")
            status = "wrote explicit OSV advisory"
        else:
            out, created = write_advisory(
                advisory, versioned_output_path(args.sbom, advisory)
            )
            status = (
                "generated new OSV advisory"
                if created
                else "OSV advisory version already exists"
            )
        if args.s3_uri:
            LOGGER.info("publishing OSV advisory to S3 path=%s", out)
            summary = upload_files(
                local_paths=[out],
                root=advisory_channel_root(out),
                s3_uri=args.s3_uri,
                profile=args.s3_profile,
                region=args.s3_region,
                dry_run=args.s3_dry_run,
                workers=args.s3_workers,
            )
            print_s3_summary(summary, dry_run=args.s3_dry_run)
            if args.cleanup_uploaded and not args.s3_dry_run:
                print_cleanup_summary(
                    cleanup_uploaded_files(summary, root=advisory_channel_root(out))
                )
    except (OsvError, S3PublishError) as exc:
        LOGGER.error("OSV correlation failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)

    LOGGER.info("completed OSV correlation status=%s output=%s", status, out)
    print(status, file=sys.stderr)
    print_log_location(log_path)
    print(out)


if __name__ == "__main__":
    main()
