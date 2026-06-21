"""Correlate CycloneDX component PURLs against OSV.

This local/demo downstream step reads one generated CycloneDX SBOM, queries OSV
for versioned component PURLs, and writes a small advisory sidecar next to the
local SBOM channel.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


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


def _has_version(purl: str) -> bool:
    base = purl.split("#", 1)[0].split("?", 1)[0]
    return "@" in base.rsplit("/", 1)[-1]


def _component_identity(component: dict[str, Any]) -> dict[str, str | None]:
    return {
        "bom_ref": component.get("bom-ref")
        if isinstance(component.get("bom-ref"), str)
        else None,
        "name": component.get("name") if isinstance(component.get("name"), str) else None,
        "version": component.get("version")
        if isinstance(component.get("version"), str)
        else None,
        "purl": component.get("purl") if isinstance(component.get("purl"), str) else None,
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


def _post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
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
    try:
        with urlopen(request, timeout=60) as response:
            data = json.load(response)
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise OsvError(f"OSV request failed with HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise OsvError(f"OSV request failed: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise OsvError(f"OSV returned invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise OsvError("OSV returned a non-object JSON payload")
    return data


def query_osv_batch(
    purls: list[str], *, api_url: str = DEFAULT_OSV_BATCH_URL
) -> dict[str, list[dict[str, Any]]]:
    """Return ``{purl: vulns}``, following OSV querybatch pagination."""

    results: dict[str, list[dict[str, Any]]] = {purl: [] for purl in purls}
    pending = [{"purl": purl, "page_token": None} for purl in purls]

    while pending:
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
        response = _post_json(api_url, payload)
        batch_results = response.get("results")
        if not isinstance(batch_results, list):
            raise OsvError("OSV response is missing results[]")
        if len(batch_results) != len(pending):
            raise OsvError(
                "OSV response result count does not match request query count"
            )

        next_pending: list[dict[str, str | None]] = []
        for item, result in zip(pending, batch_results, strict=True):
            if not isinstance(result, dict):
                raise OsvError("OSV result entry must be an object")
            vulns = result.get("vulns") or []
            if not isinstance(vulns, list):
                raise OsvError("OSV result vulns must be an array")
            purl = str(item["purl"])
            results[purl].extend(v for v in vulns if isinstance(v, dict))
            token = result.get("next_page_token")
            if isinstance(token, str) and token:
                next_pending.append({"purl": purl, "page_token": token})
        pending = next_pending

    return results


def _subject(sbom: dict[str, Any]) -> dict[str, Any] | None:
    metadata = sbom.get("metadata")
    if not isinstance(metadata, dict):
        return None
    component = metadata.get("component")
    if not isinstance(component, dict):
        return None
    return _component_identity(component)


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
                    "modified": vuln.get("modified"),
                }
            )
    return findings


def correlate_sbom(
    sbom: dict[str, Any],
    *,
    source_sbom: str,
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
    osv_results = query_osv_batch(purls, api_url=api_url) if purls else {}

    correlated: list[dict[str, Any]] = []
    for component in queryable:
        purl = str(component["purl"])
        vulnerabilities = osv_results.get(purl, [])
        correlated.append(
            {
                **component,
                "vulnerability_count": len(vulnerabilities),
                "vulnerabilities": vulnerabilities,
            }
        )

    findings = _flatten_findings(correlated)
    return {
        "schema_version": 1,
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


def default_output_path(sbom_path: Path) -> Path:
    if sbom_path.parent.name == "sboms":
        stem = sbom_path.name.removesuffix(".cdx.json")
        return sbom_path.parent.parent / "advisories" / f"{stem}.osv.json"
    return sbom_path.with_suffix(".osv.json")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sbom", type=Path, help="CycloneDX SBOM JSON file")
    parser.add_argument("--out", type=Path, help="explicit advisory output file")
    parser.add_argument(
        "--api-url",
        default=DEFAULT_OSV_BATCH_URL,
        help="OSV querybatch endpoint",
    )
    args = parser.parse_args()

    try:
        sbom = _load_json_path(args.sbom)
        advisory = correlate_sbom(
            sbom, source_sbom=str(args.sbom), api_url=args.api_url
        )
        out = args.out or default_output_path(args.sbom)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(advisory, indent=2) + "\n")
    except OsvError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)

    print(out)


if __name__ == "__main__":
    main()
