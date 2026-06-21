"""Generate a CycloneDX SBOM for one conda-forge artifact.

This is a local/demo downstream consumer of the package identity mappings in
this repository. It keeps the SBOM subject as the concrete conda artifact and
adds the mapped upstream PURL as a component for later OSV correlation.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MAPPING_INDEX = ROOT / "web" / "public" / "mappings-index.json"
DEFAULT_MAPPING_PAYLOAD = ROOT / "mappings" / "auto.json"
DEFAULT_LOCAL_CHANNEL = ROOT / "local-advisory-channel"
DEFAULT_CHANNEL = "conda-forge"


class SbomError(RuntimeError):
    """User-facing SBOM generation failure."""


def _load_json_path(path: Path) -> dict[str, Any]:
    try:
        with path.open() as f:
            data = json.load(f)
    except FileNotFoundError as exc:
        raise SbomError(f"{path}: file does not exist") from exc
    except json.JSONDecodeError as exc:
        raise SbomError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SbomError(f"{path}: expected a JSON object")
    return data


def _load_json_ref(ref: str) -> dict[str, Any]:
    if ref.startswith(("http://", "https://")):
        try:
            with urlopen(ref, timeout=60) as response:
                data = json.load(response)
        except URLError as exc:
            raise SbomError(f"{ref}: could not fetch JSON: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise SbomError(f"{ref}: invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise SbomError(f"{ref}: expected a JSON object")
        return data
    return _load_json_path(Path(ref))


def load_mapping_entry(
    name: str,
    *,
    mapping_index: Path = DEFAULT_MAPPING_INDEX,
    mapping_payload: Path = DEFAULT_MAPPING_PAYLOAD,
) -> dict[str, Any]:
    """Load a package mapping from split frontend payloads or auto.json."""

    if mapping_index.exists():
        index = _load_json_path(mapping_index)
        packages = index.get("packages")
        if not isinstance(packages, dict):
            raise SbomError(f"{mapping_index}: packages must be an object")
        package_index = packages.get(name)
        if not isinstance(package_index, dict):
            raise SbomError(f"{name!r} is not present in {mapping_index}")
        detail_path = package_index.get("detail_path")
        if not isinstance(detail_path, str):
            raise SbomError(f"{mapping_index}:{name}: detail_path is missing")
        detail_file = mapping_index.parent / detail_path
        detail = _load_json_path(detail_file)
        detail_packages = detail.get("packages")
        if not isinstance(detail_packages, dict):
            raise SbomError(f"{detail_file}: packages must be an object")
        entry = detail_packages.get(name)
        if not isinstance(entry, dict):
            raise SbomError(f"{detail_file}: missing package {name!r}")
        return dict(entry)

    payload = _load_json_path(mapping_payload)
    packages = payload.get("packages")
    if not isinstance(packages, dict):
        raise SbomError(f"{mapping_payload}: packages must be an object")
    entry = packages.get(name)
    if not isinstance(entry, dict):
        raise SbomError(f"{name!r} is not present in {mapping_payload}")
    return dict(entry)


def _filename_from_url(url: Any) -> str | None:
    if not isinstance(url, str) or not url:
        return None
    filename = Path(urlparse(url).path).name
    return filename or None


def _iter_repodata_records(
    repodata: dict[str, Any],
) -> list[tuple[str, dict[str, Any]]]:
    records: list[tuple[str, dict[str, Any]]] = []
    for section in ("packages.conda", "packages"):
        packages = repodata.get(section)
        if not isinstance(packages, dict):
            continue
        for filename, record in packages.items():
            if isinstance(filename, str) and isinstance(record, dict):
                records.append((filename, record))
    return records


def select_repodata_record(
    repodata: dict[str, Any],
    *,
    name: str,
    version: str | None = None,
    build: str | None = None,
    filename: str | None = None,
) -> tuple[str, dict[str, Any]]:
    records = _iter_repodata_records(repodata)
    if filename:
        for record_filename, record in records:
            if record_filename == filename:
                return record_filename, dict(record)
        raise SbomError(f"{filename!r} was not found in repodata")

    matches: list[tuple[str, dict[str, Any]]] = []
    for record_filename, record in records:
        if record.get("name") != name:
            continue
        if version is not None and record.get("version") != version:
            continue
        if build is not None and record.get("build") != build:
            continue
        matches.append((record_filename, dict(record)))

    if not matches:
        filters = ", ".join(
            f"{key}={value!r}"
            for key, value in (("name", name), ("version", version), ("build", build))
            if value is not None
        )
        raise SbomError(f"no repodata record matched {filters}")
    if len(matches) > 1:
        choices = ", ".join(filename for filename, _record in matches[:8])
        suffix = "" if len(matches) <= 8 else f", ... ({len(matches)} total)"
        raise SbomError(
            "multiple repodata records matched; pass --filename or --build. "
            f"Matches: {choices}{suffix}"
        )
    return matches[0]


def _quote_purl_part(value: str) -> str:
    return quote(value, safe="-._~")


def conda_purl(
    *,
    channel: str,
    name: str,
    version: str,
    subdir: str,
    build: str | None,
) -> str:
    qualifiers: dict[str, str] = {"subdir": subdir}
    if build:
        qualifiers["build"] = build
    query = urlencode(qualifiers, quote_via=quote, safe="-._~")
    return (
        f"pkg:conda/{_quote_purl_part(channel)}/{_quote_purl_part(name)}"
        f"@{_quote_purl_part(version)}?{query}"
    )


def purl_type(purl: str | None) -> str | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    rest = purl.removeprefix("pkg:")
    return rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0] or None


def add_version_to_purl(purl: str, version: str) -> str:
    """Return ``purl`` with ``@version`` added when the PURL is versionless."""

    base = purl
    subpath = ""
    if "#" in base:
        base, subpath = base.split("#", 1)
        subpath = "#" + subpath

    qualifiers = ""
    if "?" in base:
        base, qualifiers = base.split("?", 1)
        qualifiers = "?" + qualifiers

    last_segment = base.rsplit("/", 1)[-1]
    if "@" not in last_segment:
        base = f"{base}@{_quote_purl_part(version)}"
    return f"{base}{qualifiers}{subpath}"


def _distribution_url(
    *,
    channel: str,
    subdir: str,
    filename: str,
    record: dict[str, Any],
) -> str:
    if isinstance(record.get("url"), str):
        return record["url"]
    return f"https://conda.anaconda.org/{channel}/{subdir}/{filename}"


def _hashes(record: dict[str, Any]) -> list[dict[str, str]]:
    hashes: list[dict[str, str]] = []
    if isinstance(record.get("sha256"), str):
        hashes.append({"alg": "SHA-256", "content": record["sha256"]})
    if isinstance(record.get("md5"), str):
        hashes.append({"alg": "MD5", "content": record["md5"]})
    return hashes


def _licenses(record: dict[str, Any]) -> list[dict[str, dict[str, str]]] | None:
    license_name = record.get("license")
    if not isinstance(license_name, str) or not license_name:
        return None
    return [{"license": {"name": license_name}}]


def _property(name: str, value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if isinstance(value, list):
        if not value:
            return None
        value = ",".join(str(item) for item in value)
    return {"name": name, "value": str(value)}


def _properties(*items: tuple[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for name, value in items:
        prop = _property(name, value)
        if prop is not None:
            out.append(prop)
    return out


def build_cyclonedx_sbom(
    *,
    mapping: dict[str, Any],
    record: dict[str, Any],
    filename: str,
    channel: str,
    subdir: str,
) -> dict[str, Any]:
    name = str(record.get("name") or mapping.get("name"))
    version = str(record.get("version") or mapping.get("version"))
    build = record.get("build") if isinstance(record.get("build"), str) else None
    subject_ref = conda_purl(
        channel=channel, name=name, version=version, subdir=subdir, build=build
    )

    distribution_url = _distribution_url(
        channel=channel, subdir=subdir, filename=filename, record=record
    )
    subject: dict[str, Any] = {
        "type": "library",
        "name": name,
        "version": version,
        "purl": subject_ref,
        "bom-ref": subject_ref,
        "externalReferences": [
            {"type": "distribution", "url": distribution_url},
        ],
        "properties": _properties(
            ("conda:channel", channel),
            ("conda:subdir", subdir),
            ("conda:filename", filename),
            ("conda:build", build),
            ("conda:build_number", record.get("build_number")),
        ),
    }
    hashes = _hashes(record)
    if hashes:
        subject["hashes"] = hashes
    licenses = _licenses(record)
    if licenses:
        subject["licenses"] = licenses

    mapped_purl = mapping.get("purl")
    if not isinstance(mapped_purl, str) or not mapped_purl:
        raise SbomError(f"{name!r} does not have a mapped PURL")
    upstream_ref = add_version_to_purl(mapped_purl, version)
    upstream_name = (
        mapping.get("pkg_name") if isinstance(mapping.get("pkg_name"), str) else name
    )
    upstream: dict[str, Any] = {
        "type": "library",
        "name": upstream_name,
        "version": version,
        "purl": upstream_ref,
        "bom-ref": upstream_ref,
        "properties": _properties(
            ("purl:source", "purl-associator"),
            ("purl-associator:mapping-source", mapping.get("source")),
            ("purl-associator:status", mapping.get("status")),
            ("purl-associator:confidence", mapping.get("confidence")),
            ("purl-associator:sources", mapping.get("sources")),
            ("purl-associator:auto-verified", mapping.get("auto_verified")),
        ),
    }

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, subject_ref)}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
            "component": subject,
        },
        "components": [upstream],
        "dependencies": [
            {"ref": subject_ref, "dependsOn": [upstream_ref]},
            {"ref": upstream_ref, "dependsOn": []},
        ],
    }


def default_output_path(root: Path, *, subdir: str, filename: str) -> Path:
    return root / subdir / "sboms" / f"{filename}.cdx.json"


def _default_repodata_url(channel: str, subdir: str) -> str:
    return f"https://conda.anaconda.org/{channel}/{subdir}/repodata.json"


def generate_sbom(
    *,
    package: str,
    version: str | None,
    build: str | None,
    subdir: str | None,
    filename: str | None,
    channel: str,
    repodata_ref: str | None,
    mapping_index: Path,
    mapping_payload: Path,
    purl_type_filter: str,
) -> tuple[str, str, dict[str, Any]]:
    mapping = load_mapping_entry(
        package, mapping_index=mapping_index, mapping_payload=mapping_payload
    )
    selected_subdir = subdir or mapping.get("subdir")
    if not isinstance(selected_subdir, str) or not selected_subdir:
        raise SbomError("subdir is required; pass --subdir")

    selected_version = version or mapping.get("version")
    if not isinstance(selected_version, str) or not selected_version:
        selected_version = None

    selected_build = build or mapping.get("build")
    if not isinstance(selected_build, str) or not selected_build:
        selected_build = None

    selected_filename = filename
    if (
        selected_filename is None
        and subdir is None
        and version is None
        and build is None
    ):
        selected_filename = _filename_from_url(mapping.get("url"))
    selected_type = purl_type(mapping.get("purl"))
    if purl_type_filter != "any" and selected_type != purl_type_filter:
        raise SbomError(
            f"{package!r} maps to PURL type {selected_type!r}; "
            f"expected {purl_type_filter!r}. Pass --purl-type any to allow it."
        )

    repodata = _load_json_ref(
        repodata_ref or _default_repodata_url(channel, selected_subdir)
    )
    record_filename, record = select_repodata_record(
        repodata,
        name=package,
        version=selected_version,
        build=selected_build,
        filename=selected_filename,
    )
    return (
        record_filename,
        selected_subdir,
        build_cyclonedx_sbom(
            mapping=mapping,
            record=record,
            filename=record_filename,
            channel=channel,
            subdir=selected_subdir,
        ),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", help="conda-forge package name")
    parser.add_argument("--version", help="conda package version")
    parser.add_argument("--build", help="conda package build string")
    parser.add_argument("--subdir", help="conda subdir, e.g. linux-64 or noarch")
    parser.add_argument("--filename", help="exact repodata filename to select")
    parser.add_argument("--channel", default=DEFAULT_CHANNEL, help="conda channel")
    parser.add_argument(
        "--repodata",
        dest="repodata_ref",
        help="local repodata.json path or URL; defaults to the selected channel/subdir",
    )
    parser.add_argument(
        "--mappings-index",
        type=Path,
        default=DEFAULT_MAPPING_INDEX,
        help="split mappings index JSON",
    )
    parser.add_argument(
        "--mappings",
        type=Path,
        default=DEFAULT_MAPPING_PAYLOAD,
        help="fallback auto-style mapping payload",
    )
    parser.add_argument(
        "--purl-type",
        default="pypi",
        help="required mapped PURL type, or 'any'",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=DEFAULT_LOCAL_CHANNEL,
        help="local advisory-channel root for default output paths",
    )
    parser.add_argument("--out", type=Path, help="explicit output file")
    args = parser.parse_args()

    try:
        filename, subdir, sbom = generate_sbom(
            package=args.package,
            version=args.version,
            build=args.build,
            subdir=args.subdir,
            filename=args.filename,
            channel=args.channel,
            repodata_ref=args.repodata_ref,
            mapping_index=args.mappings_index,
            mapping_payload=args.mappings,
            purl_type_filter=args.purl_type,
        )
        out = args.out or default_output_path(
            args.out_dir, subdir=subdir, filename=filename
        )
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(sbom, indent=2) + "\n")
    except SbomError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)

    print(out)


if __name__ == "__main__":
    main()
