"""Generate CycloneDX SBOMs from a purl-associator mapping JSON payload."""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import random
import re
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from scripts.advisory_index import AdvisoryIndexError, AdvisoryIndexState
from scripts.cli_logging import add_logging_args, configure_logging, print_log_location
from scripts.generate_sbom import (
    DEFAULT_CHANNEL,
    DEFAULT_LOCAL_CHANNEL,
    DEFAULT_MAPPING_PAYLOAD,
    SbomError,
    _default_repodata_url,
    _iter_repodata_records,
    _load_json_path,
    _load_json_ref,
    generate_sbom_from_record,
    generate_sbom_from_mapping,
    get_security_sbom_artifact_sha256,
    purl_type,
    sbom_artifact_paths,
    sbom_output_path,
    write_versioned_sbom,
)
from scripts.load_progress import ProgressTracker
from scripts.s3_publish import (
    S3PublishError,
    add_s3_args,
    cleanup_uploaded_files,
    inventory_upload_summary,
    load_s3_object_inventory,
    paths_present_in_inventory,
    upload_files,
)
from scripts.s3_sbom_inventory import is_sbom_artifact_path

DEFAULT_REPODATA_CACHE = Path(".cache") / "repodata"
DEFAULT_REPODATA_CACHE_SECONDS = 1200
DEFAULT_REPODATA_RETRIES = 3
DEFAULT_REPODATA_RETRY_DELAY_SECONDS = 1.0
DEFAULT_ARTIFACT_SUBDIRS = (
    "noarch",
    "linux-64",
    "linux-aarch64",
    "linux-ppc64le",
    "osx-64",
    "osx-arm64",
    "win-64",
    "win-32",
)
ARTIFACT_SELECTION_LATEST = "latest-build-per-version-per-subdir"
ARTIFACT_SELECTION_ALL_BUILDS = "all-builds"
LOGGER = logging.getLogger("scripts.generate_sboms")


@dataclass(frozen=True)
class BatchResult:
    generated: list[Path]
    existing: int
    skipped: int
    errors: list[str]
    inventory_skipped: int = 0


@dataclass(frozen=True)
class GeneratedSbom:
    index: int
    name: str
    subdir: str
    filename: str
    path: Path
    created: bool
    inventory_skipped: bool = False


@dataclass(frozen=True)
class SbomWorkItem:
    index: int
    name: str
    mapping: dict[str, Any]
    subdir: str
    filename: str | None = None
    record: dict[str, Any] | None = None


ArtifactHandler = Callable[[list[Path]], None]
ArtifactSkipPredicate = Callable[[list[Path]], bool]


def load_s3_sbom_inventory(path: Path) -> set[str]:
    try:
        return load_s3_object_inventory(path)
    except S3PublishError as exc:
        raise SbomError(str(exc)) from exc


def _mapping_with_name(name: str, entry: dict[str, Any]) -> dict[str, Any]:
    mapping = dict(entry)
    mapping.setdefault("name", name)
    return mapping


def load_mapping_entries(path: Path) -> list[tuple[str, dict[str, Any]]]:
    """Load entries from auto/detail/index-style purl-associator JSON."""

    payload = _load_json_path(path)
    packages = payload.get("packages")
    if not isinstance(packages, dict):
        if isinstance(payload.get("name"), str):
            return [(str(payload["name"]), payload)]
        raise SbomError(f"{path}: expected packages object or single mapping entry")

    detail_cache: dict[Path, dict[str, Any]] = {}
    entries: list[tuple[str, dict[str, Any]]] = []
    for name, entry in sorted(packages.items()):
        if not isinstance(name, str) or not isinstance(entry, dict):
            continue
        detail_path = entry.get("detail_path")
        if isinstance(detail_path, str):
            detail_file = path.parent / detail_path
            if detail_file not in detail_cache:
                detail = _load_json_path(detail_file)
                detail_packages = detail.get("packages")
                if not isinstance(detail_packages, dict):
                    raise SbomError(f"{detail_file}: packages must be an object")
                detail_cache[detail_file] = detail_packages
            detail_entry = detail_cache[detail_file].get(name)
            if isinstance(detail_entry, dict):
                entries.append((name, _mapping_with_name(name, detail_entry)))
            continue
        entries.append((name, _mapping_with_name(name, entry)))
    return entries


def is_eligible_mapping(
    mapping: dict[str, Any], *, purl_type_filter: str
) -> tuple[bool, str | None]:
    purl = mapping.get("purl")
    if not isinstance(purl, str) or not purl:
        return False, "missing purl"
    actual_type = purl_type(purl)
    if purl_type_filter != "any" and actual_type != purl_type_filter:
        return False, f"purl type {actual_type!r} does not match {purl_type_filter!r}"
    if not isinstance(mapping.get("subdir"), str) or not mapping.get("subdir"):
        return False, "missing subdir"
    return True, None


def _cache_paths(cache_dir: Path, *, channel: str, subdir: str) -> tuple[Path, Path]:
    root = cache_dir / channel / subdir
    return root / "repodata.json", root / "metadata.json"


def _read_cache_metadata(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open() as f:
            data = json.load(f)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _is_fresh(metadata: dict[str, Any], max_age_seconds: int) -> bool:
    fetched_at = metadata.get("fetched_at")
    if not isinstance(fetched_at, (int, float)):
        return False
    return time.time() - fetched_at < max_age_seconds


def _request_headers(metadata: dict[str, Any]) -> dict[str, str]:
    headers: dict[str, str] = {"Accept": "application/json"}
    etag = metadata.get("etag")
    last_modified = metadata.get("last_modified")
    if isinstance(etag, str):
        headers["If-None-Match"] = etag
    if isinstance(last_modified, str):
        headers["If-Modified-Since"] = last_modified
    return headers


def _retry_after_seconds(exc: HTTPError, fallback: float) -> float:
    retry_after = exc.headers.get("Retry-After")
    if retry_after is None:
        return fallback
    try:
        return max(float(retry_after), 0.0)
    except ValueError:
        return fallback


def load_repodata(
    *,
    channel: str,
    subdir: str,
    cache_dir: Path | None,
    cache_max_age_seconds: int,
    refresh_cache: bool,
) -> dict[str, Any]:
    url = _default_repodata_url(channel, subdir)
    if cache_dir is None:
        LOGGER.info(
            "fetching repodata without cache channel=%s subdir=%s url=%s",
            channel,
            subdir,
            url,
        )
        return _load_json_ref(url)

    repodata_path, metadata_path = _cache_paths(
        cache_dir, channel=channel, subdir=subdir
    )
    metadata = _read_cache_metadata(metadata_path)
    if (
        repodata_path.exists()
        and not refresh_cache
        and _is_fresh(metadata, cache_max_age_seconds)
    ):
        LOGGER.info(
            "using fresh repodata cache channel=%s subdir=%s path=%s",
            channel,
            subdir,
            repodata_path,
        )
        return _load_json_path(repodata_path)

    LOGGER.info(
        "fetching repodata channel=%s subdir=%s url=%s cache_path=%s",
        channel,
        subdir,
        url,
        repodata_path,
    )
    request = Request(url, headers=_request_headers(metadata))
    for attempt in range(DEFAULT_REPODATA_RETRIES + 1):
        try:
            with urlopen(request, timeout=120) as response:
                repodata = json.load(response)
                new_metadata = {
                    "url": url,
                    "fetched_at": time.time(),
                    "etag": response.headers.get("ETag"),
                    "last_modified": response.headers.get("Last-Modified"),
                    "cache_control": response.headers.get("Cache-Control"),
                }
            break
        except HTTPError as exc:
            if exc.code == 304 and repodata_path.exists():
                LOGGER.info(
                    "repodata cache revalidated channel=%s subdir=%s path=%s",
                    channel,
                    subdir,
                    repodata_path,
                )
                metadata["fetched_at"] = time.time()
                metadata_path.parent.mkdir(parents=True, exist_ok=True)
                metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
                return _load_json_path(repodata_path)
            retryable = exc.code == 429 or 500 <= exc.code <= 599
            if retryable and attempt < DEFAULT_REPODATA_RETRIES:
                fallback = DEFAULT_REPODATA_RETRY_DELAY_SECONDS * (2**attempt)
                delay = _retry_after_seconds(exc, fallback)
                LOGGER.warning(
                    "repodata fetch retry channel=%s subdir=%s http_status=%s "
                    "attempt=%d delay_seconds=%.2f",
                    channel,
                    subdir,
                    exc.code,
                    attempt + 1,
                    delay,
                )
                time.sleep(delay)
                continue
            if repodata_path.exists():
                LOGGER.warning(
                    "using stale repodata cache after HTTP error channel=%s "
                    "subdir=%s http_status=%s path=%s",
                    channel,
                    subdir,
                    exc.code,
                    repodata_path,
                )
                return _load_json_path(repodata_path)
            detail = exc.read().decode("utf-8", errors="replace")
            LOGGER.error(
                "repodata fetch failed channel=%s subdir=%s http_status=%s error=%s",
                channel,
                subdir,
                exc.code,
                detail,
            )
            raise SbomError(f"{url}: HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            if attempt < DEFAULT_REPODATA_RETRIES:
                delay = DEFAULT_REPODATA_RETRY_DELAY_SECONDS * (2**attempt)
                LOGGER.warning(
                    "repodata fetch retry channel=%s subdir=%s error=%s "
                    "attempt=%d delay_seconds=%.2f",
                    channel,
                    subdir,
                    exc.reason,
                    attempt + 1,
                    delay,
                )
                time.sleep(delay)
                continue
            if repodata_path.exists():
                LOGGER.warning(
                    "using stale repodata cache after URL error channel=%s "
                    "subdir=%s path=%s",
                    channel,
                    subdir,
                    repodata_path,
                )
                return _load_json_path(repodata_path)
            LOGGER.error(
                "repodata fetch failed channel=%s subdir=%s error=%s",
                channel,
                subdir,
                exc.reason,
            )
            raise SbomError(f"{url}: could not fetch repodata: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise SbomError(f"{url}: invalid JSON: {exc}") from exc
    else:
        raise SbomError(f"{url}: could not fetch repodata after retries")

    if not isinstance(repodata, dict):
        raise SbomError(f"{url}: expected a JSON object")

    repodata_path.parent.mkdir(parents=True, exist_ok=True)
    repodata_path.write_text(json.dumps(repodata) + "\n")
    metadata_path.write_text(json.dumps(new_metadata, indent=2) + "\n")
    LOGGER.info(
        "cached repodata channel=%s subdir=%s path=%s",
        channel,
        subdir,
        repodata_path,
    )
    return repodata


def _select_entries(
    entries: list[tuple[str, dict[str, Any]]],
    *,
    purl_type_filter: str,
    random_one: bool,
    seed: str | None,
    limit: int | None,
) -> tuple[list[tuple[str, dict[str, Any]]], int, dict[str, int]]:
    skipped = 0
    skip_reasons: Counter[str] = Counter()
    eligible: list[tuple[str, dict[str, Any]]] = []
    for name, mapping in entries:
        ok, _reason = is_eligible_mapping(mapping, purl_type_filter=purl_type_filter)
        if ok:
            eligible.append((name, mapping))
        else:
            skipped += 1
            skip_reasons[str(_reason or "ineligible")] += 1

    if random_one:
        if not eligible:
            raise SbomError("no eligible package mappings found")
        rng = random.Random(seed)
        selected = rng.choice(eligible)
        return [selected], skipped, dict(skip_reasons)

    if limit is not None:
        eligible = eligible[:limit]
    return eligible, skipped, dict(skip_reasons)


def _validate_workers(value: int, *, option: str) -> None:
    if value < 1:
        raise SbomError(f"{option} must be at least 1")


def _validate_versions_per_package(value: int | None) -> None:
    if value is not None and value < 1:
        raise SbomError("--versions-per-package must be at least 1")


def _version_sort_key(version: str) -> tuple[tuple[int, int | str], ...]:
    parts: list[tuple[int, int | str]] = []
    for part in re.split(r"([0-9]+)", version):
        if not part:
            continue
        if part.isdigit():
            parts.append((1, int(part)))
        else:
            parts.append((0, part.lower()))
    return tuple(parts)


def _numeric_timestamp(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return 0.0
    return 0.0


def _filename_format_priority(filename: str) -> int:
    return 1 if filename.endswith(".conda") else 0


def _record_sort_key(
    filename: str, record: dict[str, Any]
) -> tuple[int, float, int, str]:
    build_number = record.get("build_number")
    if not isinstance(build_number, int):
        build_number = -1
    return (
        build_number,
        _numeric_timestamp(record.get("timestamp")),
        _filename_format_priority(filename),
        str(record.get("build") or ""),
    )


def _records_by_package(repodata: dict[str, Any]) -> dict[str, list[tuple[str, dict]]]:
    by_name: dict[str, list[tuple[str, dict]]] = {}
    for filename, record in _iter_repodata_records(repodata):
        name = record.get("name")
        if isinstance(name, str):
            by_name.setdefault(name, []).append((filename, record))
    return by_name


def _resolve_artifact_subdirs(mapping: dict[str, Any], value: str) -> list[str]:
    cleaned = value.strip()
    if cleaned == "mapped":
        subdir = mapping.get("subdir")
        if not isinstance(subdir, str) or not subdir:
            raise SbomError("mapping entry is missing subdir")
        return [subdir]
    if cleaned == "all":
        return list(DEFAULT_ARTIFACT_SUBDIRS)
    subdirs = [part.strip() for part in cleaned.split(",") if part.strip()]
    if not subdirs:
        raise SbomError("--artifact-subdirs must be 'mapped', 'all', or a list")
    return list(dict.fromkeys(subdirs))


def _validate_artifact_selection(value: str) -> None:
    if value not in {ARTIFACT_SELECTION_LATEST, ARTIFACT_SELECTION_ALL_BUILDS}:
        raise SbomError(
            "--artifact-selection must be "
            f"{ARTIFACT_SELECTION_LATEST!r} or {ARTIFACT_SELECTION_ALL_BUILDS!r}"
        )


def select_package_artifacts(
    *,
    name: str,
    mapping: dict[str, Any],
    records_for_package: Callable[[str, str], list[tuple[str, dict]]],
    versions_per_package: int,
    artifact_subdirs: str,
    artifact_selection: str,
) -> list[SbomWorkItem]:
    _validate_artifact_selection(artifact_selection)
    candidates: list[tuple[str, str, dict[str, Any]]] = []
    for subdir in _resolve_artifact_subdirs(mapping, artifact_subdirs):
        for filename, record in records_for_package(subdir, name):
            version = record.get("version")
            if isinstance(version, str) and version:
                candidates.append((subdir, filename, dict(record)))

    if not candidates:
        return []

    versions = sorted(
        {str(record["version"]) for _subdir, _filename, record in candidates},
        key=_version_sort_key,
        reverse=True,
    )[:versions_per_package]
    selected_versions = set(versions)
    candidates = [
        candidate
        for candidate in candidates
        if str(candidate[2].get("version")) in selected_versions
    ]

    if artifact_selection == ARTIFACT_SELECTION_ALL_BUILDS:
        # `repodata.json` can contain both `.conda` and legacy `.tar.bz2`
        # variants for the same conda build. Keep the preferred package format
        # for each equivalent build to avoid duplicate SBOMs for one build.
        by_build: dict[tuple[str, str, str, int | None], tuple[str, str, dict]] = {}
        for subdir, filename, record in candidates:
            key = (
                subdir,
                str(record.get("version") or ""),
                str(record.get("build") or ""),
                record.get("build_number")
                if isinstance(record.get("build_number"), int)
                else None,
            )
            prior = by_build.get(key)
            if prior is None or _record_sort_key(filename, record) > _record_sort_key(
                prior[1], prior[2]
            ):
                by_build[key] = (subdir, filename, record)
        selected = list(by_build.values())
    else:
        by_version_subdir: dict[tuple[str, str], tuple[str, str, dict]] = {}
        for subdir, filename, record in candidates:
            key = (str(record.get("version") or ""), subdir)
            prior = by_version_subdir.get(key)
            if prior is None or _record_sort_key(filename, record) > _record_sort_key(
                prior[1], prior[2]
            ):
                by_version_subdir[key] = (subdir, filename, record)
        selected = list(by_version_subdir.values())

    selected.sort(
        key=lambda item: (
            _version_sort_key(str(item[2].get("version") or "")),
            item[0],
            _record_sort_key(item[1], item[2]),
        ),
        reverse=True,
    )
    return [
        SbomWorkItem(
            index=0,
            name=name,
            mapping=mapping,
            subdir=subdir,
            filename=filename,
            record=record,
        )
        for subdir, filename, record in selected
    ]


def generate_many(
    entries: list[tuple[str, dict[str, Any]]],
    *,
    channel: str,
    out_dir: Path,
    purl_type_filter: str,
    random_one: bool = False,
    seed: str | None = None,
    limit: int | None = None,
    fail_fast: bool = False,
    repodata_cache_dir: Path | None = None,
    cache_max_age_seconds: int = DEFAULT_REPODATA_CACHE_SECONDS,
    refresh_cache: bool = False,
    workers: int = 1,
    progress: ProgressTracker | None = None,
    on_artifacts: ArtifactHandler | None = None,
    versions_per_package: int | None = None,
    artifact_subdirs: str = "mapped",
    artifact_selection: str = ARTIFACT_SELECTION_LATEST,
    skip_artifacts: ArtifactSkipPredicate | None = None,
) -> BatchResult:
    _validate_workers(workers, option="--workers")
    _validate_versions_per_package(versions_per_package)
    _validate_artifact_selection(artifact_selection)
    selected_mappings, skipped, skip_reasons = _select_entries(
        entries,
        purl_type_filter=purl_type_filter,
        random_one=random_one,
        seed=seed,
        limit=limit,
    )

    generated: list[Path] = []
    existing = 0
    inventory_skipped = 0
    errors: list[str] = []
    repodata_cache: dict[str, dict[str, Any]] = {}
    repodata_index_cache: dict[str, dict[str, list[tuple[str, dict]]]] = {}
    repodata_lock = threading.Lock()
    processed = 0
    new_count = 0

    def repodata_for_subdir(subdir: str) -> dict[str, Any]:
        with repodata_lock:
            if subdir not in repodata_cache:
                LOGGER.info("loading repodata for SBOM batch subdir=%s", subdir)
                repodata_cache[subdir] = load_repodata(
                    channel=channel,
                    subdir=subdir,
                    cache_dir=repodata_cache_dir,
                    cache_max_age_seconds=cache_max_age_seconds,
                    refresh_cache=refresh_cache,
                )
            return repodata_cache[subdir]

    def records_for_package(subdir: str, name: str) -> list[tuple[str, dict]]:
        with repodata_lock:
            if subdir not in repodata_index_cache:
                if subdir not in repodata_cache:
                    LOGGER.info("loading repodata for SBOM batch subdir=%s", subdir)
                    repodata_cache[subdir] = load_repodata(
                        channel=channel,
                        subdir=subdir,
                        cache_dir=repodata_cache_dir,
                        cache_max_age_seconds=cache_max_age_seconds,
                        refresh_cache=refresh_cache,
                    )
                LOGGER.info("indexing repodata for SBOM batch subdir=%s", subdir)
                repodata_index_cache[subdir] = _records_by_package(
                    repodata_cache[subdir]
                )
            return [
                (filename, dict(record))
                for filename, record in repodata_index_cache[subdir].get(name, [])
            ]

    def make_work_items() -> list[SbomWorkItem]:
        if versions_per_package is None:
            return [
                SbomWorkItem(
                    index=index,
                    name=name,
                    mapping=mapping,
                    subdir=str(mapping["subdir"]),
                )
                for index, (name, mapping) in enumerate(selected_mappings, start=1)
            ]

        work: list[SbomWorkItem] = []
        for name, mapping in selected_mappings:
            try:
                artifacts = select_package_artifacts(
                    name=name,
                    mapping=mapping,
                    records_for_package=records_for_package,
                    versions_per_package=versions_per_package,
                    artifact_subdirs=artifact_subdirs,
                    artifact_selection=artifact_selection,
                )
                if not artifacts:
                    raise SbomError(
                        "no repodata records matched historical version selection"
                    )
                work.extend(artifacts)
            except SbomError as exc:
                record_error(name, str(mapping.get("subdir") or "?"), exc)
                if fail_fast:
                    raise SbomError(f"{name}: {exc}") from exc

        return [
            SbomWorkItem(
                index=index,
                name=item.name,
                mapping=item.mapping,
                subdir=item.subdir,
                filename=item.filename,
                record=item.record,
            )
            for index, item in enumerate(work, start=1)
        ]

    def record_error(name: str, subdir: str, exc: SbomError) -> None:
        message = f"{name}: {exc}"
        errors.append(message)
        LOGGER.error(
            "SBOM package failed package=%s subdir=%s error=%s",
            name,
            subdir,
            exc,
        )

    work_items = make_work_items()

    if progress:
        progress.update(
            totals={
                "selected": len(work_items),
                "selected_mappings": len(selected_mappings),
                "skipped_ineligible": skipped,
            },
            counts={
                "processed": 0,
                "new_sboms": 0,
                "existing_sboms": 0,
                "inventory_skipped_sboms": 0,
                "errors": len(errors),
                "workers": workers,
            },
        )
    LOGGER.info(
        "SBOM selection complete total_mappings=%d selected_mappings=%d "
        "selected_artifacts=%d skipped=%d skip_reasons=%s random=%s seed=%s "
        "limit=%s purl_type=%s workers=%d versions_per_package=%s "
        "artifact_subdirs=%s artifact_selection=%s",
        len(entries),
        len(selected_mappings),
        len(work_items),
        skipped,
        skip_reasons,
        random_one,
        seed,
        limit,
        purl_type_filter,
        workers,
        versions_per_package,
        artifact_subdirs,
        artifact_selection,
    )

    def process_item(item: SbomWorkItem) -> GeneratedSbom:
        LOGGER.info(
            "generating SBOM package=%s subdir=%s index=%d total=%d purl=%s "
            "filename=%s historical=%s",
            item.name,
            item.subdir,
            item.index,
            len(work_items),
            item.mapping.get("purl"),
            item.filename,
            item.record is not None,
        )
        if item.record is not None and item.filename is not None:
            filename, selected_subdir, sbom = generate_sbom_from_record(
                item.mapping,
                record=item.record,
                filename=item.filename,
                subdir=item.subdir,
                channel=channel,
                purl_type_filter=purl_type_filter,
            )
        else:
            filename, selected_subdir, sbom = generate_sbom_from_mapping(
                item.mapping,
                version=None,
                build=None,
                subdir=None,
                filename=None,
                channel=channel,
                repodata_ref=None,
                purl_type_filter=purl_type_filter,
                repodata=repodata_for_subdir(item.subdir),
            )
        artifact_sha256 = get_security_sbom_artifact_sha256(sbom)
        expected_path = sbom_output_path(
            out_dir,
            subdir=selected_subdir,
            filename=filename,
            version=artifact_sha256,
        )
        if skip_artifacts is not None and skip_artifacts([expected_path]):
            LOGGER.info(
                "skipping inventory-present SBOM package=%s subdir=%s "
                "filename=%s path=%s",
                item.name,
                selected_subdir,
                filename,
                expected_path,
            )
            return GeneratedSbom(
                index=item.index,
                name=item.name,
                subdir=selected_subdir,
                filename=filename,
                path=expected_path,
                created=False,
                inventory_skipped=True,
            )
        out, created = write_versioned_sbom(
            sbom=sbom,
            root=out_dir,
            subdir=selected_subdir,
            filename=filename,
        )
        LOGGER.info(
            "SBOM package complete package=%s filename=%s path=%s created=%s",
            item.name,
            filename,
            out,
            created,
        )
        if on_artifacts:
            LOGGER.info(
                "handling generated SBOM artifacts package=%s path=%s",
                item.name,
                out,
            )
            on_artifacts(sbom_artifact_paths(out))
        return GeneratedSbom(
            index=item.index,
            name=item.name,
            subdir=selected_subdir,
            filename=filename,
            path=out,
            created=created,
        )

    def record_success(result: GeneratedSbom) -> None:
        nonlocal existing, inventory_skipped, new_count
        if result.inventory_skipped:
            inventory_skipped += 1
            return
        generated.append(result.path)
        existing += 0 if result.created else 1
        new_count += 1 if result.created else 0

    def update_processed(count: int, name: str, subdir: str) -> None:
        if progress:
            progress.update(
                current={
                    "index": count,
                    "total": len(work_items),
                    "package": name,
                    "subdir": subdir,
                },
                counts={
                    "processed": processed,
                    "new_sboms": new_count,
                    "existing_sboms": existing,
                    "inventory_skipped_sboms": inventory_skipped,
                    "errors": len(errors),
                },
            )

    if workers == 1:
        for item in work_items:
            try:
                record_success(process_item(item))
            except S3PublishError:
                raise
            except SbomError as exc:
                record_error(item.name, item.subdir, exc)
                if fail_fast:
                    raise SbomError(f"{item.name}: {exc}") from exc
            finally:
                processed += 1
                update_processed(processed, item.name, item.subdir)
        return BatchResult(
            generated=generated,
            existing=existing,
            skipped=skipped,
            errors=errors,
            inventory_skipped=inventory_skipped,
        )

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(process_item, item): item for item in work_items}
        for future in as_completed(futures):
            item = futures[future]
            try:
                record_success(future.result())
            except S3PublishError:
                raise
            except SbomError as exc:
                record_error(item.name, item.subdir, exc)
                if fail_fast:
                    raise SbomError(f"{item.name}: {exc}") from exc
            finally:
                processed += 1
                update_processed(processed, item.name, item.subdir)

    return BatchResult(
        generated=generated,
        existing=existing,
        skipped=skipped,
        errors=errors,
        inventory_skipped=inventory_skipped,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mapping_json",
        nargs="?",
        type=Path,
        default=DEFAULT_MAPPING_PAYLOAD,
        help="purl-associator JSON payload",
    )
    parser.add_argument("--channel", default=DEFAULT_CHANNEL, help="conda channel")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=DEFAULT_LOCAL_CHANNEL,
        help="local advisory-channel root",
    )
    parser.add_argument(
        "--purl-type",
        default="pypi",
        help="required mapped PURL type, or 'any'",
    )
    parser.add_argument(
        "--random",
        action="store_true",
        help="generate one random eligible package from the mapping payload",
    )
    parser.add_argument("--seed", help="seed for --random selection")
    parser.add_argument(
        "--limit",
        type=int,
        help="process at most N eligible package mappings",
    )
    parser.add_argument(
        "--versions-per-package",
        type=int,
        help=(
            "generate SBOMs for the latest N distinct conda versions per "
            "eligible package instead of only the mapped artifact"
        ),
    )
    parser.add_argument(
        "--artifact-subdirs",
        default="mapped",
        help=(
            "subdirs to scan for --versions-per-package: 'mapped', 'all', "
            "or a comma-separated list"
        ),
    )
    parser.add_argument(
        "--artifact-selection",
        choices=[ARTIFACT_SELECTION_LATEST, ARTIFACT_SELECTION_ALL_BUILDS],
        default=ARTIFACT_SELECTION_LATEST,
        help="which artifacts to emit for each selected package version",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        help="optional on-disk repodata cache directory",
    )
    parser.add_argument(
        "--cache-max-age-seconds",
        type=int,
        default=DEFAULT_REPODATA_CACHE_SECONDS,
        help="reuse cached repodata younger than this many seconds",
    )
    parser.add_argument(
        "--refresh-cache",
        action="store_true",
        help="revalidate cached repodata before generation",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="stop after the first generation error",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="parallel package generation/upload workers",
    )
    parser.add_argument(
        "--progress-file",
        type=Path,
        help="write JSON progress for this SBOM refresh load",
    )
    parser.add_argument(
        "--update-index",
        action="store_true",
        help="update mutable advisory-channel indexes for generated SBOMs",
    )
    parser.add_argument(
        "--s3-sbom-inventory",
        type=Path,
        help=(
            "local inventory from sbom:s3-inventory; artifacts listed there "
            "skip S3 HEAD/PUT checks"
        ),
    )
    parser.add_argument(
        "--skip-existing-s3-sboms",
        action="store_true",
        help=(
            "with --s3-sbom-inventory, skip local SBOM generation when the exact "
            "SBOM path already exists in the inventory"
        ),
    )
    add_s3_args(parser)
    add_logging_args(parser, command_name="sbom-refresh")
    args = parser.parse_args()
    log_path = configure_logging(
        command_name="sbom-refresh",
        log_level=args.log_level,
        log_file=args.log_file,
    )
    LOGGER.info(
        "starting SBOM refresh mapping_json=%s channel=%s out_dir=%s random=%s "
        "seed=%s limit=%s purl_type=%s cache_dir=%s s3_uri=%s s3_dry_run=%s "
        "cleanup_uploaded=%s update_index=%s workers=%d s3_workers=%d "
        "versions_per_package=%s artifact_subdirs=%s artifact_selection=%s "
        "skip_existing_s3_sboms=%s",
        args.mapping_json,
        args.channel,
        args.out_dir,
        args.random,
        args.seed,
        args.limit,
        args.purl_type,
        args.cache_dir,
        args.s3_uri,
        args.s3_dry_run,
        args.cleanup_uploaded,
        args.update_index,
        args.workers,
        args.s3_workers,
        args.versions_per_package,
        args.artifact_subdirs,
        args.artifact_selection,
        args.skip_existing_s3_sboms,
    )

    progress = (
        ProgressTracker(
            path=args.progress_file,
            load_type="sbom-refresh",
            metadata={
                "mapping_json": str(args.mapping_json),
                "channel": args.channel,
                "out_dir": str(args.out_dir),
                "s3_uri": args.s3_uri,
                "cleanup_uploaded": args.cleanup_uploaded,
                "update_index": args.update_index,
                "workers": args.workers,
                "s3_workers": args.s3_workers,
                "versions_per_package": args.versions_per_package,
                "artifact_subdirs": args.artifact_subdirs,
                "artifact_selection": args.artifact_selection,
                "skip_existing_s3_sboms": args.skip_existing_s3_sboms,
                "s3_sbom_inventory": str(args.s3_sbom_inventory)
                if args.s3_sbom_inventory
                else None,
            },
        )
        if args.progress_file
        else None
    )
    s3_uploaded = 0
    s3_existing = 0
    cleaned = 0
    inventory_existing = 0
    s3_inventory: set[str] | None = None
    try:
        if args.s3_sbom_inventory and not args.s3_uri:
            raise SbomError("--s3-sbom-inventory requires --s3-uri")
        if args.skip_existing_s3_sboms and not args.s3_sbom_inventory:
            raise SbomError("--skip-existing-s3-sboms requires --s3-sbom-inventory")
        if args.update_index and args.skip_existing_s3_sboms:
            raise SbomError(
                "--update-index cannot be combined with --skip-existing-s3-sboms; "
                "run advisory:index from the S3 inventory after the refresh instead"
            )
        if args.s3_sbom_inventory:
            s3_inventory = load_s3_sbom_inventory(args.s3_sbom_inventory)
            LOGGER.info(
                "loaded S3 SBOM inventory path=%s objects=%d",
                args.s3_sbom_inventory,
                len(s3_inventory),
            )
    except SbomError as exc:
        if progress:
            progress.fail(exc)
        LOGGER.error("could not load S3 SBOM inventory error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)
    index_state = (
        AdvisoryIndexState.load(channel_root=args.out_dir, channel=args.channel)
        if args.update_index
        else None
    )
    publish_lock = threading.Lock()

    def publish_artifacts(paths: list[Path]) -> None:
        nonlocal s3_uploaded, s3_existing, cleaned, inventory_existing
        if index_state:
            with publish_lock:
                for path in paths:
                    try:
                        relative = (
                            path.resolve().relative_to(args.out_dir.resolve()).as_posix()
                        )
                    except ValueError:
                        continue
                    if is_sbom_artifact_path(relative):
                        LOGGER.info("updating advisory index from SBOM path=%s", path)
                        index_state.update_sbom(path)
        if not args.s3_uri:
            return
        if s3_inventory is not None and paths_present_in_inventory(
            paths,
            root=args.out_dir,
            inventory=s3_inventory,
        ):
            LOGGER.info(
                "skipping S3 upload for inventory-present SBOM artifacts count=%d",
                len(paths),
            )
            summary = inventory_upload_summary(
                paths,
                root=args.out_dir,
                s3_uri=args.s3_uri,
            )
            if args.cleanup_uploaded and not args.s3_dry_run:
                cleanup = cleanup_uploaded_files(summary, root=args.out_dir)
            else:
                cleanup = None
            with publish_lock:
                if cleanup:
                    cleaned += cleanup.count
                s3_existing += summary.existing
                inventory_existing += summary.existing
                if progress:
                    progress.update(
                        counts={
                            "s3_uploaded": s3_uploaded,
                            "s3_existing": s3_existing,
                            "s3_inventory_existing": inventory_existing,
                            "local_artifacts_cleaned": cleaned,
                        }
                    )
            return
        LOGGER.info("publishing SBOM artifacts to S3 count=%d", len(paths))
        summary = upload_files(
            local_paths=paths,
            root=args.out_dir,
            s3_uri=args.s3_uri,
            profile=args.s3_profile,
            region=args.s3_region,
            dry_run=args.s3_dry_run,
            workers=args.s3_workers,
        )
        if args.cleanup_uploaded and not args.s3_dry_run:
            LOGGER.info(
                "cleaning local SBOM artifacts after S3 publish count=%d",
                len(paths),
            )
            cleanup = cleanup_uploaded_files(summary, root=args.out_dir)
        else:
            cleanup = None
        with publish_lock:
            s3_uploaded += summary.uploaded
            s3_existing += summary.existing
            if cleanup:
                cleaned += cleanup.count
            if progress:
                progress.update(
                    counts={
                        "s3_uploaded": s3_uploaded,
                        "s3_existing": s3_existing,
                        "s3_inventory_existing": inventory_existing,
                        "local_artifacts_cleaned": cleaned,
                    }
                )

    def skip_inventory_artifacts(paths: list[Path]) -> bool:
        nonlocal s3_existing, inventory_existing
        if not args.skip_existing_s3_sboms or s3_inventory is None:
            return False
        if not paths_present_in_inventory(
            paths,
            root=args.out_dir,
            inventory=s3_inventory,
        ):
            return False
        LOGGER.info(
            "skipping local SBOM generation for inventory-present artifacts count=%d",
            len(paths),
        )
        summary = inventory_upload_summary(
            paths,
            root=args.out_dir,
            s3_uri=args.s3_uri,
        )
        with publish_lock:
            s3_existing += summary.existing
            inventory_existing += summary.existing
            if progress:
                progress.update(
                    counts={
                        "s3_uploaded": s3_uploaded,
                        "s3_existing": s3_existing,
                        "s3_inventory_existing": inventory_existing,
                        "local_artifacts_cleaned": cleaned,
                    }
                )
        return True

    try:
        entries = load_mapping_entries(args.mapping_json)
        LOGGER.info(
            "loaded mapping entries count=%d path=%s",
            len(entries),
            args.mapping_json,
        )
        result = generate_many(
            entries,
            channel=args.channel,
            out_dir=args.out_dir,
            purl_type_filter=args.purl_type,
            random_one=args.random,
            seed=args.seed,
            limit=args.limit,
            fail_fast=args.fail_fast,
            repodata_cache_dir=args.cache_dir,
            cache_max_age_seconds=args.cache_max_age_seconds,
            refresh_cache=args.refresh_cache,
            workers=args.workers,
            progress=progress,
            on_artifacts=publish_artifacts,
            versions_per_package=args.versions_per_package,
            artifact_subdirs=args.artifact_subdirs,
            artifact_selection=args.artifact_selection,
            skip_artifacts=skip_inventory_artifacts,
        )
    except (SbomError, S3PublishError, AdvisoryIndexError) as exc:
        if progress:
            progress.fail(exc)
        LOGGER.error("SBOM refresh failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)

    if progress:
        progress.complete(
            status="complete_with_errors" if result.errors else "complete"
        )
    try:
        index_paths: list[Path] = []
        if index_state:
            LOGGER.info("writing advisory indexes")
            index_paths = index_state.write()
            if progress:
                progress.update(counts={"indexes_written": len(index_paths)})
            if args.s3_uri:
                LOGGER.info(
                    "publishing mutable advisory indexes to S3 count=%d",
                    len(index_paths),
                )
                index_summary = upload_files(
                    local_paths=index_paths,
                    root=args.out_dir,
                    s3_uri=args.s3_uri,
                    profile=args.s3_profile,
                    region=args.s3_region,
                    dry_run=args.s3_dry_run,
                    overwrite=True,
                    workers=args.s3_workers,
                )
                if progress:
                    progress.update(
                        counts={
                            "indexes_uploaded": index_summary.uploaded,
                            "indexes_existing": index_summary.existing,
                        }
                    )
                action = "would upload" if args.s3_dry_run else "uploaded"
                print(
                    f"{action} {index_summary.uploaded} mutable index file(s)",
                    file=sys.stderr,
                )
    except (AdvisoryIndexError, S3PublishError) as exc:
        if progress:
            progress.fail(exc)
        LOGGER.error("SBOM refresh index update failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)
    for path in result.generated:
        print(path)
    for path in index_paths:
        print(path)
    if args.s3_uri:
        action = "would upload" if args.s3_dry_run else "uploaded"
        print(
            f"{action} {s3_uploaded} S3 artifact(s); {s3_existing} already existed",
            file=sys.stderr,
        )
        if inventory_existing:
            print(
                f"skipped {inventory_existing} S3 artifact check(s) from inventory",
                file=sys.stderr,
            )
        if args.cleanup_uploaded and not args.s3_dry_run:
            print(f"cleaned {cleaned} local artifact(s)", file=sys.stderr)
    print(
        "generated "
        f"{len(result.generated) - result.existing} new SBOM(s); "
        f"{result.existing} already existed; "
        f"{result.inventory_skipped} skipped from S3 inventory; "
        f"skipped {result.skipped} ineligible mapping(s); "
        f"{len(result.errors)} error(s)",
        file=sys.stderr,
    )
    LOGGER.info(
        "completed SBOM refresh new=%d existing=%d skipped=%d errors=%d "
        "inventory_skipped=%d s3_uploaded=%d s3_existing=%d "
        "s3_inventory_existing=%d cleaned=%d",
        len(result.generated) - result.existing,
        result.existing,
        result.skipped,
        len(result.errors),
        result.inventory_skipped,
        s3_uploaded,
        s3_existing,
        inventory_existing,
        cleaned,
    )
    print_log_location(log_path)
    for error in result.errors[:20]:
        print(f"error: {error}", file=sys.stderr)
    if result.errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
