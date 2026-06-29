"""Generate CycloneDX SBOMs from a purl-associator mapping JSON payload."""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import random
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
    _load_json_path,
    _load_json_ref,
    generate_sbom_from_mapping,
    purl_type,
    sbom_artifact_paths,
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

DEFAULT_REPODATA_CACHE = Path(".cache") / "repodata"
DEFAULT_REPODATA_CACHE_SECONDS = 1200
DEFAULT_REPODATA_RETRIES = 3
DEFAULT_REPODATA_RETRY_DELAY_SECONDS = 1.0
LOGGER = logging.getLogger("scripts.generate_sboms")


@dataclass(frozen=True)
class BatchResult:
    generated: list[Path]
    existing: int
    skipped: int
    errors: list[str]


@dataclass(frozen=True)
class GeneratedSbom:
    index: int
    name: str
    subdir: str
    filename: str
    path: Path
    created: bool


ArtifactHandler = Callable[[list[Path]], None]


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
) -> BatchResult:
    _validate_workers(workers, option="--workers")
    selected, skipped, skip_reasons = _select_entries(
        entries,
        purl_type_filter=purl_type_filter,
        random_one=random_one,
        seed=seed,
        limit=limit,
    )

    generated: list[Path] = []
    existing = 0
    errors: list[str] = []
    repodata_cache: dict[str, dict[str, Any]] = {}
    repodata_lock = threading.Lock()
    processed = 0
    new_count = 0

    if progress:
        progress.update(
            totals={
                "selected": len(selected),
                "skipped_ineligible": skipped,
            },
            counts={
                "processed": 0,
                "new_sboms": 0,
                "existing_sboms": 0,
                "errors": 0,
                "workers": workers,
            },
        )
    LOGGER.info(
        "SBOM selection complete total_mappings=%d selected=%d skipped=%d "
        "skip_reasons=%s random=%s seed=%s limit=%s purl_type=%s workers=%d",
        len(entries),
        len(selected),
        skipped,
        skip_reasons,
        random_one,
        seed,
        limit,
        purl_type_filter,
        workers,
    )

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

    def process_entry(index: int, name: str, mapping: dict[str, Any]) -> GeneratedSbom:
        subdir = str(mapping["subdir"])
        LOGGER.info(
            "generating SBOM package=%s subdir=%s index=%d total=%d purl=%s",
            name,
            subdir,
            index,
            len(selected),
            mapping.get("purl"),
        )
        filename, selected_subdir, sbom = generate_sbom_from_mapping(
            mapping,
            version=None,
            build=None,
            subdir=None,
            filename=None,
            channel=channel,
            repodata_ref=None,
            purl_type_filter=purl_type_filter,
            repodata=repodata_for_subdir(subdir),
        )
        out, created = write_versioned_sbom(
            sbom=sbom,
            root=out_dir,
            subdir=selected_subdir,
            filename=filename,
        )
        LOGGER.info(
            "SBOM package complete package=%s filename=%s path=%s created=%s",
            name,
            filename,
            out,
            created,
        )
        if on_artifacts:
            LOGGER.info(
                "handling generated SBOM artifacts package=%s path=%s",
                name,
                out,
            )
            on_artifacts(sbom_artifact_paths(out))
        return GeneratedSbom(
            index=index,
            name=name,
            subdir=selected_subdir,
            filename=filename,
            path=out,
            created=created,
        )

    def record_success(result: GeneratedSbom) -> None:
        nonlocal existing, new_count
        generated.append(result.path)
        existing += 0 if result.created else 1
        new_count += 1 if result.created else 0

    def record_error(name: str, subdir: str, exc: SbomError) -> None:
        message = f"{name}: {exc}"
        errors.append(message)
        LOGGER.error(
            "SBOM package failed package=%s subdir=%s error=%s",
            name,
            subdir,
            exc,
        )

    def update_processed(count: int, name: str, subdir: str) -> None:
        if progress:
            progress.update(
                current={
                    "index": count,
                    "total": len(selected),
                    "package": name,
                    "subdir": subdir,
                },
                counts={
                    "processed": processed,
                    "new_sboms": new_count,
                    "existing_sboms": existing,
                    "errors": len(errors),
                },
            )

    if workers == 1:
        for index, (name, mapping) in enumerate(selected, start=1):
            subdir = str(mapping["subdir"])
            try:
                record_success(process_entry(index, name, mapping))
            except S3PublishError:
                raise
            except SbomError as exc:
                record_error(name, subdir, exc)
                if fail_fast:
                    raise SbomError(f"{name}: {exc}") from exc
            finally:
                processed += 1
                update_processed(processed, name, subdir)
        return BatchResult(
            generated=generated, existing=existing, skipped=skipped, errors=errors
        )

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(process_entry, index, name, mapping): (
                name,
                str(mapping["subdir"]),
            )
            for index, (name, mapping) in enumerate(selected, start=1)
        }
        for future in as_completed(futures):
            name, subdir = futures[future]
            try:
                record_success(future.result())
            except S3PublishError:
                raise
            except SbomError as exc:
                record_error(name, subdir, exc)
                if fail_fast:
                    raise SbomError(f"{name}: {exc}") from exc
            finally:
                processed += 1
                update_processed(processed, name, subdir)

    return BatchResult(
        generated=generated, existing=existing, skipped=skipped, errors=errors
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
    parser.add_argument("--limit", type=int, help="generate at most N SBOMs")
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
        "cleanup_uploaded=%s update_index=%s workers=%d s3_workers=%d",
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
                    if path.name.startswith("sbom-") and path.name.endswith(
                        ".cdx.json"
                    ):
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
        f"skipped {result.skipped} ineligible mapping(s); "
        f"{len(result.errors)} error(s)",
        file=sys.stderr,
    )
    LOGGER.info(
        "completed SBOM refresh new=%d existing=%d skipped=%d errors=%d "
        "s3_uploaded=%d s3_existing=%d s3_inventory_existing=%d cleaned=%d",
        len(result.generated) - result.existing,
        result.existing,
        result.skipped,
        len(result.errors),
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
