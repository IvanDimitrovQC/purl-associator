"""Refresh OSV advisory artifacts for generated local SBOMs."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import shutil
import subprocess
import sys
import threading
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from scripts.advisory_index import AdvisoryIndexError, AdvisoryIndexState
from scripts.cli_logging import add_logging_args, configure_logging, print_log_location
from scripts.correlate_osv import (
    DEFAULT_OSV_BATCH_SIZE,
    DEFAULT_OSV_BATCH_URL,
    OsvError,
    _load_json_path,
    correlate_sbom_with_results,
    extract_component_purls,
    query_osv_chunked,
    versioned_output_path,
    write_advisory,
)
from scripts.generate_sbom import DEFAULT_LOCAL_CHANNEL
from scripts.load_progress import ProgressTracker
from scripts.s3_publish import (
    Runner,
    S3PublishError,
    add_s3_args,
    cleanup_uploaded_files,
    download_files,
    inventory_upload_summary,
    list_s3_relative_paths,
    load_s3_object_inventory,
    paths_present_in_inventory,
    s3_uri_for_path,
    upload_files,
)


LOGGER = logging.getLogger("scripts.refresh_osv")
DEFAULT_S3_SBOM_STAGE_DIR = Path(".tmp") / "osv-sbom-stage"


@dataclass(frozen=True)
class RefreshResult:
    scanned: int
    queried_purls: int
    written: int
    existing: int
    outputs: list[Path]


@dataclass(frozen=True)
class AdvisoryArtifact:
    index: int
    path: Path
    created: bool


OutputHandler = Callable[[Path], None]
SourceSbomResolver = Callable[[Path], str]


def load_s3_osv_inventory(path: Path) -> set[str]:
    try:
        return load_s3_object_inventory(path)
    except S3PublishError as exc:
        raise OsvError(str(exc)) from exc


def load_s3_sbom_source_inventory(path: Path) -> set[str]:
    try:
        return load_s3_object_inventory(path)
    except S3PublishError as exc:
        raise OsvError(str(exc)) from exc


def iter_sbom_paths(channel_root: Path) -> list[Path]:
    versioned = channel_root.glob("*/sboms/*/sbom-*.cdx.json")
    legacy = channel_root.glob("*/sboms/*.cdx.json")
    return sorted([*versioned, *legacy])


def is_s3_sbom_artifact_path(path: str) -> bool:
    name = Path(path).name
    return "/sboms/" in path and name.startswith("sbom-") and name.endswith(".cdx.json")


def filter_s3_sbom_artifact_paths(paths: list[str]) -> list[str]:
    return sorted(
        path for path in dict.fromkeys(paths) if is_s3_sbom_artifact_path(path)
    )


def s3_sbom_source_paths(
    *,
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    inventory_path: Path | None = None,
    limit: int | None = None,
    runner: Runner = subprocess.run,
) -> list[str]:
    if inventory_path:
        all_paths = sorted(load_s3_sbom_source_inventory(inventory_path))
        LOGGER.info(
            "loaded S3 SBOM source inventory path=%s objects=%d",
            inventory_path,
            len(all_paths),
        )
    else:
        all_paths = list_s3_relative_paths(
            s3_uri=s3_uri,
            profile=profile,
            region=region,
            runner=runner,
        )
    sbom_paths = filter_s3_sbom_artifact_paths(all_paths)
    if limit is not None:
        sbom_paths = sbom_paths[:limit]
    LOGGER.info(
        "selected S3 SBOM source objects s3_uri=%s count=%d limit=%s",
        s3_uri,
        len(sbom_paths),
        limit,
    )
    return sbom_paths


def stage_s3_sboms(
    *,
    s3_uri: str,
    stage_root: Path,
    profile: str | None = None,
    region: str | None = None,
    inventory_path: Path | None = None,
    limit: int | None = None,
    workers: int = 1,
    runner: Runner = subprocess.run,
) -> list[Path]:
    relative_paths = s3_sbom_source_paths(
        s3_uri=s3_uri,
        profile=profile,
        region=region,
        inventory_path=inventory_path,
        limit=limit,
        runner=runner,
    )
    LOGGER.info(
        "downloading S3 SBOM source objects count=%d stage_root=%s",
        len(relative_paths),
        stage_root,
    )
    summary = download_files(
        relative_paths=relative_paths,
        root=stage_root,
        s3_uri=s3_uri,
        profile=profile,
        region=region,
        workers=workers,
        runner=runner,
    )
    return summary.local_paths


def collect_queryable_purls(sboms: list[dict]) -> list[str]:
    purls: list[str] = []
    for sbom in sboms:
        for component in extract_component_purls(sbom):
            if component.get("queryable") and isinstance(component.get("purl"), str):
                purls.append(component["purl"])
    return list(dict.fromkeys(purls))


def _validate_workers(value: int, *, option: str) -> None:
    if value < 1:
        raise OsvError(f"{option} must be at least 1")


def _load_sboms(sbom_paths: list[Path], *, workers: int) -> list[dict]:
    if workers == 1 or len(sbom_paths) <= 1:
        return [_load_json_path(path) for path in sbom_paths]

    sboms: list[dict | None] = [None] * len(sbom_paths)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_load_json_path, path): index
            for index, path in enumerate(sbom_paths)
        }
        for future in as_completed(futures):
            sboms[futures[future]] = future.result()
    return [sbom for sbom in sboms if sbom is not None]


def refresh_osv(
    *,
    channel_root: Path,
    api_url: str = DEFAULT_OSV_BATCH_URL,
    batch_size: int = DEFAULT_OSV_BATCH_SIZE,
    limit: int | None = None,
    dry_run: bool = False,
    workers: int = 1,
    progress: ProgressTracker | None = None,
    on_output: OutputHandler | None = None,
    source_sbom_resolver: SourceSbomResolver | None = None,
) -> RefreshResult:
    _validate_workers(workers, option="--workers")
    sbom_paths = iter_sbom_paths(channel_root)
    if limit is not None:
        sbom_paths = sbom_paths[:limit]
    LOGGER.info(
        "scanning SBOMs for OSV refresh channel_root=%s sbom_count=%d limit=%s",
        channel_root,
        len(sbom_paths),
        limit,
    )

    sboms = _load_sboms(sbom_paths, workers=workers)
    purls = collect_queryable_purls(sboms)
    LOGGER.info("collected queryable PURLs for OSV refresh unique_purls=%d", len(purls))
    if progress:
        progress.update(
            totals={"sboms": len(sbom_paths), "unique_purls": len(purls)},
            current={"stage": "query_osv", "unique_purls": len(purls)},
        )
    osv_results = (
        query_osv_chunked(
            purls,
            api_url=api_url,
            batch_size=batch_size,
            detail_workers=workers,
        )
        if purls
        else {}
    )
    if not purls:
        LOGGER.info("skipping OSV query because no queryable PURLs were found")
    if progress:
        progress.update(
            counts={
                "processed": 0,
                "new_advisories": 0,
                "existing_advisories": 0,
            },
        )

    outputs: list[Path] = []
    written = 0
    existing = 0

    def process_sbom(index: int, sbom_path: Path, sbom: dict) -> AdvisoryArtifact:
        LOGGER.info(
            "building OSV advisory artifact sbom=%s index=%d total=%d",
            sbom_path,
            index,
            len(sbom_paths),
        )
        advisory = correlate_sbom_with_results(
            sbom,
            source_sbom=source_sbom_resolver(sbom_path)
            if source_sbom_resolver
            else str(sbom_path),
            osv_results=osv_results,
            api_url=api_url,
        )
        out = versioned_output_path(sbom_path, advisory)
        if dry_run:
            created = not out.exists()
            LOGGER.info(
                "dry-run OSV advisory path=%s would_create=%s",
                out,
                created,
            )
            if on_output:
                on_output(out)
            return AdvisoryArtifact(index=index, path=out, created=created)
        out, created = write_advisory(advisory, out)
        LOGGER.info(
            "OSV advisory artifact complete path=%s created=%s",
            out,
            created,
        )
        if on_output:
            on_output(out)
        return AdvisoryArtifact(index=index, path=out, created=created)

    def record_result(result: AdvisoryArtifact) -> None:
        nonlocal written, existing
        outputs.append(result.path)
        written += 1 if result.created else 0
        existing += 0 if result.created else 1

    def update_processed(count: int, path: Path) -> None:
        if progress:
            progress.update(
                current={
                    "index": count,
                    "total": len(sbom_paths),
                    "sbom": str(path),
                },
                counts={
                    "processed": count,
                    "new_advisories": written,
                    "existing_advisories": existing,
                },
            )

    if workers == 1:
        for index, (sbom_path, sbom) in enumerate(
            zip(sbom_paths, sboms, strict=True), 1
        ):
            record_result(process_sbom(index, sbom_path, sbom))
            update_processed(index, sbom_path)
    else:
        processed = 0
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(process_sbom, index, sbom_path, sbom): sbom_path
                for index, (sbom_path, sbom) in enumerate(
                    zip(sbom_paths, sboms, strict=True), 1
                )
            }
            for future in as_completed(futures):
                processed += 1
                sbom_path = futures[future]
                record_result(future.result())
                update_processed(processed, sbom_path)

    return RefreshResult(
        scanned=len(sbom_paths),
        queried_purls=len(purls),
        written=written,
        existing=existing,
        outputs=outputs,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--channel-root",
        type=Path,
        default=DEFAULT_LOCAL_CHANNEL,
        help="local advisory-channel root",
    )
    parser.add_argument(
        "--api-url",
        default=DEFAULT_OSV_BATCH_URL,
        help="OSV querybatch endpoint",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_OSV_BATCH_SIZE,
        help="number of deduplicated PURLs per OSV querybatch call",
    )
    parser.add_argument("--limit", type=int, help="process at most N SBOM files")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print planned advisory paths without writing files",
    )
    parser.add_argument(
        "--progress-file",
        type=Path,
        help="write JSON progress for this OSV refresh load",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="parallel SBOM loading and OSV advisory generation/upload workers",
    )
    parser.add_argument(
        "--update-index",
        action="store_true",
        help="update mutable advisory-channel indexes for generated advisories",
    )
    parser.add_argument(
        "--s3-osv-inventory",
        type=Path,
        help=(
            "local inventory from osv:s3-inventory; exact advisory paths listed "
            "there skip S3 HEAD/PUT checks"
        ),
    )
    parser.add_argument(
        "--s3-sbom-source-uri",
        help=(
            "optional s3://bucket/prefix advisory-channel source to read SBOM "
            "artifacts from before querying OSV"
        ),
    )
    parser.add_argument(
        "--s3-sbom-source-inventory",
        type=Path,
        help=(
            "local inventory from sbom:s3-inventory; avoids listing S3 before "
            "downloading source SBOMs"
        ),
    )
    parser.add_argument(
        "--s3-sbom-stage-dir",
        type=Path,
        default=DEFAULT_S3_SBOM_STAGE_DIR,
        help="parent directory for temporary S3-sourced SBOM staging",
    )
    parser.add_argument(
        "--keep-s3-sbom-stage",
        action="store_true",
        help="keep temporary S3-sourced SBOM staging files after a successful run",
    )
    add_s3_args(parser)
    add_logging_args(parser, command_name="osv-refresh")
    args = parser.parse_args()
    log_path = configure_logging(
        command_name="osv-refresh",
        log_level=args.log_level,
        log_file=args.log_file,
    )
    LOGGER.info(
        "starting OSV refresh channel_root=%s api_url=%s batch_size=%d limit=%s "
        "dry_run=%s s3_uri=%s s3_dry_run=%s cleanup_uploaded=%s update_index=%s "
        "workers=%d s3_workers=%d s3_sbom_source_uri=%s "
        "s3_sbom_source_inventory=%s s3_sbom_stage_dir=%s",
        args.channel_root,
        args.api_url,
        args.batch_size,
        args.limit,
        args.dry_run,
        args.s3_uri,
        args.s3_dry_run,
        args.cleanup_uploaded,
        args.update_index,
        args.workers,
        args.s3_workers,
        args.s3_sbom_source_uri,
        args.s3_sbom_source_inventory,
        args.s3_sbom_stage_dir,
    )

    run_channel_root = args.channel_root
    staged_channel_root: Path | None = None
    staged_sbom_count = 0
    progress = (
        ProgressTracker(
            path=args.progress_file,
            load_type="osv-refresh",
            metadata={
                "channel_root": str(args.channel_root),
                "api_url": args.api_url,
                "batch_size": args.batch_size,
                "s3_uri": args.s3_uri,
                "cleanup_uploaded": args.cleanup_uploaded,
                "dry_run": args.dry_run,
                "update_index": args.update_index,
                "workers": args.workers,
                "s3_workers": args.s3_workers,
                "s3_osv_inventory": str(args.s3_osv_inventory)
                if args.s3_osv_inventory
                else None,
                "s3_sbom_source_uri": args.s3_sbom_source_uri,
                "s3_sbom_source_inventory": str(args.s3_sbom_source_inventory)
                if args.s3_sbom_source_inventory
                else None,
                "s3_sbom_stage_dir": str(args.s3_sbom_stage_dir),
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
        if args.s3_osv_inventory and not args.s3_uri:
            raise OsvError("--s3-osv-inventory requires --s3-uri")
        if args.s3_sbom_source_inventory and not args.s3_sbom_source_uri:
            raise OsvError("--s3-sbom-source-inventory requires --s3-sbom-source-uri")
        if args.s3_osv_inventory:
            s3_inventory = load_s3_osv_inventory(args.s3_osv_inventory)
            LOGGER.info(
                "loaded S3 OSV inventory path=%s objects=%d",
                args.s3_osv_inventory,
                len(s3_inventory),
            )
        if args.s3_sbom_source_uri:
            args.s3_sbom_stage_dir.mkdir(parents=True, exist_ok=True)
            staged_channel_root = Path(
                tempfile.mkdtemp(prefix="run-", dir=args.s3_sbom_stage_dir)
            )
            LOGGER.info(
                "created S3 SBOM staging channel_root=%s",
                staged_channel_root,
            )
            staged_sboms = stage_s3_sboms(
                s3_uri=args.s3_sbom_source_uri,
                stage_root=staged_channel_root,
                profile=args.s3_profile,
                region=args.s3_region,
                inventory_path=args.s3_sbom_source_inventory,
                limit=args.limit,
                workers=args.s3_workers,
            )
            staged_sbom_count = len(staged_sboms)
            if staged_sbom_count == 0:
                raise OsvError(
                    f"no SBOM artifacts found in S3 source {args.s3_sbom_source_uri}"
                )
            run_channel_root = staged_channel_root
            LOGGER.info(
                "staged S3 SBOM source objects count=%d channel_root=%s",
                staged_sbom_count,
                run_channel_root,
            )
            if progress:
                progress.update(
                    metadata={"run_channel_root": str(run_channel_root)},
                    counts={"s3_sboms_downloaded": staged_sbom_count},
                )
    except OsvError as exc:
        if progress:
            progress.fail(exc)
        LOGGER.error("could not load S3 OSV inventory error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)
    except S3PublishError as exc:
        if progress:
            progress.fail(exc)
        LOGGER.error("could not stage S3 SBOM source error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)
    index_state = (
        AdvisoryIndexState.load(channel_root=run_channel_root)
        if args.update_index and not args.dry_run
        else None
    )
    publish_lock = threading.Lock()

    def publish_output(path: Path) -> None:
        nonlocal s3_uploaded, s3_existing, cleaned, inventory_existing
        if index_state and path.exists():
            with publish_lock:
                LOGGER.info("updating advisory index from OSV artifact path=%s", path)
                index_state.update_advisory(path)
        if not args.s3_uri:
            return
        publish_dry_run = args.dry_run or args.s3_dry_run
        if s3_inventory is not None and paths_present_in_inventory(
            [path],
            root=run_channel_root,
            inventory=s3_inventory,
        ):
            LOGGER.info(
                "skipping S3 upload for inventory-present OSV advisory path=%s",
                path,
            )
            summary = inventory_upload_summary(
                [path],
                root=run_channel_root,
                s3_uri=args.s3_uri,
            )
            if args.cleanup_uploaded and not publish_dry_run:
                cleanup = cleanup_uploaded_files(summary, root=run_channel_root)
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
        LOGGER.info(
            "publishing OSV advisory artifact to S3 path=%s dry_run=%s",
            path,
            publish_dry_run,
        )
        summary = upload_files(
            local_paths=[path],
            root=run_channel_root,
            s3_uri=args.s3_uri,
            profile=args.s3_profile,
            region=args.s3_region,
            dry_run=publish_dry_run,
            workers=args.s3_workers,
        )
        if args.cleanup_uploaded and not publish_dry_run:
            LOGGER.info(
                "cleaning local OSV advisory artifact after S3 publish path=%s",
                path,
            )
            cleanup = cleanup_uploaded_files(summary, root=run_channel_root)
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
        if index_state:
            sbom_index_paths = iter_sbom_paths(run_channel_root)
            LOGGER.info(
                "updating advisory indexes from SBOM artifacts count=%d",
                len(sbom_index_paths),
            )
            for path in sbom_index_paths:
                index_state.update_sbom(path)
        result = refresh_osv(
            channel_root=run_channel_root,
            api_url=args.api_url,
            batch_size=args.batch_size,
            limit=None if args.s3_sbom_source_uri else args.limit,
            dry_run=args.dry_run,
            workers=args.workers,
            progress=progress,
            on_output=publish_output,
            source_sbom_resolver=(
                (
                    lambda path: s3_uri_for_path(
                        local_path=path,
                        root=run_channel_root,
                        s3_uri=args.s3_sbom_source_uri,
                    )
                )
                if args.s3_sbom_source_uri
                else None
            ),
        )
    except (OsvError, S3PublishError, AdvisoryIndexError) as exc:
        if progress:
            progress.fail(exc)
        LOGGER.error("OSV refresh failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)

    if progress:
        progress.complete()
    try:
        index_paths: list[Path] = []
        if index_state:
            LOGGER.info("writing advisory indexes after OSV refresh")
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
                    root=run_channel_root,
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
        LOGGER.error("OSV refresh index update failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)
    for path in result.outputs:
        print(path)
    for path in index_paths:
        print(path)
    if args.s3_uri:
        s3_dry_run = args.dry_run or args.s3_dry_run
        action = "would upload" if s3_dry_run else "uploaded"
        print(
            f"{action} {s3_uploaded} S3 artifact(s); {s3_existing} already existed",
            file=sys.stderr,
        )
        if inventory_existing:
            print(
                f"skipped {inventory_existing} S3 artifact check(s) from inventory",
                file=sys.stderr,
            )
        if args.cleanup_uploaded and not s3_dry_run:
            print(f"cleaned {cleaned} local artifact(s)", file=sys.stderr)
    if staged_channel_root and not args.keep_s3_sbom_stage:
        shutil.rmtree(staged_channel_root, ignore_errors=True)
        LOGGER.info("removed S3 SBOM staging channel_root=%s", staged_channel_root)
        if progress:
            progress.update(counts={"s3_staged_sboms_cleaned": staged_sbom_count})
    action = "would generate" if args.dry_run else "generated"
    print(
        f"{action} {result.written} new OSV advisory artifact(s); "
        f"{result.existing} already existed; "
        f"scanned {result.scanned} SBOM(s); "
        f"queried {result.queried_purls} unique PURL(s)",
        file=sys.stderr,
    )
    LOGGER.info(
        "completed OSV refresh written=%d existing=%d scanned=%d queried_purls=%d "
        "s3_uploaded=%d s3_existing=%d s3_inventory_existing=%d cleaned=%d",
        result.written,
        result.existing,
        result.scanned,
        result.queried_purls,
        s3_uploaded,
        s3_existing,
        inventory_existing,
        cleaned,
    )
    print_log_location(log_path)


if __name__ == "__main__":
    main()
