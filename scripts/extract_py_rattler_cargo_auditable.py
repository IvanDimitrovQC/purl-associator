"""Extract cargo-auditable JSON for py-rattler artifacts from conda packages."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen
import zipfile

from scripts.cli_logging import add_logging_args, configure_logging, print_log_location
from scripts.generate_sbom import DEFAULT_CHANNEL, conda_artifact_stem
from scripts.generate_sboms import (
    ARTIFACT_SELECTION_ALL_BUILDS,
    ARTIFACT_SELECTION_LATEST,
    DEFAULT_ARTIFACT_SUBDIRS,
    DEFAULT_REPODATA_CACHE,
    DEFAULT_REPODATA_CACHE_SECONDS,
    SbomError,
    load_repodata,
)
from scripts.py_rattler_advisory_channel import (
    PyRattlerAdvisoryError,
    records_for_package,
    select_py_rattler_records,
)
from scripts.rust_crate_advisory_channel import CondaLockRecord

LOGGER = logging.getLogger("scripts.extract_py_rattler_cargo_auditable")
DEFAULT_PACKAGE = "py-rattler"
DEFAULT_OUTPUT_DIR = Path(".tmp") / "py-rattler-cargo-auditable"
DEFAULT_PACKAGE_CACHE_DIR = Path(".cache") / "conda-packages"
DEFAULT_WORKERS = 4
BINARY_SUFFIXES = (".so", ".dylib", ".dll", ".exe")


class CargoAuditableExtractionError(RuntimeError):
    """User-facing cargo-auditable extraction failure."""


@dataclass(frozen=True)
class ExtractionResult:
    record: CondaLockRecord
    output_path: Path | None
    checked_binaries: int
    status: str
    message: str | None = None


def _split_csv(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return list(dict.fromkeys(out))


def _cache_dir(value: Path | None) -> Path | None:
    if value is None:
        return None
    if str(value) == "":
        return None
    return value


def _artifact_output_path(record: CondaLockRecord, out_dir: Path) -> Path:
    return out_dir / f"{conda_artifact_stem(record.filename)}.json"


def _package_cache_path(record: CondaLockRecord, cache_dir: Path) -> Path:
    return cache_dir / record.subdir / record.filename


def download_package(record: CondaLockRecord, *, cache_dir: Path) -> Path:
    out = _package_cache_path(record, cache_dir)
    if out.exists():
        LOGGER.info("using cached conda artifact path=%s", out)
        return out
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(f".{out.name}.tmp")
    LOGGER.info("downloading conda artifact url=%s path=%s", record.url, out)
    request = Request(record.url, headers={"User-Agent": "purl-associator/1"})
    try:
        with urlopen(request, timeout=120) as response, tmp.open("wb") as f:
            shutil.copyfileobj(response, f)
    except URLError as exc:
        raise CargoAuditableExtractionError(
            f"could not download {record.url}: {exc.reason}"
        ) from exc
    except OSError as exc:
        raise CargoAuditableExtractionError(
            f"could not write downloaded artifact {out}: {exc}"
        ) from exc
    tmp.replace(out)
    return out


def _safe_extract_tar(archive: tarfile.TarFile, *, out_dir: Path) -> None:
    out_resolved = out_dir.resolve()
    for member in archive.getmembers():
        target = (out_dir / member.name).resolve()
        try:
            target.relative_to(out_resolved)
        except ValueError as exc:
            raise CargoAuditableExtractionError(
                f"refusing to extract unsafe tar member {member.name!r}"
            ) from exc
    archive.extractall(out_dir)


def _safe_extract_tar_stream(archive: tarfile.TarFile, *, out_dir: Path) -> None:
    out_resolved = out_dir.resolve()
    for member in archive:
        target = (out_dir / member.name).resolve()
        try:
            target.relative_to(out_resolved)
        except ValueError as exc:
            raise CargoAuditableExtractionError(
                f"refusing to extract unsafe tar member {member.name!r}"
            ) from exc
        archive.extract(member, out_dir)


def _extract_tar_zst_with_python(tar_zst: Path, *, out_dir: Path) -> bool:
    try:
        import zstandard  # type: ignore[import-not-found]
    except ImportError:
        return False

    LOGGER.info("extracting zstd tar with Python zstandard path=%s", tar_zst)
    with tar_zst.open("rb") as compressed:
        reader = zstandard.ZstdDecompressor().stream_reader(compressed)
        with tarfile.open(fileobj=reader, mode="r|") as archive:
            _safe_extract_tar_stream(archive, out_dir=out_dir)
    return True


def _run_tar(command: list[str]) -> bool:
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode == 0:
        return True
    LOGGER.debug(
        "tar extraction command failed command=%s stderr=%s",
        command,
        result.stderr.strip(),
    )
    return False


def _extract_tar_zst_with_tar(tar_zst: Path, *, out_dir: Path) -> None:
    commands = [
        ["tar", "--zstd", "-xf", str(tar_zst), "-C", str(out_dir)],
        ["tar", "-I", "zstd", "-xf", str(tar_zst), "-C", str(out_dir)],
        ["tar", "-xf", str(tar_zst), "-C", str(out_dir)],
    ]
    for command in commands:
        if _run_tar(command):
            return
    raise CargoAuditableExtractionError(
        "could not extract .conda payload; install zstd or a tar with zstd support"
    )


def extract_package_payload(package_path: Path, *, out_dir: Path) -> Path:
    payload_dir = out_dir / "payload"
    payload_dir.mkdir(parents=True, exist_ok=True)
    if package_path.name.endswith(".tar.bz2"):
        LOGGER.info("extracting legacy conda package path=%s", package_path)
        with tarfile.open(package_path, mode="r:bz2") as archive:
            _safe_extract_tar(archive, out_dir=payload_dir)
        return payload_dir

    if package_path.name.endswith(".conda"):
        LOGGER.info("extracting .conda package path=%s", package_path)
        with zipfile.ZipFile(package_path) as package:
            payload_names = [
                name
                for name in package.namelist()
                if Path(name).name.startswith("pkg-") and name.endswith(".tar.zst")
            ]
            if not payload_names:
                raise CargoAuditableExtractionError(
                    f"{package_path}: missing pkg-*.tar.zst payload"
                )
            tar_zst = out_dir / Path(payload_names[0]).name
            with package.open(payload_names[0]) as source, tar_zst.open("wb") as dest:
                shutil.copyfileobj(source, dest)
        if not _extract_tar_zst_with_python(tar_zst, out_dir=payload_dir):
            _extract_tar_zst_with_tar(tar_zst, out_dir=payload_dir)
        return payload_dir

    raise CargoAuditableExtractionError(f"{package_path}: unsupported package format")


def _is_binary_candidate(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.name.endswith(BINARY_SUFFIXES):
        return True
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return bool(mode & (os.X_OK))


def _binary_candidates(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if _is_binary_candidate(path))


def _load_rust_audit_info(path: Path, *, tool: str) -> dict[str, Any] | None:
    result = subprocess.run([tool, str(path)], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        LOGGER.debug("rust-audit-info returned non-JSON output path=%s", path)
        return None
    if not isinstance(data, dict):
        return None
    packages = data.get("packages")
    if isinstance(packages, list) and packages:
        return data
    return None


def _decorate_audit_payload(
    payload: dict[str, Any],
    *,
    record: CondaLockRecord,
    source_binary: Path,
    payload_root: Path,
) -> dict[str, Any]:
    decorated = dict(payload)
    try:
        relative_binary = source_binary.relative_to(payload_root).as_posix()
    except ValueError:
        relative_binary = source_binary.as_posix()
    decorated["conda_artifact"] = {
        "name": record.name,
        "version": record.version,
        "build": record.build,
        "build_number": record.build_number,
        "subdir": record.subdir,
        "filename": record.filename,
        "url": record.url,
        "sha256": record.sha256,
        "md5": record.md5,
    }
    decorated["source_binary"] = relative_binary
    return decorated


def extract_audit_info_for_record(
    record: CondaLockRecord,
    *,
    out_dir: Path,
    package_cache_dir: Path,
    rust_audit_info: str,
    force: bool = False,
) -> ExtractionResult:
    out_path = _artifact_output_path(record, out_dir)
    if out_path.exists() and not force:
        return ExtractionResult(
            record=record,
            output_path=out_path,
            checked_binaries=0,
            status="exists",
        )

    package_path = download_package(record, cache_dir=package_cache_dir)
    with tempfile.TemporaryDirectory(prefix="py-rattler-audit-") as tmp:
        payload_root = extract_package_payload(package_path, out_dir=Path(tmp))
        checked = 0
        for candidate in _binary_candidates(payload_root):
            checked += 1
            payload = _load_rust_audit_info(candidate, tool=rust_audit_info)
            if payload is None:
                continue
            out_path.parent.mkdir(parents=True, exist_ok=True)
            decorated = _decorate_audit_payload(
                payload,
                record=record,
                source_binary=candidate,
                payload_root=payload_root,
            )
            tmp_out = out_path.with_name(f".{out_path.name}.tmp")
            tmp_out.write_text(json.dumps(decorated, indent=2, sort_keys=True) + "\n")
            tmp_out.replace(out_path)
            return ExtractionResult(
                record=record,
                output_path=out_path,
                checked_binaries=checked,
                status="created",
            )

    return ExtractionResult(
        record=record,
        output_path=None,
        checked_binaries=checked,
        status="missing",
        message="no cargo-auditable metadata found",
    )


def collect_py_rattler_records(
    *,
    channel: str,
    package_name: str,
    subdirs: list[str],
    artifact_selection: str,
    limit_versions: int | None,
    cache_dir: Path | None,
    cache_max_age_seconds: int,
    refresh_cache: bool,
) -> list[CondaLockRecord]:
    records: list[CondaLockRecord] = []
    for subdir in subdirs:
        repodata = load_repodata(
            channel=channel,
            subdir=subdir,
            cache_dir=cache_dir,
            cache_max_age_seconds=cache_max_age_seconds,
            refresh_cache=refresh_cache,
        )
        records.extend(
            records_for_package(
                channel=channel,
                subdir=subdir,
                package_name=package_name,
                repodata=repodata,
            )
        )
    return select_py_rattler_records(
        records,
        artifact_selection=artifact_selection,
        limit_versions=limit_versions,
    )


def extract_many(
    records: list[CondaLockRecord],
    *,
    out_dir: Path,
    package_cache_dir: Path,
    rust_audit_info: str,
    workers: int,
    force: bool,
) -> list[ExtractionResult]:
    if workers < 1:
        raise CargoAuditableExtractionError("--workers must be at least 1")
    if shutil.which(rust_audit_info) is None:
        raise CargoAuditableExtractionError(
            f"{rust_audit_info!r} was not found on PATH"
        )
    if workers == 1 or len(records) <= 1:
        return [
            extract_audit_info_for_record(
                record,
                out_dir=out_dir,
                package_cache_dir=package_cache_dir,
                rust_audit_info=rust_audit_info,
                force=force,
            )
            for record in records
        ]

    results: list[ExtractionResult | None] = [None] * len(records)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                extract_audit_info_for_record,
                record,
                out_dir=out_dir,
                package_cache_dir=package_cache_dir,
                rust_audit_info=rust_audit_info,
                force=force,
            ): index
            for index, record in enumerate(records)
        }
        for future in as_completed(futures):
            index = futures[future]
            results[index] = future.result()
    return [result for result in results if result is not None]


def _summary(results: list[ExtractionResult], *, out_dir: Path) -> dict[str, Any]:
    created = [result for result in results if result.status == "created"]
    existing = [result for result in results if result.status == "exists"]
    missing = [result for result in results if result.status == "missing"]
    return {
        "selected_artifacts": len(results),
        "created": len(created),
        "existing": len(existing),
        "missing": len(missing),
        "out_dir": out_dir.as_posix(),
        "outputs": [
            result.output_path.as_posix()
            for result in results
            if result.output_path is not None
        ],
        "missing_artifacts": [
            f"{result.record.subdir}/{result.record.filename}" for result in missing
        ],
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-name", default=DEFAULT_PACKAGE)
    parser.add_argument("--channel", default=DEFAULT_CHANNEL)
    parser.add_argument(
        "--subdir",
        action="append",
        default=[],
        help=(
            "conda subdir to include; can be repeated or comma-separated. "
            "Defaults to all common conda-forge subdirs."
        ),
    )
    parser.add_argument(
        "--artifact-selection",
        default=ARTIFACT_SELECTION_LATEST,
        choices=[ARTIFACT_SELECTION_LATEST, ARTIFACT_SELECTION_ALL_BUILDS],
    )
    parser.add_argument("--limit-versions", type=int)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--package-cache-dir",
        type=Path,
        default=DEFAULT_PACKAGE_CACHE_DIR,
        help="local cache for downloaded conda artifacts",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=DEFAULT_REPODATA_CACHE,
        help="repodata cache directory; pass an empty string to disable caching",
    )
    parser.add_argument(
        "--cache-max-age-seconds",
        type=int,
        default=DEFAULT_REPODATA_CACHE_SECONDS,
    )
    parser.add_argument("--refresh-cache", action="store_true")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--rust-audit-info", default="rust-audit-info")
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--require-all",
        action="store_true",
        help="fail if any selected artifact has no cargo-auditable metadata",
    )
    add_logging_args(parser, command_name="py-rattler-cargo-auditable")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    log_path = configure_logging(
        command_name="py-rattler-cargo-auditable",
        log_level=args.log_level,
        log_file=args.log_file,
    )
    try:
        subdirs = _split_csv(args.subdir) or list(DEFAULT_ARTIFACT_SUBDIRS)
        records = collect_py_rattler_records(
            channel=args.channel,
            package_name=args.package_name,
            subdirs=subdirs,
            artifact_selection=args.artifact_selection,
            limit_versions=args.limit_versions,
            cache_dir=_cache_dir(args.cache_dir),
            cache_max_age_seconds=args.cache_max_age_seconds,
            refresh_cache=args.refresh_cache,
        )
        if not records:
            raise CargoAuditableExtractionError(
                f"no {args.package_name!r} package records found"
            )
        LOGGER.info("selected py-rattler artifacts for extraction count=%d", len(records))
        results = extract_many(
            records,
            out_dir=args.out_dir,
            package_cache_dir=args.package_cache_dir,
            rust_audit_info=args.rust_audit_info,
            workers=args.workers,
            force=args.force,
        )
        summary = _summary(results, out_dir=args.out_dir)
        if args.require_all and summary["missing"]:
            raise CargoAuditableExtractionError(
                "missing cargo-auditable metadata for "
                f"{summary['missing']} artifact(s): "
                + ", ".join(summary["missing_artifacts"][:10])
            )
    except (
        CargoAuditableExtractionError,
        PyRattlerAdvisoryError,
        SbomError,
        OSError,
        zipfile.BadZipFile,
        tarfile.TarError,
    ) as exc:
        LOGGER.error("py-rattler cargo-auditable extraction failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        raise SystemExit(1) from exc

    print(json.dumps(summary, indent=2, sort_keys=True))
    print_log_location(log_path)


if __name__ == "__main__":
    main()
