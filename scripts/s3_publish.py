"""Publish local advisory-channel artifacts to S3 using the AWS CLI."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse


class S3PublishError(RuntimeError):
    """User-facing S3 publishing failure."""


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class S3Location:
    bucket: str
    prefix: str


@dataclass(frozen=True)
class S3UploadResult:
    local_path: Path
    s3_uri: str
    uploaded: bool
    already_exists: bool


@dataclass(frozen=True)
class S3UploadSummary:
    results: list[S3UploadResult]

    @property
    def uploaded(self) -> int:
        return sum(1 for result in self.results if result.uploaded)

    @property
    def existing(self) -> int:
        return sum(1 for result in self.results if result.already_exists)


@dataclass(frozen=True)
class S3DownloadResult:
    relative_path: str
    local_path: Path
    s3_uri: str


@dataclass(frozen=True)
class S3DownloadSummary:
    results: list[S3DownloadResult]

    @property
    def downloaded(self) -> int:
        return len(self.results)

    @property
    def local_paths(self) -> list[Path]:
        return [result.local_path for result in self.results]


@dataclass(frozen=True)
class LocalCleanupSummary:
    removed: list[Path]

    @property
    def count(self) -> int:
        return len(self.removed)


Runner = Callable[..., subprocess.CompletedProcess[str]]


def parse_s3_uri(uri: str) -> S3Location:
    parsed = urlparse(uri)
    if parsed.scheme != "s3" or not parsed.netloc:
        raise S3PublishError(f"{uri!r} is not a valid s3://bucket[/prefix] URI")
    return S3Location(bucket=parsed.netloc, prefix=parsed.path.strip("/"))


def aws_global_args(*, profile: str | None, region: str | None) -> list[str]:
    args: list[str] = []
    if profile:
        args.extend(["--profile", profile])
    if region:
        args.extend(["--region", region])
    return args


def _json_or_error(result: subprocess.CompletedProcess[str], *, action: str) -> dict:
    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise S3PublishError(f"{action}: AWS CLI returned invalid JSON") from exc
    if not isinstance(data, dict):
        raise S3PublishError(f"{action}: AWS CLI returned a non-object JSON payload")
    return data


def load_s3_object_inventory(path: Path) -> set[str]:
    try:
        with path.open() as f:
            data = json.load(f)
    except FileNotFoundError as exc:
        raise S3PublishError(f"{path}: file does not exist") from exc
    except json.JSONDecodeError as exc:
        raise S3PublishError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise S3PublishError(f"{path}: expected a JSON object")
    objects = data.get("objects")
    if not isinstance(objects, list):
        raise S3PublishError(f"{path}: expected objects array")
    out: set[str] = set()
    for item in objects:
        if isinstance(item, str) and item:
            out.add(item)
    return out


def paths_present_in_inventory(
    paths: list[Path], *, root: Path, inventory: set[str]
) -> bool:
    relative_paths: list[str] = []
    for path in paths:
        try:
            relative_paths.append(path.resolve().relative_to(root.resolve()).as_posix())
        except ValueError as exc:
            raise S3PublishError(f"{path} is not under inventory root {root}") from exc
    return bool(relative_paths) and all(path in inventory for path in relative_paths)


def inventory_upload_summary(
    paths: list[Path], *, root: Path, s3_uri: str
) -> S3UploadSummary:
    return S3UploadSummary(
        [
            S3UploadResult(
                local_path=path,
                s3_uri=s3_uri_for_path(local_path=path, root=root, s3_uri=s3_uri),
                uploaded=False,
                already_exists=True,
            )
            for path in paths
        ]
    )


def add_s3_args(
    parser: argparse.ArgumentParser,
    *,
    include_cleanup: bool = True,
    include_dry_run: bool = True,
) -> None:
    parser.add_argument(
        "--s3-uri",
        help="optional s3://bucket/prefix destination for generated artifacts",
    )
    parser.add_argument("--s3-profile", help="AWS CLI profile for S3 publishing")
    parser.add_argument("--s3-region", help="AWS region for S3 publishing")
    if include_dry_run:
        parser.add_argument(
            "--s3-dry-run",
            action="store_true",
            help="print S3 destinations without calling AWS or uploading files",
        )
        parser.add_argument(
            "--s3-workers",
            type=int,
            default=1,
            help="parallel S3 object checks/uploads for each upload batch",
        )
    if include_cleanup:
        parser.add_argument(
            "--cleanup-uploaded",
            action="store_true",
            help=(
                "delete local artifacts after successful S3 upload or remote existence"
            ),
        )


def s3_uri_for_path(*, local_path: Path, root: Path, s3_uri: str) -> str:
    location = parse_s3_uri(s3_uri)
    try:
        relative = local_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise S3PublishError(f"{local_path} is not under publish root {root}") from exc

    key = "/".join(part for part in (location.prefix, relative) if part)
    return f"s3://{location.bucket}/{key}"


def s3_uri_for_relative_path(*, relative_path: str, s3_uri: str) -> str:
    location = parse_s3_uri(s3_uri)
    clean_relative = relative_path.strip("/")
    if not clean_relative:
        raise S3PublishError("relative S3 object path must not be empty")
    key = "/".join(part for part in (location.prefix, clean_relative) if part)
    return f"s3://{location.bucket}/{key}"


def content_type_for_path(path: Path) -> str:
    if path.name.endswith(".json"):
        return "application/json"
    if path.name.endswith(".conda"):
        return "application/octet-stream"
    return "application/octet-stream"


def _relative_key(key: str, *, prefix: str) -> str | None:
    clean_prefix = prefix.strip("/")
    if not clean_prefix:
        return key
    prefix_with_slash = f"{clean_prefix}/"
    if key == clean_prefix:
        return ""
    if key.startswith(prefix_with_slash):
        return key.removeprefix(prefix_with_slash)
    return None


def list_s3_relative_paths(
    *,
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    runner: Runner = subprocess.run,
) -> list[str]:
    """List S3 object keys below ``s3_uri`` as channel-relative paths."""

    location = parse_s3_uri(s3_uri)
    aws_args = aws_global_args(profile=profile, region=region)
    paths: list[str] = []
    token: str | None = None
    while True:
        cmd = [
            "aws",
            *aws_args,
            "s3api",
            "list-objects-v2",
            "--bucket",
            location.bucket,
            "--prefix",
            location.prefix,
            "--output",
            "json",
        ]
        if token:
            cmd.extend(["--continuation-token", token])
        LOGGER.info(
            "listing S3 objects s3_uri=%s continuation=%s",
            s3_uri,
            bool(token),
        )
        result = runner(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise S3PublishError(
                f"could not list {s3_uri}: {(result.stderr or '').strip()}"
            )
        data = _json_or_error(result, action=f"could not list {s3_uri}")
        contents = data.get("Contents") or []
        if not isinstance(contents, list):
            raise S3PublishError("S3 list response Contents must be an array")
        for item in contents:
            if not isinstance(item, dict) or not isinstance(item.get("Key"), str):
                continue
            relative = _relative_key(item["Key"], prefix=location.prefix)
            if relative:
                paths.append(relative)
        next_token = data.get("NextContinuationToken")
        if not isinstance(next_token, str) or not next_token:
            break
        token = next_token
    return paths


def _s3_key(destination: str) -> tuple[str, str]:
    location = parse_s3_uri(destination)
    if not location.prefix:
        raise S3PublishError(f"{destination!r} does not include an object key")
    return location.bucket, location.prefix


def _head_object_error_hint(
    *, stderr: str, profile: str | None, region: str | None
) -> str:
    if not any(
        marker in stderr
        for marker in ("400", "Bad Request", "301", "PermanentRedirect")
    ):
        return ""

    details = []
    if region:
        details.append(f"current --s3-region is {region!r}")
    else:
        details.append("no --s3-region was provided")
    if profile:
        details.append(f"current --s3-profile is {profile!r}")
    else:
        details.append("using the AWS CLI default profile/credential chain")

    return (
        " This often means the AWS CLI is checking the bucket with the wrong "
        "S3 region, profile, or account. Pass the bucket region with "
        "--s3-region, or configure that region on the selected AWS profile "
        f"({'; '.join(details)})."
    )


def _object_exists(
    *,
    destination: str,
    aws_args: list[str],
    profile: str | None,
    region: str | None,
    runner: Runner,
) -> bool:
    bucket, key = _s3_key(destination)
    LOGGER.info("checking S3 object destination=%s", destination)
    result = runner(
        [
            "aws",
            *aws_args,
            "s3api",
            "head-object",
            "--bucket",
            bucket,
            "--key",
            key,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        LOGGER.info("S3 object already exists destination=%s", destination)
        return True
    stderr = result.stderr or ""
    if "404" in stderr or "Not Found" in stderr or "NotFound" in stderr:
        LOGGER.info("S3 object does not exist destination=%s", destination)
        return False
    hint = _head_object_error_hint(stderr=stderr, profile=profile, region=region)
    LOGGER.error(
        "could not check S3 object destination=%s error=%s hint=%s",
        destination,
        stderr.strip(),
        hint.strip(),
    )
    raise S3PublishError(f"could not check {destination}: {stderr.strip()}{hint}")


def upload_file(
    *,
    local_path: Path,
    root: Path,
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    dry_run: bool = False,
    overwrite: bool = False,
    runner: Runner = subprocess.run,
) -> S3UploadResult:
    destination = s3_uri_for_path(local_path=local_path, root=root, s3_uri=s3_uri)
    if dry_run:
        LOGGER.info(
            "S3 dry run local=%s destination=%s overwrite=%s",
            local_path,
            destination,
            overwrite,
        )
        return S3UploadResult(local_path, destination, True, False)
    if not local_path.exists():
        LOGGER.error(
            "cannot upload missing file local=%s destination=%s",
            local_path,
            destination,
        )
        raise S3PublishError(f"{local_path}: file does not exist")

    aws_args = aws_global_args(profile=profile, region=region)
    if not overwrite and _object_exists(
        destination=destination,
        aws_args=aws_args,
        profile=profile,
        region=region,
        runner=runner,
    ):
        return S3UploadResult(local_path, destination, False, True)

    LOGGER.info(
        "uploading file to S3 local=%s destination=%s overwrite=%s",
        local_path,
        destination,
        overwrite,
    )
    result = runner(
        [
            "aws",
            *aws_args,
            "s3",
            "cp",
            str(local_path),
            destination,
            "--content-type",
            content_type_for_path(local_path),
            "--only-show-errors",
            "--no-progress",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        LOGGER.error(
            "S3 upload failed local=%s destination=%s error=%s",
            local_path,
            destination,
            result.stderr.strip(),
        )
        raise S3PublishError(f"could not upload {destination}: {result.stderr.strip()}")
    LOGGER.info("uploaded file to S3 local=%s destination=%s", local_path, destination)
    return S3UploadResult(local_path, destination, True, False)


def upload_files(
    *,
    local_paths: list[Path],
    root: Path,
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    dry_run: bool = False,
    overwrite: bool = False,
    workers: int = 1,
    runner: Runner = subprocess.run,
) -> S3UploadSummary:
    if workers < 1:
        raise S3PublishError("--s3-workers must be at least 1")
    unique_paths = list(dict.fromkeys(local_paths))
    if workers == 1 or len(unique_paths) <= 1:
        return S3UploadSummary(
            [
                upload_file(
                    local_path=path,
                    root=root,
                    s3_uri=s3_uri,
                    profile=profile,
                    region=region,
                    dry_run=dry_run,
                    overwrite=overwrite,
                    runner=runner,
                )
                for path in unique_paths
            ]
        )

    results: list[S3UploadResult | None] = [None] * len(unique_paths)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                upload_file,
                local_path=path,
                root=root,
                s3_uri=s3_uri,
                profile=profile,
                region=region,
                dry_run=dry_run,
                overwrite=overwrite,
                runner=runner,
            ): index
            for index, path in enumerate(unique_paths)
        }
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    return S3UploadSummary([result for result in results if result is not None])


def download_file(
    *,
    relative_path: str,
    root: Path,
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    runner: Runner = subprocess.run,
) -> S3DownloadResult:
    source = s3_uri_for_relative_path(relative_path=relative_path, s3_uri=s3_uri)
    local_path = root / relative_path
    local_path.parent.mkdir(parents=True, exist_ok=True)
    aws_args = aws_global_args(profile=profile, region=region)
    LOGGER.info("downloading S3 object source=%s local=%s", source, local_path)
    result = runner(
        [
            "aws",
            *aws_args,
            "s3",
            "cp",
            source,
            str(local_path),
            "--only-show-errors",
            "--no-progress",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        LOGGER.error(
            "S3 download failed source=%s local=%s error=%s",
            source,
            local_path,
            result.stderr.strip(),
        )
        raise S3PublishError(f"could not download {source}: {result.stderr.strip()}")
    LOGGER.info("downloaded S3 object source=%s local=%s", source, local_path)
    return S3DownloadResult(
        relative_path=relative_path,
        local_path=local_path,
        s3_uri=source,
    )


def download_files(
    *,
    relative_paths: list[str],
    root: Path,
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    workers: int = 1,
    runner: Runner = subprocess.run,
) -> S3DownloadSummary:
    if workers < 1:
        raise S3PublishError("--s3-workers must be at least 1")
    unique_paths = list(dict.fromkeys(relative_paths))
    if workers == 1 or len(unique_paths) <= 1:
        return S3DownloadSummary(
            [
                download_file(
                    relative_path=path,
                    root=root,
                    s3_uri=s3_uri,
                    profile=profile,
                    region=region,
                    runner=runner,
                )
                for path in unique_paths
            ]
        )

    results: list[S3DownloadResult | None] = [None] * len(unique_paths)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                download_file,
                relative_path=path,
                root=root,
                s3_uri=s3_uri,
                profile=profile,
                region=region,
                runner=runner,
            ): index
            for index, path in enumerate(unique_paths)
        }
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    return S3DownloadSummary([result for result in results if result is not None])


def _remove_empty_parents(*, start: Path, stop: Path) -> None:
    current = start.resolve()
    stop_resolved = stop.resolve()
    while current != stop_resolved:
        try:
            current.relative_to(stop_resolved)
        except ValueError:
            return
        try:
            current.rmdir()
        except OSError:
            return
        current = current.parent


def cleanup_uploaded_files(
    summary: S3UploadSummary, *, root: Path
) -> LocalCleanupSummary:
    removed: list[Path] = []
    root_resolved = root.resolve()
    for result in summary.results:
        if not (result.uploaded or result.already_exists):
            continue
        path = result.local_path
        if not path.exists():
            continue
        try:
            path.resolve().relative_to(root_resolved)
        except ValueError as exc:
            raise S3PublishError(f"{path} is not under cleanup root {root}") from exc
        path.unlink()
        removed.append(path)
        LOGGER.info("removed local uploaded artifact path=%s", path)
        _remove_empty_parents(start=path.parent, stop=root)
    return LocalCleanupSummary(removed)


def print_s3_summary(summary: S3UploadSummary, *, dry_run: bool) -> None:
    action = "would upload" if dry_run else "uploaded"
    print(
        f"{action} {summary.uploaded} S3 artifact(s); "
        f"{summary.existing} already existed",
        file=sys.stderr,
    )


def print_cleanup_summary(summary: LocalCleanupSummary) -> None:
    print(f"cleaned {summary.count} local artifact(s)", file=sys.stderr)
