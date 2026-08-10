"""Build a static JSON payload for the advisory dashboard."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.cli_logging import add_logging_args, configure_logging, print_log_location
from scripts.advisory_index import SHARDS_DIR
from scripts.correlate_osv import default_osv_vulnerability_url
from scripts.generate_sboms import load_mapping_entries
from scripts.s3_publish import (
    Runner,
    S3PublishError,
    add_s3_args,
    aws_global_args,
    s3_uri_for_relative_path,
    upload_file,
)

DEFAULT_OUTPUT_PATH = Path("web") / "public" / "advisory-dashboard-data.json"
DEFAULT_MAPPING_JSON = Path("mappings") / "auto.json"
DEFAULT_OSV_SUMMARY = Path(".tmp") / "osv-vulnerability-summary.json"
DEFAULT_WORKERS = 8
ADVISORY_DASHBOARD_SCHEMA_VERSION = 2
LOGGER = logging.getLogger("scripts.advisory_dashboard_data")
AdvisoryChannelSource = dict[str, Any]


class DashboardDataError(RuntimeError):
    """User-facing dashboard data generation failure."""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _load_json_path(path: Path) -> dict[str, Any]:
    try:
        with path.open() as f:
            data = json.load(f)
    except FileNotFoundError as exc:
        raise DashboardDataError(f"{path}: file does not exist") from exc
    except json.JSONDecodeError as exc:
        raise DashboardDataError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise DashboardDataError(f"{path}: expected a JSON object")
    return data


def _validate_workers(workers: int) -> None:
    if workers < 1:
        raise DashboardDataError("--workers must be at least 1")


def read_s3_json(
    *,
    relative_path: str,
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    source = s3_uri_for_relative_path(relative_path=relative_path, s3_uri=s3_uri)
    aws_args = aws_global_args(profile=profile, region=region)
    LOGGER.info("reading S3 JSON source=%s", source)
    result = runner(
        [
            "aws",
            *aws_args,
            "s3",
            "cp",
            source,
            "-",
            "--only-show-errors",
            "--no-progress",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise DashboardDataError(
            f"could not read {source}: {(result.stderr or '').strip()}"
        )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DashboardDataError(f"{source}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise DashboardDataError(f"{source}: expected a JSON object")
    return data


def _is_s3_uri(value: str) -> bool:
    return value.startswith("s3://")


def _local_channel_path(*, relative_path: str, channel_uri: str) -> Path:
    root = channel_uri.removeprefix("file://")
    return Path(root).expanduser() / relative_path.strip("/")


def read_channel_json(
    *,
    relative_path: str,
    channel_uri: str,
    profile: str | None = None,
    region: str | None = None,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    if _is_s3_uri(channel_uri):
        return read_s3_json(
            relative_path=relative_path,
            s3_uri=channel_uri,
            profile=profile,
            region=region,
            runner=runner,
        )

    path = _local_channel_path(relative_path=relative_path, channel_uri=channel_uri)
    LOGGER.info("reading local advisory-channel JSON source=%s", path)
    return _load_json_path(path)


def _shard_relative_path(*, subdir_index: dict[str, Any], entry: Any) -> str | None:
    if isinstance(entry, str) and entry:
        digest = entry
        path = None
    elif isinstance(entry, dict):
        path = entry.get("path")
        digest = entry.get("sha256")
    else:
        return None
    if isinstance(path, str) and path:
        return path.lstrip("/")
    if not isinstance(digest, str) or not digest:
        return None
    base_url = subdir_index.get("shards_base_url")
    if not isinstance(base_url, str) or not base_url:
        base_url = f"{SHARDS_DIR}/"
    return f"{base_url.rstrip('/')}/{digest}.json"


def _s3_shard_path(*, subdir_index: dict[str, Any], entry: Any) -> str | None:
    subdir = subdir_index.get("subdir")
    if not isinstance(subdir, str) or not subdir:
        return None
    shard_relative = _shard_relative_path(subdir_index=subdir_index, entry=entry)
    if not shard_relative:
        return None
    return f"{subdir}/{shard_relative}"


def expand_s3_sharded_indexes(
    subdir_indexes: list[dict[str, Any]],
    *,
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    workers: int = DEFAULT_WORKERS,
    runner: Runner = subprocess.run,
) -> list[dict[str, Any]]:
    _validate_workers(workers)
    expanded = [dict(index) for index in subdir_indexes]
    shard_reads: list[tuple[int, str]] = []
    for index, subdir_index in enumerate(expanded):
        packages = subdir_index.get("packages")
        if isinstance(packages, dict):
            continue
        shards = subdir_index.get("shards")
        if not isinstance(shards, dict):
            subdir_index["packages"] = {}
            continue
        for name, entry in sorted(shards.items()):
            shard_path = _s3_shard_path(subdir_index=subdir_index, entry=entry)
            if not shard_path:
                raise DashboardDataError(
                    f"invalid shard entry for package {name!r} in subdir index"
                )
            shard_reads.append((index, shard_path))

    if not shard_reads:
        return expanded

    LOGGER.info("loading advisory-channel shards count=%d", len(shard_reads))
    shard_results: list[tuple[int, dict[str, Any]] | None] = [None] * len(shard_reads)
    if workers == 1 or len(shard_reads) <= 1:
        for index, (subdir_index, shard_path) in enumerate(shard_reads):
            shard_results[index] = (
                subdir_index,
                read_channel_json(
                    relative_path=shard_path,
                    channel_uri=s3_uri,
                    profile=profile,
                    region=region,
                    runner=runner,
                ),
            )
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    read_channel_json,
                    relative_path=shard_path,
                    channel_uri=s3_uri,
                    profile=profile,
                    region=region,
                    runner=runner,
                ): (index, subdir_index)
                for index, (subdir_index, shard_path) in enumerate(shard_reads)
            }
            for future in as_completed(futures):
                result_index, subdir_index = futures[future]
                shard_results[result_index] = (subdir_index, future.result())

    for result in shard_results:
        if result is None:
            continue
        subdir_index, shard = result
        shard_packages = shard.get("packages.conda")
        if not isinstance(shard_packages, dict):
            shard_packages = shard.get("packages")
        if not isinstance(shard_packages, dict):
            raise DashboardDataError("advisory-channel shard is missing packages")
        packages = expanded[subdir_index].setdefault("packages", {})
        if not isinstance(packages, dict):
            raise DashboardDataError("expanded subdir packages must be an object")
        packages.update(shard_packages)
    return expanded


def load_s3_advisory_indexes(
    *,
    s3_uri: str,
    profile: str | None = None,
    region: str | None = None,
    workers: int = DEFAULT_WORKERS,
    runner: Runner = subprocess.run,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    _validate_workers(workers)
    channel_index = read_channel_json(
        relative_path="channel-index.json",
        channel_uri=s3_uri,
        profile=profile,
        region=region,
        runner=runner,
    )
    subdirs = channel_index.get("subdirs")
    if not isinstance(subdirs, dict):
        raise DashboardDataError("channel-index.json is missing subdirs object")

    index_paths: list[str] = []
    for value in subdirs.values():
        if isinstance(value, dict) and isinstance(value.get("index"), str):
            index_paths.append(value["index"])
    index_paths = sorted(dict.fromkeys(index_paths))
    LOGGER.info("loading subdir advisory indexes count=%d", len(index_paths))

    if workers == 1 or len(index_paths) <= 1:
        subdir_indexes = [
            read_channel_json(
                relative_path=path,
                channel_uri=s3_uri,
                profile=profile,
                region=region,
                runner=runner,
            )
            for path in index_paths
        ]
        return channel_index, expand_s3_sharded_indexes(
            subdir_indexes,
            s3_uri=s3_uri,
            profile=profile,
            region=region,
            workers=workers,
            runner=runner,
        )

    indexes: list[dict[str, Any] | None] = [None] * len(index_paths)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                read_channel_json,
                relative_path=path,
                channel_uri=s3_uri,
                profile=profile,
                region=region,
                runner=runner,
            ): index
            for index, path in enumerate(index_paths)
        }
        for future in as_completed(futures):
            indexes[futures[future]] = future.result()
    subdir_indexes = [index for index in indexes if index is not None]
    return channel_index, expand_s3_sharded_indexes(
        subdir_indexes,
        s3_uri=s3_uri,
        profile=profile,
        region=region,
        workers=workers,
        runner=runner,
    )


def load_mapping_by_name(path: Path) -> dict[str, dict[str, Any]]:
    try:
        entries = load_mapping_entries(path)
    except Exception as exc:
        raise DashboardDataError(f"could not load mapping JSON {path}: {exc}") from exc
    return {name: mapping for name, mapping in entries}


def load_osv_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        LOGGER.warning("OSV vulnerability summary does not exist path=%s", path)
        return {
            "schema_version": 1,
            "packages": {},
            "vulnerability_count": 0,
            "package_count": 0,
        }
    data = _load_json_path(path)
    packages = data.get("packages")
    if not isinstance(packages, dict):
        raise DashboardDataError(f"{path}: expected packages object")
    return data


def empty_osv_summary() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "packages": {},
        "vulnerability_count": 0,
        "package_count": 0,
    }


def _default_channel_name(s3_uri: str, *, priority: int) -> str:
    clean = s3_uri.rstrip("/")
    tail = clean.rsplit("/", 1)[-1]
    return tail or f"channel-{priority + 1}"


def parse_advisory_channel_arg(value: str, *, priority: int) -> AdvisoryChannelSource:
    raw = value.strip()
    if not raw:
        raise DashboardDataError("--advisory-channel must not be empty")
    if "=" in raw:
        name, s3_uri = raw.split("=", 1)
        name = name.strip()
        s3_uri = s3_uri.strip()
        if not name or not s3_uri:
            raise DashboardDataError(
                "--advisory-channel must be NAME=s3://bucket/prefix or NAME=path"
            )
    else:
        s3_uri = raw
        name = _default_channel_name(s3_uri, priority=priority)
    return {
        "name": name,
        "s3_uri": s3_uri,
        "priority": priority,
    }


def resolve_advisory_channels(
    *,
    s3_uri: str | None,
    advisory_channel_args: list[str],
) -> list[AdvisoryChannelSource]:
    if advisory_channel_args:
        return [
            parse_advisory_channel_arg(value, priority=index)
            for index, value in enumerate(advisory_channel_args)
        ]
    if s3_uri:
        return [
            {
                "name": _default_channel_name(s3_uri, priority=0),
                "s3_uri": s3_uri,
                "priority": 0,
            }
        ]
    raise DashboardDataError("--s3-uri or --advisory-channel is required")


def _source_name(source: AdvisoryChannelSource | None) -> str | None:
    name = source.get("name") if isinstance(source, dict) else None
    return name if isinstance(name, str) and name else None


def _source_uri(source: AdvisoryChannelSource | None) -> str | None:
    s3_uri = source.get("s3_uri") if isinstance(source, dict) else None
    return s3_uri if isinstance(s3_uri, str) and s3_uri else None


def _source_priority(source: AdvisoryChannelSource | None) -> int | None:
    priority = source.get("priority") if isinstance(source, dict) else None
    return priority if isinstance(priority, int) else None


def _source_ref(source: AdvisoryChannelSource | None) -> dict[str, Any] | None:
    name = _source_name(source)
    s3_uri = _source_uri(source)
    priority = _source_priority(source)
    if name is None and s3_uri is None:
        return None
    out: dict[str, Any] = {}
    if name is not None:
        out["name"] = name
    if s3_uri is not None:
        out["s3_uri"] = s3_uri
    if priority is not None:
        out["priority"] = priority
    return out


def _state_with_source(
    state: dict[str, Any],
    *,
    source: AdvisoryChannelSource | None,
) -> dict[str, Any]:
    out = dict(state)
    name = _source_name(source)
    s3_uri = _source_uri(source)
    priority = _source_priority(source)
    if name is not None:
        out["advisory_channel"] = name
    if s3_uri is not None:
        out["advisory_channel_uri"] = s3_uri
    if priority is not None:
        out["advisory_channel_priority"] = priority
    return out


def _vulnerability_with_source(
    vulnerability: dict[str, Any],
    *,
    source: AdvisoryChannelSource | None,
) -> dict[str, Any]:
    out = dict(vulnerability)
    source_ref = _source_ref(source)
    if source_ref is None:
        return out
    out["advisory_channel"] = source_ref.get("name")
    out["advisory_channel_uri"] = source_ref.get("s3_uri")
    out["advisory_channel_priority"] = source_ref.get("priority")
    out["advisory_channels"] = [source_ref]
    return out


def _version_sort_key(version: str | None) -> tuple:
    if not version:
        return ()
    parts: list[tuple[int, int | str]] = []
    for part in re.split(r"([0-9]+)", version):
        if not part:
            continue
        if part.isdigit():
            parts.append((1, int(part)))
        else:
            parts.append((0, part.lower()))
    return tuple(parts)


def _unique_sorted(values: list[str]) -> list[str]:
    return sorted(dict.fromkeys(values))


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _bool_exists(path: Any) -> bool:
    return isinstance(path, str) and bool(path)


def _url_for_vulnerability(vulnerability_id: Any, explicit_url: Any) -> str | None:
    if isinstance(explicit_url, str) and explicit_url:
        return explicit_url
    if isinstance(vulnerability_id, str) and vulnerability_id:
        return default_osv_vulnerability_url(vulnerability_id)
    return None


def _vulnerability_identifier(vulnerability: dict[str, Any]) -> str | None:
    for key in ("id", "vulnerability_id"):
        value = vulnerability.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _vulnerability_id(vulnerability: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(_vulnerability_identifier(vulnerability) or ""),
        str(vulnerability.get("component_purl") or ""),
        str(vulnerability.get("component_version") or ""),
    )


def _vulnerability_channels(vulnerability: dict[str, Any]) -> list[dict[str, Any]]:
    channels: list[dict[str, Any]] = []
    for value in _as_list(vulnerability.get("advisory_channels")):
        if not isinstance(value, dict):
            continue
        name = value.get("name")
        s3_uri = value.get("s3_uri")
        priority = value.get("priority")
        entry: dict[str, Any] = {}
        if isinstance(name, str) and name:
            entry["name"] = name
        if isinstance(s3_uri, str) and s3_uri:
            entry["s3_uri"] = s3_uri
        if isinstance(priority, int):
            entry["priority"] = priority
        if entry:
            channels.append(entry)

    name = vulnerability.get("advisory_channel")
    s3_uri = vulnerability.get("advisory_channel_uri")
    priority = vulnerability.get("advisory_channel_priority")
    if isinstance(name, str) and name:
        entry = {"name": name}
        if isinstance(s3_uri, str) and s3_uri:
            entry["s3_uri"] = s3_uri
        if isinstance(priority, int):
            entry["priority"] = priority
        channels.append(entry)

    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for channel in channels:
        key = (str(channel.get("name") or ""), str(channel.get("s3_uri") or ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(channel)
    return sorted(
        out,
        key=lambda item: (
            int(item.get("priority")) if isinstance(item.get("priority"), int) else 0,
            str(item.get("name") or ""),
        ),
    )


def _source_advisories(vulnerability: dict[str, Any]) -> list[str]:
    paths = [
        value
        for value in _as_list(vulnerability.get("source_advisories"))
        if isinstance(value, str) and value
    ]
    value = vulnerability.get("source_advisory")
    if isinstance(value, str) and value:
        paths.append(value)
    return sorted(dict.fromkeys(paths))


def _merge_vulnerability(
    existing: dict[str, Any],
    update: dict[str, Any],
) -> dict[str, Any]:
    merged = dict(existing)
    for key, value in update.items():
        if key in {
            "advisory_channel",
            "advisory_channel_uri",
            "advisory_channel_priority",
            "advisory_channels",
            "source_advisories",
        }:
            continue
        if merged.get(key) is None and value is not None:
            merged[key] = value

    channels = _vulnerability_channels(existing) + _vulnerability_channels(update)
    if channels:
        merged_channels = _vulnerability_channels({"advisory_channels": channels})
        merged["advisory_channels"] = merged_channels
        preferred = merged_channels[-1]
        merged["advisory_channel"] = preferred.get("name")
        merged["advisory_channel_uri"] = preferred.get("s3_uri")
        merged["advisory_channel_priority"] = preferred.get("priority")

    advisories = _source_advisories(existing) + _source_advisories(update)
    if advisories:
        merged["source_advisories"] = sorted(dict.fromkeys(advisories))
        merged["source_advisory"] = merged["source_advisories"][-1]
    return merged


def vulnerability_indexes(
    osv_summary: dict[str, Any],
) -> tuple[
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
]:
    by_package: dict[str, list[dict[str, Any]]] = {}
    by_advisory: dict[str, list[dict[str, Any]]] = {}
    packages = osv_summary.get("packages")
    if not isinstance(packages, dict):
        return by_package, by_advisory
    for package, vulnerabilities in packages.items():
        if not isinstance(package, str) or not isinstance(vulnerabilities, list):
            continue
        cleaned: list[dict[str, Any]] = []
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue
            vuln_id = _vulnerability_identifier(vulnerability)
            item = {
                "id": vuln_id,
                "component_purl": vulnerability.get("component_purl"),
                "component_name": vulnerability.get("component_name"),
                "component_version": vulnerability.get("component_version"),
                "modified": vulnerability.get("modified"),
                "url": _url_for_vulnerability(vuln_id, vulnerability.get("url")),
                "source_advisory": vulnerability.get("source_advisory"),
            }
            for severity_key in (
                "severity",
                "severity_score",
                "severity_vector",
                "severity_source",
            ):
                if vulnerability.get(severity_key) is not None:
                    item[severity_key] = vulnerability.get(severity_key)
            cleaned.append(item)
            source_advisory = item["source_advisory"]
            if isinstance(source_advisory, str):
                by_advisory.setdefault(source_advisory, []).append(item)
        by_package[package] = cleaned
    return by_package, by_advisory


def _placeholder_vulnerabilities(osv: dict[str, Any]) -> list[dict[str, Any]]:
    current = _string_or_none(osv.get("current"))
    out: list[dict[str, Any]] = []
    for finding_id in _as_list(osv.get("finding_ids")):
        if isinstance(finding_id, str):
            out.append(
                {
                    "id": finding_id,
                    "url": default_osv_vulnerability_url(finding_id),
                    "source_advisory": current,
                }
            )
    return out


def _indexed_vulnerabilities(osv: dict[str, Any]) -> list[dict[str, Any]]:
    vulnerabilities: list[dict[str, Any]] = []
    for vulnerability in _as_list(osv.get("vulnerabilities")):
        if not isinstance(vulnerability, dict):
            continue
        vuln_id = _vulnerability_identifier(vulnerability)
        item = {
            **vulnerability,
            "id": vuln_id,
            "url": _url_for_vulnerability(vuln_id, vulnerability.get("url")),
        }
        vulnerabilities.append(item)
    return vulnerabilities


def _current_sbom_record(record: dict[str, Any]) -> dict[str, Any]:
    sboms = record.get("sboms")
    if isinstance(sboms, dict):
        preferred = sboms.get("sbom.v1")
        if isinstance(preferred, dict):
            return preferred
        for value in sboms.values():
            if isinstance(value, dict):
                return value
    return _as_dict(record.get("sbom"))


def artifact_from_record(
    *,
    filename: str,
    record: dict[str, Any],
    vulnerabilities_by_advisory: dict[str, list[dict[str, Any]]],
    advisory_channel: AdvisoryChannelSource | None = None,
) -> dict[str, Any]:
    sbom = _current_sbom_record(record)
    osv = _as_dict(record.get("osv"))
    sbom_current = _string_or_none(sbom.get("current"))
    osv_current = _string_or_none(osv.get("current"))
    vulnerabilities = (
        vulnerabilities_by_advisory.get(osv_current, []) if osv_current else []
    )
    if not vulnerabilities:
        vulnerabilities = _indexed_vulnerabilities(osv)
    if not vulnerabilities and int(osv.get("vulnerability_count") or 0) > 0:
        vulnerabilities = _placeholder_vulnerabilities(osv)
    vulnerabilities = [
        _vulnerability_with_source(vulnerability, source=advisory_channel)
        for vulnerability in vulnerabilities
        if isinstance(vulnerability, dict)
    ]
    vulnerability_count = int(osv.get("vulnerability_count") or len(vulnerabilities))
    channel_ref = _source_ref(advisory_channel)
    advisory_channels = [channel_ref] if channel_ref is not None else []
    return {
        "filename": filename,
        "name": record.get("name"),
        "version": record.get("version"),
        "subdir": record.get("subdir"),
        "build": record.get("build"),
        "conda_purl": record.get("conda_purl"),
        "advisory_channels": advisory_channels,
        "component_purls": _as_list(sbom.get("component_purls")),
        "sbom": _state_with_source(
            {
                "exists": _bool_exists(sbom_current),
                "path": sbom_current,
                "version": sbom.get("version"),
                "input_sha256": sbom.get("input_sha256")
                if sbom.get("input_sha256") is not None
                else sbom.get("sbom_input_sha256"),
                "mapping_sha256": sbom.get("mapping_sha256"),
            },
            source=advisory_channel,
        ),
        "osv": _state_with_source(
            {
                "exists": _bool_exists(osv_current),
                "path": osv_current,
                "status": osv.get("status"),
                "correlation_version": osv.get("correlation_version"),
                "query_count": osv.get("query_count", 0),
                "vulnerability_count": vulnerability_count,
                "finding_ids": _as_list(osv.get("finding_ids")),
            },
            source=advisory_channel,
        ),
        "vulnerabilities": sorted(vulnerabilities, key=_vulnerability_id),
    }


def _artifact_merge_key(artifact: dict[str, Any]) -> tuple[str, str]:
    return (
        str(artifact.get("subdir") or ""),
        str(artifact.get("filename") or ""),
    )


def _merge_channel_refs(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for artifact in artifacts:
        for value in _as_list(artifact.get("advisory_channels")):
            if isinstance(value, dict):
                refs.append(value)
    return _vulnerability_channels({"advisory_channels": refs})


def _state_priority(state: dict[str, Any]) -> int:
    priority = state.get("advisory_channel_priority")
    return priority if isinstance(priority, int) else -1


def _state_layer(state: dict[str, Any]) -> dict[str, Any]:
    layer = {
        "exists": state.get("exists", False),
        "path": state.get("path"),
        "advisory_channel": state.get("advisory_channel"),
        "advisory_channel_uri": state.get("advisory_channel_uri"),
        "advisory_channel_priority": state.get("advisory_channel_priority"),
    }
    for key in (
        "status",
        "version",
        "correlation_version",
        "query_count",
        "vulnerability_count",
        "finding_ids",
    ):
        if state.get(key) is not None:
            layer[key] = state.get(key)
    return layer


def _merge_artifact_state(
    artifacts: list[dict[str, Any]],
    *,
    key: str,
) -> dict[str, Any]:
    states = [artifact.get(key) for artifact in artifacts]
    states = [state for state in states if isinstance(state, dict)]
    if not states:
        return {"exists": False, "path": None}
    existing = [state for state in states if state.get("exists")]
    candidates = existing or states
    selected = max(candidates, key=_state_priority)
    merged = dict(selected)
    merged["exists"] = bool(existing)
    layers = [_state_layer(state) for state in states]
    if layers:
        merged["layers"] = layers
    return merged


def _merge_layered_artifacts(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for artifact in artifacts:
        grouped.setdefault(_artifact_merge_key(artifact), []).append(artifact)

    merged_artifacts: list[dict[str, Any]] = []
    for key in sorted(grouped):
        items = sorted(
            grouped[key],
            key=lambda item: max(
                [
                    int(channel.get("priority"))
                    for channel in _as_list(item.get("advisory_channels"))
                    if isinstance(channel, dict)
                    and isinstance(channel.get("priority"), int)
                ]
                or [-1]
            ),
        )
        selected = items[-1]
        vulnerabilities = _dedupe_vulnerabilities(
            [
                vulnerability
                for item in items
                for vulnerability in _as_list(item.get("vulnerabilities"))
                if isinstance(vulnerability, dict)
            ]
        )
        merged_osv = _merge_artifact_state(items, key="osv")
        finding_ids = [
            vuln_id
            for vuln_id in (
                _vulnerability_identifier(vulnerability)
                for vulnerability in vulnerabilities
            )
            if vuln_id is not None
        ]
        if finding_ids:
            merged_osv["finding_ids"] = sorted(dict.fromkeys(finding_ids))
            merged_osv["vulnerability_count"] = len(finding_ids)
            merged_osv["status"] = "vulnerabilities_found"
        else:
            merged_osv["finding_ids"] = _unique_sorted(
                [
                    str(finding_id)
                    for item in items
                    for finding_id in _as_list(_as_dict(item.get("osv")).get("finding_ids"))
                    if finding_id
                ]
            )
            merged_osv["vulnerability_count"] = len(merged_osv["finding_ids"])
            if not merged_osv["exists"]:
                merged_osv["status"] = "missing"
            elif not merged_osv["finding_ids"]:
                merged_osv["status"] = "no_known_vulnerabilities"

        component_purls = _unique_sorted(
            [
                str(component_purl)
                for item in items
                for component_purl in _as_list(item.get("component_purls"))
                if component_purl
            ]
        )
        merged_artifacts.append(
            {
                "filename": selected.get("filename"),
                "name": selected.get("name"),
                "version": selected.get("version"),
                "subdir": selected.get("subdir"),
                "build": selected.get("build"),
                "conda_purl": selected.get("conda_purl"),
                "advisory_channels": _merge_channel_refs(items),
                "component_purls": component_purls,
                "sbom": _merge_artifact_state(items, key="sbom"),
                "osv": merged_osv,
                "vulnerabilities": vulnerabilities,
            }
        )
    return merged_artifacts


def artifacts_from_indexes(
    subdir_indexes: list[dict[str, Any]],
    *,
    vulnerabilities_by_advisory: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for index in subdir_indexes:
        advisory_channel = index.get("_advisory_channel")
        if not isinstance(advisory_channel, dict):
            advisory_channel = None
        packages = index.get("packages")
        if not isinstance(packages, dict):
            continue
        for filename, record in packages.items():
            if not isinstance(filename, str) or not isinstance(record, dict):
                continue
            artifacts.append(
                artifact_from_record(
                    filename=filename,
                    record=record,
                    vulnerabilities_by_advisory=vulnerabilities_by_advisory,
                    advisory_channel=advisory_channel,
                )
            )
    artifacts = _merge_layered_artifacts(artifacts)
    artifacts.sort(
        key=lambda item: (
            str(item.get("name") or ""),
            _version_sort_key(_string_or_none(item.get("version"))),
            str(item.get("subdir") or ""),
            str(item.get("build") or ""),
            str(item.get("filename") or ""),
        )
    )
    return artifacts


def _dedupe_vulnerabilities(
    vulnerabilities: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for vulnerability in vulnerabilities:
        vuln_id = _vulnerability_identifier(vulnerability)
        normalized = {
            **vulnerability,
            "id": vuln_id,
            "url": _url_for_vulnerability(vuln_id, vulnerability.get("url")),
        }
        key = _vulnerability_id(normalized)
        existing = by_key.get(key)
        by_key[key] = (
            normalized
            if existing is None
            else _merge_vulnerability(existing, normalized)
        )
    return [by_key[key] for key in sorted(by_key)]


def package_flags(
    *,
    has_purl: bool,
    artifact_count: int,
    sbom_existing: int,
    osv_existing: int,
    total_vulnerability_findings: int,
    latest_artifact_count: int,
    latest_osv_existing: int,
    latest_vulnerability_findings: int,
) -> list[str]:
    flags = ["has_purl" if has_purl else "missing_purl"]
    if artifact_count == 0 or sbom_existing == 0:
        flags.append("missing_sbom")
    elif sbom_existing < artifact_count:
        flags.append("partial_sbom")
    else:
        flags.append("has_sbom")

    if artifact_count == 0 or osv_existing == 0:
        flags.append("missing_osv")
    elif osv_existing < artifact_count:
        flags.append("partial_osv")
    else:
        flags.append("osv_checked")

    if total_vulnerability_findings > 0:
        flags.append("vulnerabilities_found")
    elif artifact_count > 0 and osv_existing == artifact_count:
        flags.append("no_known_vulnerabilities")

    if latest_artifact_count > 0:
        if latest_osv_existing == 0:
            flags.append("latest_version_missing_osv")
        elif latest_osv_existing < latest_artifact_count:
            flags.append("latest_version_partial_osv")
        elif latest_vulnerability_findings > 0:
            flags.append("latest_version_vulnerabilities_found")
        else:
            flags.append("latest_version_no_known_vulnerabilities")
    return flags


def build_package_payload(
    *,
    name: str,
    mapping: dict[str, Any] | None,
    artifacts: list[dict[str, Any]],
    summary_vulnerabilities: list[dict[str, Any]],
) -> dict[str, Any]:
    mapping = mapping or {}
    has_purl = isinstance(mapping.get("purl"), str) and bool(mapping.get("purl"))
    versions = _unique_sorted(
        [
            str(artifact.get("version"))
            for artifact in artifacts
            if artifact.get("version")
        ]
    )
    latest_version = max(versions, key=_version_sort_key) if versions else None
    latest_artifacts = [
        artifact for artifact in artifacts if artifact.get("version") == latest_version
    ]
    artifact_vulnerabilities = [
        vulnerability
        for artifact in artifacts
        for vulnerability in _as_list(artifact.get("vulnerabilities"))
        if isinstance(vulnerability, dict)
    ]
    vulnerabilities = _dedupe_vulnerabilities(
        [
            *artifact_vulnerabilities,
            *[
                vulnerability
                for vulnerability in summary_vulnerabilities
                if isinstance(vulnerability, dict)
            ],
        ]
    )

    artifact_count = len(artifacts)
    sbom_existing = sum(1 for artifact in artifacts if artifact["sbom"]["exists"])
    osv_existing = sum(1 for artifact in artifacts if artifact["osv"]["exists"])
    total_vulnerability_findings = sum(
        int(artifact["osv"].get("vulnerability_count") or 0) for artifact in artifacts
    )
    if total_vulnerability_findings == 0:
        total_vulnerability_findings = len(vulnerabilities)

    latest_osv_existing = sum(
        1 for artifact in latest_artifacts if artifact["osv"]["exists"]
    )
    latest_vulnerability_findings = sum(
        int(artifact["osv"].get("vulnerability_count") or 0)
        for artifact in latest_artifacts
    )
    return {
        "name": name,
        "mapped_purl": mapping.get("purl"),
        "purl_type": mapping.get("type"),
        "purl_confidence": mapping.get("confidence"),
        "has_purl": has_purl,
        "artifact_count": artifact_count,
        "version_count": len(versions),
        "subdir_count": len(
            _unique_sorted(
                [
                    str(artifact.get("subdir"))
                    for artifact in artifacts
                    if artifact.get("subdir")
                ]
            )
        ),
        "latest_version": latest_version,
        "latest_version_basis": "advisory_index" if latest_version else None,
        "sbom": {
            "any_exists": sbom_existing > 0,
            "all_artifacts_have_sbom": artifact_count > 0
            and sbom_existing == artifact_count,
            "missing_count": max(artifact_count - sbom_existing, 0),
        },
        "osv": {
            "any_artifact_checked": osv_existing > 0,
            "all_artifacts_checked": artifact_count > 0
            and osv_existing == artifact_count,
            "missing_count": max(artifact_count - osv_existing, 0),
            "any_vulnerabilities_found": total_vulnerability_findings > 0,
            "total_vulnerability_findings": total_vulnerability_findings,
            "unique_vulnerability_count": len(vulnerabilities),
            "no_vulnerabilities_found_for_any_artifact": (
                artifact_count > 0
                and osv_existing == artifact_count
                and total_vulnerability_findings == 0
            ),
            "vulnerabilities_found_in_any_artifact": total_vulnerability_findings > 0,
            "latest_version": latest_version,
            "latest_version_basis": "advisory_index" if latest_version else None,
            "latest_version_artifact_count": len(latest_artifacts),
            "latest_version_any_checked": latest_osv_existing > 0,
            "latest_version_all_checked": (
                bool(latest_artifacts) and latest_osv_existing == len(latest_artifacts)
            ),
            "latest_version_any_vulnerabilities_found": latest_vulnerability_findings
            > 0,
            "latest_version_total_vulnerability_findings": latest_vulnerability_findings,
        },
        "flags": package_flags(
            has_purl=has_purl,
            artifact_count=artifact_count,
            sbom_existing=sbom_existing,
            osv_existing=osv_existing,
            total_vulnerability_findings=total_vulnerability_findings,
            latest_artifact_count=len(latest_artifacts),
            latest_osv_existing=latest_osv_existing,
            latest_vulnerability_findings=latest_vulnerability_findings,
        ),
        "vulnerabilities": vulnerabilities,
        "artifacts": artifacts,
    }


def dashboard_payload(
    *,
    s3_uri: str,
    mapping_json: Path,
    osv_summary_path: Path | None,
    channel_index: dict[str, Any],
    subdir_indexes: list[dict[str, Any]],
    mappings: dict[str, dict[str, Any]],
    osv_summary: dict[str, Any],
    advisory_channels: list[AdvisoryChannelSource] | None = None,
) -> dict[str, Any]:
    vulnerabilities_by_package, vulnerabilities_by_advisory = vulnerability_indexes(
        osv_summary
    )
    artifacts = artifacts_from_indexes(
        subdir_indexes,
        vulnerabilities_by_advisory=vulnerabilities_by_advisory,
    )
    artifacts_by_package: dict[str, list[dict[str, Any]]] = {}
    for artifact in artifacts:
        name = artifact.get("name")
        if isinstance(name, str) and name:
            artifacts_by_package.setdefault(name, []).append(artifact)

    package_names = sorted(
        set(mappings) | set(artifacts_by_package) | set(vulnerabilities_by_package)
    )
    packages = {
        name: build_package_payload(
            name=name,
            mapping=mappings.get(name),
            artifacts=artifacts_by_package.get(name, []),
            summary_vulnerabilities=vulnerabilities_by_package.get(name, []),
        )
        for name in package_names
    }
    channels = advisory_channels or [
        {
            "name": _default_channel_name(s3_uri, priority=0),
            "s3_uri": s3_uri,
            "priority": 0,
            "channel_index_generated_at": channel_index.get("generated_at"),
        }
    ]
    return {
        "schema_version": ADVISORY_DASHBOARD_SCHEMA_VERSION,
        "generated_at": _now(),
        "sources": {
            "s3_uri": s3_uri,
            "s3_uris": [channel["s3_uri"] for channel in channels],
            "advisory_channels": channels,
            "mapping_json": str(mapping_json),
            "osv_summary": str(osv_summary_path) if osv_summary_path else None,
            "channel_index_generated_at": channel_index.get("generated_at"),
            "osv_summary_generated_at": osv_summary.get("generated_at"),
        },
        "counts": {
            "packages": len(packages),
            "artifacts": len(artifacts),
            "packages_with_purl": sum(
                1 for package in packages.values() if package["has_purl"]
            ),
            "packages_with_sbom": sum(
                1 for package in packages.values() if package["sbom"]["any_exists"]
            ),
            "packages_with_osv": sum(
                1
                for package in packages.values()
                if package["osv"]["any_artifact_checked"]
            ),
            "packages_with_vulnerabilities": sum(
                1
                for package in packages.values()
                if package["osv"]["any_vulnerabilities_found"]
            ),
            "vulnerability_findings": sum(
                int(package["osv"]["total_vulnerability_findings"])
                for package in packages.values()
            ),
        },
        "packages": packages,
    }


def write_dashboard_payload(*, payload: dict[str, Any], out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(f"{out.name}.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    tmp.replace(out)
    return out


def upload_dashboard_payload(
    *,
    out: Path,
    s3_output_uri: str,
    profile: str | None = None,
    region: str | None = None,
    runner: Runner = subprocess.run,
) -> str:
    result = upload_file(
        local_path=out,
        root=out.parent,
        s3_uri=s3_output_uri,
        profile=profile,
        region=region,
        overwrite=True,
        runner=runner,
    )
    return result.s3_uri


def build_dashboard_data(
    *,
    s3_uri: str | None,
    advisory_channels: list[AdvisoryChannelSource] | None = None,
    mapping_json: Path,
    osv_summary_path: Path,
    skip_osv_summary: bool = False,
    workers: int = DEFAULT_WORKERS,
    profile: str | None = None,
    region: str | None = None,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    channels = advisory_channels or resolve_advisory_channels(
        s3_uri=s3_uri,
        advisory_channel_args=[],
    )
    subdir_indexes: list[dict[str, Any]] = []
    channel_indexes: list[dict[str, Any]] = []
    resolved_channels: list[AdvisoryChannelSource] = []
    for channel in channels:
        channel_s3_uri = _source_uri(channel)
        if channel_s3_uri is None:
            raise DashboardDataError("advisory channel source is missing s3_uri")
        channel_index, channel_subdir_indexes = load_s3_advisory_indexes(
            s3_uri=channel_s3_uri,
            profile=profile,
            region=region,
            workers=workers,
            runner=runner,
        )
        channel_indexes.append(channel_index)
        source = {
            **channel,
            "channel_index_generated_at": channel_index.get("generated_at"),
        }
        resolved_channels.append(source)
        for subdir_index in channel_subdir_indexes:
            subdir_indexes.append(
                {
                    **subdir_index,
                    "_advisory_channel": source,
                }
            )
    mappings = load_mapping_by_name(mapping_json)
    osv_summary = empty_osv_summary() if skip_osv_summary else load_osv_summary(
        osv_summary_path
    )
    primary_s3_uri = (
        _source_uri(resolved_channels[0])
        if resolved_channels
        else s3_uri
    )
    if primary_s3_uri is None:
        raise DashboardDataError("no advisory channel source configured")
    return dashboard_payload(
        s3_uri=primary_s3_uri,
        mapping_json=mapping_json,
        osv_summary_path=None if skip_osv_summary else osv_summary_path,
        channel_index=channel_indexes[0] if channel_indexes else {},
        subdir_indexes=subdir_indexes,
        mappings=mappings,
        osv_summary=osv_summary,
        advisory_channels=resolved_channels,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mapping-json",
        type=Path,
        default=DEFAULT_MAPPING_JSON,
        help="purl-associator mapping JSON",
    )
    parser.add_argument(
        "--osv-summary",
        type=Path,
        default=DEFAULT_OSV_SUMMARY,
        help="local OSV vulnerability summary JSON",
    )
    parser.add_argument(
        "--skip-osv-summary",
        action="store_true",
        help=(
            "build from advisory indexes/shards only; this skips the OSV "
            "vulnerability-summary file and avoids the per-OSV-artifact summary scan"
        ),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help="dashboard data JSON output path",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="parallel S3 advisory-index reads",
    )
    parser.add_argument(
        "--s3-output-uri",
        help=(
            "optional s3://bucket/prefix destination for the generated dashboard "
            "JSON; the output filename is written below this prefix"
        ),
    )
    parser.add_argument(
        "--advisory-channel",
        action="append",
        default=[],
        metavar="NAME=SOURCE",
        help=(
            "advisory channel layer to include; repeat to build a layered "
            "dashboard. SOURCE may be an s3:// prefix or a local channel root. "
            "Later entries have higher display priority. If omitted, --s3-uri "
            "is used as a single channel."
        ),
    )
    add_s3_args(parser, include_cleanup=False, include_dry_run=False)
    add_logging_args(parser, command_name="advisory-dashboard-data")
    args = parser.parse_args()
    log_path = configure_logging(
        command_name="advisory-dashboard-data",
        log_level=args.log_level,
        log_file=args.log_file,
    )

    try:
        advisory_channels = resolve_advisory_channels(
            s3_uri=args.s3_uri,
            advisory_channel_args=args.advisory_channel,
        )
        LOGGER.info(
            "starting dashboard data build s3_uri=%s advisory_channels=%s mapping_json=%s "
            "osv_summary=%s skip_osv_summary=%s out=%s workers=%d s3_output_uri=%s",
            args.s3_uri,
            advisory_channels,
            args.mapping_json,
            args.osv_summary,
            args.skip_osv_summary,
            args.out,
            args.workers,
            args.s3_output_uri,
        )
        payload = build_dashboard_data(
            s3_uri=args.s3_uri,
            advisory_channels=advisory_channels,
            mapping_json=args.mapping_json,
            osv_summary_path=args.osv_summary,
            skip_osv_summary=args.skip_osv_summary,
            workers=args.workers,
            profile=args.s3_profile,
            region=args.s3_region,
        )
        out = write_dashboard_payload(payload=payload, out=args.out)
        uploaded_uri = (
            upload_dashboard_payload(
                out=out,
                s3_output_uri=args.s3_output_uri,
                profile=args.s3_profile,
                region=args.s3_region,
            )
            if args.s3_output_uri
            else None
        )
    except (DashboardDataError, S3PublishError) as exc:
        LOGGER.error("dashboard data build failed error=%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        print_log_location(log_path)
        sys.exit(2)

    print(out)
    print(
        "wrote advisory dashboard data "
        f"for {payload['counts']['packages']} package(s), "
        f"{payload['counts']['artifacts']} artifact(s)",
        file=sys.stderr,
    )
    if uploaded_uri:
        print(f"uploaded advisory dashboard data to {uploaded_uri}", file=sys.stderr)
    LOGGER.info(
        "completed dashboard data build out=%s packages=%d artifacts=%d "
        "vulnerability_findings=%d s3_output=%s",
        out,
        payload["counts"]["packages"],
        payload["counts"]["artifacts"],
        payload["counts"]["vulnerability_findings"],
        uploaded_uri,
    )
    print_log_location(log_path)


if __name__ == "__main__":
    main()
