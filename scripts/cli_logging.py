"""Shared logging setup for advisory-channel CLI scripts."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG_DIR = ROOT / ".tmp" / "logs"


def default_log_path(command_name: str) -> Path:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    safe_name = command_name.replace(":", "-").replace("/", "-")
    return DEFAULT_LOG_DIR / f"{safe_name}-{timestamp}-{os.getpid()}.log"


def add_logging_args(parser: argparse.ArgumentParser, *, command_name: str) -> None:
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        help="minimum log level for stderr and the local log file",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        help=(
            "local log file path; defaults to "
            f"{default_log_path(command_name).parent}/"
            f"{command_name.replace(':', '-')}-<timestamp>-<pid>.log"
        ),
    )


def _formatter() -> logging.Formatter:
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    formatter.converter = time.gmtime
    return formatter


def configure_logging(
    *, command_name: str, log_level: str, log_file: Path | None
) -> Path:
    path = log_file or default_log_path(command_name)
    path.parent.mkdir(parents=True, exist_ok=True)

    formatter = _formatter()
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    file_handler = logging.FileHandler(path, mode="w")
    file_handler.setFormatter(formatter)

    logging.basicConfig(
        level=getattr(logging, log_level),
        handlers=[stderr_handler, file_handler],
        force=True,
    )
    logging.getLogger(__name__).info(
        "logging configured command=%s file=%s level=%s",
        command_name,
        path,
        log_level,
    )
    return path


def print_log_location(path: Path) -> None:
    print(f"logs written to {path}", file=sys.stderr)
