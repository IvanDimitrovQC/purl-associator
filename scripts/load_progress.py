"""Progress tracking for local advisory-channel maintenance runs."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_UNSET = object()


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class ProgressTracker:
    def __init__(
        self,
        *,
        path: Path,
        load_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.path = path
        self._lock = threading.RLock()
        self.data: dict[str, Any] = {
            "schema_version": 1,
            "load_type": load_type,
            "status": "running",
            "started_at": _now(),
            "updated_at": _now(),
            "metadata": metadata or {},
            "totals": {},
            "counts": {},
            "current": None,
        }
        self.write()

    def write(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(f"{self.path.name}.tmp")
            tmp.write_text(json.dumps(self.data, indent=2) + "\n")
            tmp.replace(self.path)

    def update(
        self,
        *,
        status: str | None = None,
        metadata: dict[str, Any] | None = None,
        totals: dict[str, Any] | None = None,
        counts: dict[str, Any] | None = None,
        current: dict[str, Any] | None | object = _UNSET,
        error: str | None = None,
    ) -> None:
        with self._lock:
            if status is not None:
                self.data["status"] = status
            if metadata:
                self.data["metadata"].update(metadata)
            if totals:
                self.data["totals"].update(totals)
            if counts:
                self.data["counts"].update(counts)
            if current is not _UNSET:
                self.data["current"] = current
            if error is not None:
                self.data["error"] = error
            self.data["updated_at"] = _now()
            self.write()

    def fail(self, error: Exception) -> None:
        self.update(status="failed", error=str(error))

    def complete(self, *, status: str = "complete") -> None:
        self.update(status=status, current=None)
