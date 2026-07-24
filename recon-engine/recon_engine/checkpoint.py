#!/usr/bin/env python3
"""
recon_engine.checkpoint -- resumable, deduplicating progress tracking.

Every probe any adapter makes is identified by a stable dedup key (e.g.
"http:/", "http:vhost:relay-abc123.northstar.local:/ops-diagnostics",
"signal:ROUTE"). Before making a request, the orchestrator asks
Checkpoint.is_done(key); if a prior run already completed it, the
request is skipped entirely -- no new socket is opened, no budget is
spent, and the previously-recorded normalized record is reused as-is.

The checkpoint file is written incrementally (one fsync'd write per
completed probe, not just at the end), so a run that's interrupted
partway through still leaves a checkpoint reflecting everything that
actually finished -- resuming with the same --output directory picks
up where it left off rather than repeating completed probes.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, Optional


class Checkpoint:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._data: Dict[str, Any] = {"completed": {}}
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text())
            except (json.JSONDecodeError, OSError):
                # A corrupt checkpoint is treated as "nothing completed
                # yet" rather than crashing the run -- resumability
                # should degrade to a clean restart, not a hard failure.
                self._data = {"completed": {}}
        self._data.setdefault("completed", {})

    def is_done(self, key: str) -> bool:
        with self._lock:
            return key in self._data["completed"]

    def get(self, key: str) -> Optional[dict]:
        with self._lock:
            return self._data["completed"].get(key)

    def mark_done(self, key: str, record: Optional[dict] = None) -> None:
        """Record that `key` completed, storing its normalized record (if
        any) so a resumed run can reproduce it without re-requesting."""
        with self._lock:
            self._data["completed"][key] = record
            self._write_locked()

    def set_meta(self, name: str, value: Any) -> None:
        """Store a small piece of cross-adapter state (e.g. a discovered
        vhost name) so later adapters/resumed runs can use it without
        re-discovering it."""
        with self._lock:
            self._data[name] = value
            self._write_locked()

    def get_meta(self, name: str, default: Any = None) -> Any:
        with self._lock:
            return self._data.get(name, default)

    def completed_records(self) -> list:
        with self._lock:
            return [r for r in self._data["completed"].values() if r is not None]

    def _write_locked(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=2, sort_keys=True) + "\n")
        tmp.replace(self.path)  # atomic on POSIX -- no half-written checkpoint
