#!/usr/bin/env python3
"""
recon_engine.ledger -- the engine's OWN request ledger.

This is deliberately separate from target-request-ledger.jsonl, which is
written independently by the lab target itself (see local_lab.py's
Runtime.record()). Earlier work in this project mistakenly pointed
ScopeGuard's own logging at that same file -- but that file belongs to
the target, not to us, and "the engine ledger" and "the target ledger"
only mean anything as two independent records that can be reconciled
against each other (see recon_engine.reconcile). This module is that
independent, engine-owned record.

Written before concurrency is introduced (per the phase 2 brief), so
every entry unambiguously has a purpose, a target, a result, and a
scope verdict, in that single combined line -- not split across a
"decision" line and a separate "outcome" line.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Optional


class RequestLedger:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # A lock now costs nothing and makes this ledger already safe to
        # share across threads once a later phase adds concurrency.
        self._lock = threading.Lock()
        # Resume support: if this ledger file already has entries (a
        # prior process wrote them, then stopped -- the exact resume
        # scenario), a fresh RequestLedger instance must not restart
        # counting at 0, or its new entries collide with sequence
        # numbers that already exist on disk. Pick up where the file
        # left off instead.
        self._sequence = self._read_last_sequence()

    def _read_last_sequence(self) -> int:
        if not self.path.exists():
            return 0
        last = 0
        with open(self.path) as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    last = json.loads(line).get("sequence", last)
                except json.JSONDecodeError:
                    continue
        return last

    def record(
        self,
        *,
        purpose: str,
        host: str,
        port: int,
        protocol: str,
        attempt: int,
        scope_verdict: str,
        result: str,
        notes: str = "",
        runtime_id: Optional[str] = None,
    ) -> dict:
        """Write one ledger line. Called once per attempt, after the
        attempt has concluded (denied by scope, or completed/failed at
        the network layer) -- never split across two lines, so every
        entry always carries all four required fields together."""
        with self._lock:
            self._sequence += 1
            entry = {
                "sequence": self._sequence,
                "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "purpose": purpose,
                "target": f"{host}:{port}",
                "host": host,
                "port": port,
                "protocol": protocol,
                "attempt": attempt,
                "scope_verdict": scope_verdict,
                "result": result,
                "notes": notes,
                "runtime_id": runtime_id,
            }
            with open(self.path, "a") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
            return entry
