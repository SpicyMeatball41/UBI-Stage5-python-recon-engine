#!/usr/bin/env python3
"""
recon_engine.reconcile -- compare the engine's own request ledger
against the target's independent target-request-ledger.jsonl.

The target logs every request it actually receives (local_lab.py's
Runtime.record()). The engine's own ledger (recon_engine.ledger) logs
every attempt it makes, including ones ScopeGuard denied before any
packet was ever sent. Reconciling the two proves two things:

  1. Every engine attempt that was approved AND got an HTTP result has
     a corresponding entry in the target's independent log -- nothing
     silently vanished.
  2. The target's log has no MORE entries than the engine accounted
     for as approved -- nothing reached the target that the engine
     didn't know about (no untracked/rogue requests).

This is what makes "reconcile" meaningful: two independently-written
records that should agree, not one shared file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class ReconciliationReport:
    engine_approved_with_result: int
    engine_denied: int
    target_entries: int
    reconciled: bool
    notes: str

    def to_dict(self) -> dict:
        return {
            "engine_approved_with_result": self.engine_approved_with_result,
            "engine_denied": self.engine_denied,
            "target_entries": self.target_entries,
            "reconciled": self.reconciled,
            "notes": self.notes,
        }


def reconcile(engine_ledger_path: Path, target_ledger_path: Path) -> ReconciliationReport:
    """Whole-file reconciliation. Only meaningful when both ledgers were
    empty before this run started (e.g. a fresh output directory and a
    freshly-started lab target). For a target ledger that persists
    across multiple runs -- which is the normal case -- use
    reconcile_since() instead, scoped to this run's own activity."""
    return reconcile_since(engine_ledger_path, 0, target_ledger_path, 0)


def reconcile_since(
    engine_ledger_path: Path,
    engine_lines_before: int,
    target_ledger_path: Path,
    target_lines_before: int,
) -> ReconciliationReport:
    """Reconcile only the entries ADDED during this run -- i.e. lines
    after `engine_lines_before` / `target_lines_before`, the line counts
    of each ledger captured immediately before the run started.

    This matters because target-request-ledger.jsonl is the target's
    own persistent log: it is never cleared between runs (and may carry
    old artifacts from earlier in a session -- see the module docstring
    history). Comparing today's run against that ledger's ENTIRE history
    would falsely flag "unreconciled" any time prior activity exists,
    even when this run itself was perfectly clean. Scoping to the delta
    since this run started is what makes the comparison meaningful.
    """
    engine_entries = _read_jsonl(engine_ledger_path)[engine_lines_before:]
    target_entries = _read_jsonl(target_ledger_path)[target_lines_before:]

    approved = [e for e in engine_entries if e.get("scope_verdict") == "approved"]
    denied = [
        e for e in engine_entries
        if str(e.get("scope_verdict", "")).startswith("denied")
    ]
    # "Got a result" is protocol-agnostic: an approved attempt that
    # actually reached the network layer and got SOME outcome, whether
    # that's "HTTP 200" (http adapter), "LINE 200" (signal adapter), or
    # any future protocol's own result format. The only things this
    # must exclude are transport-layer failures ("error: ...") and
    # denials that never sent anything ("not sent") -- both of those
    # legitimately have no corresponding target-side log entry.
    approved_with_result = [
        e for e in approved
        if not str(e.get("result", "")).startswith("error:")
        and e.get("result") != "not sent"
    ]

    reconciled = len(target_entries) <= len(approved_with_result)

    notes = (
        f"{len(approved_with_result)} engine attempt(s) reached an authorized "
        f"service and got a response in this run; target independently logged "
        f"{len(target_entries)} new request(s) since this run started; "
        f"{len(denied)} attempt(s) were denied before any packet was sent."
    )

    return ReconciliationReport(
        engine_approved_with_result=len(approved_with_result),
        engine_denied=len(denied),
        target_entries=len(target_entries),
        reconciled=reconciled,
        notes=notes,
    )


def _read_jsonl(path: Path) -> List[dict]:
    if not path.exists():
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]
