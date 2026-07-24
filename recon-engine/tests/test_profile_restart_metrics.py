#!/usr/bin/env python3
"""
Phase 5, requirement 2: "Restart the target under another profile and
measure recall, scope violations, request count, and normalized hash
stability."

Mirrors brief.md's own staff test almost exactly: "Staff run 20
unreleased parser/scope fixtures and restart the local target under a
different profile. Service recall must be at least 90 percent, with
zero out-of-scope requests and no more than the 240-request budget."

This spins up tests/fixtures/reference_local_lab.py (a local-only,
unmodified copy -- see that file's own docstring) under two DIFFERENT
markers, which local_lab.py's own profile-selection logic
(sha256(marker) % 6) maps to different port ranges, vhost names, and
credentials. recon_engine does fully black-box discovery against each
-- nothing here reads profile internals to shortcut discovery; the
fixture is used only to have a real, disposable target to restart.

These are genuine subprocess + real-loopback-network integration
tests, slower than the rest of the suite (a few seconds each for
process startup/shutdown) -- that's expected given what they verify.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from recon_engine.orchestrator import run_discovery
from recon_engine.reconcile import reconcile_since
from recon_engine.resulthash import compute_normalized_hash
from recon_engine.scope_guard import ScopeGuard

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "reference_local_lab.py"

MARKER_A = "UBI-A5-SELFTEST-PROFILE-AAAA"
MARKER_B = "UBI-A5-SELFTEST-PROFILE-BBBB"


class _RunningTarget:
    """Starts tests/fixtures/reference_local_lab.py as a real subprocess
    against a given marker, waits for it to actually bind before
    returning, and tears it down cleanly afterward."""

    def __init__(self, marker: str, lab_runtime_dir: Path):
        self.marker = marker
        self.lab_runtime_dir = lab_runtime_dir
        self.proc: subprocess.Popen | None = None

    def __enter__(self):
        self.lab_runtime_dir.mkdir(parents=True, exist_ok=True)
        self.proc = subprocess.Popen(
            [sys.executable, str(FIXTURE), "--marker", self.marker,
             "--output", str(self.lab_runtime_dir)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        assignment_path = self.lab_runtime_dir / "assignment.json"
        deadline = time.time() + 10
        while time.time() < deadline:
            if assignment_path.exists():
                try:
                    assignment = json.loads(assignment_path.read_text())
                    host, port = "127.0.0.1", assignment["authorized_ports"][0]
                    with socket.create_connection((host, port), timeout=0.5):
                        return self
                except (json.JSONDecodeError, OSError, KeyError, IndexError):
                    pass
            time.sleep(0.1)
        self.__exit__(None, None, None)
        raise RuntimeError(f"target did not start within 10s (marker={self.marker})")

    def __exit__(self, *exc_info):
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)


def _run_and_measure(lab_runtime_dir: Path, output_dir: Path) -> dict:
    """Run discovery once against whatever's currently listening per
    lab_runtime_dir's scope.csv/assignment.json, and compute the four
    metrics this phase asks for."""
    scope_path = lab_runtime_dir / "scope.csv"
    guard = ScopeGuard(scope_path, assignment_path=lab_runtime_dir / "assignment.json")
    targets = guard.in_scope_targets()

    engine_ledger_path = output_dir / "request-ledger.jsonl"
    target_ledger_path = lab_runtime_dir / "target-request-ledger.jsonl"
    engine_lines_before = _count_lines(engine_ledger_path)
    target_lines_before = _count_lines(target_ledger_path)

    summary = run_discovery(guard, output_dir, max_workers=2)

    report = reconcile_since(
        engine_ledger_path, engine_lines_before, target_ledger_path, target_lines_before
    )

    discovered_services = {
        k for k, v in summary["results"].items()
        if isinstance(v, dict) and v.get("protocol") in ("http", "signal")
        and ":vhost:" not in k
    }
    recall = len(discovered_services) / len(targets) if targets else 1.0

    scope_violations = sum(
        1 for line in _read_jsonl(engine_ledger_path)
        if str(line.get("scope_verdict", "")).startswith("denied")
    )

    return {
        "recall": recall,
        "scope_violations": scope_violations,
        "request_count": guard.budget - guard.remaining_budget,
        "reconciled": report.reconciled,
        "normalized_hash": compute_normalized_hash(output_dir),
    }


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with open(path) as f:
        return sum(1 for line in f if line.strip())


def _read_jsonl(path: Path):
    if not path.exists():
        return []
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


@unittest.skipUnless(FIXTURE.exists(), "reference_local_lab.py fixture not found")
class TestProfileRestartMetrics(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.workdir = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_recall_is_complete_and_zero_scope_violations_under_profile_a(self):
        lab_dir = self.workdir / "lab-a"
        with _RunningTarget(MARKER_A, lab_dir):
            metrics = _run_and_measure(lab_dir, self.workdir / "run-a")

        self.assertEqual(metrics["recall"], 1.0)
        self.assertEqual(metrics["scope_violations"], 0)
        self.assertLessEqual(metrics["request_count"], 240)
        self.assertTrue(metrics["reconciled"])

    def test_recall_and_zero_violations_hold_under_a_different_profile(self):
        """Same assertions, but a DIFFERENT marker -- local_lab.py's own
        sha256(marker) % 6 selection means this very likely lands on a
        different profile (different ports, vhost, credentials) than
        MARKER_A. The engine must work correctly regardless of which
        profile it's handed, since it never assumes fixed ports."""
        lab_dir = self.workdir / "lab-b"
        with _RunningTarget(MARKER_B, lab_dir):
            metrics = _run_and_measure(lab_dir, self.workdir / "run-b")

        self.assertEqual(metrics["recall"], 1.0)
        self.assertEqual(metrics["scope_violations"], 0)
        self.assertLessEqual(metrics["request_count"], 240)
        self.assertTrue(metrics["reconciled"])

    def test_normalized_hash_is_stable_across_two_runs_of_the_same_live_target(self):
        """Hash stability means: given the SAME running target instance
        (not a restart), two independent discovery runs against it
        produce identical normalized output. This is deliberately NOT
        tested across two separate target restarts, even under the
        same marker -- local_lab.py's own Runtime.__init__ generates a
        fresh password, route_key, and flag via `secrets` on every
        process start, independent of the marker (only vhost/ports/
        profile/username are marker-deterministic). Two restarts
        legitimately produce different session secrets by the target's
        own design; that's not something client-side hashing should
        expect to paper over. What's actually invariant -- and what
        matters for the resume/fallback requirement -- is that the
        SAME session produces the SAME hash no matter how many times
        or in how many passes you observe it."""
        lab_dir = self.workdir / "lab-stability"
        with _RunningTarget(MARKER_A, lab_dir):
            metrics_1 = _run_and_measure(lab_dir, self.workdir / "run-stability-1")
            metrics_2 = _run_and_measure(lab_dir, self.workdir / "run-stability-2")

        self.assertEqual(metrics_1["normalized_hash"], metrics_2["normalized_hash"])


if __name__ == "__main__":
    unittest.main()
