#!/usr/bin/env python3
"""Standalone script: run discovery against a locally started target and
print the four Phase 5 metrics, rather than just pass/fail assertions.
Run from the recon-engine/ directory, with the target already running:

    python3 print_metrics.py /path/to/lab-runtime /path/to/output-dir
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, "tests")  # to reuse the helper functions

from recon_engine.orchestrator import run_discovery
from recon_engine.reconcile import reconcile_since
from recon_engine.resulthash import compute_normalized_hash
from recon_engine.scope_guard import ScopeGuard
import json


def count_lines(path):
    if not path.exists():
        return 0
    with open(path) as f:
        return sum(1 for l in f if l.strip())


def main():
    lab_runtime_dir = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])

    scope_path = lab_runtime_dir / "scope.csv"
    guard = ScopeGuard(scope_path, assignment_path=lab_runtime_dir / "assignment.json")
    targets = guard.in_scope_targets()

    engine_ledger_path = output_dir / "request-ledger.jsonl"
    target_ledger_path = lab_runtime_dir / "target-request-ledger.jsonl"
    engine_lines_before = count_lines(engine_ledger_path)
    target_lines_before = count_lines(target_ledger_path)

    summary = run_discovery(guard, output_dir, max_workers=2)

    report = reconcile_since(
        engine_ledger_path, engine_lines_before, target_ledger_path, target_lines_before
    )

    discovered = {
        k for k, v in summary["results"].items()
        if isinstance(v, dict) and v.get("protocol") in ("http", "signal")
        and ":vhost:" not in k
    }
    recall = len(discovered) / len(targets) if targets else 1.0

    with open(engine_ledger_path) as f:
        violations = sum(
            1 for l in f if l.strip()
            and str(json.loads(l).get("scope_verdict", "")).startswith("denied")
        )

    print(f"recall           : {recall:.0%}  ({len(discovered)}/{len(targets)} assigned services found)")
    print(f"scope_violations : {violations}")
    print(f"request_count    : {guard.budget - guard.remaining_budget} / {guard.budget} budget")
    print(f"reconciled       : {report.reconciled}")
    print(f"normalized_hash  : {compute_normalized_hash(output_dir)}")


if __name__ == "__main__":
    main()
