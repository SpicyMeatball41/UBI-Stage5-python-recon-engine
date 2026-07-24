#!/usr/bin/env python3
"""
recon_engine.cli -- preflight validation + one complete discovery adapter.

    python3 -m recon_engine.cli --target HOST[:PORT] --scope SCOPE.csv \
        --output OUTDIR --rate N

Two phases, in order:

  PHASE 1 -- validation (always runs):
    1. Parses and validates its own arguments.
    2. Loads and validates the scope file (fails clearly on a malformed
       or missing scope.csv).
    3. Confirms the requested --target is loopback and is covered by an
       "IN" row in scope.
    4. If an assignment.json sits next to --scope, cross-checks --rate
       against its maximum_rate_per_second and, if a port was given,
       the port against authorized_ports.
    5. Preserves the generated scope profile into evidence/<runtime_id>/.
    6. Prepares --output as a writable directory.
    This phase calls ScopeGuard.validate() -- it does not touch budget,
    the rate-limit window, or the ledger, and sends no network traffic.

  PHASE 2 -- one complete discovery adapter (runs only if assignment.json
  was found and has an entry_url):
    7. Runs a fixed, ordered sequence of HTTP probes against
       assignment.json's entry_url only -- never against a
       caller-supplied host/port, so there is no way to steer this
       phase at any other host/port, including the OUT port.
    8. Every attempt goes through ScopeGuard.check() (budget/rate
       -consuming) and is written to the engine's OWN request ledger
       (<output>/request-ledger.jsonl) with its purpose, target,
       result, and scope verdict together in one line -- kept separate
       from target-request-ledger.jsonl, which the lab target writes
       independently, so the two can be reconciled against each other
       (see recon_engine.reconcile).
    9. Saves the unedited response for every attempt to <output>/raw/http/.
    10. Normalizes each successful probe into
        <output>/normalized/assets.jsonl, in the same fixed order the
        probes were scheduled in.
    11. Writes a manifest (including the reconciliation report) to
        <output>/run.json.

  If no assignment.json is found, the CLI stops after phase 1 (matches
  the original validation-only behavior for scope.csv-only usage).

Exit codes:
  0  -- validation (and discovery, if it ran) succeeded
  2  -- bad arguments / missing or unreadable files / malformed input
  3  -- target rejected by the scope guard (out of scope, non-loopback,
        unauthorized port, or an unsafe --rate)
  4  -- validation passed but discovery itself failed after retries
        (network error, unsupported entry_url scheme, etc.)
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Optional, Tuple

from .ledger import RequestLedger
from .orchestrator import run_discovery
from .reconcile import reconcile_since
from .report import generate_report
from .resulthash import compute_normalized_hash
from .scope_guard import ScopeGuard, ScopeViolation


class CliError(Exception):
    """Argument- or environment-level failure (exit code 2)."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m recon_engine.cli",
        description=(
            "Recon engine preflight validator. Checks that --target is "
            "in scope, --scope parses, --output is usable, and --rate is "
            "safe. Does not scan or send any network traffic."
        ),
    )
    parser.add_argument(
        "--target",
        required=True,
        metavar="HOST[:PORT]",
        help="Target to validate, e.g. 127.0.0.1 or 127.0.0.1:18467",
    )
    parser.add_argument(
        "--scope",
        required=True,
        type=Path,
        metavar="PATH",
        help="Path to scope.csv",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        metavar="DIR",
        help="Output directory for run artifacts (created if missing)",
    )
    parser.add_argument(
        "--rate",
        required=True,
        type=int,
        metavar="N",
        help="Requests per second cap requested for this run",
    )
    return parser


def parse_target(raw: str) -> Tuple[str, Optional[int]]:
    """Split HOST or HOST:PORT. Raises CliError with a clear message on
    anything malformed. Returns (host, port_or_None)."""
    raw = raw.strip()
    if not raw:
        raise CliError("--target must not be empty")

    if ":" not in raw:
        return raw, None

    host, _, port_str = raw.rpartition(":")
    if not host:
        raise CliError(f"--target {raw!r} is missing a host before ':'")
    if not port_str.isdigit():
        raise CliError(f"--target {raw!r} has a non-numeric port {port_str!r}")

    port = int(port_str)
    if not (1 <= port <= 65535):
        raise CliError(f"--target {raw!r} has port {port} outside 1-65535")

    return host, port


def prepare_output_dir(path: Path) -> Path:
    """Create --output if needed and confirm it's a writable directory.
    Raises CliError with a clear message on any problem."""
    if path.exists() and not path.is_dir():
        raise CliError(f"--output {path} exists and is not a directory")

    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CliError(f"could not create --output directory {path}: {exc}")

    probe = path / ".recon_engine_write_test"
    try:
        probe.write_text("")
    except OSError as exc:
        raise CliError(f"--output {path} is not writable: {exc}")
    finally:
        if probe.exists():
            probe.unlink()

    return path.resolve()


def load_guard(scope_path: Path) -> ScopeGuard:
    """Load scope.csv (and assignment.json alongside it, if present).
    Raises CliError with a clear message on a missing or malformed
    scope file."""
    if not scope_path.exists():
        raise CliError(f"--scope file not found: {scope_path}")

    assignment_path = scope_path.parent / "assignment.json"
    kwargs = {"scope_csv_path": scope_path}
    if assignment_path.exists():
        kwargs["assignment_path"] = assignment_path

    try:
        return ScopeGuard(**kwargs)
    except (FileNotFoundError, ValueError) as exc:
        raise CliError(f"failed to load scope file {scope_path}: {exc}")


def validate_rate(rate: int, guard: ScopeGuard) -> None:
    if rate <= 0:
        raise CliError(f"--rate must be a positive integer, got {rate}")
    if guard.max_rate_per_second and rate > guard.max_rate_per_second:
        raise ScopeViolation(
            f"--rate {rate} exceeds maximum_rate_per_second "
            f"{guard.max_rate_per_second} from assignment.json"
        )


def preserve_scope_profile(scope_path: Path, guard: ScopeGuard) -> Optional[Path]:
    """Snapshot the generated scope.csv (and assignment.json, if present)
    into evidence/<runtime_id>/, so this run's specific scope profile is
    preserved even though a fresh one gets generated on future runs
    (assignment.json's runtime_id/started_at change each time the lab
    restarts -- confirmed by comparing successive assignment.json
    contents across runs).

    Idempotent: if a snapshot for this runtime_id already exists, it is
    left alone rather than overwritten, so the FIRST-seen generated
    profile for a given run is what's preserved.

    Returns the evidence directory path, or None if no runtime_id was
    available to key the snapshot by (e.g. no assignment.json at all).
    This is best-effort: a failure here is reported but does not abort
    the run, since preservation is a record-keeping step, not a scope
    check.
    """
    runtime_id = guard.assignment.get("runtime_id")
    if not runtime_id:
        return None

    evidence_dir = Path("evidence") / runtime_id
    if evidence_dir.exists():
        return evidence_dir  # already preserved for this runtime_id

    try:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(scope_path, evidence_dir / "scope.csv")
        if guard.assignment_path is not None:
            shutil.copy2(guard.assignment_path, evidence_dir / "assignment.json")
        (evidence_dir / "preserved_at.txt").write_text(
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + "\n"
        )
    except OSError as exc:
        print(f"warning: could not preserve scope profile: {exc}", file=sys.stderr)
        return None

    return evidence_dir


def run(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        host, port = parse_target(args.target)
        guard = load_guard(args.scope)
        evidence_dir = preserve_scope_profile(args.scope, guard)
        validate_rate(args.rate, guard)
        address = guard.validate(host, port)
        output_dir = prepare_output_dir(args.output)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ScopeViolation as exc:
        print(f"scope violation: {exc}", file=sys.stderr)
        return 3

    target_display = f"{host}:{port}" if port is not None else host
    manifest = {
        "phase1_validation": {
            "target": target_display,
            "resolved_address": address,
            "scope_file": str(args.scope.resolve()),
            "assignment_file": (
                str(guard.assignment_path.resolve()) if guard.assignment_path else None
            ),
            "evidence_dir": str(evidence_dir.resolve()) if evidence_dir else None,
            "output_dir": str(output_dir),
            "requested_rate": args.rate,
        },
        "phase2_observation": None,
    }

    print(f"OK: target {target_display} ({address}) is in scope")
    print(f"    scope file : {args.scope.resolve()}")
    if guard.assignment_path is not None:
        print(f"    assignment : {guard.assignment_path.resolve()}")
    if evidence_dir is not None:
        print(f"    evidence   : {evidence_dir.resolve()}")
    print(f"    output dir : {output_dir}")
    print(f"    rate cap   : {args.rate} req/s")

    if guard.assignment_path is None or not guard.assignment.get("entry_url"):
        print("No assignment.json / entry_url found -- validation-only run, "
              "nothing was sent.")
        manifest["observation_performed"] = False
        _write_manifest(output_dir, manifest)
        return 0

    # Phase 2/3: discover every assigned (IN-scope, authorized) service
    # via the orchestrator -- bounded concurrency across adapters,
    # resumable checkpointing, and a structural guarantee that only
    # scope.csv's own "IN" rows are ever touched (the decoy and every
    # non-loopback destination are excluded by construction, not by a
    # runtime check alone). The engine's own ledger stays separate from
    # target-request-ledger.jsonl, which the lab target writes
    # independently, so the two can be reconciled.
    target_ledger_path = args.scope.parent / "target-request-ledger.jsonl"
    engine_ledger_path = output_dir / "request-ledger.jsonl"

    # Snapshot both ledgers' line counts BEFORE this run's own requests,
    # so reconciliation only considers what THIS run added -- not a
    # target ledger's entire history, which persists across runs.
    engine_lines_before = _count_lines(engine_ledger_path)
    target_lines_before = _count_lines(target_ledger_path)

    discovery = run_discovery(guard, output_dir)
    report_path = generate_report(output_dir)
    result_hash = compute_normalized_hash(output_dir)

    reconciliation = reconcile_since(
        engine_ledger_path, engine_lines_before, target_ledger_path, target_lines_before
    )

    manifest["phase2_observation"] = discovery
    manifest["observation_performed"] = len(discovery["results"]) > 0
    manifest["reconciliation"] = reconciliation.to_dict()
    manifest["engine_ledger"] = str(engine_ledger_path)
    manifest["target_ledger"] = str(target_ledger_path)
    manifest["report_path"] = str(report_path)
    manifest["normalized_result_hash"] = result_hash
    _write_manifest(output_dir, manifest)

    print(f"Discovered {len(discovery['results'])}/{len(discovery['targets'])} "
          f"assigned service(s)" + (
              f" + vhost {discovery['vhost_discovered']!r}" if discovery["vhost_discovered"] else ""
          ))
    for key, result in discovery["results"].items():
        if isinstance(result, dict) and "protocol" in result:
            print(f"    {key:<28} {result['protocol']}")
    if discovery.get("tool_fallbacks"):
        for key, note in discovery["tool_fallbacks"].items():
            print(f"    FALLBACK {key}: {note}")
    if discovery["errors"]:
        for key, err in discovery["errors"].items():
            print(f"    ERROR {key}: {err}", file=sys.stderr)
    if discovery.get("foothold"):
        fh = discovery["foothold"]
        if fh.get("success"):
            print(f"    FOOTHOLD        : flag captured -- {fh['flag']}")
        else:
            print(f"    FOOTHOLD        : evidence used but not successful (see errors)")
    print(f"    engine ledger   : {engine_ledger_path}")
    print(f"    target ledger   : {target_ledger_path}")
    print(f"    checkpoint      : {discovery['checkpoint_path']}")
    print(f"    report          : {report_path}")
    print(f"    reconciled      : {reconciliation.reconciled} -- {reconciliation.notes}")
    print(f"    result hash     : {result_hash}")
    print(f"    budget used     : {guard.budget - guard.remaining_budget} "
          f"(remaining {guard.remaining_budget})")

    if discovery["errors"] and not discovery["results"]:
        return 4
    return 0


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with open(path) as f:
        return sum(1 for line in f if line.strip())


def _write_manifest(output_dir: Path, manifest: dict) -> None:
    manifest["written_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(output_dir / "run.json", "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
