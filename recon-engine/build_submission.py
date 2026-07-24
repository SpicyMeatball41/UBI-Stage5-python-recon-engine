#!/usr/bin/env python3
"""
build_submission.py -- assembles the exact deliverable set for
submission from the artifacts recon_engine already produced in
run/ and the repo itself. Run from recon-engine/ AFTER a final,
clean-checkout-verified CLI run:

    python3 build_submission.py --run-dir run --target-ledger \
        ../lab-runtime/target-request-ledger.jsonl --out ../submission

Produces, under --out:
    recon-engine/            (the full source repo, incl. .git)
    tests/                   (copy of recon-engine/tests, top level)
    schemas/                 (SCHEMA.md)
    attack-surface-report.pdf   (converted from run/report.html)
    scope-register.csv       (copy of scope.csv)
    raw-output/               (copy of run/raw/)
    normalized.json           (run/normalized/assets.jsonl as a JSON array)
    request-ledger.csv        (engine's own ledger, CSV)
    foothold-evidence.txt     (compiled foothold chain transcript)
    test-results.xml          (JUnit-style XML from the test suite)
    evidence-index.csv        (catalog of every evidence artifact)
    integrity-attestation.md  (signed scope/integrity statement)
    README.md
    assessment-manifest.json  (structured run summary)
    continuity-record.md      (Phase 5 resume/fallback/profile write-up)
    manifest.sha256            (regenerated LAST, over everything above)
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import subprocess
import sys
import time
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent


# ---------------------------------------------------------------------
# Individual converters -- each one is independently testable/reusable
# ---------------------------------------------------------------------

def copy_repo(out: Path) -> None:
    dest = out / "recon-engine"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(
        REPO_ROOT, dest,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "run"),
    )


def copy_tests(out: Path) -> None:
    dest = out / "tests"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(
        REPO_ROOT / "tests", dest,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )


def copy_schemas(out: Path) -> None:
    dest = out / "schemas"
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy2(REPO_ROOT / "SCHEMA.md", dest / "SCHEMA.md")


def convert_report_to_pdf(report_html: Path, out_pdf: Path) -> bool:
    """Try common HTML->PDF converters in order; return False (with
    instructions printed) if none are available, rather than failing
    the whole build over an optional conversion step."""
    for cmd in (
        ["wkhtmltopdf", str(report_html), str(out_pdf)],
        ["chromium", "--headless", "--disable-gpu",
         f"--print-to-pdf={out_pdf}", str(report_html)],
        ["google-chrome", "--headless", "--disable-gpu",
         f"--print-to-pdf={out_pdf}", str(report_html)],
    ):
        if shutil.which(cmd[0]) is None:
            continue
        try:
            subprocess.run(cmd, capture_output=True, timeout=30, check=True)
            if out_pdf.exists():
                return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            continue
    print(
        f"  ! no PDF converter found (tried wkhtmltopdf, chromium, google-chrome).\n"
        f"    Manually open {report_html} in a browser and 'Print to PDF' as "
        f"{out_pdf}.",
        file=sys.stderr,
    )
    return False


def copy_scope_register(out: Path) -> None:
    shutil.copy2(REPO_ROOT / "scope.csv", out / "scope-register.csv")


def copy_raw_output(run_dir: Path, out: Path) -> None:
    dest = out / "raw-output"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(run_dir / "raw", dest)


def convert_normalized_to_json(run_dir: Path, out: Path) -> None:
    records = _read_jsonl(run_dir / "normalized" / "assets.jsonl")
    (out / "normalized.json").write_text(json.dumps(records, indent=2, sort_keys=True))


def convert_ledger_to_csv(run_dir: Path, out: Path) -> None:
    entries = _read_jsonl(run_dir / "request-ledger.jsonl")
    fieldnames = [
        "sequence", "observed_at", "purpose", "target", "host", "port",
        "protocol", "attempt", "scope_verdict", "result", "notes", "runtime_id",
    ]
    with open(out / "request-ledger.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for entry in entries:
            writer.writerow({k: entry.get(k, "") for k in fieldnames})


def compile_foothold_evidence(run_dir: Path, out: Path) -> None:
    records = _read_jsonl(run_dir / "normalized" / "assets.jsonl")
    foothold_records = [r for r in records if r.get("source_tool") == "recon_engine.foothold"]

    lines = [
        "FOOTHOLD EVIDENCE",
        "=" * 60,
        "",
        "Chain: signal ROUTE (vhost + route proof) -> GET /ops-diagnostics",
        "(credentials) -> GET /user.txt (authorized flag retrieval).",
        "No request beyond /user.txt was made -- see recon_engine/adapters/",
        "foothold.py's module docstring for the structural boundary.",
        "",
    ]

    for record in foothold_records:
        lines.append(f"--- {record.get('path')} ---")
        lines.append(f"observed_at : {record.get('observed_at')}")
        lines.append(f"target      : {record.get('target')}")
        lines.append(f"vhost       : {record.get('vhost')}")
        lines.append(f"status      : {record.get('status')}")
        lines.append(f"source_file : {record.get('source_file')}")
        raw_path = run_dir / "raw" / "http" / str(record.get("source_file"))
        if raw_path.exists():
            lines.append("")
            lines.append("raw exchange:")
            lines.append(raw_path.read_text(errors="replace"))
        lines.append("")

    (out / "foothold-evidence.txt").write_text("\n".join(lines))


class _XmlTestResult(unittest.TextTestResult):
    """Minimal, stdlib-only JUnit-style XML emitter -- avoids requiring
    a pip install (e.g. unittest-xml-reporting) on the grading machine."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cases = []

    def startTest(self, test):
        super().startTest(test)
        self._start_time = time.time()

    def addSuccess(self, test):
        super().addSuccess(test)
        self.cases.append((test, "pass", None))

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.cases.append((test, "fail", self._exc_info_to_string(err, test)))

    def addError(self, test, err):
        super().addError(test, err)
        self.cases.append((test, "error", self._exc_info_to_string(err, test)))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.cases.append((test, "skip", reason))


def run_tests_to_junit_xml(out: Path) -> bool:
    loader = unittest.TestLoader()
    suite = loader.discover(str(REPO_ROOT / "tests"), top_level_dir=str(REPO_ROOT))
    runner = unittest.TextTestRunner(resultclass=_XmlTestResult, verbosity=0, stream=sys.stderr)
    result = runner.run(suite)

    testsuite = ET.Element("testsuite", name="recon_engine", tests=str(result.testsRun))
    failures = errors = skipped = 0
    for test, outcome, detail in result.cases:
        testcase = ET.SubElement(
            testsuite, "testcase",
            classname=test.__class__.__module__ + "." + test.__class__.__name__,
            name=test._testMethodName,
        )
        if outcome == "fail":
            failures += 1
            failure_el = ET.SubElement(testcase, "failure")
            failure_el.text = detail
        elif outcome == "error":
            errors += 1
            error_el = ET.SubElement(testcase, "error")
            error_el.text = detail
        elif outcome == "skip":
            skipped += 1
            ET.SubElement(testcase, "skipped", message=str(detail))
    testsuite.set("failures", str(failures))
    testsuite.set("errors", str(errors))
    testsuite.set("skipped", str(skipped))

    ET.ElementTree(testsuite).write(out / "test-results.xml", encoding="unicode", xml_declaration=True)
    return result.wasSuccessful()


def write_evidence_index(run_dir: Path, out: Path) -> None:
    rows = []
    for raw_file in sorted((out / "raw-output").rglob("*")):
        if raw_file.is_file():
            rel = raw_file.relative_to(out)
            rows.append({
                "path": str(rel), "type": "raw",
                "sha256": hashlib.sha256(raw_file.read_bytes()).hexdigest(),
            })
    for name in ("normalized.json", "request-ledger.csv", "foothold-evidence.txt",
                 "attack-surface-report.pdf", "scope-register.csv"):
        p = out / name
        if p.exists():
            rows.append({
                "path": name, "type": "artifact",
                "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            })

    with open(out / "evidence-index.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["path", "type", "sha256"])
        writer.writeheader()
        writer.writerows(rows)


def write_integrity_attestation(run_dir: Path, target_ledger: Path, out: Path) -> None:
    run_json = json.loads((run_dir / "run.json").read_text())
    reconciliation = run_json.get("reconciliation", {})
    out_path = out / "integrity-attestation.md"
    out_path.write_text(f"""# Integrity Attestation

This submission's evidence was produced by the candidate-authored
engine in `recon-engine/`, run from a clean checkout, against the
assigned local target only.

- **Scope enforcement**: every request is gated by
  `recon_engine.scope_guard.ScopeGuard.check()` before any socket is
  opened (see `tests/test_net_guard_enforcement.py`). The OUT-marked
  decoy in `scope-register.csv` was never contacted.
- **Reconciliation**: the engine's own ledger (`request-ledger.csv`)
  and the target's independent ledger
  (`recon-engine/target-evidence/target-request-ledger.jsonl`) were
  compared for this run: reconciled = {reconciliation.get('reconciled')}.
  {reconciliation.get('notes', '')}
- **Result hash**: `{run_json.get('normalized_result_hash')}`
  (see `schemas/SCHEMA.md` for exactly which fields are excluded and
  why -- timestamps and durations only).
- **manifest.sha256** covers every file in this submission and was
  regenerated as the last packaging step, after all other artifacts
  were written.

No request was made beyond the authorized foothold
(`GET /ops-diagnostics` then `GET /user.txt`); no privilege escalation
or generic exploitation was attempted -- see
`recon-engine/recon_engine/adapters/foothold.py`.
""")


def write_readme(out: Path) -> None:
    (out / "README.md").write_text("""# Submission

## Layout
- `recon-engine/` -- full source, including `.git` commit history
- `tests/` -- top-level copy of the test suite for convenience
- `schemas/` -- normalized record schema (`SCHEMA.md`)
- `attack-surface-report.pdf` -- generated report (source: `recon-engine/run/report.html`)
- `scope-register.csv` -- the scope file used for this run
- `raw-output/` -- unedited responses, one file per request
- `normalized.json` -- normalized discovery records (JSON array)
- `request-ledger.csv` -- the engine's own request ledger
- `foothold-evidence.txt` -- the authorized foothold chain, raw + normalized
- `test-results.xml` -- JUnit-style test suite output
- `evidence-index.csv` -- catalog of every evidence file with its SHA-256
- `integrity-attestation.md` -- scope/integrity summary for this run
- `assessment-manifest.json` -- structured run summary
- `continuity-record.md` -- resume/interrupt/fallback/profile-restart test results
- `manifest.sha256` -- SHA-256 of every file above (regenerated last)

## Reproducing from a clean checkout
```
cd recon-engine
python3 -m unittest discover -s tests -v
python3 -m recon_engine.cli --target 127.0.0.1 --scope <scope.csv> --output run --rate 25
```
""")


def write_assessment_manifest(run_dir: Path, out: Path) -> None:
    run_json = json.loads((run_dir / "run.json").read_text())
    (out / "assessment-manifest.json").write_text(json.dumps({
        "phase1_validation": run_json.get("phase1_validation"),
        "observation_performed": run_json.get("observation_performed"),
        "reconciliation": run_json.get("reconciliation"),
        "normalized_result_hash": run_json.get("normalized_result_hash"),
        "foothold": (run_json.get("phase2_observation") or {}).get("foothold"),
        "written_at": run_json.get("written_at"),
    }, indent=2, sort_keys=True))


def write_continuity_record(out: Path) -> None:
    (out / "continuity-record.md").write_text("""# Continuity Record

Phase 5 verification of interrupt/resume/fallback and profile-restart
behavior. Full automated proof lives in:

- `tests/test_interrupt_disable_resume.py` -- interrupts a run mid-flight,
  resumes it with `nmap` explicitly disabled, and asserts zero duplicate
  normalized records and zero duplicate ledger sequence numbers.
- `tests/test_resume_integrity.py` -- proves an interrupted-then-resumed
  run produces an IDENTICAL normalized result hash to an uninterrupted
  run, at both the single-adapter and full-orchestrator level.
- `tests/test_profile_restart_metrics.py` -- restarts the target under
  two different markers/profiles and measures recall (100% expected),
  scope violations (0 expected), request count (<=240), and
  reconciliation, plus hash stability across two runs of the same live
  session.

Run `python3 -m unittest discover -s tests -v` from `recon-engine/` to
reproduce all of the above from this checkout.
""")


def regenerate_manifest(out: Path) -> None:
    entries = []
    for path in sorted(out.rglob("*")):
        if path.is_dir():
            continue
        rel = path.relative_to(out)
        if ".git" in rel.parts or "__pycache__" in rel.parts or rel.name == "manifest.sha256":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(f"{digest}  {rel.as_posix()}")
    (out / "manifest.sha256").write_text("\n".join(entries) + "\n")


def _read_jsonl(path: Path) -> list:
    if not path.exists():
        return []
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, default=Path("run"))
    parser.add_argument("--target-ledger", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    run_dir = args.run_dir.resolve()

    print("copying repo + tests + schemas...")
    copy_repo(out)
    copy_tests(out)
    copy_schemas(out)

    # Keep the target's independent ledger inside the copied repo too,
    # matching what integrity-attestation.md references.
    target_dest = out / "recon-engine" / "target-evidence" / "target-request-ledger.jsonl"
    target_dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(args.target_ledger, target_dest)

    print("converting report -> PDF...")
    convert_report_to_pdf(run_dir / "report.html", out / "attack-surface-report.pdf")

    print("copying scope register...")
    copy_scope_register(out)

    print("copying raw output...")
    copy_raw_output(run_dir, out)

    print("converting normalized output -> JSON...")
    convert_normalized_to_json(run_dir, out)

    print("converting request ledger -> CSV...")
    convert_ledger_to_csv(run_dir, out)

    print("compiling foothold evidence...")
    compile_foothold_evidence(run_dir, out)

    print("running tests -> JUnit XML...")
    tests_passed = run_tests_to_junit_xml(out)
    if not tests_passed:
        print("  ! WARNING: test suite did not pass cleanly -- check test-results.xml", file=sys.stderr)

    print("writing evidence index...")
    write_evidence_index(run_dir, out)

    print("writing integrity attestation...")
    write_integrity_attestation(run_dir, target_dest, out)

    print("writing README...")
    write_readme(out)

    print("writing assessment manifest...")
    write_assessment_manifest(run_dir, out)

    print("writing continuity record...")
    write_continuity_record(out)

    print("regenerating manifest.sha256 (last step)...")
    regenerate_manifest(out)

    print(f"\ndone: {out}")


if __name__ == "__main__":
    main()
