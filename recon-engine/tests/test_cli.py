#!/usr/bin/env python3
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from recon_engine.cli import run

REPO_ROOT = Path(__file__).resolve().parent.parent
SCOPE_CSV = REPO_ROOT / "scope.csv"          # has an assignment.json next to it
ASSIGNMENT_JSON = REPO_ROOT / "assignment.json"


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = run(argv)
        except SystemExit as exc:
            # argparse itself exits directly (e.g. missing required arg)
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class TestCliPhase1ValidationOnly(unittest.TestCase):
    """Uses a scope.csv with NO assignment.json next to it, so the CLI
    never reaches phase 2 (the real network call) and exit 0 doesn't
    depend on anything actually listening."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.tmpdir.name) / "run"
        self.scope_only_path = Path(self.tmpdir.name) / "scope.csv"
        self.scope_only_path.write_text(SCOPE_CSV.read_text())
        # deliberately do NOT copy assignment.json alongside it

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_help_exits_zero(self):
        with self.assertRaises(SystemExit) as ctx:
            with redirect_stdout(io.StringIO()):
                run(["--help"])
        self.assertEqual(ctx.exception.code, 0)

    def test_missing_required_arg_exits_2(self):
        code, out, err = _run(
            ["--target", "127.0.0.1", "--scope", str(self.scope_only_path),
             "--output", str(self.output_dir)]
        )
        self.assertEqual(code, 2)
        self.assertIn("--rate", err)

    def test_valid_target_exits_0_and_creates_output_dir(self):
        code, out, err = _run(
            ["--target", "127.0.0.1:18467", "--scope", str(self.scope_only_path),
             "--output", str(self.output_dir), "--rate", "25"]
        )
        self.assertEqual(code, 0)
        self.assertIn("OK: target", out)
        self.assertIn("validation-only run", out)
        self.assertTrue(self.output_dir.is_dir())

    def test_bare_host_without_port_is_valid(self):
        code, out, err = _run(
            ["--target", "127.0.0.1", "--scope", str(self.scope_only_path),
             "--output", str(self.output_dir), "--rate", "25"]
        )
        self.assertEqual(code, 0)

    def test_out_port_rejected_with_exit_3(self):
        code, out, err = _run(
            ["--target", "127.0.0.1:26035", "--scope", str(self.scope_only_path),
             "--output", str(self.output_dir), "--rate", "25"]
        )
        self.assertEqual(code, 3)
        self.assertIn("scope violation", err)

    def test_non_loopback_rejected_with_exit_3(self):
        code, out, err = _run(
            ["--target", "93.184.216.34", "--scope", str(self.scope_only_path),
             "--output", str(self.output_dir), "--rate", "25"]
        )
        self.assertEqual(code, 3)
        self.assertIn("loopback", err)

    def test_unlisted_port_rejected(self):
        code, out, err = _run(
            ["--target", "127.0.0.1:9999", "--scope", str(self.scope_only_path),
             "--output", str(self.output_dir), "--rate", "25"]
        )
        self.assertEqual(code, 3)

    def test_zero_rate_rejected(self):
        code, out, err = _run(
            ["--target", "127.0.0.1:18467", "--scope", str(self.scope_only_path),
             "--output", str(self.output_dir), "--rate", "0"]
        )
        self.assertEqual(code, 2)

    def test_negative_rate_rejected(self):
        code, out, err = _run(
            ["--target", "127.0.0.1:18467", "--scope", str(self.scope_only_path),
             "--output", str(self.output_dir), "--rate", "-5"]
        )
        self.assertEqual(code, 2)

    def test_missing_scope_file_rejected(self):
        code, out, err = _run(
            ["--target", "127.0.0.1:18467", "--scope", str(Path(self.tmpdir.name) / "nope.csv"),
             "--output", str(self.output_dir), "--rate", "25"]
        )
        self.assertEqual(code, 2)
        self.assertIn("--scope", err)

    def test_malformed_target_port_rejected(self):
        code, out, err = _run(
            ["--target", "127.0.0.1:notaport", "--scope", str(self.scope_only_path),
             "--output", str(self.output_dir), "--rate", "25"]
        )
        self.assertEqual(code, 2)
        self.assertIn("--target", err)

    def test_output_path_is_existing_file_rejected(self):
        file_path = Path(self.tmpdir.name) / "im-a-file"
        file_path.write_text("x")
        code, out, err = _run(
            ["--target", "127.0.0.1:18467", "--scope", str(self.scope_only_path),
             "--output", str(file_path), "--rate", "25"]
        )
        self.assertEqual(code, 2)
        self.assertIn("not a directory", err)


class TestCliPhase1WithAssignmentRateCheck(unittest.TestCase):
    """These specifically need assignment.json present (for its
    maximum_rate_per_second) but must fail during phase 1, before any
    network call would happen."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.tmpdir.name) / "run"
        # preserve_scope_profile() runs before the rate check even for a
        # request that ends up rejected, so chdir to avoid writing
        # evidence/<runtime_id>/ into the real repo during tests.
        self._prev_cwd = Path.cwd()
        import os
        os.chdir(self.tmpdir.name)

    def tearDown(self):
        import os
        os.chdir(self._prev_cwd)
        self.tmpdir.cleanup()

    def test_rate_exceeding_assignment_max_rejected(self):
        code, out, err = _run(
            ["--target", "127.0.0.1:18467", "--scope", str(SCOPE_CSV),
             "--output", str(self.output_dir), "--rate", "999"]
        )
        self.assertEqual(code, 3)
        self.assertIn("maximum_rate_per_second", err)


class TestCliPhase2Discovery(unittest.TestCase):
    """Phase 2/3 now runs the orchestrator (bounded concurrency across
    every assigned service), so these mock recon_engine.cli.run_discovery
    directly rather than re-mocking 3 different network protocols --
    each adapter's own network behavior is already covered by
    test_http_discovery.py / test_signal_discovery.py, and the
    orchestrator's own wiring (concurrency, decoy safety, vhost
    follow-up) is covered by test_orchestrator.py. These tests are
    about the CLI's own behavior: manifest writing, exit codes, and
    printed output."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.tmpdir.name) / "run"
        self.scope_copy = Path(self.tmpdir.name) / "scope.csv"
        self.assignment_copy = Path(self.tmpdir.name) / "assignment.json"
        self.scope_copy.write_text(SCOPE_CSV.read_text())
        self.assignment_copy.write_text(ASSIGNMENT_JSON.read_text())
        # preserve_scope_profile() writes evidence/<runtime_id>/ relative
        # to the current working directory -- chdir into the temp dir so
        # running this test suite never writes into the real repo.
        self._prev_cwd = Path.cwd()
        import os
        os.chdir(self.tmpdir.name)

    def tearDown(self):
        import os
        os.chdir(self._prev_cwd)
        self.tmpdir.cleanup()

    def _argv(self, rate="25", target="127.0.0.1:18467"):
        return [
            "--target", target,
            "--scope", str(self.scope_copy),
            "--output", str(self.output_dir),
            "--rate", rate,
        ]

    def _write_fake_normalized_records(self, n=2):
        normalized_dir = self.output_dir / "normalized"
        normalized_dir.mkdir(parents=True, exist_ok=True)
        with open(normalized_dir / "assets.jsonl", "w") as f:
            for i in range(n):
                f.write(json.dumps({
                    "observed_at": "2026-01-01T00:00:00Z", "target": "127.0.0.1:18467",
                    "protocol": "http", "service": "http", "notes": f"probe {i}",
                    "status": 200, "source_file": f"probe_{i}.raw",
                }) + "\n")

    def test_successful_discovery_writes_manifest_and_report(self):
        self._write_fake_normalized_records(2)
        fake_discovery = {
            "targets": [{"host": "127.0.0.1", "port": 18467, "note": "HTTP discovery target"}],
            "results": {"127.0.0.1:18467": {"protocol": "http", "records_written": 2}},
            "errors": {},
            "ledger_path": str(self.output_dir / "request-ledger.jsonl"),
            "checkpoint_path": str(self.output_dir / "checkpoint.json"),
            "vhost_discovered": None,
        }
        with patch("recon_engine.cli.run_discovery", return_value=fake_discovery):
            code, out, err = _run(self._argv())

        self.assertEqual(code, 0)
        self.assertIn("Discovered 1/1 assigned service(s)", out)

        run_json = json.loads((self.output_dir / "run.json").read_text())
        self.assertTrue(run_json["observation_performed"])
        self.assertIn("reconciliation", run_json)
        self.assertEqual(run_json["phase2_observation"], fake_discovery)

        # generate_report() ran for real (not mocked) and read the fake
        # normalized records we wrote above.
        report_path = self.output_dir / "report.html"
        self.assertTrue(report_path.exists())
        self.assertIn("2 normalized record", report_path.read_text())

    def test_only_authorized_targets_are_ever_passed_to_run_discovery(self):
        """--target naming the OUT port must be rejected in phase 1;
        run_discovery must never even be called."""
        with patch("recon_engine.cli.run_discovery") as mock_run:
            code, out, err = _run(self._argv(target="127.0.0.1:26035"))
        self.assertEqual(code, 3)
        mock_run.assert_not_called()

    def test_total_failure_exits_4_cleanly(self):
        """If every assigned service failed (no results at all),
        that's a real failure, not a partial success."""
        fake_discovery = {
            "targets": [{"host": "127.0.0.1", "port": 18467, "note": "HTTP discovery target"}],
            "results": {},
            "errors": {"127.0.0.1:18467": "connection refused after retries"},
            "ledger_path": str(self.output_dir / "request-ledger.jsonl"),
            "checkpoint_path": str(self.output_dir / "checkpoint.json"),
            "vhost_discovered": None,
        }
        with patch("recon_engine.cli.run_discovery", return_value=fake_discovery):
            code, out, err = _run(self._argv())
        self.assertEqual(code, 4)
        self.assertIn("connection refused", err)

    def test_partial_failure_still_reports_what_succeeded(self):
        """One adapter failing while another succeeds is a partial
        result, not a hard failure -- exit 0, with the error surfaced
        on stderr for visibility."""
        fake_discovery = {
            "targets": [
                {"host": "127.0.0.1", "port": 18467, "note": "HTTP discovery target"},
                {"host": "127.0.0.1", "port": 23390, "note": "line-protocol discovery target"},
            ],
            "results": {"127.0.0.1:18467": {"protocol": "http", "records_written": 2}},
            "errors": {"127.0.0.1:23390": "timed out after retries"},
            "ledger_path": str(self.output_dir / "request-ledger.jsonl"),
            "checkpoint_path": str(self.output_dir / "checkpoint.json"),
            "vhost_discovered": None,
        }
        with patch("recon_engine.cli.run_discovery", return_value=fake_discovery):
            code, out, err = _run(self._argv())
        self.assertEqual(code, 0)
        self.assertIn("timed out", err)

    def test_rate_over_budget_never_reaches_run_discovery(self):
        with patch("recon_engine.cli.run_discovery") as mock_run:
            code, out, err = _run(self._argv(rate="999"))
        self.assertEqual(code, 3)
        mock_run.assert_not_called()

    def test_preexisting_target_ledger_history_does_not_break_reconciliation(self):
        """Regression test: a target ledger that already has old entries
        (from a prior run, or an old architecture artifact) must not
        make a clean new run look unreconciled."""
        target_ledger_path = self.scope_copy.parent / "target-request-ledger.jsonl"
        target_ledger_path.write_text(
            json.dumps({"ts": 1.0, "host": "127.0.0.1", "port": 18467}) + "\n"
            + json.dumps({"sequence": 1, "result": 200}) + "\n"
        )

        def _fake_run_discovery(guard, output_dir, **kwargs):
            # Simulate the engine's own ledger AND the target's own
            # ledger both gaining one new entry during this run.
            engine_ledger = output_dir / "request-ledger.jsonl"
            engine_ledger.parent.mkdir(parents=True, exist_ok=True)
            with open(engine_ledger, "a") as f:
                f.write(json.dumps({"scope_verdict": "approved", "result": "HTTP 200"}) + "\n")
            with open(target_ledger_path, "a") as f:
                f.write(json.dumps({"sequence": 2, "result": 200}) + "\n")
            return {
                "targets": [{"host": "127.0.0.1", "port": 18467, "note": "HTTP discovery target"}],
                "results": {"127.0.0.1:18467": {"protocol": "http"}},
                "errors": {},
                "ledger_path": str(engine_ledger),
                "checkpoint_path": str(output_dir / "checkpoint.json"),
                "vhost_discovered": None,
            }

        with patch("recon_engine.cli.run_discovery", side_effect=_fake_run_discovery):
            code, out, err = _run(self._argv())

        self.assertEqual(code, 0)
        self.assertIn("reconciled      : True", out)


if __name__ == "__main__":
    unittest.main()
