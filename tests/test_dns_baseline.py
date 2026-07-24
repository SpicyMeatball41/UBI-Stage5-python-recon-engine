#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recon_engine.adapters.dns_baseline import establish_dns_baseline
from recon_engine.checkpoint import Checkpoint
from recon_engine.ledger import RequestLedger
from recon_engine.scope_guard import ScopeGuard, ScopeViolation

REPO_ROOT = Path(__file__).resolve().parent.parent
SCOPE_CSV = REPO_ROOT / "scope.csv"
ASSIGNMENT_JSON = REPO_ROOT / "assignment.json"


class TestDnsBaseline(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.workdir = Path(self.tmpdir.name)
        self.output_dir = self.workdir / "run"
        self.scope_copy = self.workdir / "scope.csv"
        self.assignment_copy = self.workdir / "assignment.json"
        self.scope_copy.write_text(SCOPE_CSV.read_text())
        self.assignment_copy.write_text(ASSIGNMENT_JSON.read_text())
        self.guard = ScopeGuard(self.scope_copy, assignment_path=self.assignment_copy)
        self.ledger = RequestLedger(self.output_dir / "request-ledger.jsonl")

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_literal_ip_needs_no_dns_query(self):
        with patch("socket.gethostbyname") as mock_dns:
            establish_dns_baseline(self.guard, "127.0.0.1", 18467, self.output_dir, self.ledger)
            mock_dns.assert_not_called()

    def test_literal_ip_never_calls_guard_check(self):
        """No network packet is sent for a literal IP -- there's
        nothing for ScopeGuard.check() to gate, so it must not be
        called (and therefore must not consume budget)."""
        budget_before = self.guard.remaining_budget
        establish_dns_baseline(self.guard, "127.0.0.1", 18467, self.output_dir, self.ledger)
        self.assertEqual(self.guard.remaining_budget, budget_before)

    def test_writes_one_normalized_record(self):
        establish_dns_baseline(self.guard, "127.0.0.1", 18467, self.output_dir, self.ledger)
        records = [
            json.loads(l)
            for l in (self.output_dir / "normalized" / "assets.jsonl").read_text().splitlines()
        ]
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]["is_literal_ip"])
        self.assertEqual(records[0]["protocol"], "dns")
        self.assertIn("fingerprint", records[0])

    def test_writes_one_ledger_line(self):
        establish_dns_baseline(self.guard, "127.0.0.1", 18467, self.output_dir, self.ledger)
        lines = self.ledger.path.read_text().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["protocol"], "dns")

    def test_hostname_resolves_via_the_same_path_scopeguard_uses(self):
        with patch("socket.gethostbyname", return_value="127.0.0.1") as mock_dns:
            establish_dns_baseline(
                self.guard, "loopback-alias.example", 18467, self.output_dir, self.ledger
            )
            mock_dns.assert_called_once_with("loopback-alias.example")

    def test_dns_failure_raises_scope_violation_not_a_crash(self):
        import socket as socket_module

        with patch(
            "socket.gethostbyname",
            side_effect=socket_module.gaierror("not known"),
        ):
            with self.assertRaises(ScopeViolation):
                establish_dns_baseline(
                    self.guard, "does-not-resolve.invalid", 18467, self.output_dir, self.ledger
                )

    def test_checkpoint_dedup_skips_repeat_calls(self):
        checkpoint = Checkpoint(self.output_dir / "checkpoint.json")
        establish_dns_baseline(
            self.guard, "127.0.0.1", 18467, self.output_dir, self.ledger, checkpoint=checkpoint
        )
        result = establish_dns_baseline(
            self.guard, "127.0.0.1", 23390, self.output_dir, self.ledger, checkpoint=checkpoint
        )
        self.assertEqual(result["records_written"], 0)
        lines = self.ledger.path.read_text().splitlines()
        self.assertEqual(len(lines), 1)  # only the first call actually ran


if __name__ == "__main__":
    unittest.main()
