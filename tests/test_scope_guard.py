#!/usr/bin/env python3
import csv
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from recon_engine.scope_guard import ScopeGuard, ScopeViolation

REPO_ROOT = Path(__file__).resolve().parent.parent
SCOPE_CSV = REPO_ROOT / "scope.csv"
ASSIGNMENT_JSON = REPO_ROOT / "assignment.json"


def make_guard(**overrides):
    kwargs = dict(
        scope_csv_path=SCOPE_CSV,
        assignment_path=ASSIGNMENT_JSON,
        ledger_path=None,  # tests don't touch the real ledger by default
    )
    kwargs.update(overrides)
    return ScopeGuard(**kwargs)


class TestScopeGuardAgainstRealFiles(unittest.TestCase):
    """Exercises the guard against the actual scope.csv / assignment.json."""

    def test_loads_scope_and_assignment(self):
        guard = make_guard()
        self.assertIn(("127.0.0.1", 18467), guard._exact)
        self.assertEqual(guard.budget, 240)
        self.assertEqual(guard.max_rate_per_second, 25)
        self.assertEqual(guard.authorized_ports, {18467, 23390})

    def test_allows_in_scope_authorized_port(self):
        guard = make_guard()
        guard.check("127.0.0.1", 18467)  # entry_url port, IN + authorized
        guard.check("127.0.0.1", 23390)

    def test_rejects_out_port(self):
        """127.0.0.1:26035 is explicitly marked OUT in scope.csv."""
        guard = make_guard()
        with self.assertRaises(ScopeViolation) as ctx:
            guard.check("127.0.0.1", 26035)
        self.assertIn("OUT", str(ctx.exception))

    def test_rejects_non_loopback_address(self):
        """0.0.0.0/0 OUT catches every non-loopback destination."""
        guard = make_guard()
        with self.assertRaises(ScopeViolation) as ctx:
            guard.check("93.184.216.34", 80)
        self.assertIn("loopback", str(ctx.exception))

    def test_rejects_unlisted_port(self):
        """9999 has no exact row; the 0.0.0.0/0 OUT catch-all applies to it
        too (it's just a network, not scoped to non-loopback addresses),
        so it's denied via that row rather than a bare "not listed" error.
        Either way it must be rejected.
        """
        guard = make_guard()
        with self.assertRaises(ScopeViolation) as ctx:
            guard.check("127.0.0.1", 9999)
        self.assertTrue(
            "not listed" in str(ctx.exception)
            or "not in authorized_ports" in str(ctx.exception)
            or "marked OUT" in str(ctx.exception)
        )

    def test_rejects_request_after_budget_exhausted(self):
        guard = make_guard(budget=2, max_rate_per_second=None)
        guard.check("127.0.0.1", 18467)  # 1/2
        guard.check("127.0.0.1", 23390)  # 2/2
        with self.assertRaises(ScopeViolation) as ctx:
            guard.check("127.0.0.1", 18467)  # would be 3/2
        self.assertIn("budget", str(ctx.exception))

    def test_rejects_request_over_rate_limit(self):
        guard = make_guard(budget=100, max_rate_per_second=2)
        guard.check("127.0.0.1", 18467)
        guard.check("127.0.0.1", 23390)
        with self.assertRaises(ScopeViolation) as ctx:
            guard.check("127.0.0.1", 18467)
        self.assertIn("rate limit", str(ctx.exception))

    def test_rate_limit_window_clears_over_time(self):
        guard = make_guard(budget=100, max_rate_per_second=1)
        guard.check("127.0.0.1", 18467)
        with self.assertRaises(ScopeViolation):
            guard.check("127.0.0.1", 18467)
        time.sleep(1.05)
        guard.check("127.0.0.1", 18467)  # window cleared, should succeed

    def test_failed_checks_do_not_consume_budget(self):
        guard = make_guard(budget=1, max_rate_per_second=None)
        with self.assertRaises(ScopeViolation):
            guard.check("127.0.0.1", 26035)  # OUT, rejected
        guard.check("127.0.0.1", 18467)  # budget still intact
        self.assertEqual(guard.remaining_budget, 0)


class TestScopeGuardLedger(unittest.TestCase):
    """Every check() call, approved or denied, must be recorded."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.ledger_path = Path(self.tmpdir.name) / "ledger.jsonl"

    def tearDown(self):
        self.tmpdir.cleanup()

    def _read_ledger(self):
        if not self.ledger_path.exists():
            return []
        with open(self.ledger_path) as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_approved_call_is_logged(self):
        guard = make_guard(ledger_path=self.ledger_path)
        guard.check("127.0.0.1", 18467)
        records = self._read_ledger()
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]["approved"])
        self.assertEqual(records[0]["port"], 18467)

    def test_denied_call_is_logged(self):
        guard = make_guard(ledger_path=self.ledger_path)
        with self.assertRaises(ScopeViolation):
            guard.check("127.0.0.1", 26035)
        records = self._read_ledger()
        self.assertEqual(len(records), 1)
        self.assertFalse(records[0]["approved"])
        self.assertIn("OUT", records[0]["reason"])


class TestScopeGuardWithTemporaryScopeFile(unittest.TestCase):
    """Isolated tests using a throwaway scope.csv, independent of repo files."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.scope_path = Path(self.tmpdir.name) / "scope.csv"
        with open(self.scope_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["asset", "scope", "notes"])
            writer.writerow(["127.0.0.1:8080", "IN", "allowed"])
            writer.writerow(["127.0.0.1:9999", "OUT", "explicitly excluded"])
            writer.writerow(["0.0.0.0/0", "OUT", "deny everything else"])

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_missing_scope_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            ScopeGuard(Path(self.tmpdir.name) / "does-not-exist.csv")

    def test_exact_out_row_beats_cidr(self):
        guard = ScopeGuard(self.scope_path, budget=5)
        with self.assertRaises(ScopeViolation) as ctx:
            guard.check("127.0.0.1", 9999)
        self.assertIn("9999", str(ctx.exception))

    def test_exact_in_row_survives_alongside_cidr_out(self):
        guard = ScopeGuard(self.scope_path, budget=5)
        guard.check("127.0.0.1", 8080)  # exact IN row wins even with 0.0.0.0/0 OUT

    def test_non_loopback_caught_by_cidr(self):
        guard = ScopeGuard(self.scope_path, budget=5)
        with self.assertRaises(ScopeViolation):
            guard.check("8.8.8.8", 53)

    def test_unlisted_port_rejected(self):
        guard = ScopeGuard(self.scope_path, budget=5)
        with self.assertRaises(ScopeViolation):
            guard.check("127.0.0.1", 12345)

    def test_budget_of_zero_rejects_everything(self):
        guard = ScopeGuard(self.scope_path, budget=0)
        with self.assertRaises(ScopeViolation) as ctx:
            guard.check("127.0.0.1", 8080)
        self.assertIn("budget", str(ctx.exception))


class TestScopeGuardHostnameResolution(unittest.TestCase):
    """The 'target' in scope isn't always a bare IP -- ScopeGuard resolves
    hostnames via DNS before checking loopback/scope. These mock
    socket.gethostbyname so the tests don't depend on real DNS or network
    access, but exercise the same code path (ScopeGuard._resolve)."""

    def test_hostname_resolving_to_loopback_is_checked_like_an_ip(self):
        guard = make_guard()
        with patch("socket.gethostbyname", return_value="127.0.0.1") as mock_dns:
            guard.check("loopback-alias.example", 18467)
        mock_dns.assert_called_once_with("loopback-alias.example")

    def test_hostname_resolving_to_public_ip_is_rejected(self):
        guard = make_guard()
        with patch("socket.gethostbyname", return_value="93.184.216.34"):
            with self.assertRaises(ScopeViolation) as ctx:
                guard.check("some-external-host.example", 80)
        self.assertIn("loopback", str(ctx.exception))

    def test_dns_resolution_failure_is_a_clean_scope_violation(self):
        import socket as socket_module

        guard = make_guard()
        with patch(
            "socket.gethostbyname",
            side_effect=socket_module.gaierror("name or service not known"),
        ):
            with self.assertRaises(ScopeViolation) as ctx:
                guard.check("does-not-resolve.invalid", 18467)
        self.assertIn("could not resolve", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
