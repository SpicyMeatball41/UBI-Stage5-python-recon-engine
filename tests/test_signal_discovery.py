#!/usr/bin/env python3
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from recon_engine.adapters.signal_discovery import (
    Command,
    DiscoveryError,
    discover_signal,
)
from recon_engine.checkpoint import Checkpoint
from recon_engine.ledger import RequestLedger
from recon_engine.scope_guard import ScopeGuard, ScopeViolation

REPO_ROOT = Path(__file__).resolve().parent.parent
SCOPE_CSV = REPO_ROOT / "scope.csv"
ASSIGNMENT_JSON = REPO_ROOT / "assignment.json"


def _mock_socket(exchanges):
    """exchanges: list of (banner_bytes, response_bytes_or_None) per
    connection, consumed in order. None response simulates a timeout."""
    it = iter(exchanges)

    def _create_connection(*args, **kwargs):
        banner, response = next(it)
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.__exit__.return_value = False
        file_mock = MagicMock()

        readline_results = iter([banner, response if response is not None else b""])
        file_mock.readline.side_effect = lambda *a: next(readline_results)
        sock.makefile.return_value = file_mock
        return sock

    return patch("socket.create_connection", side_effect=_create_connection)


class TestSignalDiscoveryAdapter(unittest.TestCase):
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

    def test_caps_and_route_produce_two_records(self):
        with _mock_socket([
            (b"RLY/2 READY profile=dynamic\r\n", b"commands=CAPS,ROUTE,QUIT; framing=line; auth=none\r\n"),
            (b"RLY/2 READY profile=dynamic\r\n", b"route=relay-abc123.northstar.local; proof=deadbeef\r\n"),
        ]):
            result = discover_signal(
                self.guard, "127.0.0.1", 23390, self.output_dir, self.ledger
            )
        self.assertEqual(result["records_written"], 2)

        records = [
            json.loads(l)
            for l in (self.output_dir / "normalized" / "assets.jsonl").read_text().splitlines()
        ]
        self.assertEqual(records[0]["command"], "CAPS")
        self.assertEqual(records[1]["command"], "ROUTE")
        self.assertEqual(records[1]["vhost"], "relay-abc123.northstar.local")
        self.assertEqual(records[1]["route_key"], "deadbeef")

    def test_route_result_is_stored_in_checkpoint_meta(self):
        checkpoint = Checkpoint(self.output_dir / "checkpoint.json")
        with _mock_socket([
            (b"banner\r\n", b"commands=CAPS,ROUTE,QUIT; framing=line; auth=none\r\n"),
            (b"banner\r\n", b"route=relay-xyz.harbor.local; proof=cafef00d\r\n"),
        ]):
            discover_signal(
                self.guard, "127.0.0.1", 23390, self.output_dir, self.ledger,
                checkpoint=checkpoint,
            )
        self.assertEqual(checkpoint.get_meta("vhost"), "relay-xyz.harbor.local")
        self.assertEqual(checkpoint.get_meta("route_key"), "cafef00d")

    def test_timeout_is_classified_408_and_not_retried(self):
        with _mock_socket([
            (b"banner\r\n", None),  # no response at all -> timeout
        ]):
            result = discover_signal(
                self.guard, "127.0.0.1", 23390, self.output_dir, self.ledger,
                commands=[Command(text="CAPS", purpose="capability enumeration")],
            )
        records = [
            json.loads(l)
            for l in (self.output_dir / "normalized" / "assets.jsonl").read_text().splitlines()
        ]
        self.assertEqual(records[0]["status"], 408)
        ledger_lines = [
            json.loads(l) for l in self.ledger.path.read_text().splitlines()
        ]
        self.assertEqual(len(ledger_lines), 1)  # one attempt, not retried

    def test_err_response_is_not_retried(self):
        with _mock_socket([
            (b"banner\r\n", b"ERR unsupported command\r\n"),
        ]):
            result = discover_signal(
                self.guard, "127.0.0.1", 23390, self.output_dir, self.ledger,
                commands=[Command(text="NONSENSE", purpose="probe unknown command")],
            )
        records = [
            json.loads(l)
            for l in (self.output_dir / "normalized" / "assets.jsonl").read_text().splitlines()
        ]
        self.assertEqual(records[0]["status"], 400)
        ledger_lines = [json.loads(l) for l in self.ledger.path.read_text().splitlines()]
        self.assertEqual(len(ledger_lines), 1)  # ERR is a completed attempt, not retried

    def test_scope_denial_never_opens_a_socket(self):
        with patch("socket.create_connection") as mock_conn:
            with self.assertRaises(ScopeViolation):
                discover_signal(self.guard, "127.0.0.1", 26035, self.output_dir, self.ledger)
            mock_conn.assert_not_called()

    def test_transport_failure_retries_then_raises(self):
        with patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
            with self.assertRaises(DiscoveryError):
                discover_signal(
                    self.guard, "127.0.0.1", 23390, self.output_dir, self.ledger,
                    commands=[Command(text="CAPS", purpose="capability enumeration")],
                    max_retries=1, retry_backoff=0.01,
                )
        ledger_lines = [json.loads(l) for l in self.ledger.path.read_text().splitlines()]
        self.assertEqual(len(ledger_lines), 2)  # 1 initial + 1 retry

    def test_checkpoint_skip_avoids_new_socket_and_new_budget_use(self):
        checkpoint = Checkpoint(self.output_dir / "checkpoint.json")
        checkpoint.mark_done("signal:CAPS", {"command": "CAPS", "status": 200})
        with patch("socket.create_connection") as mock_conn:
            result = discover_signal(
                self.guard, "127.0.0.1", 23390, self.output_dir, self.ledger,
                commands=[Command(text="CAPS", purpose="capability enumeration")],
                checkpoint=checkpoint,
            )
        mock_conn.assert_not_called()
        self.assertEqual(result["records_written"], 0)  # reused, not newly written
        self.assertEqual(self.guard.remaining_budget, self.guard.budget)  # no budget spent


if __name__ == "__main__":
    unittest.main()
