#!/usr/bin/env python3
import json
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from recon_engine.adapters.tls_probe import probe_tls
from recon_engine.ledger import RequestLedger
from recon_engine.scope_guard import ScopeGuard, ScopeViolation

REPO_ROOT = Path(__file__).resolve().parent.parent
SCOPE_CSV = REPO_ROOT / "scope.csv"
ASSIGNMENT_JSON = REPO_ROOT / "assignment.json"


class TestTlsProbe(unittest.TestCase):
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

    def test_no_tls_is_a_graceful_finding_not_an_exception(self):
        """This is the expected outcome for this lab's plaintext HTTP
        service: the handshake fails, and that failure IS the finding."""
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.__exit__.return_value = False

        with patch("socket.create_connection", return_value=fake_sock), patch(
            "ssl.SSLContext.wrap_socket",
            side_effect=ssl.SSLError("wrong version number"),
        ):
            record = probe_tls(
                self.guard, "127.0.0.1", 18467, self.output_dir, self.ledger
            )
        self.assertFalse(record["tls_available"])
        self.assertIn("no TLS", record["notes"])

        ledger_lines = [json.loads(l) for l in self.ledger.path.read_text().splitlines()]
        self.assertEqual(len(ledger_lines), 1)
        self.assertEqual(ledger_lines[0]["scope_verdict"], "approved")
        self.assertIn("no TLS", ledger_lines[0]["result"])

    def test_tls_available_is_recorded_when_handshake_succeeds(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.__exit__.return_value = False

        mock_tls_sock = MagicMock()
        mock_tls_sock.version.return_value = "TLSv1.3"
        mock_tls_sock.__enter__.return_value = mock_tls_sock
        mock_tls_sock.__exit__.return_value = False

        with patch("socket.create_connection", return_value=fake_sock), patch(
            "ssl.SSLContext.wrap_socket", return_value=mock_tls_sock
        ):
            record = probe_tls(
                self.guard, "127.0.0.1", 18467, self.output_dir, self.ledger
            )
        self.assertTrue(record["tls_available"])
        self.assertEqual(record["tls_version"], "TLSv1.3")

    def test_scope_denial_propagates_and_never_probes(self):
        with patch("socket.create_connection") as mock_conn:
            with self.assertRaises(ScopeViolation):
                probe_tls(self.guard, "127.0.0.1", 26035, self.output_dir, self.ledger)
            mock_conn.assert_not_called()

    def test_normalized_record_and_raw_capture_are_written(self):
        with patch("ssl.SSLContext.wrap_socket", side_effect=ssl.SSLError("no tls")):
            probe_tls(self.guard, "127.0.0.1", 18467, self.output_dir, self.ledger)

        assets_path = self.output_dir / "normalized" / "assets.jsonl"
        records = [json.loads(l) for l in assets_path.read_text().splitlines()]
        self.assertEqual(records[0]["protocol"], "tls")

        raw_path = self.output_dir / "raw" / "tls" / "127.0.0.1_18467_tls.raw"
        self.assertTrue(raw_path.exists())


if __name__ == "__main__":
    unittest.main()
