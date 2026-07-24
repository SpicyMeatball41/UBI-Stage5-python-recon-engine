#!/usr/bin/env python3
import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from recon_engine.adapters.foothold import (
    FootholdError,
    FootholdEvidenceMissing,
    pursue_foothold,
)
from recon_engine.checkpoint import Checkpoint
from recon_engine.ledger import RequestLedger
from recon_engine.scope_guard import ScopeGuard, ScopeViolation

REPO_ROOT = Path(__file__).resolve().parent.parent
SCOPE_CSV = REPO_ROOT / "scope.csv"
ASSIGNMENT_JSON = REPO_ROOT / "assignment.json"


def _mock_http_sequence(responses):
    """responses: list of (status, reason, headers, body)."""
    conn = MagicMock()
    it = iter(responses)

    def _getresponse():
        status, reason, headers, body = next(it)
        resp = MagicMock()
        resp.status, resp.reason = status, reason
        resp.getheaders.return_value = headers
        resp.read.return_value = body
        return resp

    conn.getresponse.side_effect = _getresponse
    return patch("http.client.HTTPConnection", return_value=conn)


class TestFoothold(unittest.TestCase):
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
        self.checkpoint = Checkpoint(self.output_dir / "checkpoint.json")

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_no_evidence_yet_raises_evidence_missing_not_a_generic_error(self):
        """No vhost/route_key in the checkpoint -- this adapter must
        not scan or guess for them; it just declines to run."""
        with patch("http.client.HTTPConnection") as mock_conn:
            with self.assertRaises(FootholdEvidenceMissing):
                pursue_foothold(
                    self.guard, "127.0.0.1", 18467, self.output_dir,
                    self.ledger, self.checkpoint,
                )
            mock_conn.assert_not_called()

    def test_partial_evidence_still_declines(self):
        self.checkpoint.set_meta("vhost", "relay-abc.northstar.local")
        # route_key deliberately not set
        with self.assertRaises(FootholdEvidenceMissing):
            pursue_foothold(
                self.guard, "127.0.0.1", 18467, self.output_dir,
                self.ledger, self.checkpoint,
            )

    def test_successful_chain_captures_flag_and_makes_exactly_two_requests(self):
        self.checkpoint.set_meta("vhost", "relay-abc.northstar.local")
        self.checkpoint.set_meta("route_key", "deadbeef")

        diag_body = json.dumps({
            "support_user": "operator42", "support_password": "s3cr3t",
        }).encode()
        flag_body = b"UBI-EH-A1-DEADBEEFCAFE1234\n"

        conn = MagicMock()
        responses = iter([
            (200, "OK", [("Content-Type", "application/json")], diag_body),
            (200, "OK", [("Content-Type", "text/plain")], flag_body),
        ])
        requested_paths = []
        requested_headers = []

        def _request(method, path, headers=None):
            requested_paths.append(path)
            requested_headers.append(headers or {})

        def _getresponse():
            status, reason, hdrs, body = next(responses)
            resp = MagicMock()
            resp.status, resp.reason = status, reason
            resp.getheaders.return_value = hdrs
            resp.read.return_value = body
            return resp

        conn.request.side_effect = _request
        conn.getresponse.side_effect = _getresponse

        with patch("http.client.HTTPConnection", return_value=conn):
            summary = pursue_foothold(
                self.guard, "127.0.0.1", 18467, self.output_dir,
                self.ledger, self.checkpoint,
            )

        self.assertTrue(summary["success"])
        self.assertEqual(summary["flag"], "UBI-EH-A1-DEADBEEFCAFE1234")
        self.assertEqual(summary["username"], "operator42")

        # Exactly two requests, in order, nothing else.
        self.assertEqual(requested_paths, ["/ops-diagnostics", "/user.txt"])

        # /user.txt carried the credentials read from /ops-diagnostics
        # and the route proof from the checkpoint -- not anything else.
        user_txt_headers = requested_headers[1]
        expected_auth = "Basic " + base64.b64encode(b"operator42:s3cr3t").decode()
        self.assertEqual(user_txt_headers["Authorization"], expected_auth)
        self.assertEqual(user_txt_headers["X-Route-Key"], "deadbeef")
        self.assertEqual(user_txt_headers["Host"], "relay-abc.northstar.local")

        # Normalized records for both steps, in order.
        records = [
            json.loads(l)
            for l in (self.output_dir / "normalized" / "assets.jsonl").read_text().splitlines()
        ]
        self.assertEqual(records[0]["path"], "/ops-diagnostics")
        self.assertEqual(records[1]["path"], "/user.txt")
        self.assertEqual(records[1]["status"], 200)

        # Both requests logged in the engine's own ledger.
        ledger_lines = self.ledger.path.read_text().splitlines()
        self.assertEqual(len(ledger_lines), 2)

    def test_wrong_credentials_reported_honestly_not_retried(self):
        self.checkpoint.set_meta("vhost", "relay-abc.northstar.local")
        self.checkpoint.set_meta("route_key", "deadbeef")

        diag_body = json.dumps({
            "support_user": "operator42", "support_password": "s3cr3t",
        }).encode()

        with _mock_http_sequence([
            (200, "OK", [], diag_body),
            (401, "Unauthorized", [], b"authentication required\n"),
        ]):
            with self.assertRaises(FootholdError) as ctx:
                pursue_foothold(
                    self.guard, "127.0.0.1", 18467, self.output_dir,
                    self.ledger, self.checkpoint,
                )
        self.assertIn("401", str(ctx.exception))

        # Marked done even on failure -- must not retry endlessly on
        # every subsequent run either.
        self.assertTrue(self.checkpoint.is_done("foothold:relay-abc.northstar.local"))

    def test_ops_diagnostics_failure_stops_before_user_txt(self):
        self.checkpoint.set_meta("vhost", "relay-abc.northstar.local")
        self.checkpoint.set_meta("route_key", "deadbeef")

        with _mock_http_sequence([
            (404, "Not Found", [], b"not found\n"),
        ]):
            with self.assertRaises(FootholdError):
                pursue_foothold(
                    self.guard, "127.0.0.1", 18467, self.output_dir,
                    self.ledger, self.checkpoint,
                )
        # Only ONE request happened -- /user.txt was never attempted
        # once /ops-diagnostics failed.
        ledger_lines = self.ledger.path.read_text().splitlines()
        self.assertEqual(len(ledger_lines), 1)

    def test_scope_denial_when_pointed_at_decoy(self):
        self.checkpoint.set_meta("vhost", "relay-abc.northstar.local")
        self.checkpoint.set_meta("route_key", "deadbeef")
        with patch("http.client.HTTPConnection") as mock_conn:
            with self.assertRaises(ScopeViolation):
                pursue_foothold(
                    self.guard, "127.0.0.1", 26035, self.output_dir,
                    self.ledger, self.checkpoint,
                )
            mock_conn.assert_not_called()

    def test_dedup_skips_repeat_pursuit(self):
        self.checkpoint.set_meta("vhost", "relay-abc.northstar.local")
        self.checkpoint.set_meta("route_key", "deadbeef")

        diag_body = json.dumps({
            "support_user": "u", "support_password": "p",
        }).encode()
        flag_body = b"UBI-EH-A1-ONETIME\n"

        with _mock_http_sequence([
            (200, "OK", [], diag_body),
            (200, "OK", [], flag_body),
        ]):
            first = pursue_foothold(
                self.guard, "127.0.0.1", 18467, self.output_dir,
                self.ledger, self.checkpoint,
            )

        with patch("http.client.HTTPConnection") as mock_conn:
            second = pursue_foothold(
                self.guard, "127.0.0.1", 18467, self.output_dir,
                self.ledger, self.checkpoint,
            )
            mock_conn.assert_not_called()

        self.assertEqual(first["flag"], second["flag"])


if __name__ == "__main__":
    unittest.main()
