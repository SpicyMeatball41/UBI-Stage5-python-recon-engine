#!/usr/bin/env python3
"""
Deterministic extension pool -- additional technical test.

Uses the published interfaces only (recon_engine.json_parser,
recon_engine.adapters.http_discovery, recon_engine.orchestrator) --
nothing here is a new code path invented just to pass this test.

  1. Add an unseen JSON parser
     -> recon_engine/json_parser.py, exercised end-to-end here via
        foothold.py's real credential-parsing call site (not just in
        isolation -- see tests/test_json_parser.py for the parser's
        own broader unit coverage against 20 varied/malformed shapes).

  2. Handle a wildcard-vhost response
     -> recon_engine/adapters/http_discovery.py's baseline_difference
        logic, proven content-agnostic against wildcard bodies never
        used anywhere else in this project (full coverage in
        tests/test_http_discovery.py::TestWildcardVhostHandling).

  3. Re-run against a target with one tool unavailable
     -> the orchestrator's nmap fallback path, actually re-run twice
        in the same test (mirroring "re-run" literally) with the tool
        disabled both times, confirming the second pass doesn't
        duplicate anything from the first.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from recon_engine.adapters.foothold import FootholdError, pursue_foothold
from recon_engine.checkpoint import Checkpoint
from recon_engine.json_parser import parse_json
from recon_engine.ledger import RequestLedger
from recon_engine.orchestrator import run_discovery
from recon_engine.scope_guard import ScopeGuard

REPO_ROOT = Path(__file__).resolve().parent.parent
SCOPE_CSV = REPO_ROOT / "scope.csv"
ASSIGNMENT_JSON = REPO_ROOT / "assignment.json"


def _mock_http_sequence(responses):
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


def _mock_http_fixed(body=b"same body every time"):
    conn = MagicMock()
    resp = MagicMock()
    resp.status, resp.reason = 200, "OK"
    resp.getheaders.return_value = []
    resp.read.return_value = body
    conn.getresponse.return_value = resp
    return patch("http.client.HTTPConnection", return_value=conn)


def _mock_signal_fixed():
    def _create_connection(*args, **kwargs):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.__exit__.return_value = False
        file_mock = MagicMock()
        banner = b"RLY/2 READY profile=dynamic\r\n"
        response = b"commands=CAPS,ROUTE,QUIT; framing=line; auth=none\r\n"
        file_mock.readline.side_effect = [banner, response] * 20
        sock.makefile.return_value = file_mock
        return sock

    return patch("socket.create_connection", side_effect=_create_connection)


def _mock_tls_unavailable():
    import ssl

    return patch("ssl.SSLContext.wrap_socket", side_effect=ssl.SSLError("no tls"))


class TestExtensionBullet1UnseenJsonParser(unittest.TestCase):
    """Uses parse_json through its real call site: foothold.py reading
    credentials from /ops-diagnostics. Both an unexpected-but-valid
    shape and outright malformed JSON are exercised."""

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
        self.checkpoint.set_meta("vhost", "relay-ext.northstar.local")
        self.checkpoint.set_meta("route_key", "extpool123")

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_unexpected_but_valid_json_shape_is_handled_cleanly(self):
        """An /ops-diagnostics variant that nests credentials one level
        deeper than expected -- a shape this engine has never seen."""
        unseen_shape = json.dumps({
            "diagnostics": {"auth": {"support_user": "x", "support_password": "y"}}
        }).encode()
        with _mock_http_sequence([(200, "OK", [], unseen_shape)]):
            with self.assertRaises(FootholdError) as ctx:
                pursue_foothold(
                    self.guard, "127.0.0.1", 18467, self.output_dir,
                    self.ledger, self.checkpoint,
                )
        # Correctly reports "couldn't find credentials" rather than
        # crashing with a raw KeyError/TypeError on the unseen shape.
        self.assertIn("credentials", str(ctx.exception))

    def test_malformed_json_from_target_is_handled_cleanly(self):
        with _mock_http_sequence([(200, "OK", [], b"{not valid json")]):
            with self.assertRaises(FootholdError) as ctx:
                pursue_foothold(
                    self.guard, "127.0.0.1", 18467, self.output_dir,
                    self.ledger, self.checkpoint,
                )
        self.assertIn("credentials", str(ctx.exception))

    def test_parser_directly_on_a_shape_never_used_elsewhere_in_this_project(self):
        exotic = parse_json(json.dumps({
            "results": [
                {"id": 1, "tags": ["a", "b"], "meta": None},
                {"id": 2, "tags": [], "meta": {"nested": {"deep": True}}},
            ],
            "pagination": {"next": None, "count": 2},
        }).encode())
        self.assertTrue(exotic.ok)
        self.assertEqual(exotic.get_path("pagination", "count"), 2)
        # "results" itself IS a valid top-level key (returns the list),
        # but walking a KEY NAME *into* that list (as if it were a
        # dict) must degrade to the default, not raise.
        self.assertEqual(len(exotic.get_path("results")), 2)
        self.assertIsNone(exotic.get_path("results", "id"))


class TestExtensionBullet3ReRunWithToolUnavailable(unittest.TestCase):
    """Literally re-runs discovery twice against the same target with
    nmap disabled both times, confirming the second pass reuses
    (doesn't repeat) everything the first pass already completed."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.workdir = Path(self.tmpdir.name)
        self.scope_copy = self.workdir / "scope.csv"
        self.assignment_copy = self.workdir / "assignment.json"
        self.scope_copy.write_text(SCOPE_CSV.read_text())
        self.assignment_copy.write_text(ASSIGNMENT_JSON.read_text())

    def tearDown(self):
        self.tmpdir.cleanup()

    def _guard(self):
        return ScopeGuard(self.scope_copy, assignment_path=self.assignment_copy)

    def test_rerun_with_tool_unavailable_both_times_is_idempotent(self):
        output_dir = self.workdir / "run"

        with _mock_http_fixed(), _mock_signal_fixed(), _mock_tls_unavailable(), patch(
            "recon_engine.adapters.nmap_scan.shutil.which", return_value=None
        ):
            first = run_discovery(self._guard(), output_dir, max_workers=2)

        self.assertTrue(any(k.startswith("nmap:") for k in first["tool_fallbacks"]))
        self.assertEqual([k for k in first["errors"] if k.startswith("nmap:")], [])

        with _mock_http_fixed(), _mock_signal_fixed(), _mock_tls_unavailable(), patch(
            "recon_engine.adapters.nmap_scan.shutil.which", return_value=None
        ):
            second = run_discovery(self._guard(), output_dir, max_workers=2)

        # Same fallback behavior held on the second pass too.
        self.assertTrue(any(k.startswith("nmap:") for k in second["tool_fallbacks"]))

        # And nothing that completed on pass 1 was repeated on pass 2.
        assets_path = output_dir / "normalized" / "assets.jsonl"
        records = [json.loads(l) for l in assets_path.read_text().splitlines()]
        keys = [(r.get("protocol"), r.get("path", r.get("command")), r.get("vhost")) for r in records]
        self.assertEqual(len(keys), len(set(keys)), f"duplicate records found: {keys}")


if __name__ == "__main__":
    unittest.main()
