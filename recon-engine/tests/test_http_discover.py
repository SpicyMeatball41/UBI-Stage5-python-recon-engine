#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from recon_engine.adapters.http_discovery import (
    DEFAULT_PROBES,
    DiscoveryError,
    Probe,
    discover_http,
)
from recon_engine.ledger import RequestLedger
from recon_engine.scope_guard import ScopeGuard, ScopeViolation

REPO_ROOT = Path(__file__).resolve().parent.parent
SCOPE_CSV = REPO_ROOT / "scope.csv"
ASSIGNMENT_JSON = REPO_ROOT / "assignment.json"


def _mock_connection_sequence(responses):
    """responses: list of (status, reason, headers, body) OR an
    exception instance, consumed in order across calls to
    http.client.HTTPConnection(...).getresponse()."""
    conn = MagicMock()
    resp_iter = iter(responses)

    def _getresponse():
        item = next(resp_iter)
        if isinstance(item, Exception):
            raise item
        status, reason, headers, body = item
        resp = MagicMock()
        resp.status, resp.reason = status, reason
        resp.getheaders.return_value = headers
        resp.read.return_value = body
        return resp

    conn.getresponse.side_effect = _getresponse
    return patch("http.client.HTTPConnection", return_value=conn)


class TestHttpDiscoveryAdapter(unittest.TestCase):
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

    def test_default_probes_are_fixed_and_ordered(self):
        # Scheduling determinism: this list must never depend on runtime
        # state (no randomness, no dict-ordering surprises).
        self.assertEqual(
            [p.path for p in DEFAULT_PROBES], ["/", "/robots.txt"]
        )

    def test_successful_discovery_writes_normalized_records_in_order(self):
        with _mock_connection_sequence([
            (200, "OK", [("Content-Type", "text/html")], b"root body"),
            (200, "OK", [("Content-Type", "text/plain")], b"robots body"),
        ]):
            result = discover_http(
                self.guard, "http://127.0.0.1:18467/", self.output_dir, self.ledger
            )

        self.assertEqual(result["records_written"], 2)
        records = [
            json.loads(l)
            for l in (self.output_dir / "normalized" / "assets.jsonl").read_text().splitlines()
        ]
        self.assertEqual(records[0]["path"], "/")
        self.assertEqual(records[1]["path"], "/robots.txt")
        self.assertEqual(records[0]["status"], 200)
        self.assertEqual(records[0]["service"], "http")
        self.assertEqual(records[0]["source_tool"], "recon_engine.http_discovery")

    def test_raw_capture_is_written_per_probe(self):
        with _mock_connection_sequence([
            (200, "OK", [], b"root"),
            (200, "OK", [], b"robots"),
        ]):
            discover_http(self.guard, "http://127.0.0.1:18467/", self.output_dir, self.ledger)

        raw_dir = self.output_dir / "raw" / "http"
        raw_files = sorted(p.name for p in raw_dir.glob("*.raw"))
        self.assertEqual(
            raw_files,
            ["127.0.0.1_18467_default_robots.txt.raw", "127.0.0.1_18467_default_root.raw"],
        )
        self.assertIn(
            b"HTTP/1.1 200 OK",
            (raw_dir / "127.0.0.1_18467_default_root.raw").read_bytes(),
        )

    def test_ledger_gets_one_line_per_successful_attempt_with_all_fields(self):
        with _mock_connection_sequence([
            (200, "OK", [], b"root"),
            (200, "OK", [], b"robots"),
        ]):
            discover_http(self.guard, "http://127.0.0.1:18467/", self.output_dir, self.ledger)

        lines = [json.loads(l) for l in self.ledger.path.read_text().splitlines()]
        self.assertEqual(len(lines), 2)
        for line in lines:
            self.assertIn("purpose", line)
            self.assertIn("target", line)
            self.assertIn("result", line)
            self.assertIn("scope_verdict", line)
            self.assertEqual(line["scope_verdict"], "approved")
            self.assertEqual(line["result"], "HTTP 200")

    def test_scope_denial_is_logged_and_never_retried(self):
        """Point discovery at the OUT port directly (bypassing entry_url)
        to prove a scope denial is fatal on the first attempt -- no
        retry loop, and the network mock is never invoked."""
        with patch("http.client.HTTPConnection") as mock_conn:
            with self.assertRaises(ScopeViolation):
                discover_http(
                    self.guard, "http://127.0.0.1:26035/", self.output_dir, self.ledger
                )
            mock_conn.assert_not_called()

        lines = [json.loads(l) for l in self.ledger.path.read_text().splitlines()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["attempt"], 1)
        self.assertTrue(lines[0]["scope_verdict"].startswith("denied"))
        self.assertEqual(lines[0]["result"], "not sent")

    def test_transient_failure_retries_then_succeeds(self):
        with _mock_connection_sequence([
            ConnectionRefusedError("refused"),
            (200, "OK", [], b"root ok on retry"),
            (200, "OK", [], b"robots"),
        ]):
            result = discover_http(
                self.guard,
                "http://127.0.0.1:18467/",
                self.output_dir,
                self.ledger,
                retry_backoff=0.01,
            )
        self.assertEqual(result["records_written"], 2)

        lines = [json.loads(l) for l in self.ledger.path.read_text().splitlines()]
        # attempt 1 (fail), attempt 2 (success) for probe 1; attempt 1 (success) for probe 2
        self.assertEqual(len(lines), 3)
        self.assertIn("error", lines[0]["result"])
        self.assertEqual(lines[1]["result"], "HTTP 200")
        self.assertEqual(lines[1]["attempt"], 2)

    def test_retries_exhausted_raises_discovery_error(self):
        with _mock_connection_sequence([
            ConnectionRefusedError("refused"),
            ConnectionRefusedError("refused"),
            ConnectionRefusedError("refused"),
        ]):
            with self.assertRaises(DiscoveryError):
                discover_http(
                    self.guard,
                    "http://127.0.0.1:18467/",
                    self.output_dir,
                    self.ledger,
                    max_retries=2,
                    retry_backoff=0.01,
                )

        lines = [json.loads(l) for l in self.ledger.path.read_text().splitlines()]
        self.assertEqual(len(lines), 3)  # 1 initial + 2 retries, all logged

    def test_each_retry_attempt_consumes_budget(self):
        """Retries are real packets -- they must count against the
        request budget, not be free re-attempts."""
        with _mock_connection_sequence([
            ConnectionRefusedError("refused"),
            (200, "OK", [], b"ok"),
            (200, "OK", [], b"robots"),
        ]):
            discover_http(
                self.guard,
                "http://127.0.0.1:18467/",
                self.output_dir,
                self.ledger,
                retry_backoff=0.01,
            )
        # 2 attempts for probe 1 (1 fail + 1 success) + 1 for probe 2 = 3
        self.assertEqual(self.guard.remaining_budget, self.guard.budget - 3)

    def test_custom_probe_list_is_respected_in_order(self):
        probes = [Probe(path="/a", purpose="a"), Probe(path="/b", purpose="b")]
        with _mock_connection_sequence([
            (200, "OK", [], b"a"),
            (200, "OK", [], b"b"),
        ]):
            discover_http(
                self.guard, "http://127.0.0.1:18467/", self.output_dir, self.ledger,
                probes=probes,
            )
        records = [
            json.loads(l)
            for l in (self.output_dir / "normalized" / "assets.jsonl").read_text().splitlines()
        ]
        self.assertEqual([r["path"] for r in records], ["/a", "/b"])


class TestWildcardVhostHandling(unittest.TestCase):
    """Extension test, bullet 2: 'Handle a wildcard-vhost response.'

    baseline_difference must be a purely structural comparison
    (status/length/hash) -- it must correctly identify "same as
    wildcard" or "different from wildcard" no matter WHAT the
    wildcard's actual content is, including content never seen in any
    other test in this project. If this were accidentally hardcoded to
    a specific known wildcard string, these would fail."""

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

    def test_vhost_response_identical_to_wildcard_is_flagged_no_difference(self):
        """An entirely unseen wildcard body -- if the vhost-targeted
        probe gets back the EXACT same thing, baseline_difference must
        be False, regardless of what that content actually is."""
        unseen_wildcard_body = b"<html><body>Service unavailable at this edge node. Contact your administrator for routing details.</body></html>"
        probes = [
            Probe(path="/status", purpose="wildcard baseline"),  # host_header=None
            Probe(path="/status", purpose="vhost probe", host_header="some-unseen-vhost.example"),
        ]
        with _mock_connection_sequence([
            (200, "OK", [], unseen_wildcard_body),
            (200, "OK", [], unseen_wildcard_body),
        ]):
            discover_http(
                self.guard, "http://127.0.0.1:18467/", self.output_dir, self.ledger,
                probes=probes,
            )
        records = [
            json.loads(l)
            for l in (self.output_dir / "normalized" / "assets.jsonl").read_text().splitlines()
        ]
        vhost_record = records[1]
        self.assertEqual(vhost_record["baseline_difference"], False)

    def test_vhost_response_different_from_wildcard_is_flagged_different(self):
        """Same unseen wildcard body, but the vhost probe gets back
        something genuinely different -- baseline_difference must be
        True. This is the actual discovery signal: a real, provisioned
        service behind the right Host header looks different from the
        generic 'nothing here' response every other Host header gets."""
        unseen_wildcard_body = b"<html><body>Service unavailable at this edge node. Contact your administrator for routing details.</body></html>"
        real_service_body = b'{"status": "ok", "endpoints": ["/api/v2/status", "/api/v2/config"]}'
        probes = [
            Probe(path="/status", purpose="wildcard baseline"),
            Probe(path="/status", purpose="vhost probe", host_header="some-unseen-vhost.example"),
        ]
        with _mock_connection_sequence([
            (200, "OK", [], unseen_wildcard_body),
            (200, "OK", [], real_service_body),
        ]):
            discover_http(
                self.guard, "http://127.0.0.1:18467/", self.output_dir, self.ledger,
                probes=probes,
            )
        records = [
            json.loads(l)
            for l in (self.output_dir / "normalized" / "assets.jsonl").read_text().splitlines()
        ]
        vhost_record = records[1]
        self.assertEqual(vhost_record["baseline_difference"], True)

    def test_same_length_different_content_is_still_caught_via_hash(self):
        """Two different bodies can coincidentally have the same
        length -- length alone isn't enough to detect a difference.
        baseline_difference also compares body_sha256, so equal-length
        but different-content bodies are still correctly flagged."""
        wildcard_body = b"AAAAAAAAAA"  # 10 bytes
        different_body = b"BBBBBBBBBB"  # also 10 bytes, different content
        self.assertEqual(len(wildcard_body), len(different_body))

        probes = [
            Probe(path="/x", purpose="wildcard baseline"),
            Probe(path="/x", purpose="vhost probe", host_header="unseen-vhost-2.example"),
        ]
        with _mock_connection_sequence([
            (200, "OK", [], wildcard_body),
            (200, "OK", [], different_body),
        ]):
            discover_http(
                self.guard, "http://127.0.0.1:18467/", self.output_dir, self.ledger,
                probes=probes,
            )
        records = [
            json.loads(l)
            for l in (self.output_dir / "normalized" / "assets.jsonl").read_text().splitlines()
        ]
        self.assertEqual(records[1]["baseline_difference"], True)

    def test_no_baseline_available_yields_none_not_a_crash(self):
        """If a vhost probe runs for a path that was never probed as a
        wildcard baseline first, baseline_difference must be None
        (unknown), not raise or silently default to False/True."""
        probes = [
            Probe(path="/never-baselined", purpose="vhost only",
                  host_header="unseen-vhost-3.example"),
        ]
        with _mock_connection_sequence([(200, "OK", [], b"anything")]):
            discover_http(
                self.guard, "http://127.0.0.1:18467/", self.output_dir, self.ledger,
                probes=probes,
            )
        records = [
            json.loads(l)
            for l in (self.output_dir / "normalized" / "assets.jsonl").read_text().splitlines()
        ]
        self.assertIsNone(records[0]["baseline_difference"])

    def test_wildcard_baseline_probe_itself_has_no_vhost_or_diff_fields(self):
        """The wildcard/default probe (host_header=None) is the
        baseline itself -- it shouldn't carry vhost/title/redirect/
        baseline_difference fields at all, since those only make sense
        for a probe being COMPARED against a baseline."""
        with _mock_connection_sequence([(200, "OK", [], b"wildcard content")]):
            discover_http(
                self.guard, "http://127.0.0.1:18467/", self.output_dir, self.ledger,
                probes=[Probe(path="/", purpose="baseline discovery")],
            )
        records = [
            json.loads(l)
            for l in (self.output_dir / "normalized" / "assets.jsonl").read_text().splitlines()
        ]
        self.assertNotIn("vhost", records[0])
        self.assertNotIn("baseline_difference", records[0])


if __name__ == "__main__":
    unittest.main()
