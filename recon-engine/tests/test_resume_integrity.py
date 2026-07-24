#!/usr/bin/env python3
"""
The test that actually matters for the brief's resume requirement:
"the resumed/fallback run must produce the same normalized result hash
as an uninterrupted run." Everything else in test_checkpoint.py and
test_orchestrator.py tests the RESUME MECHANISM in isolation
(is_done/mark_done). This file tests the thing that mechanism is
supposed to guarantee: that stopping partway through and picking back
up produces IDENTICAL discovery output to never having stopped at all.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from recon_engine.adapters.http_discovery import DEFAULT_PROBES, discover_http
from recon_engine.checkpoint import Checkpoint
from recon_engine.ledger import RequestLedger
from recon_engine.orchestrator import run_discovery
from recon_engine.resulthash import compute_normalized_hash
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
    resp.getheaders.return_value = [("Content-Type", "text/html")]
    resp.read.return_value = body
    conn.getresponse.return_value = resp
    return patch("http.client.HTTPConnection", return_value=conn)


def _mock_signal_fixed():
    def _create_connection(*args, **kwargs):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.__exit__.return_value = False
        file_mock = MagicMock()
        # Always the CAPS-shaped response; ROUTE parsing this won't
        # find a "route=" key, so no vhost is discovered here, which
        # keeps this test focused purely on resume/interrupt behavior
        # rather than also exercising the vhost follow-up wave.
        banner = b"RLY/2 READY profile=dynamic\r\n"
        response = b"commands=CAPS,ROUTE,QUIT; framing=line; auth=none\r\n"
        file_mock.readline.side_effect = [banner, response] * 20
        sock.makefile.return_value = file_mock
        return sock

    return patch("socket.create_connection", side_effect=_create_connection)


def _mock_tls_unavailable():
    """The orchestrator's TLS probe also calls socket.create_connection,
    which _mock_signal_fixed's patch would otherwise intercept and feed
    a non-SSL-wrappable mock socket. Patching wrap_socket directly gives
    the TLS probe a clean, deterministic 'no TLS' outcome regardless of
    what socket.create_connection returns."""
    import ssl

    return patch("ssl.SSLContext.wrap_socket", side_effect=ssl.SSLError("no tls"))


class TestHttpDiscoveryResumeIntegrity(unittest.TestCase):
    """Adapter-level: interrupt after probe 1, resume with a fresh
    Checkpoint instance pointed at the same on-disk file (simulating a
    new process picking up where an old one stopped), and confirm the
    final normalized output hashes identically to a clean run."""

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

    def test_interrupted_and_resumed_run_matches_clean_run(self):
        responses = [
            (200, "OK", [("Content-Type", "text/html")], b"root body"),
            (200, "OK", [("Content-Type", "text/plain")], b"robots body"),
        ]

        clean_dir = self.workdir / "clean"
        ledger_clean = RequestLedger(clean_dir / "request-ledger.jsonl")
        with _mock_http_sequence(list(responses)):
            discover_http(self._guard(), "http://127.0.0.1:18467/", clean_dir, ledger_clean)
        clean_hash = compute_normalized_hash(clean_dir)

        resumed_dir = self.workdir / "resumed"
        ledger_resumed = RequestLedger(resumed_dir / "request-ledger.jsonl")

        # "First process": completes only probe 1, then stops (as if
        # killed here -- no explicit interruption code needed, we just
        # never call it again with the remaining probes in this pass).
        with _mock_http_sequence([responses[0]]):
            discover_http(
                self._guard(), "http://127.0.0.1:18467/", resumed_dir, ledger_resumed,
                probes=[DEFAULT_PROBES[0]],
                checkpoint=Checkpoint(resumed_dir / "checkpoint.json"),
            )

        # "Resumed process": a brand new Checkpoint object reading the
        # SAME on-disk file, given the FULL probe list again. Probe 1
        # must be skipped (reused from checkpoint), only probe 2 should
        # cause a new request.
        with _mock_http_sequence([responses[1]]):
            discover_http(
                self._guard(), "http://127.0.0.1:18467/", resumed_dir, ledger_resumed,
                probes=list(DEFAULT_PROBES),
                checkpoint=Checkpoint(resumed_dir / "checkpoint.json"),
            )

        resumed_hash = compute_normalized_hash(resumed_dir)
        self.assertEqual(clean_hash, resumed_hash)

        # Exactly 2 ledger lines total across both passes -- probe 1
        # was never re-requested during "resume".
        ledger_lines = ledger_resumed.path.read_text().splitlines()
        self.assertEqual(len(ledger_lines), 2)


class TestOrchestratorResumeIntegrity(unittest.TestCase):
    """Orchestrator-level: interrupt mid-run (one adapter succeeds, the
    other raises as if the process died), then resume by calling
    run_discovery again against the SAME --output directory. Final
    normalized output must hash identically to an uninterrupted run."""

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

    def test_interrupted_then_resumed_orchestrator_run_matches_clean_run(self):
        clean_dir = self.workdir / "clean"
        with _mock_http_fixed(), _mock_signal_fixed(), _mock_tls_unavailable():
            run_discovery(self._guard(), clean_dir, max_workers=2)
        clean_hash = compute_normalized_hash(clean_dir)

        resumed_dir = self.workdir / "resumed"

        # Simulate a crash: HTTP succeeds, signal blows up mid-flight
        # (as if the process died before it could finish). The
        # ThreadPoolExecutor still waits for the HTTP future to finish
        # before the exception propagates, so HTTP's checkpoint state
        # and normalized records survive -- exactly what a real crash
        # after partial progress would leave behind.
        with _mock_http_fixed(), _mock_tls_unavailable(), patch(
            "recon_engine.adapters.base.discover_signal",
            side_effect=RuntimeError("simulated crash mid-discovery"),
        ):
            try:
                run_discovery(self._guard(), resumed_dir, max_workers=2)
            except RuntimeError:
                pass  # expected -- this IS the simulated interruption

        # "Resume": call again against the same --output directory,
        # this time with everything working. HTTP's already-completed
        # probes must be skipped via the checkpoint; only signal (and
        # anything HTTP left unfinished) should run again.
        with _mock_http_fixed(), _mock_signal_fixed(), _mock_tls_unavailable():
            run_discovery(self._guard(), resumed_dir, max_workers=2)

        resumed_hash = compute_normalized_hash(resumed_dir)
        self.assertEqual(clean_hash, resumed_hash)


if __name__ == "__main__":
    unittest.main()
