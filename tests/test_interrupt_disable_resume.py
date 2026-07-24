#!/usr/bin/env python3
"""
Phase 5, requirement 1: "Interrupt a run, resume it, disable one
adapter, and confirm completed requests are not repeated or
duplicated."

This goes one step further than test_resume_integrity.py (which only
proved hash equality between a clean run and an interrupted/resumed
one): here we ALSO disable an optional adapter (nmap) specifically
during the resume, mirroring brief.md's staff test ("interrupt one run
and remove one external tool"), and assert directly on duplicate
counts -- not just hash equality, which could theoretically mask a
duplicate-then-cancel-out coincidence.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from recon_engine.orchestrator import run_discovery
from recon_engine.scope_guard import ScopeGuard

REPO_ROOT = Path(__file__).resolve().parent.parent
SCOPE_CSV = REPO_ROOT / "scope.csv"
ASSIGNMENT_JSON = REPO_ROOT / "assignment.json"


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
        banner = b"RLY/2 READY profile=dynamic\r\n"
        response = b"commands=CAPS,ROUTE,QUIT; framing=line; auth=none\r\n"
        file_mock.readline.side_effect = [banner, response] * 20
        sock.makefile.return_value = file_mock
        return sock

    return patch("socket.create_connection", side_effect=_create_connection)


def _mock_tls_unavailable():
    import ssl

    return patch("ssl.SSLContext.wrap_socket", side_effect=ssl.SSLError("no tls"))


def _count_records(output_dir: Path) -> dict:
    """Count normalized records per (protocol, path/command) dedup-like
    key, to directly detect duplicates rather than inferring them from
    a hash."""
    assets_path = output_dir / "normalized" / "assets.jsonl"
    counts: dict = {}
    if not assets_path.exists():
        return counts
    with open(assets_path) as f:
        for line in f:
            if not line.strip():
                continue
            record = json.loads(line)
            key = (
                record.get("protocol"),
                record.get("path", record.get("command")),
                record.get("vhost"),
            )
            counts[key] = counts.get(key, 0) + 1
    return counts


class TestInterruptDisableResumeNoDuplication(unittest.TestCase):
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

    def test_interrupted_run_resumed_with_nmap_disabled_has_no_duplicates(self):
        output_dir = self.workdir / "run"

        # Pass 1 ("first process"): http succeeds; signal is made to
        # crash mid-flight, simulating the process dying before nmap
        # or the vhost follow-up ever ran.
        with _mock_http_fixed(), _mock_tls_unavailable(), patch(
            "recon_engine.adapters.base.discover_signal",
            side_effect=RuntimeError("simulated crash"),
        ):
            try:
                run_discovery(self._guard(), output_dir, max_workers=2)
            except RuntimeError:
                pass  # this IS the interruption

        counts_after_interrupt = _count_records(output_dir)
        self.assertGreaterEqual(sum(counts_after_interrupt.values()), 1)

        # Pass 2 ("resumed process"): everything works EXCEPT nmap,
        # which is explicitly disabled here -- the documented fallback
        # case, exercised together with resume rather than separately.
        with _mock_http_fixed(), _mock_signal_fixed(), _mock_tls_unavailable(), patch(
            "recon_engine.adapters.nmap_scan.shutil.which", return_value=None
        ):
            summary = run_discovery(self._guard(), output_dir, max_workers=2)

        # nmap's absence must be a fallback note, not an error, even
        # while resuming an interrupted run.
        self.assertTrue(any(k.startswith("nmap:") for k in summary["tool_fallbacks"]))
        self.assertEqual([k for k in summary["errors"] if k.startswith("nmap:")], [])

        # The actual point of this test: nothing that completed during
        # pass 1 was repeated during pass 2. Every dedup key appears
        # in the normalized output exactly once, never twice.
        final_counts = _count_records(output_dir)
        duplicated = {k: v for k, v in final_counts.items() if v > 1}
        self.assertEqual(duplicated, {}, f"duplicate records found: {duplicated}")

        # And the engine's own ledger has exactly one line per attempt
        # -- no attempt was logged twice either.
        ledger_lines = (output_dir / "request-ledger.jsonl").read_text().splitlines()
        seen_sequences = [json.loads(l)["sequence"] for l in ledger_lines]
        self.assertEqual(len(seen_sequences), len(set(seen_sequences)))


if __name__ == "__main__":
    unittest.main()
