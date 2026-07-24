#!/usr/bin/env python3
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from recon_engine.adapters.base import ToolUnavailableError
from recon_engine.adapters.nmap_scan import scan_with_nmap
from recon_engine.checkpoint import Checkpoint
from recon_engine.ledger import RequestLedger
from recon_engine.scope_guard import ScopeGuard, ScopeViolation

REPO_ROOT = Path(__file__).resolve().parent.parent
SCOPE_CSV = REPO_ROOT / "scope.csv"
ASSIGNMENT_JSON = REPO_ROOT / "assignment.json"

_SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
<port protocol="tcp" portid="18467">
<state state="open"/>
<service name="http" product="TransitGateway" version="2.4"/>
</port>
</ports>
</host>
</nmaprun>"""


class TestNmapAdapter(unittest.TestCase):
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

    def test_missing_nmap_raises_tool_unavailable_and_never_calls_guard(self):
        """The documented fallback case: nmap isn't on PATH."""
        budget_before = self.guard.remaining_budget
        with patch("shutil.which", return_value=None):
            with self.assertRaises(ToolUnavailableError):
                scan_with_nmap(
                    self.guard, "127.0.0.1", 18467, self.output_dir, self.ledger
                )
        # No budget spent -- the guard was never even reached, because
        # there was nothing to run in the first place.
        self.assertEqual(self.guard.remaining_budget, budget_before)

    def test_scope_denial_when_pointed_at_out_port(self):
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            with patch("subprocess.run") as mock_run:
                with self.assertRaises(ScopeViolation):
                    scan_with_nmap(
                        self.guard, "127.0.0.1", 26035, self.output_dir, self.ledger
                    )
                mock_run.assert_not_called()

    def test_successful_scan_parses_xml_into_normalized_record(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = _SAMPLE_NMAP_XML.encode()

        with patch("shutil.which", return_value="/usr/bin/nmap"), patch(
            "subprocess.run", return_value=mock_proc
        ) as mock_run:
            result = scan_with_nmap(
                self.guard, "127.0.0.1", 18467, self.output_dir, self.ledger
            )

        self.assertEqual(result["records_written"], 1)
        # Constrained invocation: exactly one host, one port, no host
        # discovery ping sweep, XML to stdout only.
        args = mock_run.call_args[0][0]
        self.assertIn("-Pn", args)
        self.assertIn("-p", args)
        self.assertIn("18467", args)
        self.assertEqual(args[-1], "127.0.0.1")

        records = [
            json.loads(l)
            for l in (self.output_dir / "normalized" / "assets.jsonl").read_text().splitlines()
        ]
        self.assertEqual(records[0]["service"], "http")
        self.assertEqual(records[0]["product"], "TransitGateway")
        self.assertEqual(records[0]["version"], "2.4")
        self.assertIn("fingerprint", records[0])

    def test_malformed_xml_does_not_crash(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"not valid xml at all"

        with patch("shutil.which", return_value="/usr/bin/nmap"), patch(
            "subprocess.run", return_value=mock_proc
        ):
            result = scan_with_nmap(
                self.guard, "127.0.0.1", 18467, self.output_dir, self.ledger
            )
        self.assertEqual(result["records_written"], 1)  # still writes a low-confidence record

    def test_nmap_timeout_propagates_as_a_real_error(self):
        with patch("shutil.which", return_value="/usr/bin/nmap"), patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=30),
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                scan_with_nmap(self.guard, "127.0.0.1", 18467, self.output_dir, self.ledger)

    def test_checkpoint_dedup_skips_repeat_scans(self):
        checkpoint = Checkpoint(self.output_dir / "checkpoint.json")
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = _SAMPLE_NMAP_XML.encode()

        with patch("shutil.which", return_value="/usr/bin/nmap"), patch(
            "subprocess.run", return_value=mock_proc
        ) as mock_run:
            scan_with_nmap(
                self.guard, "127.0.0.1", 18467, self.output_dir, self.ledger,
                checkpoint=checkpoint,
            )
            scan_with_nmap(
                self.guard, "127.0.0.1", 18467, self.output_dir, self.ledger,
                checkpoint=checkpoint,
            )
        self.assertEqual(mock_run.call_count, 1)  # second call was skipped

    @unittest.skipUnless(shutil.which("nmap"), "requires a real nmap binary on PATH")
    def test_real_nmap_against_a_local_listener(self):
        """No mocks at all: spins up a real HTTP server on loopback and
        runs the actual nmap binary against it, end to end. Only runs
        on machines that genuinely have nmap installed (e.g. a stock
        Kali box) -- skipped elsewhere rather than faked."""
        import http.server
        import threading

        server = http.server.HTTPServer(
            ("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler
        )
        real_port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            scope_path = self.workdir / "real_scope.csv"
            scope_path.write_text(
                "asset,scope,notes\n"
                f"127.0.0.1:{real_port},IN,real nmap target\n"
            )
            guard = ScopeGuard(scope_path, budget=100)
            result = scan_with_nmap(
                guard, "127.0.0.1", real_port, self.output_dir, self.ledger, timeout=30.0
            )
            self.assertEqual(result["records_written"], 1)
            records = [
                json.loads(l)
                for l in (self.output_dir / "normalized" / "assets.jsonl").read_text().splitlines()
            ]
            self.assertEqual(records[0]["protocol"], "nmap")
            # Real nmap output should at least confirm the port is open,
            # even if service-version fingerprinting is inconclusive.
            raw_files = list((self.output_dir / "raw" / "nmap").glob("*.xml"))
            self.assertEqual(len(raw_files), 1)
            self.assertIn("nmaprun", raw_files[0].read_text())
        finally:
            server.shutdown()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
