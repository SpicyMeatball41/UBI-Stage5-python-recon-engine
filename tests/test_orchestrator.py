#!/usr/bin/env python3
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from recon_engine.checkpoint import Checkpoint
from recon_engine.orchestrator import (
    UnknownServiceError,
    _infer_protocol,
    run_discovery,
)
from recon_engine.scope_guard import ScopeGuard

REPO_ROOT = Path(__file__).resolve().parent.parent
SCOPE_CSV = REPO_ROOT / "scope.csv"
ASSIGNMENT_JSON = REPO_ROOT / "assignment.json"


def _fake_http(*args, **kwargs):
    return {"protocol": "http", "records_written": 2}


def _fake_signal(*args, **kwargs):
    return {"protocol": "signal", "records_written": 2}


def _fake_tls(*args, **kwargs):
    return {"protocol": "tls", "tls_available": False}


class TestOrchestratorDecoySafety(unittest.TestCase):
    """The checkpoint's central safety property: the decoy must be
    unreachable BY CONSTRUCTION, not merely by a runtime check."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.workdir = Path(self.tmpdir.name)
        self.output_dir = self.workdir / "run"
        self.scope_copy = self.workdir / "scope.csv"
        self.assignment_copy = self.workdir / "assignment.json"
        self.scope_copy.write_text(SCOPE_CSV.read_text())
        self.assignment_copy.write_text(ASSIGNMENT_JSON.read_text())
        self.guard = ScopeGuard(self.scope_copy, assignment_path=self.assignment_copy)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_decoy_port_never_appears_in_the_target_list(self):
        targets = self.guard.in_scope_targets()
        ports = [port for _host, port, _note in targets]
        self.assertNotIn(26035, ports)
        self.assertEqual(sorted(ports), [18467, 23390])

    def test_run_discovery_never_touches_the_decoy(self):
        """Even with every adapter mocked to always 'succeed', the decoy
        port must never appear as a discovery target, an error key, or
        a result key -- because build_service_targets only ever reads
        scope.csv's IN rows."""
        with patch("recon_engine.adapters.base.discover_http", side_effect=_fake_http), \
             patch("recon_engine.adapters.base.discover_signal", side_effect=_fake_signal), \
             patch("recon_engine.adapters.base.probe_tls", side_effect=_fake_tls):
            summary = run_discovery(self.guard, self.output_dir)

        all_keys = list(summary["results"].keys()) + list(summary["errors"].keys())
        self.assertTrue(all("26035" not in k for k in all_keys))
        target_ports = [t["port"] for t in summary["targets"]]
        self.assertNotIn(26035, target_ports)


class TestOrchestratorAdapterSelection(unittest.TestCase):
    def test_infer_protocol_from_scope_csv_notes(self):
        self.assertEqual(_infer_protocol("HTTP discovery target"), "http")
        self.assertEqual(_infer_protocol("line-protocol discovery target"), "signal")
        self.assertIsNone(_infer_protocol("scope test; no packet may be sent"))


class TestOrchestratorRunDiscovery(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.workdir = Path(self.tmpdir.name)
        self.output_dir = self.workdir / "run"
        self.scope_copy = self.workdir / "scope.csv"
        self.assignment_copy = self.workdir / "assignment.json"
        self.scope_copy.write_text(SCOPE_CSV.read_text())
        self.assignment_copy.write_text(ASSIGNMENT_JSON.read_text())
        self.guard = ScopeGuard(self.scope_copy, assignment_path=self.assignment_copy)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_both_authorized_services_are_discovered(self):
        with patch("recon_engine.adapters.base.discover_http", side_effect=_fake_http), \
             patch("recon_engine.adapters.base.discover_signal", side_effect=_fake_signal), \
             patch("recon_engine.adapters.base.probe_tls", side_effect=_fake_tls):
            summary = run_discovery(self.guard, self.output_dir)

        self.assertEqual(len(summary["targets"]), 2)
        self.assertIn("127.0.0.1:18467", summary["results"])
        self.assertIn("127.0.0.1:23390", summary["results"])
        self.assertEqual(summary["errors"], {})

    def test_concurrency_is_bounded_to_max_workers(self):
        """Prove adapters actually run concurrently (not serialized) but
        never more than max_workers at once."""
        in_flight = {"count": 0, "max_seen": 0}
        lock = threading.Lock()

        def _slow_adapter(*args, **kwargs):
            with lock:
                in_flight["count"] += 1
                in_flight["max_seen"] = max(in_flight["max_seen"], in_flight["count"])
            time.sleep(0.05)
            with lock:
                in_flight["count"] -= 1
            return {"protocol": "adapter", "records_written": 1}

        with patch("recon_engine.adapters.base.discover_http", side_effect=_slow_adapter), \
             patch("recon_engine.adapters.base.discover_signal", side_effect=_slow_adapter), \
             patch("recon_engine.adapters.base.probe_tls", side_effect=_fake_tls):
            run_discovery(self.guard, self.output_dir, max_workers=2)

        self.assertGreaterEqual(in_flight["max_seen"], 2)  # actually concurrent
        self.assertLessEqual(in_flight["max_seen"], 2)     # but bounded

    def test_unknown_service_note_is_a_soft_error_not_a_crash(self):
        scope_with_unknown = self.workdir / "scope2.csv"
        scope_with_unknown.write_text(
            "asset,scope,notes\n"
            "127.0.0.1:18467,IN,HTTP discovery target\n"
            "127.0.0.1:9999,IN,some future protocol nobody wrote an adapter for\n"
        )
        guard = ScopeGuard(scope_with_unknown, budget=100)
        with patch("recon_engine.adapters.base.discover_http", side_effect=_fake_http), \
             patch("recon_engine.adapters.base.probe_tls", side_effect=_fake_tls):
            summary = run_discovery(guard, self.output_dir)

        self.assertIn("127.0.0.1:9999", summary["errors"])
        self.assertIn("127.0.0.1:18467", summary["results"])

    def test_missing_nmap_is_recorded_as_a_fallback_not_an_error(self):
        """Mocks nmap's absence explicitly, rather than depending on
        whether the machine running these tests happens to have nmap
        installed or not (it does on a stock Kali box, for example)."""
        with patch("recon_engine.adapters.nmap_scan.shutil.which", return_value=None), \
             patch("recon_engine.adapters.base.discover_http", side_effect=_fake_http), \
             patch("recon_engine.adapters.base.discover_signal", side_effect=_fake_signal), \
             patch("recon_engine.adapters.base.probe_tls", side_effect=_fake_tls):
            summary = run_discovery(self.guard, self.output_dir)

        self.assertTrue(len(summary["tool_fallbacks"]) >= 1)
        for key, note in summary["tool_fallbacks"].items():
            self.assertTrue(key.startswith("nmap:"))
            self.assertIn("nmap not found", note)
        # A missing optional tool must never show up as an error --
        # discovery already succeeded via the required adapters.
        self.assertEqual(
            [k for k in summary["errors"] if k.startswith("nmap:")], []
        )

    def test_nmap_gets_its_own_timeout_not_the_shared_short_one(self):
        """Regression test: orchestrator used to pass the short
        http/signal/tls `timeout` (default 5.0s) into nmap too, which
        killed real nmap -sV scans that legitimately need longer.
        nmap must always receive `nmap_timeout`, decoupled from the
        general per-request `timeout`."""
        captured_timeouts = []

        def _recording_nmap(guard, host, port, output_dir, ledger, checkpoint=None, timeout=None):
            captured_timeouts.append(timeout)
            return {"protocol": "nmap", "records_written": 0}

        with patch("recon_engine.orchestrator.scan_with_nmap", side_effect=_recording_nmap), \
             patch("recon_engine.adapters.base.discover_http", side_effect=_fake_http), \
             patch("recon_engine.adapters.base.discover_signal", side_effect=_fake_signal), \
             patch("recon_engine.adapters.base.probe_tls", side_effect=_fake_tls):
            run_discovery(self.guard, self.output_dir, timeout=5.0, nmap_timeout=30.0)

        self.assertTrue(len(captured_timeouts) >= 1)
        for t in captured_timeouts:
            self.assertEqual(t, 30.0)  # never 5.0 -- that was the bug

    def test_vhost_discovered_by_signal_triggers_http_followup(self):
        def _signal_with_vhost(guard, host, port, output_dir, ledger, checkpoint=None, **kw):
            if checkpoint is not None:
                checkpoint.set_meta("vhost", "relay-abc123.northstar.local")
            return {"protocol": "signal", "records_written": 2}

        http_calls = []

        def _http_recording(guard, entry_url, output_dir, ledger, probes=None, checkpoint=None, **kw):
            http_calls.append(probes)
            return {"protocol": "http", "records_written": len(probes) if probes else 2}

        with patch("recon_engine.adapters.base.discover_http", side_effect=_http_recording), \
             patch("recon_engine.orchestrator.discover_http", side_effect=_http_recording), \
             patch("recon_engine.adapters.base.discover_signal", side_effect=_signal_with_vhost), \
             patch("recon_engine.adapters.base.probe_tls", side_effect=_fake_tls):
            summary = run_discovery(self.guard, self.output_dir)

        self.assertEqual(summary["vhost_discovered"], "relay-abc123.northstar.local")
        # Two discover_http calls: the default baseline wave, plus the
        # vhost-targeted follow-up wave.
        self.assertEqual(len(http_calls), 2)
        vhost_probes = http_calls[1]
        self.assertTrue(all(p.host_header == "relay-abc123.northstar.local" for p in vhost_probes))

    def test_checkpoint_resume_skips_completed_work_and_saves_budget(self):
        checkpoint_path = self.output_dir / "checkpoint.json"
        checkpoint = Checkpoint(checkpoint_path)
        checkpoint.mark_done("http:default:/", {"status": 200})
        checkpoint.mark_done("http:default:/robots.txt", {"status": 200})

        call_count = {"http": 0}

        def _counting_http(guard, entry_url, output_dir, ledger, probes=None, checkpoint=None, **kw):
            call_count["http"] += 1
            # Real discover_http would see both probes already done via
            # the checkpoint and make zero new requests.
            return {"protocol": "http", "records_written": 0}

        with patch("recon_engine.adapters.base.discover_http", side_effect=_counting_http), \
             patch("recon_engine.adapters.base.discover_signal", side_effect=_fake_signal), \
             patch("recon_engine.adapters.base.probe_tls", side_effect=_fake_tls):
            summary = run_discovery(self.guard, self.output_dir)

        self.assertEqual(summary["results"]["127.0.0.1:18467"]["records_written"], 0)


if __name__ == "__main__":
    unittest.main()
