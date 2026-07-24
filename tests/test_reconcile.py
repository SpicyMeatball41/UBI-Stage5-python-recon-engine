#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from recon_engine.reconcile import reconcile


def _write_jsonl(path: Path, records):
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


class TestReconcile(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.workdir = Path(self.tmpdir.name)
        self.engine_path = self.workdir / "request-ledger.jsonl"
        self.target_path = self.workdir / "target-request-ledger.jsonl"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_matching_counts_reconcile_true(self):
        _write_jsonl(self.engine_path, [
            {"scope_verdict": "approved", "result": "HTTP 200"},
            {"scope_verdict": "approved", "result": "HTTP 200"},
        ])
        _write_jsonl(self.target_path, [
            {"sequence": 1, "result": 200},
            {"sequence": 2, "result": 200},
        ])
        report = reconcile(self.engine_path, self.target_path)
        self.assertTrue(report.reconciled)
        self.assertEqual(report.engine_approved_with_result, 2)
        self.assertEqual(report.target_entries, 2)

    def test_denied_attempts_never_expected_in_target_ledger(self):
        _write_jsonl(self.engine_path, [
            {"scope_verdict": "approved", "result": "HTTP 200"},
            {"scope_verdict": "denied: out of scope", "result": "not sent"},
        ])
        _write_jsonl(self.target_path, [
            {"sequence": 1, "result": 200},
        ])
        report = reconcile(self.engine_path, self.target_path)
        self.assertTrue(report.reconciled)
        self.assertEqual(report.engine_denied, 1)
        self.assertEqual(report.target_entries, 1)

    def test_target_logging_more_than_engine_approved_fails_reconciliation(self):
        """If the target's independent log shows MORE requests than the
        engine ever approved, something reached it that the engine
        didn't account for -- reconciliation must fail."""
        _write_jsonl(self.engine_path, [
            {"scope_verdict": "approved", "result": "HTTP 200"},
        ])
        _write_jsonl(self.target_path, [
            {"sequence": 1, "result": 200},
            {"sequence": 2, "result": 200},
        ])
        report = reconcile(self.engine_path, self.target_path)
        self.assertFalse(report.reconciled)

    def test_target_logging_fewer_than_engine_approved_still_reconciles(self):
        """A network failure after approval but before the target could
        respond is a legitimate reason for the target to log fewer
        entries -- this is not a scope problem."""
        _write_jsonl(self.engine_path, [
            {"scope_verdict": "approved", "result": "HTTP 200"},
            {"scope_verdict": "approved", "result": "error: timed out"},
        ])
        _write_jsonl(self.target_path, [
            {"sequence": 1, "result": 200},
        ])
        report = reconcile(self.engine_path, self.target_path)
        self.assertTrue(report.reconciled)

    def test_missing_ledger_files_are_treated_as_empty(self):
        report = reconcile(self.engine_path, self.target_path)
        self.assertEqual(report.engine_approved_with_result, 0)
        self.assertEqual(report.target_entries, 0)
        self.assertTrue(report.reconciled)


if __name__ == "__main__":
    unittest.main()
