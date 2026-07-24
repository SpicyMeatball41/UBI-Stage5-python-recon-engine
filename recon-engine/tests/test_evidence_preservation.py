#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from recon_engine.cli import preserve_scope_profile, run
from recon_engine.scope_guard import ScopeGuard

REPO_ROOT = Path(__file__).resolve().parent.parent
SCOPE_CSV = REPO_ROOT / "scope.csv"
ASSIGNMENT_JSON = REPO_ROOT / "assignment.json"


def _mock_http_connection(status=200, reason="OK", headers=None, body=b""):
    mock_response = MagicMock()
    mock_response.status = status
    mock_response.reason = reason
    mock_response.getheaders.return_value = headers or []
    mock_response.read.return_value = body
    mock_conn = MagicMock()
    mock_conn.getresponse.return_value = mock_response
    return patch("http.client.HTTPConnection", return_value=mock_conn)


class TestPreserveScopeProfile(unittest.TestCase):
    """Unit tests for preserve_scope_profile() in isolation."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.workdir = Path(self.tmpdir.name)
        self.scope_copy = self.workdir / "scope.csv"
        self.assignment_copy = self.workdir / "assignment.json"
        self.scope_copy.write_text(SCOPE_CSV.read_text())
        self.assignment_copy.write_text(ASSIGNMENT_JSON.read_text())
        self._prev_cwd = Path.cwd()
        import os
        os.chdir(self.workdir)

    def tearDown(self):
        import os
        os.chdir(self._prev_cwd)
        self.tmpdir.cleanup()

    def test_snapshot_written_under_evidence_runtime_id(self):
        guard = ScopeGuard(self.scope_copy, assignment_path=self.assignment_copy)
        evidence_dir = preserve_scope_profile(self.scope_copy, guard)

        runtime_id = json.loads(self.assignment_copy.read_text())["runtime_id"]
        expected_dir = self.workdir / "evidence" / runtime_id
        self.assertEqual(evidence_dir.resolve(), expected_dir.resolve())
        self.assertTrue((expected_dir / "scope.csv").exists())
        self.assertTrue((expected_dir / "assignment.json").exists())
        self.assertTrue((expected_dir / "preserved_at.txt").exists())
        self.assertEqual(
            (expected_dir / "scope.csv").read_text(), self.scope_copy.read_text()
        )

    def test_no_assignment_means_no_snapshot(self):
        guard = ScopeGuard(self.scope_copy)  # no assignment_path at all
        evidence_dir = preserve_scope_profile(self.scope_copy, guard)
        self.assertIsNone(evidence_dir)
        self.assertFalse((self.workdir / "evidence").exists())

    def test_second_call_does_not_overwrite_existing_snapshot(self):
        guard = ScopeGuard(self.scope_copy, assignment_path=self.assignment_copy)
        first = preserve_scope_profile(self.scope_copy, guard)

        # Mutate the live scope.csv after the first snapshot.
        self.scope_copy.write_text(self.scope_copy.read_text() + "\n# tampered\n")

        second = preserve_scope_profile(self.scope_copy, guard)
        self.assertEqual(first, second)
        # The preserved copy must NOT reflect the post-snapshot mutation.
        self.assertNotIn("# tampered", (first / "scope.csv").read_text())


class TestCliPreservesScopeProfile(unittest.TestCase):
    """End-to-end: running the CLI actually preserves the profile."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.workdir = Path(self.tmpdir.name)
        self.output_dir = self.workdir / "run"
        self.scope_copy = self.workdir / "scope.csv"
        self.assignment_copy = self.workdir / "assignment.json"
        self.scope_copy.write_text(SCOPE_CSV.read_text())
        self.assignment_copy.write_text(ASSIGNMENT_JSON.read_text())
        self._prev_cwd = Path.cwd()
        import os
        os.chdir(self.workdir)

    def tearDown(self):
        import os
        os.chdir(self._prev_cwd)
        self.tmpdir.cleanup()

    def test_run_preserves_profile_and_reports_it_in_manifest(self):
        with _mock_http_connection(body=b'{"ok": true}'):
            code = run([
                "--target", "127.0.0.1:18467",
                "--scope", str(self.scope_copy),
                "--output", str(self.output_dir),
                "--rate", "25",
            ])
        self.assertEqual(code, 0)

        runtime_id = json.loads(self.assignment_copy.read_text())["runtime_id"]
        evidence_dir = self.workdir / "evidence" / runtime_id
        self.assertTrue((evidence_dir / "scope.csv").exists())
        self.assertTrue((evidence_dir / "assignment.json").exists())

        manifest = json.loads((self.output_dir / "run.json").read_text())
        self.assertEqual(
            manifest["phase1_validation"]["evidence_dir"], str(evidence_dir.resolve())
        )


if __name__ == "__main__":
    unittest.main()
