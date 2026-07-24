#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recon_engine.report import generate_report


class TestGenerateReport(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_empty_state_does_not_error(self):
        report_path = generate_report(self.output_dir)
        self.assertTrue(report_path.exists())
        self.assertIn("No records yet", report_path.read_text())

    def test_renders_normalized_records(self):
        normalized_dir = self.output_dir / "normalized"
        normalized_dir.mkdir(parents=True)
        with open(normalized_dir / "assets.jsonl", "w") as f:
            f.write(json.dumps({
                "observed_at": "2026-01-01T00:00:00Z", "target": "127.0.0.1:18467",
                "protocol": "http", "service": "http", "notes": "baseline",
                "status": 200, "source_file": "root.raw",
            }) + "\n")

        report_path = generate_report(self.output_dir)
        html = report_path.read_text()
        self.assertIn("127.0.0.1:18467", html)
        self.assertIn("root.raw", html)
        self.assertIn("1 normalized record", html)

    def test_never_opens_anything_under_raw(self):
        """Report generation must be readable from normalized records
        alone -- it should never need to touch raw/."""
        normalized_dir = self.output_dir / "normalized"
        normalized_dir.mkdir(parents=True)
        with open(normalized_dir / "assets.jsonl", "w") as f:
            f.write(json.dumps({"target": "127.0.0.1:18467", "source_file": "x.raw"}) + "\n")

        real_open = open

        def _tracking_open(path, *args, **kwargs):
            if "raw" in str(path):
                raise AssertionError(f"report generation touched raw evidence: {path}")
            return real_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=_tracking_open):
            generate_report(self.output_dir)

    def test_html_escapes_untrusted_field_content(self):
        normalized_dir = self.output_dir / "normalized"
        normalized_dir.mkdir(parents=True)
        with open(normalized_dir / "assets.jsonl", "w") as f:
            f.write(json.dumps({
                "target": "127.0.0.1:18467", "notes": "<script>alert(1)</script>",
                "source_file": "x.raw",
            }) + "\n")

        report_path = generate_report(self.output_dir)
        html = report_path.read_text()
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)


if __name__ == "__main__":
    unittest.main()
