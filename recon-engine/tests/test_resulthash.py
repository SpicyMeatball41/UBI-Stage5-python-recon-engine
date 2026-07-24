#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from recon_engine.resulthash import compute_normalized_hash


def _write_assets(output_dir: Path, records):
    normalized_dir = output_dir / "normalized"
    normalized_dir.mkdir(parents=True, exist_ok=True)
    with open(normalized_dir / "assets.jsonl", "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


class TestComputeNormalizedHash(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_empty_output_dir_has_a_stable_hash(self):
        h1 = compute_normalized_hash(self.output_dir)
        h2 = compute_normalized_hash(self.output_dir)
        self.assertEqual(h1, h2)

    def test_identical_records_with_different_timestamps_hash_equal(self):
        _write_assets(self.output_dir, [
            {"target": "127.0.0.1:18467", "protocol": "http", "path": "/",
             "status": 200, "observed_at": "2026-01-01T00:00:00Z", "duration_s": 0.01},
        ])
        hash_a = compute_normalized_hash(self.output_dir)

        _write_assets(self.output_dir, [
            {"target": "127.0.0.1:18467", "protocol": "http", "path": "/",
             "status": 200, "observed_at": "2026-06-15T12:34:56Z", "duration_s": 0.9},
        ])
        hash_b = compute_normalized_hash(self.output_dir)

        self.assertEqual(hash_a, hash_b)

    def test_different_status_produces_a_different_hash(self):
        _write_assets(self.output_dir, [
            {"target": "127.0.0.1:18467", "protocol": "http", "path": "/", "status": 200},
        ])
        hash_a = compute_normalized_hash(self.output_dir)

        _write_assets(self.output_dir, [
            {"target": "127.0.0.1:18467", "protocol": "http", "path": "/", "status": 404},
        ])
        hash_b = compute_normalized_hash(self.output_dir)

        self.assertNotEqual(hash_a, hash_b)

    def test_record_order_does_not_affect_the_hash(self):
        record_a = {"target": "127.0.0.1:18467", "protocol": "http", "path": "/", "status": 200}
        record_b = {"target": "127.0.0.1:23390", "protocol": "signal", "command": "CAPS", "status": 200}

        _write_assets(self.output_dir, [record_a, record_b])
        hash_forward = compute_normalized_hash(self.output_dir)

        _write_assets(self.output_dir, [record_b, record_a])
        hash_reversed = compute_normalized_hash(self.output_dir)

        self.assertEqual(hash_forward, hash_reversed)

    def test_missing_assets_file_does_not_raise(self):
        h = compute_normalized_hash(self.output_dir / "does-not-exist")
        self.assertIsInstance(h, str)


if __name__ == "__main__":
    unittest.main()
