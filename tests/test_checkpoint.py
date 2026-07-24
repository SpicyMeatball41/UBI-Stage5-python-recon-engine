#!/usr/bin/env python3
import json
import tempfile
import threading
import unittest
from pathlib import Path

from recon_engine.checkpoint import Checkpoint


class TestCheckpoint(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tmpdir.name) / "checkpoint.json"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_fresh_checkpoint_has_nothing_done(self):
        cp = Checkpoint(self.path)
        self.assertFalse(cp.is_done("http:default:/"))

    def test_mark_done_then_is_done(self):
        cp = Checkpoint(self.path)
        cp.mark_done("http:default:/", {"status": 200})
        self.assertTrue(cp.is_done("http:default:/"))
        self.assertEqual(cp.get("http:default:/"), {"status": 200})

    def test_persists_across_instances(self):
        cp1 = Checkpoint(self.path)
        cp1.mark_done("signal:CAPS", {"status": 200})
        cp2 = Checkpoint(self.path)  # simulates a resumed run
        self.assertTrue(cp2.is_done("signal:CAPS"))
        self.assertEqual(cp2.get("signal:CAPS"), {"status": 200})

    def test_completed_records_excludes_none_values(self):
        cp = Checkpoint(self.path)
        cp.mark_done("a", {"x": 1})
        cp.mark_done("b", None)
        self.assertEqual(cp.completed_records(), [{"x": 1}])

    def test_meta_storage(self):
        cp = Checkpoint(self.path)
        cp.set_meta("vhost", "relay-abc123.northstar.local")
        self.assertEqual(cp.get_meta("vhost"), "relay-abc123.northstar.local")
        self.assertIsNone(cp.get_meta("nonexistent"))
        self.assertEqual(cp.get_meta("nonexistent", "default"), "default")

    def test_corrupt_checkpoint_file_degrades_to_fresh_start(self):
        self.path.write_text("{not valid json")
        cp = Checkpoint(self.path)  # must not raise
        self.assertFalse(cp.is_done("anything"))

    def test_write_is_atomic_no_tmp_file_left_behind(self):
        cp = Checkpoint(self.path)
        cp.mark_done("x", {"a": 1})
        self.assertTrue(self.path.exists())
        self.assertFalse(self.path.with_suffix(".tmp").exists())

    def test_concurrent_mark_done_from_multiple_threads_is_safe(self):
        cp = Checkpoint(self.path)
        errors = []

        def worker(i):
            try:
                cp.mark_done(f"key-{i}", {"i": i})
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        for i in range(20):
            self.assertTrue(cp.is_done(f"key-{i}"))
        # File itself must still be valid JSON after concurrent writes.
        json.loads(self.path.read_text())


if __name__ == "__main__":
    unittest.main()
