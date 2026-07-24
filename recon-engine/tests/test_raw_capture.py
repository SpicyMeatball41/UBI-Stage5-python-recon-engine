#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path

from recon_engine.raw_capture import write_raw


class TestWriteRaw(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.workdir = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_writes_to_the_intended_path_when_nothing_exists_there(self):
        path = self.workdir / "capture.raw"
        result = write_raw(path, b"first content")
        self.assertEqual(result, path)
        self.assertEqual(path.read_bytes(), b"first content")

    def test_second_write_to_same_path_never_overwrites_the_first(self):
        path = self.workdir / "capture.raw"
        write_raw(path, b"original content -- must survive")
        second_path = write_raw(path, b"a second, different capture")

        self.assertNotEqual(second_path, path)
        self.assertEqual(path.read_bytes(), b"original content -- must survive")
        self.assertEqual(second_path.read_bytes(), b"a second, different capture")

    def test_third_write_gets_its_own_disambiguated_path_too(self):
        path = self.workdir / "capture.raw"
        write_raw(path, b"v1")
        write_raw(path, b"v2")
        third_path = write_raw(path, b"v3")

        self.assertEqual(third_path.name, "capture__3.raw")
        self.assertEqual(path.read_bytes(), b"v1")

    def test_works_with_text_content_too(self):
        path = self.workdir / "capture.raw"
        write_raw(path, "text content")
        second = write_raw(path, "more text")
        self.assertEqual(path.read_text(), "text content")
        self.assertEqual(second.read_text(), "more text")

    def test_preserves_file_extension_when_disambiguating(self):
        path = self.workdir / "127.0.0.1_18467_root.raw"
        write_raw(path, b"a")
        second = write_raw(path, b"b")
        self.assertTrue(second.name.endswith(".raw"))
        self.assertIn("__2", second.name)


if __name__ == "__main__":
    unittest.main()
