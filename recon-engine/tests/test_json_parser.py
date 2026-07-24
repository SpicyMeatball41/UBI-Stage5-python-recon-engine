#!/usr/bin/env python3
"""
Extension test, bullet 1: "Add an unseen JSON parser."

These fixtures are deliberately varied and NOT tied to /ops-diagnostics'
one known shape -- the point is proving recon_engine.json_parser
handles arbitrary, previously-unseen JSON structures gracefully,
including cases a naive `json.loads()` + dict-indexing approach would
crash on.
"""

import unittest

from recon_engine.json_parser import MAX_DEPTH, parse_json


class TestParseJsonUnseenShapes(unittest.TestCase):
    def test_simple_flat_object(self):
        result = parse_json(b'{"a": 1, "b": "two"}')
        self.assertTrue(result.ok)
        self.assertEqual(result.get_path("a"), 1)
        self.assertEqual(result.get_path("b"), "two")

    def test_nested_object_get_path(self):
        result = parse_json(b'{"outer": {"inner": {"value": 42}}}')
        self.assertTrue(result.ok)
        self.assertEqual(result.get_path("outer", "inner", "value"), 42)

    def test_top_level_array_not_object(self):
        """A response might not even be a JSON object -- an array (or
        a bare string/number) is valid JSON that a naive
        payload["key"] approach would crash on with a TypeError."""
        result = parse_json(b'[1, 2, 3]')
        self.assertTrue(result.ok)
        self.assertEqual(result.value, [1, 2, 3])
        # get_path against a non-dict root must degrade to default,
        # not raise.
        self.assertIsNone(result.get_path("anything"))

    def test_top_level_bare_string(self):
        result = parse_json(b'"just a string"')
        self.assertTrue(result.ok)
        self.assertEqual(result.value, "just a string")

    def test_top_level_bare_number(self):
        result = parse_json(b'42')
        self.assertTrue(result.ok)
        self.assertEqual(result.value, 42)

    def test_null_values_do_not_crash_get_path(self):
        result = parse_json(b'{"a": null, "b": {"c": null}}')
        self.assertTrue(result.ok)
        self.assertIsNone(result.get_path("a"))
        self.assertIsNone(result.get_path("b", "c"))

    def test_unicode_content(self):
        result = parse_json('{"message": "héllo wörld \u2603"}'.encode("utf-8"))
        self.assertTrue(result.ok)
        self.assertEqual(result.get_path("message"), "héllo wörld \u2603")

    def test_empty_object(self):
        result = parse_json(b'{}')
        self.assertTrue(result.ok)
        self.assertIsNone(result.get_path("anything"))

    def test_empty_array(self):
        result = parse_json(b'[]')
        self.assertTrue(result.ok)
        self.assertEqual(result.value, [])

    def test_empty_body_is_a_clean_failure(self):
        result = parse_json(b'')
        self.assertFalse(result.ok)
        self.assertIn("empty", result.error)

    def test_malformed_json_is_a_clean_failure_not_an_exception(self):
        result = parse_json(b'{"a": 1, "b":}')
        self.assertFalse(result.ok)
        self.assertIn("invalid JSON", result.error)

    def test_truncated_json_is_a_clean_failure(self):
        result = parse_json(b'{"a": {"b": {"c": ')
        self.assertFalse(result.ok)
        self.assertFalse(result.value)

    def test_non_utf8_bytes_is_a_clean_failure(self):
        result = parse_json(b'\xff\xfe{"a": 1}')
        self.assertFalse(result.ok)
        self.assertIn("UTF-8", result.error)

    def test_html_error_page_instead_of_json_is_a_clean_failure(self):
        """A service that was expected to return JSON might instead
        return an HTML error page (e.g. a proxy's 502 page) -- this
        must be a clean, reported failure, not a crash."""
        result = parse_json(b"<html><body>502 Bad Gateway</body></html>")
        self.assertFalse(result.ok)

    def test_excessive_nesting_is_rejected_not_a_stack_overflow(self):
        deeply_nested = "{" * (MAX_DEPTH + 10) + "}" * (MAX_DEPTH + 10)
        result = parse_json(deeply_nested.encode())
        # Either the depth guard catches it, or json.loads itself
        # raises RecursionError first (also handled cleanly) -- either
        # way this must never propagate an uncaught exception.
        self.assertFalse(result.ok)

    def test_get_path_returns_custom_default(self):
        result = parse_json(b'{"a": 1}')
        self.assertEqual(result.get_path("missing", default="fallback"), "fallback")

    def test_get_path_on_failed_parse_returns_default(self):
        result = parse_json(b'not json at all')
        self.assertEqual(result.get_path("anything", default="fallback"), "fallback")

    def test_numbers_as_strings_vs_actual_numbers(self):
        """A field the engine expects to be a number might arrive as a
        string in an unseen/different service version -- get_path
        should return exactly what's there (type-preserving), not
        silently coerce, so the caller can decide how to handle it."""
        result = parse_json(b'{"port": "18467"}')
        self.assertTrue(result.ok)
        self.assertEqual(result.get_path("port"), "18467")
        self.assertIsInstance(result.get_path("port"), str)

    def test_duplicate_keys_last_one_wins_per_json_spec(self):
        result = parse_json(b'{"a": 1, "a": 2}')
        self.assertTrue(result.ok)
        self.assertEqual(result.get_path("a"), 2)

    def test_oversized_body_is_rejected(self):
        from recon_engine.json_parser import MAX_BODY_BYTES

        huge = b'{"a": "' + b"x" * (MAX_BODY_BYTES + 1) + b'"}'
        result = parse_json(huge)
        self.assertFalse(result.ok)
        self.assertIn("exceeds", result.error)


if __name__ == "__main__":
    unittest.main()
