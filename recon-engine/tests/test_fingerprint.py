#!/usr/bin/env python3
import unittest

from recon_engine.fingerprint import compute_fingerprint


class TestComputeFingerprint(unittest.TestCase):
    def test_no_signals_gets_unidentified_marker(self):
        fp = compute_fingerprint({"protocol": "http"})
        self.assertIn("unidentified", fp)

    def test_server_header_included(self):
        fp = compute_fingerprint({"protocol": "http", "server": "TransitGateway/2.4"})
        self.assertIn("server=TransitGateway/2.4", fp)

    def test_server_header_extracted_from_headers_dict(self):
        fp = compute_fingerprint({
            "protocol": "http", "headers": {"Server": "nginx/1.2", "Date": "x"}
        })
        self.assertIn("server=nginx/1.2", fp)

    def test_title_and_banner_included(self):
        fp = compute_fingerprint({"protocol": "http", "title": "Relay Ops"})
        self.assertIn("title=Relay Ops", fp)

        fp2 = compute_fingerprint({"protocol": "signal", "banner": "RLY/2 READY"})
        self.assertIn("banner=RLY/2 READY", fp2)

    def test_tls_availability_included(self):
        fp = compute_fingerprint({"protocol": "tls", "tls_available": False})
        self.assertIn("tls=False", fp)

    def test_different_signals_produce_different_fingerprints(self):
        fp1 = compute_fingerprint({"protocol": "http", "server": "A"})
        fp2 = compute_fingerprint({"protocol": "http", "server": "B"})
        self.assertNotEqual(fp1, fp2)

    def test_same_signals_produce_the_same_fingerprint(self):
        record = {"protocol": "http", "server": "A", "title": "T"}
        self.assertEqual(compute_fingerprint(record), compute_fingerprint(dict(record)))

    def test_returns_a_string(self):
        self.assertIsInstance(compute_fingerprint({"protocol": "http"}), str)


if __name__ == "__main__":
    unittest.main()
