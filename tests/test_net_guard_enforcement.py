#!/usr/bin/env python3

import unittest
from pathlib import Path
from unittest.mock import patch

from recon_engine.net import GuardedConnector
from recon_engine.scope_guard import ScopeGuard, ScopeViolation

REPO_ROOT = Path(__file__).resolve().parent.parent
SCOPE_CSV = REPO_ROOT / "scope.csv"
ASSIGNMENT_JSON = REPO_ROOT / "assignment.json"


class TestGuardEnforcedBeforeSocket(unittest.TestCase):
    def setUp(self):
        self.guard = ScopeGuard(
            SCOPE_CSV, assignment_path=ASSIGNMENT_JSON, ledger_path=None
        )
        self.connector = GuardedConnector(self.guard)

    def test_out_of_scope_never_reaches_socket_layer(self):
        with patch("socket.create_connection") as mock_conn:
            with self.assertRaises(ScopeViolation):
                self.connector.open_socket("127.0.0.1", 26035)  # OUT
            mock_conn.assert_not_called()

    def test_unlisted_port_never_reaches_socket_layer(self):
        with patch("socket.create_connection") as mock_conn:
            with self.assertRaises(ScopeViolation):
                self.connector.open_socket("127.0.0.1", 45000)
            mock_conn.assert_not_called()

    def test_non_loopback_never_reaches_socket_layer(self):
        with patch("socket.create_connection") as mock_conn:
            with self.assertRaises(ScopeViolation):
                self.connector.open_socket("93.184.216.34", 80)
            mock_conn.assert_not_called()

    def test_in_scope_reaches_socket_layer(self):
        with patch("socket.create_connection") as mock_conn:
            self.connector.open_socket("127.0.0.1", 18467)  # entry_url port
            mock_conn.assert_called_once_with(("127.0.0.1", 18467), timeout=3.0)

    def test_http_get_blocked_when_out_of_scope(self):
        with patch("http.client.HTTPConnection") as mock_http:
            with self.assertRaises(ScopeViolation):
                self.connector.http_get("127.0.0.1", 26035)
            mock_http.assert_not_called()


if __name__ == "__main__":
    unittest.main()
