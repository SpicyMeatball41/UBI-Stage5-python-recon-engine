#!/usr/bin/env python3
"""
Thin networking wrapper for the recon engine.

Nothing in this codebase should call `socket.create_connection` or an
HTTP client directly. Instead, scanner code calls the helpers below,
which call ScopeGuard.check(...) first and only proceed if it doesn't
raise. This makes "guard before every request" a structural property
of the code rather than a convention someone can forget.
"""

from __future__ import annotations

import socket
from typing import Optional

from .scope_guard import ScopeGuard  # guard.check() logs to the ledger internally


class GuardedConnector:
    def __init__(self, guard: ScopeGuard):
        self.guard = guard

    def open_socket(self, host: str, port: int, timeout: float = 3.0) -> socket.socket:
        # Guard runs first, full stop. If it raises, no socket is opened.
        self.guard.check(host, port)
        return socket.create_connection((host, port), timeout=timeout)

    def http_get(self, host: str, port: int, path: str = "/", timeout: float = 3.0) -> bytes:
        self.guard.check(host, port)
        import http.client

        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("GET", path)
            return conn.getresponse().read()
        finally:
            conn.close()

    def http_get_full(self, host: str, port: int, path: str = "/", timeout: float = 5.0):
        """Like http_get, but returns (status, reason, headers, body) so
        the caller can save the exact, unedited response -- status line,
        headers, and body -- rather than just the body bytes."""
        self.guard.check(host, port)
        import http.client

        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            status, reason = resp.status, resp.reason
            headers = resp.getheaders()
            body = resp.read()
            return status, reason, headers, body
        finally:
            conn.close()
