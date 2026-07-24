#!/usr/bin/env python3
"""
recon_engine.fingerprint -- derives a canonical fingerprint string for
a discovered service from whatever signals its adapter already
captured (Server header, banner text, page title, TLS availability).

This is deliberately NOT a new network probe -- it's a second pass over
data an adapter already has in hand, turning scattered fields
(server_header, banner, title) into one comparable fingerprint string
per record. That's what makes two DIFFERENT services distinguishable
at a glance, and what makes a service that changes its declared
identity between runs detectable (fingerprint changed even though
status/length happened to match).
"""

from __future__ import annotations

import hashlib
from typing import Optional


def compute_fingerprint(record: dict) -> str:
    """Return a short, stable fingerprint string for a normalized
    record. Combines whatever identifying signals are present into one
    value; records with no identifying signal at all get a fixed
    'unidentified' fingerprint rather than an empty string, so it's
    always safe to compare fingerprints across records."""
    parts = []

    protocol = record.get("protocol", "")
    parts.append(f"protocol={protocol}")

    server_header = _extract_server_header(record)
    if server_header:
        parts.append(f"server={server_header}")

    title = record.get("title")
    if title:
        parts.append(f"title={title}")

    banner = record.get("banner")
    if banner:
        parts.append(f"banner={banner}")

    if "tls_available" in record:
        parts.append(f"tls={record['tls_available']}")

    if len(parts) == 1:  # only "protocol=..." -- nothing else to go on
        parts.append("unidentified")

    signature = "|".join(parts)
    short_hash = hashlib.sha256(signature.encode()).hexdigest()[:12]
    return f"{signature} ({short_hash})"


def _extract_server_header(record: dict) -> Optional[str]:
    headers = record.get("headers")
    if isinstance(headers, dict):
        for key in headers:
            if key.lower() == "server":
                return headers[key]
    return record.get("server")
