#!/usr/bin/env python3
"""
One allowed observation, end to end.

This module performs exactly one real HTTP request -- to the entry
target named in assignment.json's `entry_url`, and ONLY that target.
It never accepts a host/port from the caller: the entry point is read
straight out of the assignment, so there is no code path here that can
be pointed at the OUT-of-scope port, or anywhere else, no matter what
was passed to the CLI.

Flow:
  1. Parse entry_url -> host, port, path.
  2. GuardedConnector.http_get_full() calls ScopeGuard.check() first --
     the budget/rate/ledger-consuming path -- before opening any
     socket. If entry_url were ever misconfigured to point somewhere
     out of scope, this raises and nothing is sent.
  3. Save the response completely unedited (status line, headers, body,
     verbatim) to <output_dir>/raw/.
  4. Normalize it into <output_dir>/normalized/assets.jsonl (append,
     one JSON object per observation).
  5. Return a manifest dict describing what happened, for run.json.

NOTE ON THE NORMALIZED SCHEMA: the field names below are a reasonable
default (host, port, status_code, headers, body hash, etc.), not
confirmed against this lab's tool-interface.md. Check the field names
in assets.jsonl against whatever schema that document specifies, and
adjust NORMALIZED FIELDS below if they don't match.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import time
from pathlib import Path
from urllib.parse import urlsplit

from .net import GuardedConnector
from .scope_guard import ScopeGuard


class ObserveError(Exception):
    """Raised when an observation can't be made at all (e.g. no
    entry_url in assignment.json, or an unsupported scheme). This is
    distinct from ScopeViolation, which the guard raises itself and
    which callers should let propagate."""


def observe_entry(guard: ScopeGuard, output_dir: Path) -> dict:
    entry_url = guard.assignment.get("entry_url")
    if not entry_url:
        raise ObserveError(
            "assignment.json has no entry_url -- nothing to observe"
        )

    parts = urlsplit(entry_url)
    if parts.scheme != "http":
        raise ObserveError(
            f"entry_url scheme {parts.scheme!r} not supported "
            "(only plain http is wired up so far)"
        )
    if not parts.hostname:
        raise ObserveError(f"entry_url has no host: {entry_url!r}")

    host = parts.hostname
    port = parts.port or 80
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    raw_dir = output_dir / "raw"
    normalized_dir = output_dir / "normalized"
    raw_dir.mkdir(parents=True, exist_ok=True)
    normalized_dir.mkdir(parents=True, exist_ok=True)

    connector = GuardedConnector(guard)

    started_at = time.time()
    try:
        status, reason, headers, body = connector.http_get_full(host, port, path)
    except (OSError, http.client.HTTPException) as exc:
        # Connection refused/reset, DNS failure, timeout, etc. The guard
        # already approved and logged this attempt; the failure happened
        # at the network layer, not the scope layer.
        raise ObserveError(f"request to {host}:{port}{path} failed: {exc}")
    finished_at = time.time()

    ts_tag = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(started_at))
    raw_name = f"{host}_{port}_{ts_tag}.raw"
    raw_path = raw_dir / raw_name

    # --- raw, byte-for-byte unedited response ---
    with open(raw_path, "wb") as f:
        f.write(f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        f.write(f"HTTP/1.1 {status} {reason}\r\n".encode())
        for k, v in headers:
            f.write(f"{k}: {v}\r\n".encode())
        f.write(b"\r\n")
        f.write(body)

    # --- normalized record (see NOTE above re: confirming field names) ---
    header_dict = dict(headers)
    normalized_record = {
        "observed_at": ts_tag,
        "host": host,
        "port": port,
        "url": entry_url,
        "status_code": status,
        "reason": reason,
        "content_type": header_dict.get("Content-Type"),
        "content_length": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "headers": header_dict,
        "runtime_id": guard.assignment.get("runtime_id"),
        "raw_file": str(raw_path.relative_to(output_dir)),
    }
    assets_path = normalized_dir / "assets.jsonl"
    with open(assets_path, "a") as f:
        f.write(json.dumps(normalized_record) + "\n")

    return {
        "entry_url": entry_url,
        "host": host,
        "port": port,
        "path": path,
        "status_code": status,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_s": round(finished_at - started_at, 4),
        "raw_file": str(raw_path.relative_to(output_dir)),
        "normalized_file": str(assets_path.relative_to(output_dir)),
        "request_ledger": str(guard.ledger_path) if guard.ledger_path else None,
        "budget_used": guard._used,
        "budget_remaining": guard.remaining_budget,
    }
