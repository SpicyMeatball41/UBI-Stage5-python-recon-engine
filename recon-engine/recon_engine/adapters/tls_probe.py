#!/usr/bin/env python3
"""
recon_engine.adapters.tls_probe -- optional TLS/SNI adapter.

This is deliberately allowed to conclude "no TLS here" rather than
fail: not every authorized service is expected to speak TLS (this
lab's HTTP service is plaintext), and the brief calls for "fallback
when one optional adapter is unavailable." TLS is exactly that kind of
optional adapter -- its absence is itself a normalized, evidenced
finding, not an error that should abort the run.

Still goes through ScopeGuard.check() like every other adapter (a TLS
probe is a real connection attempt), and still writes one ledger line
and one normalized record -- it just never raises DiscoveryError for
"the target doesn't speak TLS", only for a scope denial.
"""

from __future__ import annotations

import json
import socket
import ssl
import time
from pathlib import Path
from typing import Optional

from ..fingerprint import compute_fingerprint
from ..ledger import RequestLedger
from ..raw_capture import write_raw
from ..scope_guard import ScopeGuard


def probe_tls(
    guard: ScopeGuard,
    host: str,
    port: int,
    output_dir: Path,
    ledger: RequestLedger,
    timeout: float = 5.0,
) -> dict:
    """Attempt one TLS handshake against host:port. Never raises for
    "not TLS" -- only for a scope denial (ScopeViolation), which the
    caller should treat the same as any other adapter's scope denial.
    """
    runtime_id = guard.assignment.get("runtime_id")
    guard.check(host, port)  # scope denial propagates; nothing else does

    raw_dir = output_dir / "raw" / "tls"
    normalized_dir = output_dir / "normalized"
    raw_dir.mkdir(parents=True, exist_ok=True)
    normalized_dir.mkdir(parents=True, exist_ok=True)

    started_at = time.time()
    tls_available = False
    detail = ""
    negotiated_version: Optional[str] = None

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                tls_available = True
                negotiated_version = tls_sock.version()
                detail = f"TLS handshake succeeded ({negotiated_version})"
    except ssl.SSLError as exc:
        # This is the expected, non-error outcome for a plaintext
        # service: the handshake itself fails because there's no TLS
        # on the other end. That's a finding, not a failure.
        detail = f"no TLS (handshake failed: {exc})"
    except OSError as exc:
        detail = f"could not connect for TLS probe: {exc}"

    finished_at = time.time()
    result = (
        f"TLS available ({negotiated_version})"
        if tls_available
        else "no TLS (fallback: HTTP-only discovery)"
    )

    ledger.record(
        purpose="TLS/SNI availability probe", host=host, port=port, protocol="tls",
        attempt=1, scope_verdict="approved", result=result, runtime_id=runtime_id,
        notes=detail,
    )

    raw_path = write_raw(
        raw_dir / f"{host}_{port}_tls.raw", f"host={host} port={port}\n{detail}\n"
    )

    record = {
        "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at)),
        "target": f"{host}:{port}",
        "port": port,
        "protocol": "tls",
        "service": "tls",
        "source_tool": "recon_engine.tls_probe",
        "source_file": raw_path.name,
        "confidence": "high",
        "notes": detail,
        "tls_available": tls_available,
        "tls_version": negotiated_version,
        "duration_s": round(finished_at - started_at, 4),
    }
    record["fingerprint"] = compute_fingerprint(record)

    normalized_path = normalized_dir / "assets.jsonl"
    with open(normalized_path, "a") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")

    return record
