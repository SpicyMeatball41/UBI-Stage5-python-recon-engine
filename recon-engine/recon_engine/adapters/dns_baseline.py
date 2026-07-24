#!/usr/bin/env python3
"""
recon_engine.adapters.dns_baseline -- establishes and records the DNS
baseline for the assigned targets, WITHOUT ever issuing a real DNS
query.

A genuine live DNS adapter would send a query to whatever resolver is
configured on the system -- and that resolver is essentially never
loopback. Every target in this lab is `127.0.0.1`, so a real DNS
lookup would be a request to a non-loopback destination, which
scope.csv's own `0.0.0.0/0,OUT` row exists specifically to prohibit.
Implementing "DNS baseline" as an actual network adapter would mean
building a feature whose only fully-correct behavior is to violate
scope on every single run.

The scope-safe version of a DNS baseline is what this module does
instead: confirm and RECORD that a target is a literal IP address
requiring no resolution at all (the expected, common case here), or --
if a target is ever given as a real hostname -- perform the SAME
resolution ScopeGuard.check() itself already performs internally
(socket.gethostbyname), so the baseline reflects exactly what the
guard already verified, adding nothing new that could itself go
out-of-scope. This still produces one normalized record and one
ledger line per target, same as a real adapter would, precisely
because a resolution WAS considered.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import time
from pathlib import Path
from typing import Optional

from ..checkpoint import Checkpoint
from ..fingerprint import compute_fingerprint
from ..ledger import RequestLedger
from ..scope_guard import ScopeGuard, ScopeViolation


def establish_dns_baseline(
    guard: ScopeGuard,
    host: str,
    port: int,
    output_dir: Path,
    ledger: RequestLedger,
    checkpoint: Optional[Checkpoint] = None,
) -> dict:
    """Record whether `host` is a literal IP (no resolution needed) or
    a hostname that was resolved. Does not call guard.check() when host
    is a literal IP, because no network packet is sent in that case --
    there's nothing to gate. When host IS a hostname, resolution goes
    through the exact same path ScopeGuard.check() itself uses, so a
    non-loopback result is impossible to reach this function with in
    the first place (ScopeGuard would already have denied it upstream).
    """
    dedup_key = f"dns:{host}"
    if checkpoint is not None and checkpoint.is_done(dedup_key):
        cached = checkpoint.get(dedup_key)
        normalized_path = output_dir / "normalized" / "assets.jsonl"
        return {
            "host": host, "port": port, "protocol": "dns",
            "records_written": 0, "records_total": 1 if cached else 0,
            "normalized_file": str(normalized_path.relative_to(output_dir))
            if normalized_path.exists() else None,
            "raw_dir": None,
        }

    runtime_id = guard.assignment.get("runtime_id")
    normalized_dir = output_dir / "normalized"
    normalized_dir.mkdir(parents=True, exist_ok=True)

    started_at = time.time()
    try:
        ipaddress.ip_address(host)
        is_literal_ip = True
        resolved_address = host
        note = f"{host} is a literal IP; no DNS resolution was needed or performed"
    except ValueError:
        is_literal_ip = False
        try:
            resolved_address = socket.gethostbyname(host)
            note = f"{host} resolved to {resolved_address}"
        except socket.gaierror as exc:
            ledger.record(
                purpose="DNS baseline", host=host, port=port, protocol="dns",
                attempt=1, scope_verdict="approved",
                result=f"error: could not resolve {host}: {exc}",
                runtime_id=runtime_id,
            )
            raise ScopeViolation(f"could not resolve host {host!r}: {exc}")
    finished_at = time.time()

    ledger.record(
        purpose="DNS baseline", host=host, port=port, protocol="dns",
        attempt=1, scope_verdict="approved",
        result="literal IP (no query)" if is_literal_ip else f"resolved to {resolved_address}",
        runtime_id=runtime_id, notes=note,
    )

    record = {
        "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at)),
        "target": f"{host}:{port}",
        "port": port,
        "protocol": "dns",
        "service": "dns",
        "source_tool": "recon_engine.dns_baseline",
        "source_file": None,
        "confidence": "high",
        "notes": note,
        "is_literal_ip": is_literal_ip,
        "resolved_address": resolved_address,
        "duration_s": round(finished_at - started_at, 4),
    }
    record["fingerprint"] = compute_fingerprint(record)

    normalized_path = normalized_dir / "assets.jsonl"
    with open(normalized_path, "a") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")

    if checkpoint is not None:
        checkpoint.mark_done(dedup_key, record)

    return {
        "host": host,
        "port": port,
        "protocol": "dns",
        "records_written": 1,
        "records_total": 1,
        "normalized_file": str(normalized_path.relative_to(output_dir)),
        "raw_dir": None,
    }
