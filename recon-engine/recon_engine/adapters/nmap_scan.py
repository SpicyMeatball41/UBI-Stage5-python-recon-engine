#!/usr/bin/env python3
"""
recon_engine.adapters.nmap_scan -- optional external-tool adapter
(nmap), with a documented fallback when nmap isn't available.

This is the literal "if one external tool is missing, a documented
fallback must complete the supported discovery path" requirement.
nmap is optional and enrichment-only: the built-in http/signal/tls
adapters already complete the full supported discovery path on their
own without it. If nmap is present, this adapter runs a narrowly
constrained version scan against exactly the one host:port it's given
(never a range, never host discovery) and folds its findings in as
additional normalized records; if nmap is missing, ToolUnavailableError
is raised and the orchestrator treats that as informational, not fatal
-- discovery already succeeded via the adapters that don't need it.

Scope honesty note: ScopeGuard.check() still gates whether nmap is
invoked at all against this host:port, and nmap's own arguments are
constrained (-Pn to skip host discovery, a single -p port, one target
host, XML output only) so it cannot itself reach outside what was
already authorized. What ScopeGuard's per-request budget/rate
accounting CANNOT do is meter nmap's own internal packet-level
behavior once it's running -- that's an inherent property of shelling
out to an external tool, not something this adapter can paper over,
so it's called out here rather than left implicit.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from ..checkpoint import Checkpoint
from ..fingerprint import compute_fingerprint
from ..ledger import RequestLedger
from ..raw_capture import write_raw
from ..scope_guard import ScopeGuard, ScopeViolation
from .base import ToolUnavailableError


def _nmap_path() -> Optional[str]:
    return shutil.which("nmap")


def scan_with_nmap(
    guard: ScopeGuard,
    host: str,
    port: int,
    output_dir: Path,
    ledger: RequestLedger,
    checkpoint: Optional[Checkpoint] = None,
    timeout: float = 30.0,
) -> dict:
    """Run `nmap -Pn -p <port> -sV -oX -` against exactly host:port and
    fold the result into one normalized record. Raises
    ToolUnavailableError if nmap isn't on PATH -- callers should treat
    that as "skip this enrichment step," not as a failed run.
    """
    nmap_bin = _nmap_path()
    if nmap_bin is None:
        raise ToolUnavailableError("nmap not found on PATH")

    dedup_key = f"nmap:{host}:{port}"
    if checkpoint is not None and checkpoint.is_done(dedup_key):
        return {
            "host": host, "port": port, "protocol": "nmap",
            "records_written": 0, "records_total": 1,
            "normalized_file": "normalized/assets.jsonl", "raw_dir": "raw/nmap",
        }

    runtime_id = guard.assignment.get("runtime_id")
    guard.check(host, port)  # same gate as every other adapter

    raw_dir = output_dir / "raw" / "nmap"
    normalized_dir = output_dir / "normalized"
    raw_dir.mkdir(parents=True, exist_ok=True)
    normalized_dir.mkdir(parents=True, exist_ok=True)

    started_at = time.time()
    try:
        proc = subprocess.run(
            [
                nmap_bin, "-Pn", "-p", str(port), "-sV",
                "--version-intensity", "2",  # light probing only -- avoid
                # the full probe database, which is what turns an
                # unrecognized protocol (like this lab's custom line
                # service) into dozens of connections while nmap tries
                # every standard fingerprint it knows before giving up.
                "-oX", "-", host,
            ],
            capture_output=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        ledger.record(
            purpose="nmap version scan", host=host, port=port, protocol="nmap",
            attempt=1, scope_verdict="approved", result=f"error: {exc}",
            runtime_id=runtime_id,
        )
        raise
    finished_at = time.time()

    xml_output = proc.stdout.decode("utf-8", errors="replace")
    raw_path = write_raw(raw_dir / f"{host}_{port}_nmap.xml", xml_output)

    service_name, product, version = _parse_nmap_xml(xml_output, port)

    ledger.record(
        purpose="nmap version scan", host=host, port=port, protocol="nmap",
        attempt=1, scope_verdict="approved",
        result=f"nmap exit {proc.returncode}", runtime_id=runtime_id,
    )

    record = {
        "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at)),
        "target": f"{host}:{port}",
        "port": port,
        "protocol": "nmap",
        "service": service_name or "unknown",
        "source_tool": "nmap",
        "source_file": raw_path.name,
        "confidence": "high" if service_name else "low",
        "notes": f"nmap -sV enrichment (exit {proc.returncode})",
        "product": product,
        "version": version,
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
        "protocol": "nmap",
        "records_written": 1,
        "records_total": 1,
        "normalized_file": str(normalized_path.relative_to(output_dir)),
        "raw_dir": str(raw_dir.relative_to(output_dir)),
    }


def _parse_nmap_xml(xml_text: str, port: int):
    """Extract (service_name, product, version) for `port` from nmap's
    -oX output. Returns (None, None, None) on any parse failure --
    malformed/empty XML is tolerated, not a crash."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None, None, None

    for port_el in root.iter("port"):
        if port_el.get("portid") != str(port):
            continue
        service_el = port_el.find("service")
        if service_el is None:
            return None, None, None
        return (
            service_el.get("name"),
            service_el.get("product"),
            service_el.get("version"),
        )
    return None, None, None
