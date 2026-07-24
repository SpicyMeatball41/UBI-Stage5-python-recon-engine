#!/usr/bin/env python3
"""
recon_engine.adapters.http_discovery -- HTTP discovery, including
virtual-host probing against a wildcard baseline.

Everything from phase 2 (scheduling, timeout, retries, rate accounting,
raw capture, normalization, the request ledger) still applies here, plus:

  - virtual hosts: a probe can carry an optional `host_header` to send
    a specific Host: header, so the same path can be probed once
    against the DEFAULT (wildcard) vhost and again against a candidate
    real vhost -- this is the "DNS and wildcard baselines" technique
    done safely at the HTTP layer (no real DNS query ever leaves
    loopback; see the module-level note in recon_engine.adapters.dns_baseline
    for why a live DNS adapter is deliberately not implemented).
  - baseline comparison: vhost-specific responses are compared against
    the wildcard baseline for the same path, producing a
    `baseline_difference` field -- this is how a genuinely different,
    non-wildcard service is distinguished from the decoy "everything
    looks the same" response.
  - resumable/deduplicated: each probe has a stable key; if a Checkpoint
    says that key already completed, the probe is skipped entirely (no
    new socket, no budget spent) and the previously-recorded normalized
    record is reused as-is.
"""

from __future__ import annotations

import hashlib
import html.parser
import http.client
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlsplit

from ..checkpoint import Checkpoint
from ..fingerprint import compute_fingerprint
from ..ledger import RequestLedger
from ..raw_capture import write_raw
from ..scope_guard import ScopeGuard, ScopeViolation

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class DiscoveryError(Exception):
    """A probe failed at the network layer after retries were exhausted.
    Scope denials are NOT retried and are not this exception -- they
    propagate as ScopeViolation, since a scope decision is never
    something to retry past."""


@dataclass(frozen=True)
class Probe:
    path: str
    purpose: str
    host_header: Optional[str] = None  # None = default/wildcard vhost

    @property
    def dedup_key(self) -> str:
        vhost = self.host_header or "default"
        return f"http:{vhost}:{self.path}"


# Fixed order is the "scheduling" for this phase: deterministic because
# it never depends on timing, thread interleaving, or dict ordering.
DEFAULT_PROBES: List[Probe] = [
    Probe(path="/", purpose="baseline discovery"),
    Probe(path="/robots.txt", purpose="robots.txt enumeration"),
]


def _split_entry_url(entry_url: str):
    parts = urlsplit(entry_url)
    if parts.scheme != "http":
        raise DiscoveryError(f"unsupported scheme in entry_url: {entry_url!r}")
    if not parts.hostname:
        raise DiscoveryError(f"entry_url has no host: {entry_url!r}")
    return parts.hostname, parts.port or 80


def _extract_title(body: bytes) -> Optional[str]:
    match = _TITLE_RE.search(body)
    if not match:
        return None
    return html.parser.unescape(match.group(1).decode("utf-8", errors="replace").strip())


def discover_http(
    guard: ScopeGuard,
    entry_url: str,
    output_dir: Path,
    ledger: RequestLedger,
    probes: Optional[List[Probe]] = None,
    checkpoint: Optional[Checkpoint] = None,
    timeout: float = 5.0,
    max_retries: int = 2,
    retry_backoff: float = 0.5,
) -> dict:
    """Run every probe in `probes` (default: DEFAULT_PROBES) against the
    host:port in entry_url, in fixed order, and append one normalized
    record per probe to <output_dir>/normalized/assets.jsonl.

    Probes with `host_header` set are compared against the wildcard
    baseline (the same path probed with no host_header override) to
    compute `baseline_difference`.

    Raises ScopeViolation immediately if any probe is out of scope.
    Raises DiscoveryError if a probe exhausts its retries.
    """
    host, port = _split_entry_url(entry_url)
    probe_list = probes if probes is not None else DEFAULT_PROBES

    raw_dir = output_dir / "raw" / "http"
    normalized_dir = output_dir / "normalized"
    raw_dir.mkdir(parents=True, exist_ok=True)
    normalized_dir.mkdir(parents=True, exist_ok=True)
    normalized_path = normalized_dir / "assets.jsonl"

    baseline: Dict[str, dict] = {}  # path -> baseline record (host_header=None probes)
    records = []
    new_records = []

    for probe in probe_list:  # strict sequence -- this IS the scheduling
        if checkpoint is not None and checkpoint.is_done(probe.dedup_key):
            record = checkpoint.get(probe.dedup_key)
        else:
            record = _run_one_probe(
                guard, host, port, probe, raw_dir, ledger,
                timeout, max_retries, retry_backoff, baseline,
            )
            if checkpoint is not None:
                checkpoint.mark_done(probe.dedup_key, record)
            new_records.append(record)

        if record is not None:
            records.append(record)
            if probe.host_header is None:
                baseline[probe.path] = record

    if new_records:
        with open(normalized_path, "a") as f:
            for record in new_records:
                f.write(json.dumps(record, sort_keys=True) + "\n")

    return {
        "host": host,
        "port": port,
        "protocol": "http",
        "probes_attempted": len(probe_list),
        "records_written": len(new_records),
        "records_total": len(records),
        "normalized_file": str(normalized_path.relative_to(output_dir)),
        "raw_dir": str(raw_dir.relative_to(output_dir)),
    }


def _run_one_probe(
    guard: ScopeGuard,
    host: str,
    port: int,
    probe: Probe,
    raw_dir: Path,
    ledger: RequestLedger,
    timeout: float,
    max_retries: int,
    retry_backoff: float,
    baseline: Dict[str, dict],
) -> dict:
    runtime_id = guard.assignment.get("runtime_id")
    last_error: Optional[Exception] = None

    for attempt in range(1, max_retries + 2):  # 1 initial try + max_retries retries
        try:
            guard.check(host, port)
        except ScopeViolation as exc:
            ledger.record(
                purpose=probe.purpose, host=host, port=port, protocol="http",
                attempt=attempt, scope_verdict=f"denied: {exc}", result="not sent",
                runtime_id=runtime_id,
            )
            raise

        started_at = time.time()
        headers = {"User-Agent": "recon-engine/http-discovery"}
        if probe.host_header:
            headers["Host"] = probe.host_header
        try:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            try:
                conn.request("GET", probe.path, headers=headers)
                resp = conn.getresponse()
                status, reason = resp.status, resp.reason
                resp_headers = resp.getheaders()
                body = resp.read()
            finally:
                conn.close()
        except (OSError, http.client.HTTPException) as exc:
            last_error = exc
            ledger.record(
                purpose=probe.purpose, host=host, port=port, protocol="http",
                attempt=attempt, scope_verdict="approved", result=f"error: {exc}",
                runtime_id=runtime_id,
            )
            if attempt <= max_retries:
                time.sleep(retry_backoff * attempt)
                continue
            raise DiscoveryError(
                f"GET {host}:{port}{probe.path} (Host: {probe.host_header or host}) "
                f"failed after {attempt} attempt(s): {exc}"
            )

        finished_at = time.time()
        vhost_slug = (probe.host_header or "default").replace(".", "_").replace(":", "_")
        path_slug = probe.path.strip("/").replace("/", "_") or "root"
        raw_content = f"GET {probe.path} HTTP/1.1\r\n".encode()
        for name, value in headers.items():
            raw_content += f"{name}: {value}\r\n".encode()
        raw_content += b"\r\n"
        raw_content += f"HTTP/1.1 {status} {reason}\r\n".encode()
        for name, value in resp_headers:
            raw_content += f"{name}: {value}\r\n".encode()
        raw_content += b"\r\n" + body
        raw_path = write_raw(
            raw_dir / f"{host}_{port}_{vhost_slug}_{path_slug}.raw", raw_content
        )

        ledger.record(
            purpose=probe.purpose, host=host, port=port, protocol="http",
            attempt=attempt, scope_verdict="approved", result=f"HTTP {status}",
            runtime_id=runtime_id,
        )

        body_sha256 = hashlib.sha256(body).hexdigest()
        redirect = dict(resp_headers).get("Location")
        server_header = dict(resp_headers).get("Server")

        record = {
            "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at)),
            "target": f"{host}:{port}",
            "port": port,
            "protocol": "http",
            "service": "http",
            "source_tool": "recon_engine.http_discovery",
            "source_file": raw_path.name,
            "confidence": "high",
            "notes": probe.purpose,
            "path": probe.path,
            "status": status,
            "length": len(body),
            "body_sha256": body_sha256,
            "duration_s": round(finished_at - started_at, 4),
            "attempts": attempt,
            "server": server_header,
        }

        if probe.host_header:
            record["vhost"] = probe.host_header
            record["title"] = _extract_title(body)
            record["redirect"] = redirect
            base = baseline.get(probe.path)
            if base is not None:
                record["baseline_difference"] = (
                    status != base["status"]
                    or len(body) != base["length"]
                    or body_sha256 != base["body_sha256"]
                )
            else:
                record["baseline_difference"] = None  # no baseline available to compare

        record["fingerprint"] = compute_fingerprint(record)
        return record

    raise DiscoveryError(f"GET {host}:{port}{probe.path} failed: {last_error}")
