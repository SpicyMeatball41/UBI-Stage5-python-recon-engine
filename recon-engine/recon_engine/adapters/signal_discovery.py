#!/usr/bin/env python3
"""
recon_engine.adapters.signal_discovery -- discovery adapter for the
line-oriented "signal" protocol (the second authorized service).

Matches local_lab.py's actual protocol exactly, since we have its
source: each connection gets a banner ("RLY/2 READY ..."), then the
server reads exactly ONE line as a command and replies once before
closing -- so each command needs its own fresh connection, unlike HTTP
keep-alive. Known commands: CAPS (capability enumeration), ROUTE
(reveals the vhost + route proof needed for the HTTP foothold chain),
QUIT. Anything else gets "ERR unsupported command"; a read that times
out gets no response at all.

Same shape as http_discovery: scheduling (fixed command list),
timeout, retry-with-backoff (only for actual transport failures --
a well-formed ERR/timeout response is a completed attempt, not
something to retry past), rate/budget accounting via ScopeGuard.check()
before every attempt, raw capture, normalization, ledger, and
checkpoint-based resume/dedup.
"""

from __future__ import annotations

import hashlib
import json
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ..checkpoint import Checkpoint
from ..fingerprint import compute_fingerprint
from ..ledger import RequestLedger
from ..raw_capture import write_raw
from ..scope_guard import ScopeGuard, ScopeViolation


class DiscoveryError(Exception):
    """A command failed at the transport layer after retries were
    exhausted. Scope denials are ScopeViolation, not this, and are
    never retried."""


@dataclass(frozen=True)
class Command:
    text: str
    purpose: str

    @property
    def dedup_key(self) -> str:
        return f"signal:{self.text}"


DEFAULT_COMMANDS: List[Command] = [
    Command(text="CAPS", purpose="capability enumeration"),
    Command(text="ROUTE", purpose="route discovery"),
]


def _classify_response(line: str) -> int:
    """Map a raw response line to a status-like code, mirroring
    local_lab.py's own internal result codes exactly (200 for a
    recognized command, 400 for ERR, 408 conceptually reserved for a
    timeout -- handled separately since a timeout has no response
    line at all)."""
    if line.startswith("commands=") or line.startswith("route=") or line.startswith("bye"):
        return 200
    return 400


def discover_signal(
    guard: ScopeGuard,
    host: str,
    port: int,
    output_dir: Path,
    ledger: RequestLedger,
    commands: Optional[List[Command]] = None,
    checkpoint: Optional[Checkpoint] = None,
    timeout: float = 5.0,
    max_retries: int = 2,
    retry_backoff: float = 0.5,
) -> dict:
    """Run every command in `commands` (default: DEFAULT_COMMANDS)
    against host:port, one fresh connection per command, in fixed
    order. If a ROUTE response reveals a vhost/route proof, it's stored
    via checkpoint.set_meta() so a later HTTP vhost probe can use it
    without re-discovering it.
    """
    command_list = commands if commands is not None else DEFAULT_COMMANDS

    raw_dir = output_dir / "raw" / "signal"
    normalized_dir = output_dir / "normalized"
    raw_dir.mkdir(parents=True, exist_ok=True)
    normalized_dir.mkdir(parents=True, exist_ok=True)
    normalized_path = normalized_dir / "assets.jsonl"

    records = []
    new_records = []

    for command in command_list:
        if checkpoint is not None and checkpoint.is_done(command.dedup_key):
            record = checkpoint.get(command.dedup_key)
        else:
            record = _run_one_command(
                guard, host, port, command, raw_dir, ledger,
                timeout, max_retries, retry_backoff,
            )
            if checkpoint is not None:
                checkpoint.mark_done(command.dedup_key, record)
            new_records.append(record)

            if command.text == "ROUTE" and record is not None:
                vhost = record.get("vhost")
                route_key = record.get("route_key")
                if vhost and checkpoint is not None:
                    checkpoint.set_meta("vhost", vhost)
                    checkpoint.set_meta("route_key", route_key)

        if record is not None:
            records.append(record)

    if new_records:
        with open(normalized_path, "a") as f:
            for record in new_records:
                f.write(json.dumps(record, sort_keys=True) + "\n")

    return {
        "host": host,
        "port": port,
        "protocol": "signal",
        "commands_attempted": len(command_list),
        "records_written": len(new_records),
        "records_total": len(records),
        "normalized_file": str(normalized_path.relative_to(output_dir)),
        "raw_dir": str(raw_dir.relative_to(output_dir)),
    }


def _run_one_command(
    guard: ScopeGuard,
    host: str,
    port: int,
    command: Command,
    raw_dir: Path,
    ledger: RequestLedger,
    timeout: float,
    max_retries: int,
    retry_backoff: float,
) -> dict:
    runtime_id = guard.assignment.get("runtime_id")
    last_error: Optional[Exception] = None

    for attempt in range(1, max_retries + 2):
        try:
            guard.check(host, port)
        except ScopeViolation as exc:
            ledger.record(
                purpose=command.purpose, host=host, port=port, protocol="signal",
                attempt=attempt, scope_verdict=f"denied: {exc}", result="not sent",
                runtime_id=runtime_id,
            )
            raise

        started_at = time.time()
        banner = b""
        response_line = ""
        timed_out = False
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock_file = sock.makefile("rwb")
                banner = sock_file.readline(256)
                sock_file.write((command.text + "\r\n").encode())
                sock_file.flush()
                try:
                    response_bytes = sock_file.readline(256)
                except socket.timeout:
                    response_bytes = b""
                if not response_bytes:
                    timed_out = True
                response_line = response_bytes.decode("utf-8", errors="replace").strip()
        except (OSError, socket.timeout) as exc:
            last_error = exc
            ledger.record(
                purpose=command.purpose, host=host, port=port, protocol="signal",
                attempt=attempt, scope_verdict="approved", result=f"error: {exc}",
                runtime_id=runtime_id,
            )
            if attempt <= max_retries:
                time.sleep(retry_backoff * attempt)
                continue
            raise DiscoveryError(
                f"{command.text} to {host}:{port} failed after {attempt} attempt(s): {exc}"
            )

        finished_at = time.time()

        if timed_out:
            # A timeout is a completed, well-defined outcome for this
            # protocol (the server chose not to respond) -- not a
            # transport failure, so it is NOT retried, matching how an
            # HTTP 404 isn't retried either.
            status_code = 408
        else:
            status_code = _classify_response(response_line)

        raw_content = (
            b"BANNER: " + banner
            + f"> {command.text}\n".encode()
            + f"< {response_line or '(no response / timeout)'}\n".encode()
        )
        raw_path = write_raw(
            raw_dir / f"{host}_{port}_{command.text.lower()}.raw", raw_content
        )

        ledger.record(
            purpose=command.purpose, host=host, port=port, protocol="signal",
            attempt=attempt, scope_verdict="approved", result=f"LINE {status_code}",
            runtime_id=runtime_id,
        )

        record = {
            "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at)),
            "target": f"{host}:{port}",
            "port": port,
            "protocol": "signal",
            "service": "signal",
            "source_tool": "recon_engine.signal_discovery",
            "source_file": raw_path.name,
            "confidence": "high",
            "notes": command.purpose,
            "command": command.text,
            "status": status_code,
            "response": response_line,
            "banner": banner.decode("utf-8", errors="replace").strip(),
            "duration_s": round(finished_at - started_at, 4),
            "attempts": attempt,
        }

        if command.text == "ROUTE" and status_code == 200:
            # Parse "route=<vhost>; proof=<route_key>" -- exact format
            # from local_lab.py's signal_handler.
            parts = dict(
                kv.strip().split("=", 1) for kv in response_line.split(";") if "=" in kv
            )
            record["vhost"] = parts.get("route")
            record["route_key"] = parts.get("proof")

        record["fingerprint"] = compute_fingerprint(record)
        return record

    raise DiscoveryError(f"{command.text} to {host}:{port} failed: {last_error}")
