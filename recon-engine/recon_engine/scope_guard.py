#!/usr/bin/env python3
"""
ScopeGuard: a hard authorization gate for the recon engine.

Every piece of networking code (sockets, HTTP clients, etc.) MUST call
ScopeGuard.check(host, port) immediately before it opens a connection.
The guard is the single source of truth for "am I allowed to touch this
target right now" and enforces four independent conditions:

  1. Rate limit: no more than `maximum_rate_per_second` approved calls
     in any trailing one-second window (from assignment.json).
  2. Budget: the call must not exceed `request_budget` approved calls
     for the whole run (from assignment.json). Once exhausted, every
     further call is rejected, even for previously-approved targets.
  3. Loopback: the host must resolve to a loopback address. Any asset
     row (including a CIDR like 0.0.0.0/0 marked OUT) that matches a
     non-loopback address is refused.
  4. Scope table: the (address, port) pair must resolve to an "IN"
     entry in scope.csv AND (if authorized_ports is set in
     assignment.json) the port must be in that allow-list. Exact
     host:port rows take priority over CIDR rows, so a specific IN
     entry can carve an exception out of a broader OUT network, and a
     specific OUT entry always wins over a broader IN network.

Every check (approved or denied) is appended to the ledger file as one
JSON object per line, so there's an audit trail independent of the
scanner's own logs. Any violation raises ScopeViolation -- callers must
not catch it and silently continue; the whole point is to fail closed.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union


class ScopeViolation(Exception):
    """Raised when a network call would fall outside the approved scope."""


@dataclass
class ScopeEntry:
    raw_asset: str
    scope: str  # "IN" or "OUT"
    note: str = ""
    network: Optional[object] = None  # ipaddress network, set for CIDR rows
    host: Optional[str] = None        # set for host:port rows
    port: Optional[int] = None


class ScopeGuard:
    def __init__(
        self,
        scope_csv_path: Union[str, Path],
        assignment_path: Optional[Union[str, Path]] = None,
        ledger_path: Optional[Union[str, Path]] = None,
        budget: Optional[int] = None,
        max_rate_per_second: Optional[int] = None,
    ):
        self.scope_csv_path = Path(scope_csv_path)
        self._exact: dict = {}
        self._networks: list = []
        self._load_scope()

        self.assignment: dict = {}
        self.assignment_path = None
        if assignment_path is not None:
            self.assignment_path = Path(assignment_path)
            with open(self.assignment_path) as f:
                self.assignment = json.load(f)

        self.authorized_ports = set(self.assignment.get("authorized_ports", []))
        self.budget = budget if budget is not None else self.assignment.get(
            "request_budget", 100
        )
        self.max_rate_per_second = (
            max_rate_per_second
            if max_rate_per_second is not None
            else self.assignment.get("maximum_rate_per_second")
        )

        self.ledger_path = Path(ledger_path) if ledger_path else None

        self._used = 0
        self._approved_timestamps: list = []
        # A lock is required now that discover_http and other adapters
        # may call check() concurrently under bounded concurrency -- the
        # budget counter and rate-limit window are shared mutable state.
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------
    def _load_scope(self) -> None:
        if not self.scope_csv_path.exists():
            raise FileNotFoundError(
                f"scope file not found: {self.scope_csv_path}"
            )

        with open(self.scope_csv_path, newline="") as f:
            reader = csv.DictReader(f)
            required = {"asset", "scope"}
            if not required.issubset(set(reader.fieldnames or [])):
                raise ValueError(
                    f"scope.csv missing required columns {required}, "
                    f"got {reader.fieldnames}"
                )
            for row in reader:
                asset = row["asset"].strip()
                scope = row["scope"].strip().upper()
                note = row.get("notes", "").strip()

                if "/" in asset:
                    entry = ScopeEntry(
                        raw_asset=asset,
                        scope=scope,
                        note=note,
                        network=ipaddress.ip_network(asset, strict=False),
                    )
                    self._networks.append(entry)
                else:
                    host, _, port_str = asset.rpartition(":")
                    if not host:
                        raise ValueError(f"malformed asset row: {asset!r}")
                    port = int(port_str)
                    entry = ScopeEntry(
                        raw_asset=asset, scope=scope, note=note, host=host, port=port
                    )
                    self._exact[(host, port)] = entry

    # ------------------------------------------------------------------
    # Core check
    # ------------------------------------------------------------------
    def check(self, host: str, port: int) -> None:
        """Raise ScopeViolation unless host:port is fully in scope.

        Check order: rate limit, then budget, then loopback, then the
        scope table (exact host:port rows override CIDR rows). The
        whole decision + any state mutation happens under a single lock,
        so concurrent callers (multiple adapters running under bounded
        concurrency) never race on the budget counter or rate window --
        two threads can't both slip past a budget of 1 remaining, for
        instance.
        """
        with self._lock:
            now = time.monotonic()
            try:
                self._check_rate_limit(now)
                self._check_budget()
                address = self._resolve(host)
                self._check_loopback(host, address)
                self._check_scope_table(address, port)
            except ScopeViolation as exc:
                self._log(host, port, approved=False, reason=str(exc))
                raise

            # Only a fully-approved call consumes budget / rate slots.
            self._used += 1
            self._approved_timestamps.append(now)
            self._log(host, port, approved=True, reason="in scope")

    def in_scope_targets(self) -> list:
        """Return every (host, port, note) with an exact 'IN' row in
        scope.csv, filtered by authorized_ports if assignment.json set
        any. This is the ONLY sanctioned way to derive "the assigned
        service set" -- an OUT row (the decoy) can never appear here by
        construction, since only self._exact entries with scope=='IN'
        are considered at all."""
        targets = []
        for (host, port), entry in self._exact.items():
            if entry.scope != "IN":
                continue
            if self.authorized_ports and port not in self.authorized_ports:
                continue
            targets.append((host, port, entry.note))
        return sorted(targets)  # deterministic order

    # ------------------------------------------------------------------
    # Preflight validation (no budget/rate/ledger side effects)
    # ------------------------------------------------------------------
    def validate(self, host: str, port: Optional[int] = None) -> str:
        """Check that `host` (and `port`, if given) is in scope, WITHOUT
        consuming budget or a rate-limit slot and WITHOUT writing to the
        ledger. This is what the CLI uses before any actual scanning has
        started -- it answers "would this be allowed?" not "log that
        this happened."

        If `port` is omitted, the check only confirms the host is
        loopback and has at least one "IN" entry in scope.csv somewhere
        (any port) -- useful for validating a bare --target host before
        a specific port is chosen. Returns the resolved address.
        """
        address = self._resolve(host)
        self._check_loopback(host, address)
        if port is not None:
            self._check_scope_table(address, port)
        else:
            self._check_host_has_any_in_entry(address)
        return address

    def _check_host_has_any_in_entry(self, address: str) -> None:
        for (h, _p), entry in self._exact.items():
            if h == address and entry.scope == "IN":
                return
        for net_entry in self._networks:
            if net_entry.scope == "IN" and ipaddress.ip_address(address) in net_entry.network:
                return
        raise ScopeViolation(
            f"{address} has no 'IN' entry in {self.scope_csv_path.name} "
            "(no port specified, and no matching allow-listed row exists)"
        )

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------
    def _check_rate_limit(self, now: float) -> None:
        if not self.max_rate_per_second:
            return
        window_start = now - 1.0
        self._approved_timestamps = [
            t for t in self._approved_timestamps if t >= window_start
        ]
        if len(self._approved_timestamps) >= self.max_rate_per_second:
            raise ScopeViolation(
                f"rate limit exceeded ({self.max_rate_per_second}/s); "
                "refusing this request"
            )

    def _check_budget(self) -> None:
        if self._used >= self.budget:
            raise ScopeViolation(
                f"request budget exhausted ({self._used}/{self.budget})"
            )

    def _check_loopback(self, host: str, address: str) -> None:
        if not self._is_loopback(address):
            raise ScopeViolation(
                f"{host} ({address}) is not a loopback address; "
                "out-of-scope targets are refused"
            )

    def _check_scope_table(self, address: str, port: int) -> None:
        # Exact host:port entry wins over any CIDR entry.
        entry = self._exact.get((address, port))
        if entry is None:
            for net_entry in self._networks:
                if ipaddress.ip_address(address) in net_entry.network:
                    entry = net_entry
                    break

        if entry is None:
            raise ScopeViolation(
                f"{address}:{port} is not listed in {self.scope_csv_path.name}"
            )
        if entry.scope != "IN":
            raise ScopeViolation(
                f"{address}:{port} is marked {entry.scope} in "
                f"{self.scope_csv_path.name} ({entry.raw_asset}); refusing"
            )
        if self.authorized_ports and port not in self.authorized_ports:
            raise ScopeViolation(
                f"port {port} is not in authorized_ports "
                f"{sorted(self.authorized_ports)} from assignment"
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _resolve(host: str) -> str:
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        try:
            return socket.gethostbyname(host)
        except socket.gaierror as exc:
            raise ScopeViolation(f"could not resolve host {host!r}: {exc}")

    @staticmethod
    def _is_loopback(address: str) -> bool:
        try:
            return ipaddress.ip_address(address).is_loopback
        except ValueError:
            return False

    def _log(self, host: str, port: int, approved: bool, reason: str) -> None:
        if self.ledger_path is None:
            return
        record = {
            "ts": time.time(),
            "host": host,
            "port": port,
            "approved": approved,
            "reason": reason,
            "runtime_id": self.assignment.get("runtime_id"),
        }
        with open(self.ledger_path, "a") as f:
            f.write(json.dumps(record) + "\n")

    @property
    def remaining_budget(self) -> int:
        return max(0, self.budget - self._used)
