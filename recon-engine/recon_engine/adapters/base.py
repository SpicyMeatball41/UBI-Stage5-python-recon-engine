#!/usr/bin/env python3
"""
recon_engine.adapters.base -- the common interface every discovery
adapter implements.

Earlier phase-3 work satisfied "behind common interfaces" only by
convention: http_discovery.discover_http, signal_discovery.discover_signal,
and tls_probe.probe_tls were similarly-shaped standalone functions, but
nothing enforced that shape or let the orchestrator treat them
interchangeably. This module makes it a real, enforced contract.

Every adapter is a class implementing Adapter, with the same
`discover()` signature and the same guarantees:
  - scope decisions go through ScopeGuard.check() before any network
    action (enforced by each adapter's own implementation, not by this
    base class -- the interface can't force that, but every concrete
    adapter here does it)
  - progress is tracked via a Checkpoint for resume/dedup
  - results are appended to <output_dir>/normalized/assets.jsonl

The existing discover_http/discover_signal/probe_tls functions are kept
as-is (this is what the adapter classes call internally) -- wrapping
them in a common interface doesn't require rewriting logic that's
already tested and working.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional

from ..checkpoint import Checkpoint
from ..ledger import RequestLedger
from ..scope_guard import ScopeGuard
from .http_discovery import Probe, discover_http
from .signal_discovery import discover_signal
from .tls_probe import probe_tls


class Adapter(ABC):
    """Common interface for every discovery adapter."""

    #: Short identifier used in logs/reports (e.g. "http", "signal").
    name: str

    @abstractmethod
    def discover(
        self,
        guard: ScopeGuard,
        host: str,
        port: int,
        output_dir: Path,
        ledger: RequestLedger,
        checkpoint: Optional[Checkpoint] = None,
        timeout: float = 5.0,
    ) -> dict:
        """Run this adapter's discovery against host:port. Returns a
        summary dict describing what was attempted/written. Must never
        touch any host:port other than the one given."""
        raise NotImplementedError


class HttpAdapter(Adapter):
    name = "http"

    def __init__(
        self,
        probes: Optional[List[Probe]] = None,
        max_retries: int = 2,
        retry_backoff: float = 0.5,
    ):
        self.probes = probes
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff

    def discover(self, guard, host, port, output_dir, ledger, checkpoint=None, timeout=5.0):
        entry_url = f"http://{host}:{port}/"
        return discover_http(
            guard, entry_url, output_dir, ledger,
            probes=self.probes, checkpoint=checkpoint, timeout=timeout,
            max_retries=self.max_retries, retry_backoff=self.retry_backoff,
        )


class SignalAdapter(Adapter):
    name = "signal"

    def discover(self, guard, host, port, output_dir, ledger, checkpoint=None, timeout=5.0):
        return discover_signal(guard, host, port, output_dir, ledger, checkpoint=checkpoint, timeout=timeout)


class TlsAdapter(Adapter):
    name = "tls"

    def discover(self, guard, host, port, output_dir, ledger, checkpoint=None, timeout=5.0):
        # probe_tls doesn't take a checkpoint today (it's a single
        # cheap probe, not a multi-step sequence) -- the interface
        # still accepts one for uniformity, it's just unused here.
        return probe_tls(guard, host, port, output_dir, ledger, timeout=timeout)


class ToolUnavailableError(Exception):
    """Raised by an adapter that depends on an optional external tool
    (e.g. nmap) when that tool isn't present. Distinct from a scope
    denial or a network failure: this means "the supported discovery
    path via a different adapter should still complete," not
    "discovery failed.\""""
