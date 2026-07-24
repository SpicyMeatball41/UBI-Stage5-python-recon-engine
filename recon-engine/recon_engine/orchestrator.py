#!/usr/bin/env python3
"""
recon_engine.orchestrator -- ties every adapter together behind bounded
concurrency, with resumable checkpoints and a hard structural guarantee
that only the assigned (scope.csv "IN") service set is ever touched.

Decoy safety is NOT a runtime check here -- it's a construction
property: run_discovery() only ever builds its target list from
ScopeGuard.in_scope_targets(), which by definition excludes every "OUT"
row (including the decoy). There is no code path in this module that
can accept an arbitrary host/port from outside; the only inputs are
what scope.csv itself marked "IN". Even so, ScopeGuard.check() is still
called before every single request, so a scope mistake anywhere would
still be caught and logged, not just silently trusted.

Concurrency is bounded (a small thread pool, default 2 workers) and
safe: ScopeGuard.check(), RequestLedger.record(), and Checkpoint's
methods are all internally locked, so multiple adapters running at
once never race on the shared budget counter, rate-limit window,
ledger file, or checkpoint file.

Core adapters (http, signal) are dispatched through the common Adapter
interface (recon_engine.adapters.base) rather than protocol-specific
branching, so adding a new required adapter later is "add one dispatch
table entry," not "add another elif." nmap is handled separately
because it's optional and enrichment-only: its absence is recorded as
a fallback note, never an error, and discovery is already complete
without it.
"""

from __future__ import annotations

import concurrent.futures
import subprocess
from pathlib import Path
from typing import Optional

from .adapters.base import Adapter, HttpAdapter, SignalAdapter, TlsAdapter, ToolUnavailableError
from .adapters.dns_baseline import establish_dns_baseline
from .adapters.foothold import FootholdEvidenceMissing, FootholdError, pursue_foothold
from .adapters.http_discovery import DiscoveryError as HttpError
from .adapters.http_discovery import Probe, discover_http
from .adapters.nmap_scan import scan_with_nmap
from .adapters.signal_discovery import DiscoveryError as SignalError
from .checkpoint import Checkpoint
from .ledger import RequestLedger
from .scope_guard import ScopeGuard, ScopeViolation

# Adapter selection is driven by scope.csv's own "notes" column, which
# is how this lab's scope.csv already documents each service's kind
# (see "HTTP discovery target" / "line-protocol discovery target").
# This is a lightweight, explicit mapping -- not protocol sniffing --
# so it's always clear from the scope file itself which adapter a
# service gets.
_PROTOCOL_HINTS = (
    ("http", "http"),
    ("line-protocol", "signal"),
    ("line protocol", "signal"),
)

# Dispatch table over the common Adapter interface -- the orchestrator
# calls .discover(...) uniformly, never a protocol-specific function.
_ADAPTERS: dict = {
    "http": HttpAdapter(),
    "signal": SignalAdapter(),
}


class UnknownServiceError(Exception):
    """An IN-scope, authorized service has no adapter mapping. This is
    a configuration gap, not a scope problem -- the request was never
    attempted."""


def _infer_protocol(note: str) -> Optional[str]:
    note_lower = note.lower()
    for hint, protocol in _PROTOCOL_HINTS:
        if hint in note_lower:
            return protocol
    return None


def run_discovery(
    guard: ScopeGuard,
    output_dir: Path,
    max_workers: int = 2,
    timeout: float = 5.0,
    nmap_timeout: float = 30.0,
) -> dict:
    """Discover every assigned (IN-scope, authorized) service, bounded
    to `max_workers` concurrent adapters, with resumable checkpointing.

    `timeout` governs the http/signal/tls adapters, which each make a
    single lightweight request -- 5s is generous for those. `nmap`,
    when present, needs its own separate, much longer timeout: a
    version-detection scan (`-sV`) routinely takes well past 5
    seconds, and a scan killed by too-short a timeout can still have
    sent several probes to the target before being killed, which
    throws off ledger reconciliation without actually being a scope
    problem. Passing the short `timeout` into nmap was a bug fixed
    here -- nmap now always gets `nmap_timeout` instead.

    Returns a summary dict: targets considered, per-target results,
    per-target errors (if any), tool_fallbacks (optional tools that
    were unavailable -- informational, not a failure), and paths to
    the ledger/checkpoint.
    """
    ledger = RequestLedger(output_dir / "request-ledger.jsonl")
    checkpoint = Checkpoint(output_dir / "checkpoint.json")
    targets = guard.in_scope_targets()  # [(host, port, note), ...] -- IN only, ever

    results: dict = {}
    errors: dict = {}
    tool_fallbacks: dict = {}

    # DNS baseline: once per unique host, before anything else. Cheap
    # and (for a literal IP, which is every case in this lab) sends no
    # network traffic at all -- see dns_baseline's module docstring for
    # why a REAL DNS query would itself be a scope violation here.
    for host in sorted({h for h, _p, _n in targets}):
        rep_port = next(p for h2, p, _n in targets if h2 == host)
        try:
            results[f"dns:{host}"] = establish_dns_baseline(
                guard, host, rep_port, output_dir, ledger, checkpoint=checkpoint
            )
        except ScopeViolation as exc:
            errors[f"dns:{host}"] = str(exc)

    def _run_one(host: str, port: int, note: str):
        protocol = _infer_protocol(note)
        adapter: Optional[Adapter] = _ADAPTERS.get(protocol)
        if adapter is None:
            raise UnknownServiceError(
                f"no adapter mapping for {host}:{port} (notes={note!r})"
            )
        return adapter.discover(guard, host, port, output_dir, ledger, checkpoint=checkpoint, timeout=timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {
            pool.submit(_run_one, host, port, note): f"{host}:{port}"
            for host, port, note in targets
        }
        for future in concurrent.futures.as_completed(future_map):
            key = future_map[future]
            try:
                results[key] = future.result()
            except (ScopeViolation, HttpError, SignalError, UnknownServiceError) as exc:
                errors[key] = str(exc)

    # Vhost follow-up: if the signal adapter discovered a vhost, run a
    # SECOND, targeted wave of HTTP probes with that Host header --
    # against the SAME already-authorized HTTP target only. This is
    # still bounded to in-scope targets; it never introduces a new host
    # or port.
    vhost = checkpoint.get_meta("vhost")
    http_target = next(
        ((host, port, note) for host, port, note in targets if _infer_protocol(note) == "http"),
        None,
    )
    if vhost and http_target:
        host, port, _note = http_target
        entry_url = f"http://{host}:{port}/"
        vhost_probes = [
            Probe(path="/", purpose="vhost baseline", host_header=vhost),
            Probe(path="/robots.txt", purpose="vhost robots.txt", host_header=vhost),
        ]
        key = f"{host}:{port}:vhost:{vhost}"
        try:
            results[key] = discover_http(
                guard, entry_url, output_dir, ledger,
                probes=vhost_probes, checkpoint=checkpoint, timeout=timeout,
            )
        except (ScopeViolation, HttpError) as exc:
            errors[key] = str(exc)

    # Optional TLS/SNI probe against the HTTP target. Unavailable is a
    # graceful, normalized finding, not a failure -- see tls_probe's
    # module docstring.
    if http_target:
        host, port, _note = http_target
        tls_key = f"tls:{host}:{port}"
        if not checkpoint.is_done(tls_key):
            try:
                tls_adapter = TlsAdapter()
                tls_result = tls_adapter.discover(guard, host, port, output_dir, ledger, timeout=timeout)
                checkpoint.mark_done(tls_key, tls_result)
                results[tls_key] = {"protocol": "tls", "record": tls_result}
            except ScopeViolation as exc:
                errors[tls_key] = str(exc)

    # Optional nmap enrichment -- HTTP targets only. nmap's -sV probes
    # a large database of standard protocol fingerprints when it can't
    # immediately recognize a service; against this lab's custom line
    # protocol on the signal port, that turns into dozens of extra
    # connections while it works through probes that will never match,
    # for no real benefit (signal_discovery.py already understands that
    # protocol correctly, in exactly two requests). Restricting nmap to
    # HTTP -- a protocol it recognizes near-instantly -- keeps this
    # enrichment step fast and its request volume predictable. Missing
    # nmap entirely is a documented fallback, not a failure: everything
    # above already completed the supported discovery path without it.
    for host, port, note in targets:
        if _infer_protocol(note) != "http":
            continue
        nmap_key = f"nmap:{host}:{port}"
        try:
            results[nmap_key] = scan_with_nmap(
                guard, host, port, output_dir, ledger, checkpoint=checkpoint, timeout=nmap_timeout
            )
        except ToolUnavailableError as exc:
            tool_fallbacks[nmap_key] = (
                f"{exc} -- falling back to built-in adapters only "
                "(already completed above; this is informational, not a failure)"
            )
        except ScopeViolation as exc:
            errors[nmap_key] = str(exc)
        except (OSError, subprocess.TimeoutExpired) as exc:
            # nmap IS present but the scan itself failed -- a real
            # per-target error, but still must not abort the whole
            # run: everything else already succeeded above.
            errors[nmap_key] = f"nmap scan failed: {exc}"

    # Foothold: the ONE authorized action beyond discovery, pursued
    # only if the evidence for it (vhost + route_key) is already in
    # hand from the signal adapter's ROUTE command above. This never
    # runs speculatively -- see foothold.py's module docstring for why
    # that boundary is structural, not just a comment.
    foothold_summary = None
    if http_target and vhost:
        host, port, _note = http_target
        try:
            foothold_summary = pursue_foothold(
                guard, host, port, output_dir, ledger, checkpoint, timeout=timeout
            )
            results[f"foothold:{host}:{port}"] = foothold_summary
        except FootholdEvidenceMissing:
            pass  # not an error -- nothing to follow yet
        except (ScopeViolation, FootholdError) as exc:
            errors[f"foothold:{host}:{port}"] = str(exc)

    return {
        "targets": [{"host": h, "port": p, "note": n} for h, p, n in targets],
        "results": results,
        "errors": errors,
        "tool_fallbacks": tool_fallbacks,
        "ledger_path": str(ledger.path),
        "checkpoint_path": str(checkpoint.path),
        "vhost_discovered": vhost,
        "foothold": foothold_summary,
    }
