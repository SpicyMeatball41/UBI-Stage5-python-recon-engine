# Normalized Record Schema

All discovery output lands in `normalized/assets.jsonl` -- one JSON
object per line, one line per completed request/probe. Every record
type shares a common core; each protocol adds its own fields on top.

## Common fields (every record)

| Field | Type | Meaning |
|---|---|---|
| `observed_at` | string (ISO 8601 UTC) | When the request completed. Volatile -- excluded from the result hash. |
| `target` | string | `host:port` |
| `port` | int | Target port |
| `protocol` | string | `http`, `signal`, `tls`, `dns`, or `nmap` |
| `service` | string | Human-readable service label |
| `source_tool` | string | Which adapter produced this record (e.g. `recon_engine.http_discovery`, or `nmap` itself) |
| `source_file` | string \| null | Filename under `raw/<protocol>/` holding the unedited response this record was derived from |
| `confidence` | string | `high` or `low` -- low when a signal (e.g. nmap's service match) was inconclusive |
| `notes` | string | Free-text context (probe purpose, error detail, etc.) |
| `fingerprint` | string | Canonical multi-signal fingerprint (see `recon_engine/fingerprint.py`) -- distinguishes services with matching status/length but different declared identity |

## `protocol: "http"` (recon_engine/adapters/http_discovery.py, foothold.py)

| Field | Meaning |
|---|---|
| `path` | Request path |
| `status` | HTTP status code |
| `length` | Response body length in bytes |
| `body_sha256` | SHA-256 of the response body (baseline probes only) |
| `duration_s` | Request duration. Volatile -- excluded from the result hash. |
| `attempts` | How many tries this took (1 = succeeded first try) |
| `server` | `Server` response header, if present |
| `vhost` | Host header sent, if this was a vhost-targeted probe (absent = wildcard/default baseline) |
| `title` | `<title>` extracted from HTML body (vhost probes only) |
| `redirect` | `Location` header, if present (vhost probes only) |
| `baseline_difference` | `true`/`false`/`null` -- whether this vhost response differs from the wildcard baseline for the same path |

Foothold-specific records (`source_tool: recon_engine.foothold`) use
the same shape; `path` is `/ops-diagnostics` or `/user.txt`.

## `protocol: "signal"` (recon_engine/adapters/signal_discovery.py)

| Field | Meaning |
|---|---|
| `command` | Line-protocol command sent (`CAPS`, `ROUTE`, ...) |
| `status` | Status-like code: 200 (recognized), 400 (`ERR`), 408 (timeout) |
| `response` | Raw response line |
| `banner` | Connection banner |
| `vhost` | Extracted from a successful `ROUTE` response |
| `route_key` | Extracted from a successful `ROUTE` response |
| `duration_s`, `attempts` | Same meaning as HTTP |

## `protocol: "tls"` (recon_engine/adapters/tls_probe.py)

| Field | Meaning |
|---|---|
| `tls_available` | Whether the TLS handshake succeeded |
| `tls_version` | Negotiated version, or `null` if unavailable |
| `duration_s` | Same meaning as HTTP |

## `protocol: "dns"` (recon_engine/adapters/dns_baseline.py)

| Field | Meaning |
|---|---|
| `is_literal_ip` | Whether the target was a literal IP (no resolution performed -- see the module's docstring for why a live query is never issued) |
| `resolved_address` | The address used |
| `duration_s` | Same meaning as HTTP |

## `protocol: "nmap"` (recon_engine/adapters/nmap_scan.py -- optional enrichment)

| Field | Meaning |
|---|---|
| `product`, `version` | Parsed from nmap's `-oX` output, if identified |
| `duration_s` | Same meaning as HTTP |

Absence of any `nmap:` records in a run is not an error -- see
`tool_fallbacks` in `run.json` for the documented fallback path.

## Ledgers (not part of assets.jsonl, but part of the same evidence chain)

- `request-ledger.jsonl` -- the engine's own record of every attempt
  (approved or denied), with `purpose`, `target`, `result`, and
  `scope_verdict` together on one line. See `recon_engine/ledger.py`.
- `target-request-ledger.jsonl` -- written independently by the lab
  target itself. Reconciled against the engine's ledger by
  `recon_engine/reconcile.py`; see `reconciliation` in `run.json`.

## Top-level run manifest (`run.json`)

Includes `phase1_validation`, `phase2_observation` (the full
orchestrator summary: `targets`, `results`, `errors`,
`tool_fallbacks`), `reconciliation`, `normalized_result_hash`
(see `recon_engine/resulthash.py` for exactly which fields are
excluded and why), and paths to every other artifact.
