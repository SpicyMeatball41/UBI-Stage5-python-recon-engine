# Integrity Attestation

This submission's evidence was produced by the candidate-authored
engine in `recon-engine/`, run from a clean checkout, against the
assigned local target only.

- **Scope enforcement**: every request is gated by
  `recon_engine.scope_guard.ScopeGuard.check()` before any socket is
  opened (see `tests/test_net_guard_enforcement.py`). The OUT-marked
  decoy in `scope-register.csv` was never contacted.
- **Reconciliation**: the engine's own ledger (`request-ledger.csv`)
  and the target's independent ledger
  (`recon-engine/target-evidence/target-request-ledger.jsonl`) were
  compared for this run: reconciled = True.
  0 engine attempt(s) reached an authorized service and got a response in this run; target independently logged 0 new request(s) since this run started; 0 attempt(s) were denied before any packet was sent.
- **Result hash**: `bb740e490514bd5682d87aa95f53c9c684b614c1a5ef7d329dc9292577dc5c6b`
  (see `schemas/SCHEMA.md` for exactly which fields are excluded and
  why -- timestamps and durations only).
- **manifest.sha256** covers every file in this submission and was
  regenerated as the last packaging step, after all other artifacts
  were written.

No request was made beyond the authorized foothold
(`GET /ops-diagnostics` then `GET /user.txt`); no privilege escalation
or generic exploitation was attempted -- see
`recon-engine/recon_engine/adapters/foothold.py`.
