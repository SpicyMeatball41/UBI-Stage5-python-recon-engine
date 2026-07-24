# Continuity Record

Phase 5 verification of interrupt/resume/fallback and profile-restart
behavior. Full automated proof lives in:

- `tests/test_interrupt_disable_resume.py` -- interrupts a run mid-flight,
  resumes it with `nmap` explicitly disabled, and asserts zero duplicate
  normalized records and zero duplicate ledger sequence numbers.
- `tests/test_resume_integrity.py` -- proves an interrupted-then-resumed
  run produces an IDENTICAL normalized result hash to an uninterrupted
  run, at both the single-adapter and full-orchestrator level.
- `tests/test_profile_restart_metrics.py` -- restarts the target under
  two different markers/profiles and measures recall (100% expected),
  scope violations (0 expected), request count (<=240), and
  reconciliation, plus hash stability across two runs of the same live
  session.

Run `python3 -m unittest discover -s tests -v` from `recon-engine/` to
reproduce all of the above from this checkout.
