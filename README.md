# Submission

## Layout
- `recon-engine/` -- full source, including `.git` commit history
- `tests/` -- top-level copy of the test suite for convenience
- `schemas/` -- normalized record schema (`SCHEMA.md`)
- `attack-surface-report.pdf` -- generated report (source: `recon-engine/run/report.html`)
- `scope-register.csv` -- the scope file used for this run
- `raw-output/` -- unedited responses, one file per request
- `normalized.json` -- normalized discovery records (JSON array)
- `request-ledger.csv` -- the engine's own request ledger
- `foothold-evidence.txt` -- the authorized foothold chain, raw + normalized
- `test-results.xml` -- JUnit-style test suite output
- `evidence-index.csv` -- catalog of every evidence file with its SHA-256
- `integrity-attestation.md` -- scope/integrity summary for this run
- `assessment-manifest.json` -- structured run summary
- `continuity-record.md` -- resume/interrupt/fallback/profile-restart test results
- `manifest.sha256` -- SHA-256 of every file above (regenerated last)

## Reproducing from a clean checkout
```
cd recon-engine
python3 -m unittest discover -s tests -v
python3 -m recon_engine.cli --target 127.0.0.1 --scope <scope.csv> --output run --rate 25
```
