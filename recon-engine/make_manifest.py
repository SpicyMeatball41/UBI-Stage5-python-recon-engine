#!/usr/bin/env python3
"""
make_manifest.py -- regenerates manifest.sha256 over the submission
package: source, tests, schemas, raw output, normalized output, both
ledgers, foothold evidence, and the report.

Run from recon-engine/ after copying target-request-ledger.jsonl in
(see the accompanying instructions) and before zipping/uploading:

    python3 make_manifest.py

Writes manifest.sha256 in the current directory: one line per file,
"<sha256>  <relative_path>", sorted for a deterministic, diffable
output. .git/ and __pycache__/ are excluded -- .git is the commit
history itself (auditable via `git log`, not a flat file to hash), and
__pycache__ is a build artifact that shouldn't be part of the manifest
at all (see the .gitignore added alongside this).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

EXCLUDE_DIR_NAMES = {".git", "__pycache__", ".pytest_cache"}
EXCLUDE_FILE_NAMES = {"manifest.sha256", ".recon_engine_write_test"}


def should_skip(path: Path) -> bool:
    if path.name in EXCLUDE_FILE_NAMES:
        return True
    return any(part in EXCLUDE_DIR_NAMES for part in path.parts)


def main() -> None:
    root = Path(".").resolve()
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        rel = path.relative_to(root)
        if should_skip(rel):
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(f"{digest}  {rel.as_posix()}")

    manifest_path = root / "manifest.sha256"
    manifest_path.write_text("\n".join(entries) + "\n")
    print(f"wrote {manifest_path} ({len(entries)} files)")


if __name__ == "__main__":
    main()
