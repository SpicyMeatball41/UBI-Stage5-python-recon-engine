#!/usr/bin/env python3
"""
recon_engine.resulthash -- a canonical hash over normalized discovery
output, independent of wall-clock timing.

This exists specifically for the comparison the brief calls for:
"the resumed/fallback run must produce the same normalized result hash
as an uninterrupted run." A byte-for-byte diff of assets.jsonl would
never match between two separate runs even when the actual DISCOVERY
content is identical, because observed_at and duration_s are
necessarily different every time. This module strips exactly those
volatile fields, sorts records into a stable order, and hashes what's
left -- so the hash reflects "what was discovered," not "when."
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import List

# Fields that are expected to legitimately differ between two
# equivalent runs and must not affect the hash.
_VOLATILE_FIELDS = {"observed_at", "duration_s"}


def _canonicalize(record: dict) -> dict:
    return {k: v for k, v in record.items() if k not in _VOLATILE_FIELDS}


def _sort_key(record: dict):
    # Stable, content-based ordering so two runs that discovered the
    # same things in a different wall-clock order still hash equal.
    return (
        record.get("target", ""),
        record.get("protocol", ""),
        record.get("path", record.get("command", "")),
        record.get("vhost", ""),
    )


def compute_normalized_hash(output_dir: Path) -> str:
    """Read <output_dir>/normalized/assets.jsonl and return a sha256 hex
    digest over its canonicalized, order-independent content. Returns
    the hash of an empty list if the file doesn't exist or has no
    records -- never raises for a missing file."""
    assets_path = output_dir / "normalized" / "assets.jsonl"
    records: List[dict] = []
    if assets_path.exists():
        with open(assets_path) as f:
            records = [json.loads(line) for line in f if line.strip()]

    canonical = sorted((_canonicalize(r) for r in records), key=_sort_key)
    canonical_json = json.dumps(canonical, sort_keys=True)
    return hashlib.sha256(canonical_json.encode()).hexdigest()
