#!/usr/bin/env python3
"""
recon_engine.raw_capture -- enforces that raw evidence is never
overwritten, independent of whatever protection the checkpoint's
dedup logic happens to provide.

Before this module existed, every adapter computed a deterministic raw
filename (host_port_path.raw) and opened it with plain `open(path,
"wb")`. In normal operation the checkpoint's dedup logic prevents a
probe from ever running twice, so this never actually overwrote
anything -- but that made immutability an accident of the checkpoint
working correctly, not a property of the raw-capture code itself. If
the checkpoint file were ever deleted or desynced from raw/ (a stale
--output directory reused across unrelated runs, a bug in a future
adapter, manual intervention), a second capture at the same path would
silently destroy the first one with no record that it ever happened.

write_raw() makes overwriting structurally impossible: if the intended
path already exists, it writes to a disambiguated path instead
(appending __2, __3, ...) rather than ever touching the existing file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union


def write_raw(path: Path, content: Union[bytes, str]) -> Path:
    """Write `content` to `path`, WITHOUT ever overwriting an existing
    file at that path. If `path` already exists, writes to
    `path` with a `__2`, `__3`, ... suffix inserted before the
    extension instead. Returns the actual path written to (which
    callers should use for source_file in normalized records -- not
    necessarily the path they originally asked for).
    """
    target = _first_available_path(path)
    mode = "wb" if isinstance(content, bytes) else "w"
    with open(target, mode) as f:
        f.write(content)
    return target


def _first_available_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    n = 2
    while True:
        candidate = path.with_name(f"{stem}__{n}{suffix}")
        if not candidate.exists():
            return candidate
        n += 1
