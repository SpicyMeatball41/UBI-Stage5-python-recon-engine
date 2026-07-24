#!/usr/bin/env python3
"""
recon_engine.json_parser -- defensive JSON parsing for arbitrary,
unseen response bodies.

Every adapter that might receive a JSON response (currently
foothold.py's /ops-diagnostics, but this is written generically so any
future adapter can use it too) needs to handle whatever a target
actually sends back -- not just the one shape seen during development.
A raw `json.loads()` call fails hard on anything malformed, and a bare
`payload["key"]` fails hard on anything with a different shape. Both
are the wrong behavior for a discovery engine: a response that doesn't
parse or doesn't have the expected fields is a FINDING (worth
recording), not a crash.

This module never raises for malformed input -- it always returns a
ParseResult describing what happened, so callers can decide how to
proceed (foothold.py treats "no usable credentials" as FootholdError,
not an uncaught exception).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional, Union

# Defensive limits -- a discovery engine should not be brought down by
# a target that returns pathological input (extreme nesting is the
# classic JSON-parser DoS vector; Python's own json module has no
# built-in depth limit).
MAX_DEPTH = 32
MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MiB


@dataclass
class ParseResult:
    ok: bool
    value: Any = None
    error: Optional[str] = None

    def get_path(self, *keys: str, default: Any = None) -> Any:
        """Safely walk a chain of keys through nested dicts. Returns
        `default` the moment anything along the path isn't a dict or
        doesn't have that key -- never raises, regardless of how
        different the actual shape turns out to be from what was
        expected."""
        if not self.ok:
            return default
        current = self.value
        for key in keys:
            if not isinstance(current, dict) or key not in current:
                return default
            current = current[key]
        return current


def parse_json(body: Union[bytes, str]) -> ParseResult:
    """Parse `body` as JSON. Never raises: malformed JSON, oversized
    input, or excessive nesting all come back as ok=False with a
    human-readable `error`, not an exception."""
    if isinstance(body, bytes):
        if len(body) > MAX_BODY_BYTES:
            return ParseResult(ok=False, error=f"body exceeds {MAX_BODY_BYTES} bytes, refusing to parse")
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            return ParseResult(ok=False, error=f"body is not valid UTF-8: {exc}")
    else:
        text = body
        if len(text.encode("utf-8", errors="replace")) > MAX_BODY_BYTES:
            return ParseResult(ok=False, error=f"body exceeds {MAX_BODY_BYTES} bytes, refusing to parse")

    if not text.strip():
        return ParseResult(ok=False, error="empty body")

    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        return ParseResult(ok=False, error=f"invalid JSON: {exc}")
    except RecursionError:
        return ParseResult(ok=False, error="JSON nesting exceeded interpreter recursion limit")

    depth_error = _check_depth(value, 0)
    if depth_error:
        return ParseResult(ok=False, error=depth_error)

    return ParseResult(ok=True, value=value)


def _check_depth(value: Any, depth: int) -> Optional[str]:
    if depth > MAX_DEPTH:
        return f"JSON nesting exceeds MAX_DEPTH={MAX_DEPTH}"
    if isinstance(value, dict):
        for v in value.values():
            err = _check_depth(v, depth + 1)
            if err:
                return err
    elif isinstance(value, list):
        for v in value:
            err = _check_depth(v, depth + 1)
            if err:
                return err
    return None
