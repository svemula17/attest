"""Shared helpers: UTC timestamps and canonical JSON (stdlib only)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def now_iso() -> str:
    """Current UTC time as 'YYYY-MM-DDTHH:MM:SSZ' (second precision)."""
    return datetime.now(timezone.utc).strftime(ISO_FORMAT)


def parse_iso(s: str) -> datetime:
    """Parse 'YYYY-MM-DDTHH:MM:SSZ' (a trailing '+00:00' is also accepted) into an aware UTC datetime."""
    if not isinstance(s, str):
        raise TypeError(f"expected str, got {type(s).__name__}")
    text = s.strip()
    if text.endswith("+00:00"):
        text = text[: -len("+00:00")] + "Z"
    try:
        naive = datetime.strptime(text, ISO_FORMAT)
    except ValueError as exc:
        raise ValueError(f"invalid ISO 8601 UTC timestamp: {s!r}") from exc
    return naive.replace(tzinfo=timezone.utc)


def canonical_json(obj) -> str:
    """Deterministic JSON encoding: sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))
