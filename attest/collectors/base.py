"""What every collector shares: emitting records, reading secrets, describing itself.

A collector is `collect(ctx) -> CollectResult`. It never sees a token literal —
params name the environment variable (`token_env`) and `secret()` reads it. It
never guesses control ids — `emit()` derives them from the kind via the catalog,
and refuses kinds and sources the catalog does not know.
"""
from __future__ import annotations

import inspect
import os
from datetime import datetime, timezone

from attest.controls import default_catalog
from attest.sources import source_by_id, source_for_kind

_KIND_TO_CONTROLS: dict[str, list[str]] | None = None


def controls_for_kind(kind: str) -> list[str]:
    global _KIND_TO_CONTROLS
    if _KIND_TO_CONTROLS is None:
        m: dict[str, list[str]] = {}
        for c in default_catalog():
            for k in c.required_kinds:
                m.setdefault(k, []).append(c.id)
        _KIND_TO_CONTROLS = m
    return list(_KIND_TO_CONTROLS.get(kind, []))


def secret(params: dict, name: str, required: bool = True) -> str | None:
    """Read the secret whose environment-variable NAME is params[f"{name}_env"]."""
    env_name = params.get(f"{name}_env")
    if not env_name:
        if required:
            raise PermissionError(f"params.{name}_env must name the environment variable holding the {name}")
        return None
    value = os.environ.get(env_name)
    if not value and required:
        raise PermissionError(f"environment variable {env_name} (params.{name}_env) is not set")
    return value


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def emit(ctx, *, kind: str, summary: str, result: str, source: str | None = None, classification: str = "publishable",
         control_ids: list[str] | None = None, collected_at: str | None = None, **extra):
    """Append one evidence record through the context's store.

    `source` defaults to the catalog source that owns `kind`; `control_ids` default to the
    controls whose required kinds include it. Unknown kinds raise so a typo cannot create
    evidence nothing evaluates.
    """
    if result not in ("pass", "fail"):
        raise ValueError(f"result must be 'pass' or 'fail', got {result!r}")
    owner = source_for_kind(kind)
    if owner is None:
        raise ValueError(f"unknown evidence kind {kind!r} — add it to attest/sources.py first")
    src = source or owner.id
    if source_by_id(src) is None:
        raise ValueError(f"unknown source {src!r}")
    payload = {"summary": summary, "result": result, "collected_by": getattr(ctx.source, "id", src), **extra}
    kwargs = dict(source=src, kind=kind, control_ids=control_ids if control_ids is not None else controls_for_kind(kind),
                  classification=classification, payload=payload, collected_at=collected_at or now_iso())
    if "run_id" in inspect.signature(ctx.store.append).parameters:
        kwargs["run_id"] = getattr(ctx, "run_id", None)
    return ctx.store.append(**kwargs)
