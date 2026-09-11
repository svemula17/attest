"""One place that knows how to run each configured source type.

``COLLECTORS`` maps a ``[sources.<id>] type`` to a function that reads the source's
params, appends evidence, and returns a ``CollectResult``. ``run_source`` wraps one
collector with run bookkeeping (an optional duck-typed ``runs`` store with
``start(source_id, trigger, started_by) -> run_id`` and
``finish(run_id, status, records, error=None)``) and an audit entry either way;
``run_all`` walks every enabled source and keeps going past failures.

A collector that records a *failing* control (a leaver still active, an unprotected
branch) is still a successful run — the finding is the evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from attest.config import Config, SourceConfig


@dataclass
class CollectContext:
    store: Any
    audit: Any
    source: SourceConfig
    config: Config
    run_id: int | None = None


@dataclass
class CollectResult:
    records: int
    summary: str


def _param(ctx: CollectContext, name: str):
    value = ctx.source.params.get(name)
    if value in (None, "", []):
        raise ValueError(f"source '{ctx.source.id}' ({ctx.source.type}) needs params.{name}")
    return value


def _collect_file(ctx: CollectContext) -> CollectResult:
    """type = "csv" | "json": import a file through attest.importers (mapping inferred when omitted)."""
    from attest.importers import import_file
    path = ctx.config.resolve(str(_param(ctx, "path")))
    mapping = ctx.source.params.get("mapping") or ("evidence.json" if ctx.source.type == "json" else None)
    result = import_file(ctx.store, path, mapping=mapping, source=ctx.source.params.get("source"), run_id=ctx.run_id)
    noun = "record" if result.records == 1 else "records"
    summary = f"{result.records} {noun} from {path.name} ({', '.join(result.kinds)})"
    if result.warnings:
        summary += f"; {len(result.warnings)} warning(s): {result.warnings[0]}"
    return CollectResult(result.records, summary)


def _collect_github(ctx: CollectContext) -> CollectResult:
    """type = "github": default-branch protection for every repo in params.repos."""
    from attest.collectors.github import collect_branch_protection
    repos = _param(ctx, "repos")
    if isinstance(repos, str):
        repos = [repos]
    if not isinstance(repos, list) or not all(isinstance(r, str) for r in repos):
        raise ValueError(f"source '{ctx.source.id}': params.repos must be a list of 'owner/name' strings")
    token = ctx.source.params.get("token") or None  # collect_branch_protection falls back to $GITHUB_TOKEN / $GH_TOKEN
    total, parts = 0, []
    for repo in repos:
        records = collect_branch_protection(ctx.store, repo, token=token)
        total += len(records)
        parts.append(f"{repo}: " + ", ".join(f"{r.kind}={r.payload['result']}" for r in records))
    return CollectResult(total, "; ".join(parts))


def _collect_join(ctx: CollectContext) -> CollectResult:
    """type = "hris-idp-join": newest hris.roster × newest idp.users → access.leaver-deprovisioned."""
    from attest.collectors.joiner_leaver import run_join
    sla_hours = int(ctx.source.params.get("sla_hours", 24))
    record = run_join(ctx.store, sla_hours=sla_hours)
    return CollectResult(1, record.payload["summary"])


COLLECTORS: dict[str, Callable[[CollectContext], CollectResult]] = {
    "csv": _collect_file,
    "json": _collect_file,
    "github": _collect_github,
    "hris-idp-join": _collect_join,
}


def _lookup(config: Config, source_id: str) -> SourceConfig:
    try:
        return config.sources[source_id]
    except KeyError:
        known = ", ".join(sorted(config.sources)) or "none configured"
        raise ValueError(f"unknown source '{source_id}' (known: {known})") from None


def _execute(config: Config, src: SourceConfig, store, audit, runs, trigger: str, started_by: str | None) -> tuple[dict, BaseException | None]:
    """Run one source with bookkeeping. Never raises; returns (result dict, exception or None)."""
    collector = COLLECTORS.get(src.type)
    if collector is None:
        raise ValueError(f"source '{src.id}' has unknown type '{src.type}' (known: {', '.join(COLLECTORS)})")
    run_id = runs.start(src.id, trigger, started_by) if runs is not None else None
    actor = f"collector:{src.type}"
    out = {"source_id": src.id, "type": src.type, "status": "ok", "records": 0, "summary": "", "run_id": run_id, "error": None}
    try:
        result = collector(CollectContext(store=store, audit=audit, source=src, config=config, run_id=run_id))
    except Exception as e:  # noqa: BLE001 - every failure is recorded, then surfaced by the caller
        message = str(e) or type(e).__name__
        if runs is not None:
            runs.finish(run_id, "error", 0, message)
        audit.record(actor=actor, action="collect.error", subject=src.id, detail=message)
        out.update(status="error", error=message)
        return out, e
    if runs is not None:
        runs.finish(run_id, "ok", result.records)
    audit.record(actor=actor, action="collect.ok", subject=src.id, detail=result.summary)
    out.update(records=result.records, summary=result.summary)
    return out, None


def run_source(config: Config, source_id: str, store, audit, runs=None, trigger: str = "manual",
               started_by: str | None = None) -> dict:
    """Run one configured source. Returns {source_id, type, status, records, summary, run_id, error}.

    Unknown ids, disabled sources and unknown types raise ValueError before any run starts.
    A collector failure finishes the run as "error", audits ``collect.error`` and re-raises.
    """
    src = _lookup(config, source_id)
    if not src.enabled:
        raise ValueError(f"source '{source_id}' is disabled (set enabled = true in [sources.{source_id}])")
    out, exc = _execute(config, src, store, audit, runs, trigger, started_by)
    if exc is not None:
        raise exc
    return out


def run_all(config: Config, store, audit, runs=None, trigger: str = "schedule", only_enabled: bool = True) -> list[dict]:
    """Run every source (enabled ones unless only_enabled=False), in config order, continuing past failures."""
    results: list[dict] = []
    for src in config.sources.values():
        if only_enabled and not src.enabled:
            continue
        try:
            out, _ = _execute(config, src, store, audit, runs, trigger, None)
        except Exception as e:  # noqa: BLE001 - configuration errors (unknown type) are reported, not raised
            out = {"source_id": src.id, "type": src.type, "status": "error", "records": 0, "summary": "",
                   "run_id": None, "error": str(e) or type(e).__name__}
        results.append(out)
    return results
