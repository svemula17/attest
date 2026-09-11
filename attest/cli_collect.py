"""CLI commands for getting evidence in: ``import``, ``collect`` and ``sources list``.

Wire them up from attest.cli.build_parser() with one line after the subparsers exist:

    from attest.cli_collect import register; register(sub)

The parent parser is expected to define ``--data`` (Path) and ``--config`` (str | None).
Each command function takes the parsed ``args`` and returns an int exit code.

The JSONL layout keeps no collector-run history, so ``open_runs`` returns None here; a
storage backend with a run table replaces it (``cli_collect.open_runs = ...``) and both
``collect`` (start/finish bookkeeping) and ``sources list`` (the LAST column) pick it up.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from attest.audit import AuditLog
from attest.evidence import EvidenceStore
from attest.importers import MAPPINGS, ImportProblem, import_file

NONE = "—"


def _open(data_dir: Path) -> tuple[EvidenceStore, AuditLog]:
    return EvidenceStore(data_dir / "evidence.jsonl"), AuditLog(data_dir / "audit.jsonl")


def open_runs(args: argparse.Namespace):
    """Return a collector-run store (start()/finish()/last(source_id)) for these args, or None."""
    return None


def _load_config(args: argparse.Namespace):
    from attest.config import load_config
    return load_config(getattr(args, "config", None))


def _started_by() -> str | None:
    return os.environ.get("USER") or os.environ.get("USERNAME") or None


# -- import ------------------------------------------------------------------------

def cmd_import(args: argparse.Namespace) -> int:
    store, audit = _open(args.data)
    path = Path(args.path)
    try:
        result = import_file(store, path, mapping=args.mapping, source=args.source)
    except ImportProblem as e:
        print(f"import {path}: {len(e.problems)} problem(s); nothing was written")
        for problem in e.problems:
            print(f"  {problem}")
        audit.record(actor="importer", action="import.rejected", subject=path.name,
                     detail=f"{len(e.problems)} problem(s): {e.problems[0]}")
        return 3
    except OSError as e:
        print(f"import {path}: {e}")
        return 1
    noun = "record" if result.records == 1 else "records"
    print(f"imported {result.records} {noun} from {path} into {args.data}/evidence.jsonl")
    print(f"kinds: {', '.join(result.kinds)}")
    for warning in result.warnings:
        print(f"warning: {warning}")
    audit.record(actor="importer", action="import.ok", subject=path.name,
                 detail=f"{result.records} {noun} ({', '.join(result.kinds)})" + (f"; {len(result.warnings)} warning(s)" if result.warnings else ""))
    return 0


# -- collect -----------------------------------------------------------------------

def _print_results(results: list[dict]) -> None:
    for r in results:
        noun = "record" if r["records"] == 1 else "records"
        text = r["summary"] if r["status"] == "ok" else r["error"]
        print(f"{r['source_id']:<14} {r['type']:<14} {r['status']:<6} {r['records']:>3} {noun:<8} {text}")


def cmd_collect(args: argparse.Namespace) -> int:
    from attest.collectors.registry import run_all, run_source
    from attest.config import ConfigError
    if not args.source_id and not args.all:
        print("collect: give a source id or --all")
        return 2
    try:
        config = _load_config(args)
    except ConfigError as e:
        print(f"collect: {e}")
        return 2
    if not config.sources:
        print("collect: no sources configured (no attest.toml found, or it has no [sources.*]); pass --config")
        return 2
    store, audit = _open(args.data)
    runs = open_runs(args)
    if args.all:
        results = run_all(config, store, audit, runs=runs, trigger="manual")
        _print_results(results)
        errors = [r for r in results if r["status"] != "ok"]
        total = sum(r["records"] for r in results)
        print(f"\n{len(results) - len(errors)} ok · {len(errors)} error · {total} records appended to {args.data}/evidence.jsonl")
        return 1 if errors else 0
    src = config.sources.get(args.source_id)
    if src is None:
        print(f"collect: unknown source '{args.source_id}' (known: {', '.join(sorted(config.sources))})")
        return 2
    if not src.enabled:
        print(f"collect: source '{args.source_id}' is disabled (set enabled = true in [sources.{args.source_id}])")
        return 2
    try:
        result = run_source(config, args.source_id, store, audit, runs=runs, trigger="manual", started_by=_started_by())
    except Exception as e:  # noqa: BLE001 - already audited as collect.error by run_source; the CLI just reports it
        print(f"collect {args.source_id}: {e}")
        return 1
    _print_results([result])
    return 0


# -- sources list ------------------------------------------------------------------

def _last_status(runs, source_id: str) -> str:
    last = getattr(runs, "last", None)
    if runs is None or last is None:
        return NONE
    run = last(source_id)
    if run is None:
        return NONE
    status = run.get("status") if isinstance(run, dict) else getattr(run, "status", None)
    return str(status) if status else NONE


def cmd_sources_list(args: argparse.Namespace) -> int:
    from attest.config import ConfigError
    try:
        config = _load_config(args)
    except ConfigError as e:
        print(f"sources list: {e}")
        return 2
    if not config.sources:
        print("no sources configured (no attest.toml found, or it has no [sources.*]); pass --config")
        return 0
    runs = open_runs(args)
    print(f"{'ID':<14} {'TYPE':<14} {'SCHEDULE':<14} {'ENABLED':<8} LAST")
    print("-" * 64)
    for sid, src in config.sources.items():
        print(f"{sid:<14} {src.type:<14} {src.schedule or NONE:<14} {'yes' if src.enabled else 'no':<8} {_last_status(runs, sid)}")
    return 0


# -- registration ------------------------------------------------------------------

def register(sub) -> None:
    """Add import / collect / sources list to an argparse subparsers object.

    An existing ``sources`` parser (attest's catalog command) is reused so ``attest sources``
    keeps working and ``attest sources list`` is added beneath it.
    """
    im = sub.add_parser("import", help="import a CSV/JSON evidence file (validated whole; all-or-nothing)")
    im.add_argument("path", help="CSV or JSON file (see examples/imports/)")
    im.add_argument("--mapping", choices=MAPPINGS, help="default: inferred from the extension and CSV header")
    im.add_argument("--source", help="source id for rows/records that don't name one")
    im.set_defaults(fn=cmd_import)

    co = sub.add_parser("collect", help="run a configured source ([sources.<id>] in attest.toml), or every enabled one")
    co.add_argument("source_id", nargs="?", metavar="source-id")
    co.add_argument("--all", action="store_true", help="run every enabled source, continuing past failures")
    co.set_defaults(fn=cmd_collect)

    existing = sub.choices.get("sources")
    so = existing if existing is not None else sub.add_parser("sources", help="configured evidence sources")
    ssub = so.add_subparsers(dest="sources_cmd", required=existing is None)
    ssub.add_parser("list", help="configured sources: id, type, schedule, enabled, last run status").set_defaults(fn=cmd_sources_list)
