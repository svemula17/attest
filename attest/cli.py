"""attest — command-line entry point."""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
from dataclasses import asdict
from datetime import date, datetime, timezone
from pathlib import Path

from attest.agent import AnswerAgent, ReaderAgent
from attest.audit import AuditLog
from attest.controls import FRAMEWORKS, ControlEngine, default_catalog
from attest.evidence import EvidenceStore
from attest.guardrails import GuardrailViolation, RequesterScope
from attest.util import now_iso

STATE_MARK = {"PASS": "PASS    ", "DEGRADED": "DEGRADED", "FAIL": "FAIL    "}


def _open(data_dir: Path) -> tuple[EvidenceStore, AuditLog, ControlEngine]:
    store = EvidenceStore(data_dir / "evidence.jsonl")
    audit = AuditLog(data_dir / "audit.jsonl")
    engine = ControlEngine(default_catalog(), store)
    return store, audit, engine


def cmd_seed(args: argparse.Namespace) -> int:
    from attest.seed import seed
    store, _ = seed(args.data)
    print(f"seeded {len(store.all())} evidence records into {args.data}/evidence.jsonl")
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    _, _, engine = _open(args.data)
    if args.json:
        out = {"summary": engine.summary(), "posture": {fw: engine.posture(fw) for fw in FRAMEWORKS}}
        print(json.dumps(out, indent=2))
        return 0
    frameworks = [args.framework] if args.framework else list(FRAMEWORKS)
    for fw in frameworks:
        rows = engine.posture(fw)
        passing = sum(1 for r in rows if r["state"] == "PASS")
        print(f"\n{FRAMEWORKS[fw]}  —  {passing}/{len(rows)} passing")
        print("-" * 78)
        for r in rows:
            spec = f"  [{r['spec']}]" if fw == "hipaa" and r.get("spec") else ""
            print(f"  {STATE_MARK[r['state']]}  {r['framework_id']:<22} {r['name']}{spec}")
    s = engine.summary()
    print(f"\ncontrols: {s['pass']} pass · {s['degraded']} degraded · {s['fail']} fail · {s['total']} total")
    return 0


def cmd_answer(args: argparse.Namespace) -> int:
    store, audit, _ = _open(args.data)
    scope = RequesterScope(user=args.user, grants=frozenset(args.grants))
    drafter = None
    if getattr(args, "llm", False):
        from attest.llm import ClaudeDrafter
        drafter = ClaudeDrafter()
    agent = AnswerAgent(store, audit, scope, allowlist=frozenset(args.grants), drafter=drafter)
    draft = agent.draft(args.question_id, args.question, args.controls)
    print(f"{draft.question_id}  {draft.status}")
    print(f"Q: {draft.question}")
    if draft.status == "READY":
        print(f"A: {draft.answer}")
        print(f"cites: {', '.join(draft.evidence_ids)}")
        print("→ queued for human approval; nothing has been sent.")
    else:
        print(f"reason: {draft.reason}")
    return 0 if draft.status == "READY" else 2


def cmd_read_doc(args: argparse.Namespace) -> int:
    _, audit, _ = _open(args.data)
    text = Path(args.path).read_text(encoding="utf-8")
    try:
        reader = ReaderAgent(audit, registered_tools=args.tools)
        result = reader.read(args.doc_id or Path(args.path).name, text)
    except GuardrailViolation as e:
        print(f"refused to start: {e}")
        return 3
    if result["quarantined"]:
        print(f"{result['doc_id']}  QUARANTINED  patterns: {', '.join(result['injection_patterns'])}")
        print("extraction context had no write-capable tools; the instruction had nowhere to go.")
    else:
        print(f"{result['doc_id']}  clean")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    _, audit, _ = _open(args.data)
    for e in audit.all()[-args.last:]:
        who = e.approver or e.actor
        mv = f" ({e.model_version})" if e.model_version and e.model_version != e.actor else ""
        rule = f"  rule={e.rule}" if e.rule else ""
        print(f"{e.ts}  {e.action:<18} {e.subject:<12} {who}{mv}{rule}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    store, _, _ = _open(args.data)
    ok = store.verify_chain()
    print(f"evidence chain: {'intact' if ok else 'BROKEN'} ({len(store.all())} records)")
    return 0 if ok else 4


def cmd_export(args: argparse.Namespace) -> int:
    store, audit, engine = _open(args.data)
    out = {
        "generated_at": now_iso(),
        "summary": engine.summary(),
        "posture": {fw: engine.posture(fw) for fw in FRAMEWORKS},
        "evidence": [asdict(r) for r in store.all()],
        "audit": [asdict(e) for e in audit.all()],
        "chain_intact": store.verify_chain(),
    }
    text = json.dumps(out, indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


def cmd_collect_github(args: argparse.Namespace) -> int:
    from attest.collectors.github import collect_branch_protection, resolve_token
    store, audit, _ = _open(args.data)
    from attest.collectors.github import gh_available
    if resolve_token(args.token) is None:
        if gh_available():
            print("using the authenticated gh CLI (no GITHUB_TOKEN set)")
        else:
            print("hint: no GitHub token found (pass --token or set GITHUB_TOKEN / GH_TOKEN); "
                  "branch protection is not readable anonymously")
    try:
        records = collect_branch_protection(store, args.repo, token=args.token)
    except PermissionError as e:
        print(f"collect github: {e}")
        audit.record(actor="attest.collectors.github", action="collect.denied", subject=args.repo, detail=str(e))
        return 5
    except urllib.error.URLError as e:
        print(f"collect github: network error: {e.reason}")
        return 1
    except (ValueError, RuntimeError) as e:
        print(f"collect github: {e}")
        return 1
    for r in records:
        print(f"{r.id}  {r.kind:<20} {r.payload['result']:<4}  {r.payload['summary']}")
    audit.record(actor="attest.collectors.github", action="evidence.collected", subject=args.repo,
                 detail=f"{len(records)} records for {', '.join(sorted({c for r in records for c in r.control_ids}))}")
    print(f"appended {len(records)} records to {args.data}/evidence.jsonl")
    return 0


# -- gate -------------------------------------------------------------------------

def load_acceptances(path: Path) -> tuple[list[dict], list[str]]:
    """Read {"accepted": [{control, owner, reason, expires}]}. Returns (valid entries, warnings).

    A missing file means no acceptances. Entries without a control id or with an
    unparseable expiry are dropped (fail closed) and reported as warnings.
    """
    if not path.exists():
        return [], []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as e:
        return [], [f"{path}: not valid JSON ({e}); ignoring all acceptances"]
    entries = doc.get("accepted") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        return [], [f"{path}: expected an object with an 'accepted' list; ignoring"]
    valid: list[dict] = []
    warnings: list[str] = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("control"), str):
            warnings.append(f"{path}: accepted[{i}] has no 'control'; ignored")
            continue
        try:
            expires = date.fromisoformat(str(entry.get("expires")))
        except (TypeError, ValueError):
            warnings.append(f"{path}: accepted[{i}] ({entry['control']}) has no valid 'expires' YYYY-MM-DD; ignored")
            continue
        valid.append({
            "control": entry["control"],
            "owner": str(entry.get("owner") or "unknown"),
            "reason": str(entry.get("reason") or ""),
            "expires": expires,
        })
    return valid, warnings


def gate_rows(results, acceptances: list[dict], today: date, strict: bool = False) -> list[dict]:
    """Decide per control whether it blocks the gate. Acceptances are honoured through their expiry date."""
    by_control: dict[str, dict] = {}
    for a in acceptances:  # the latest expiry wins when a control is listed twice
        cur = by_control.get(a["control"])
        if cur is None or a["expires"] > cur["expires"]:
            by_control[a["control"]] = a
    rows = []
    for r in results:
        blocking_state = r.state == "FAIL" or (strict and r.state == "DEGRADED")
        acc = by_control.get(r.control_id)
        if not blocking_state:
            verdict = "PASS" if r.state == "PASS" else "DEGRADED (does not block)"
            blocks = False
        elif acc is not None and acc["expires"] >= today:
            verdict = f"ACCEPTED ({acc['owner']}, until {acc['expires'].isoformat()})"
            blocks = False
        elif acc is not None:
            verdict = f"{r.state} (acceptance by {acc['owner']} expired {acc['expires'].isoformat()})"
            blocks = True
        else:
            verdict = f"{r.state} (no acceptance)"
            blocks = True
        rows.append({"control_id": r.control_id, "state": r.state, "verdict": verdict,
                     "blocks": blocks, "reason": r.reason, "acceptance": acc})
    return rows


def cmd_gate(args: argparse.Namespace) -> int:
    _, audit, engine = _open(args.data)
    names = {c.id: c.name for c in engine.catalog}
    acceptances, warnings = load_acceptances(args.accept_file)
    for w in warnings:
        print(f"warning: {w}")
    today = datetime.now(timezone.utc).date()
    active = sum(1 for a in acceptances if a["expires"] >= today)
    if args.accept_file.exists():
        print(f"acceptances: {args.accept_file} ({active} active, {len(acceptances) - active} expired)")
    else:
        print(f"acceptances: none ({args.accept_file} not found)")
    if args.strict:
        print("mode: strict (DEGRADED blocks)")

    rows = gate_rows(engine.evaluate(), acceptances, today, strict=args.strict)
    print(f"\n{'CONTROL':<15} {'NAME':<28} {'STATE':<9} VERDICT")
    print("-" * 96)
    for row in rows:
        print(f"{row['control_id']:<15} {names.get(row['control_id'], ''):<28} {row['state']:<9} {row['verdict']}")
        if row["state"] != "PASS":
            print(f"{'':<15} {row['reason']}")
            if row["acceptance"] is not None and row["acceptance"]["reason"]:
                print(f"{'':<15} accepted: {row['acceptance']['reason']}")

    blocking = [r["control_id"] for r in rows if r["blocks"]]
    accepted = sum(1 for r in rows if r["verdict"].startswith("ACCEPTED"))
    counts = {s: sum(1 for r in rows if r["state"] == s) for s in ("PASS", "DEGRADED", "FAIL")}
    tally = (f"{counts['PASS']} pass · {counts['DEGRADED']} degraded · {counts['FAIL']} fail · "
             f"{accepted} accepted · {len(blocking)} blocking")
    if blocking:
        print(f"\ngate: FAIL — {tally} ({', '.join(blocking)})")
    else:
        print(f"\ngate: PASS — {tally}")
    audit.record(actor="attest-gate", action="gate.fail" if blocking else "gate.pass", subject=str(args.accept_file),
                 detail=tally + (" strict" if args.strict else ""))
    return 1 if blocking else 0


def cmd_serve(args: argparse.Namespace) -> int:
    from attest.server import main as serve
    return serve(["--port", str(args.port), "--data", str(args.data)] + (["--keep"] if args.keep else []))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="attest", description=__doc__)
    p.add_argument("--data", type=Path, default=Path("data"), help="data directory (default ./data)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("seed", help="populate the evidence store with representative records").set_defaults(fn=cmd_seed)

    e = sub.add_parser("evaluate", help="evaluate controls and print posture per framework")
    e.add_argument("--framework", choices=list(FRAMEWORKS))
    e.add_argument("--json", action="store_true")
    e.set_defaults(fn=cmd_evaluate)

    a = sub.add_parser("answer", help="draft a questionnaire answer from publishable evidence")
    a.add_argument("question_id")
    a.add_argument("question")
    a.add_argument("--controls", nargs="+", required=True)
    a.add_argument("--user", default="s.vemula")
    a.add_argument("--grants", nargs="+", default=["read:evidence"])
    a.add_argument("--llm", action="store_true", help="draft with Claude (claude-opus-5); the same guardrails validate the output")
    a.set_defaults(fn=cmd_answer)

    r = sub.add_parser("read-doc", help="read an untrusted document in an isolated context")
    r.add_argument("path")
    r.add_argument("--doc-id")
    r.add_argument("--tools", nargs="+", default=["read:documents"])
    r.set_defaults(fn=cmd_read_doc)

    au = sub.add_parser("audit", help="print the audit trail")
    au.add_argument("--last", type=int, default=20)
    au.set_defaults(fn=cmd_audit)

    sub.add_parser("verify", help="verify the evidence hash chain").set_defaults(fn=cmd_verify)

    x = sub.add_parser("export", help="export posture, evidence and audit as JSON")
    x.add_argument("--out")
    x.set_defaults(fn=cmd_export)

    c = sub.add_parser("collect", help="collect live evidence from an external system")
    csub = c.add_subparsers(dest="collector", required=True)
    gh = csub.add_parser("github", help="default-branch protection -> CTL-CHANGE-01 (pr.review-required, ci.policy-gate)")
    gh.add_argument("--repo", required=True, metavar="OWNER/NAME")
    gh.add_argument("--token", help="GitHub token (default: $GITHUB_TOKEN, then $GH_TOKEN)")
    gh.set_defaults(fn=cmd_collect_github)

    g = sub.add_parser("gate", help="CI gate: exit 1 on any FAIL without a current risk acceptance")
    g.add_argument("--accept-file", type=Path, default=Path("gate.json"),
                   help="risk acceptances JSON (default ./gate.json; missing file = no acceptances)")
    g.add_argument("--strict", action="store_true", help="DEGRADED controls also fail the gate")
    g.set_defaults(fn=cmd_gate)

    sv = sub.add_parser("serve", help="run the dashboard as a local web application")
    sv.add_argument("--port", type=int, default=8765)
    sv.add_argument("--keep", action="store_true", help="keep existing data instead of reseeding")
    sv.set_defaults(fn=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
