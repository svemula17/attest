"""`attest package | package-verify | questionnaire | audit-export` — the deliverables.

    attest package --framework soc2 --since 2026-07-01 --out soc2-q3.zip   # signed auditor package
    attest package-verify soc2-q3.zip                                       # digests + signature
    attest questionnaire import acme.xlsx --name "Acme vendor review"       # one draft per row
    attest questionnaire export QN-0001 --out acme-answers.xlsx             # the decided queue
    attest questionnaire list
    attest audit-export --out audit.jsonl --s3 s3://compliance-worm/attest --retain-days 365

Wire up from attest.cli.build_parser(): ``from attest import cli_product; cli_product.register(sub)``.
Every command builds the Service the way the admin commands do (attest.toml → migrations → engine).
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from attest.controls import FRAMEWORKS

STATE_ORDER = ("PASS", "DEGRADED", "FAIL")


def _service(args: argparse.Namespace):
    from attest.cli_admin import _engine_for
    from attest.service import Service
    cfg, engine = _engine_for(args)
    return cfg, engine, Service(cfg, engine)


def _short(digest: str | None, n: int = 16) -> str:
    return f"{digest[:n]}…" if digest else "-"


# ---- package ---------------------------------------------------------------------
def cmd_package(args: argparse.Namespace) -> int:
    from attest.auth import SYSTEM
    from attest.packages import validate_since
    try:
        since = validate_since(args.since)
    except ValueError as e:
        print(f"package: {e}")
        return 2
    cfg, engine, svc = _service(args)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out = Path(args.out) if args.out else Path(f"attest-package-{args.framework or 'all'}-{stamp}.zip")
    try:
        res = svc.build_package(SYSTEM, out, framework=args.framework, since=since, include_restricted=args.include_restricted)
    except ValueError as e:
        print(f"package: {e}")
        return 2
    m, counts = res["manifest"], res["manifest"]["counts"]
    states = " · ".join(f"{counts['states'].get(s, 0)} {s.lower()}" for s in STATE_ORDER)
    print(f"wrote {out} ({out.stat().st_size:,} bytes) · sha256 {_short(res['sha256'])}")
    print(f"scope: {FRAMEWORKS.get(args.framework, args.framework) if args.framework else 'all frameworks'} · "
          f"since {since or 'the beginning'} · restricted evidence {'included' if args.include_restricted else 'excluded'}")
    print(f"controls {counts['controls']} ({states}) · posture rows {counts['posture_rows']} · "
          f"evidence {counts['evidence']} of {counts['evidence_total']} · audit {counts['audit']} · acceptances {counts['acceptances']}")
    print(f"evidence chain {'intact' if m['chain_verified'] else 'BROKEN'} · signature {_short(m['signature'])}")
    print(f"verify with: attest package-verify {out}")
    return 0 if m["chain_verified"] else 4


def cmd_package_verify(args: argparse.Namespace) -> int:
    from attest.packages import read_manifest, verify_package
    path = Path(args.file)
    cfg, engine, svc = _service(args)
    ok, problems = verify_package(path, svc.sign_bytes)
    if ok:
        m = read_manifest(path)
        counts = m.get("counts", {})
        print(f"{path.name}: OK · {m.get('format')} · generated {m.get('generated_at')} by {m.get('generated_by')}")
        print(f"scope: {m.get('framework') or 'all frameworks'} · since {m.get('since') or 'the beginning'} · "
              f"{len(m.get('files', {}))} files · controls {counts.get('controls', '?')} · evidence {counts.get('evidence', '?')} · "
              f"audit {counts.get('audit', '?')}")
        return 0
    print(f"{path.name}: FAILED ({len(problems)} problem{'s' if len(problems) != 1 else ''})")
    for p in problems:
        print(f"  - {p}")
    return 4


# ---- questionnaire ---------------------------------------------------------------
def cmd_questionnaire(args: argparse.Namespace) -> int:
    from attest.auth import SYSTEM
    from attest.questionnaires import QuestionnaireError, parse_questionnaire
    cfg, engine, svc = _service(args)
    if args.questionnaire_cmd == "import":
        path = Path(args.file)
        try:
            res = svc.import_questionnaire(SYSTEM, path, name=args.name)
        except QuestionnaireError as e:
            print(f"questionnaire import: {path.name}: {len(e.problems)} problem{'s' if len(e.problems) != 1 else ''} — nothing imported")
            for p in e.problems:
                print(f"  - {p}")
            return 2
        qn, drafts = res["questionnaire"], res["drafts"]
        rows = parse_questionnaire(path)  # the file just parsed cleanly; carry the customer's refs onto the drafts
        for row, item in zip(rows, drafts):
            if row.get("ref"):
                svc.drafts.set_ref(item["question_id"], row["ref"])
        print(f"{qn['id']}  {qn['name']}  —  {len(drafts)} question{'s' if len(drafts) != 1 else ''} from {path.name}")
        for row, item in zip(rows, drafts):
            note = "" if item["status"] == "READY" else f"  · {item.get('reason') or ''}"
            print(f"  {(row.get('ref') or ''):<8} {item['question_id']:<8} {item['status']:<9} {item['question'][:70]}{note}")
        counts = Counter(d["status"] for d in drafts)
        print(f"ready {counts.get('READY', 0)} · declined {counts.get('DECLINED', 0)} · blocked {counts.get('BLOCKED', 0)}"
              f" — decide each READY draft in the console, then: attest questionnaire export {qn['id']} --out answers.xlsx")
        return 0
    if args.questionnaire_cmd == "export":
        out = Path(args.out)
        try:
            svc.export_questionnaire(SYSTEM, args.id, out, fmt=args.format)
        except ValueError as e:
            print(f"questionnaire export: {e}")
            return 1
        rows = svc.questionnaire_rows(args.id)
        undecided = [r["question_id"] for r in rows if r["status"] == "READY" and not r.get("decision")]
        unanswered = sum(1 for r in rows if r["status"] != "READY")
        print(f"wrote {out} ({len(rows)} rows · {unanswered} not answered)")
        if undecided:
            print(f"warning: {len(undecided)} READY answer{'s' if len(undecided) != 1 else ''} not yet approved by a human: {', '.join(undecided)}")
        return 0
    if args.questionnaire_cmd == "list":
        rows = svc.questionnaires()
        if not rows:
            print("no questionnaires — import one with: attest questionnaire import FILE.csv|xlsx")
            return 0
        for q in rows:
            drafts = svc.drafts.list_for_questionnaire(q["id"])
            pending = sum(1 for d in drafts if d["status"] == "READY" and not d.get("decision"))
            print(f"{q['id']}  {q['status']:<8} {q['row_count']:>4} rows  {pending:>3} undecided  {q['created_at']}  {q['created_by']:<32} {q['name']}")
        return 0
    return 2


# ---- audit-export ----------------------------------------------------------------
def cmd_audit_export(args: argparse.Namespace) -> int:
    from attest.auth import SYSTEM
    from attest.packages import validate_since
    from attest.worm import export_audit, upload_worm
    try:
        since = validate_since(args.since)
    except ValueError as e:
        print(f"audit-export: {e}")
        return 2
    cfg, engine, svc = _service(args)
    out = Path(args.out)
    proof = export_audit(svc.audit, out, since=since)
    print(f"wrote {out} ({proof['count']} of {proof['total']} entries{f' since {since}' if since else ''}) · proof {proof['proof_path']}")
    print(f"audit chain {'intact' if proof['chain_verified'] else 'BROKEN'} · last sha256 {_short(proof['last_sha256'])} · "
          f"file sha256 {_short(proof['sha256_of_file'])}")
    rc = 0 if proof["chain_verified"] else 4
    bucket = args.s3 or cfg.security.audit_worm_bucket
    detail = f"{proof['count']} entries · file sha256 {proof['sha256_of_file'][:16]}"
    if bucket:
        retain_days = args.retain_days or cfg.security.audit_worm_retain_days
        try:
            res = upload_worm(out, bucket, retain_days)
        except ImportError:
            print("audit-export: boto3 is not installed — pip install 'attest[aws]'")
            return 1
        except (ValueError, FileNotFoundError) as e:
            print(f"audit-export: {e}")
            return 2
        except Exception as e:  # botocore raises its own hierarchy; the file on disk is still good
            print(f"audit-export: upload to {bucket} failed: {e}")
            return 1
        print(f"uploaded s3://{res['bucket']}/{res['keys'][0]} and its proof · Object Lock {res['mode']} until {res['retain_until']} ({retain_days} days)")
        detail += f" · s3://{res['bucket']}/{res['keys'][0]} locked until {res['retain_until']}"
    svc.audit.record(actor=SYSTEM.email, action="audit.exported", subject=out.name, detail=detail)
    return rc


# ---- registration ----------------------------------------------------------------
def register(sub) -> None:
    p = sub.add_parser("package", help="build a signed auditor evidence package (zip): controls, posture, evidence, chain, audit")
    p.add_argument("--framework", choices=list(FRAMEWORKS), help="limit to one framework (default: all three)")
    p.add_argument("--since", metavar="YYYY-MM-DD", help="evidence collected and audit entries recorded on or after this date")
    p.add_argument("--out", metavar="FILE.zip", help="default: attest-package-<framework|all>-<date>.zip")
    p.add_argument("--include-restricted", action="store_true", help="also export restricted-classification evidence")
    p.set_defaults(fn=cmd_package)

    v = sub.add_parser("package-verify", help="recompute a package's file digests and manifest signature")
    v.add_argument("file", metavar="FILE.zip")
    v.set_defaults(fn=cmd_package_verify)

    q = sub.add_parser("questionnaire", help="customer questionnaires: import rows as drafts, export the decided answers")
    qs = q.add_subparsers(dest="questionnaire_cmd", required=True)
    i = qs.add_parser("import", help="CSV/XLSX with a 'question' column (optional control_ids, ref) → one draft per row")
    i.add_argument("file")
    i.add_argument("--name", help="default: the file name without its extension")
    e = qs.add_parser("export", help="write the questionnaire's answers, decisions and signatures to CSV or XLSX")
    e.add_argument("id", metavar="QN-ID")
    e.add_argument("--out", required=True, metavar="FILE.csv|xlsx")
    e.add_argument("--format", choices=["csv", "xlsx"], help="default: by the --out extension")
    qs.add_parser("list", help="imported questionnaires and how many answers still await a decision")
    q.set_defaults(fn=cmd_questionnaire)

    a = sub.add_parser("audit-export", help="export the audit trail as JSONL with a proof; optionally lock it in S3 (WORM)")
    a.add_argument("--out", default="audit.jsonl")
    a.add_argument("--since", metavar="YYYY-MM-DD")
    a.add_argument("--s3", metavar="s3://bucket/prefix", help="default: [security].audit_worm_bucket in attest.toml")
    a.add_argument("--retain-days", type=int, help="Object Lock retention (default: [security].audit_worm_retain_days)")
    a.set_defaults(fn=cmd_audit_export)
