"""attest.server — the dashboard as a running application.

Stdlib HTTP server. Every button on the page calls a real agent against the real
evidence store and writes to the real audit log. Run: python3 -m attest.server

State model
  evidence.jsonl / audit.jsonl   the ledger (append-only, owned by the agents)
  journal.jsonl                  feed events, drafts and decisions — replayed on --keep
  approval.key                   HMAC key; every human decision is signed with it
Identity comes from the X-Attest-User header (a persona name) and becomes a
RequesterScope. The agent inherits the requester's grants, never the server's.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import os
import secrets
import threading
from dataclasses import asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from attest.agent import AnswerAgent, ReaderAgent
from attest.audit import AuditLog
from attest.controls import FRAMEWORKS, ControlEngine, default_catalog
from attest.evidence import EvidenceStore
from attest.guardrails import GuardrailViolation, RequesterScope, enforce_requester_scope, scan_for_injection
from attest.seed import seed
from attest.util import canonical_json, now_iso, parse_iso

try:  # optional: Claude-backed drafting behind the same guardrails
    from attest.llm import ClaudeDrafter
except ImportError:  # pragma: no cover - module may not exist yet
    ClaudeDrafter = None

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "dashboard" / "app.html"
EXAMPLES = ROOT / "examples"
READER_TOOLS = ["read:documents"]
RULE_TAGS = {
    "untrusted-doc-isolation": "LLM01",
    "tool-allowlist": "LLM06",
    "max-steps": "LLM06",
    "egress-classification-gate": "LLM02",
    "citation-required": "grounding",
    "requester-scoped-identity": "authz",
    "hash-chain": "integrity",
}
PERSONAS = {
    "security-engineer": {"user": "s.vemula@attest.internal", "grants": ["read:evidence", "read:documents", "approve:questionnaire"],
                          "label": "Security engineer"},
    "auditor": {"user": "j.okafor@auditfirm.example", "grants": ["read:evidence"], "label": "External auditor"},
    "vendor-portal": {"user": "svc-vendor-portal", "grants": ["read:documents"], "label": "Vendor portal (service)"},
}
DEFAULT_PERSONA = "security-engineer"
IDENTITY_HEADER = "X-Attest-User"


def _age(collected_at: str, now: datetime) -> str:
    hours = (now - parse_iso(collected_at)).total_seconds() / 3600
    return f"{int(hours)}h" if hours < 48 else f"{int(hours // 24)}d"


class Forbidden(Exception):
    """A requester tried something their grants do not cover."""


class App:
    """All demo state. Ledger on disk; feed/queue journaled to disk and held in memory."""

    def __init__(self, data_dir: Path, reset: bool = True):
        self.data = data_dir
        self.lock = threading.Lock()
        self.catalog = {c.id: c for c in default_catalog()}
        self.events: list[dict] = []
        self.queue: list[dict] = []
        self.seq = 4474
        self._drafter = None
        self.data.mkdir(parents=True, exist_ok=True)
        self._load_key()
        if reset or not (data_dir / "evidence.jsonl").exists():
            self.reseed()
        else:
            self._open()
            self._replay()

    # ---- lifecycle -------------------------------------------------------
    def _open(self) -> None:
        self.store = EvidenceStore(self.data / "evidence.jsonl")
        self.audit = AuditLog(self.data / "audit.jsonl")
        self.engine = ControlEngine(list(self.catalog.values()), self.store)

    def _load_key(self) -> None:
        path = self.data / "approval.key"
        if not path.exists():
            path.write_text(secrets.token_hex(32))
            os.chmod(path, 0o600)
        self.key = bytes.fromhex(path.read_text().strip())

    def reseed(self) -> None:
        for name in ("evidence.jsonl", "audit.jsonl", "journal.jsonl"):
            path = self.data / name
            if path.exists():
                path.unlink()
        seed(self.data)
        self._open()
        self.events, self.queue, self.seq = [], [], 4474
        self._warmup()

    def _warmup(self) -> None:
        # Order matters: the feed is newest-first, so the injection lands on top.
        self.answer("Have you experienced a reportable breach in the last 24 months?", [], qid="Q-4474")
        self.answer("Describe your cadence for reviewing privileged access.", ["CTL-PRIV-01"], qid="Q-4472")
        self.answer("Is customer PHI encrypted at rest and in transit?", ["CTL-CRYPTO-01", "CTL-CRYPTO-02"], qid="Q-4471")
        self.read_doc("contoso-soc2-2025.pdf p.9", (EXAMPLES / "vendor-clean-excerpt.txt").read_text(), READER_TOOLS)
        self.read_doc("northwind-soc2-2025.pdf p.14", (EXAMPLES / "vendor-soc2-excerpt.txt").read_text(), READER_TOOLS)

    # ---- journal ---------------------------------------------------------
    def _journal(self, kind: str, obj: dict) -> None:
        with (self.data / "journal.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"t": kind, **obj}, sort_keys=True) + "\n")

    def _replay(self) -> None:
        self.events, self.queue = [], []
        path = self.data / "journal.jsonl"
        if not path.exists():
            return
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            kind = entry.pop("t")
            if kind == "event":
                self.events.insert(0, entry)
            elif kind == "draft":
                self.queue.insert(0, entry)
                num = entry["question_id"].rsplit("-", 1)[-1]
                if num.isdigit():
                    self.seq = max(self.seq, int(num))
            elif kind == "decision":
                item = next((q for q in self.queue if q["question_id"] == entry["question_id"]), None)
                if item:
                    item.update(decision=entry["decision"], approver=entry["approver"],
                                signature=entry["signature"], signed_at=entry["ts"])

    def _event(self, verdict: str, title: str, sub: str, tags=(), rule=None, enforcement="", disposition="", identity="", payload=None) -> dict:
        event = dict(ts=now_iso(), verdict=verdict, title=title, sub=sub, tags=list(tags), rule=rule,
                     enforcement=enforcement, disposition=disposition, identity=identity, payload=payload)
        self.events.insert(0, event)
        self._journal("event", event)
        return event

    # ---- identity ---------------------------------------------------------
    @staticmethod
    def scope_for(persona: str) -> RequesterScope:
        if persona not in PERSONAS:
            raise ValueError(f"unknown persona {persona!r}")
        p = PERSONAS[persona]
        return RequesterScope(user=p["user"], grants=frozenset(p["grants"]))

    def _deny(self, scope: RequesterScope, violation: GuardrailViolation, action: str, subject: str, what: str) -> None:
        self.audit.record(actor=scope.user, action=action, subject=subject, rule=violation.rule, detail=violation.detail)
        self._event("blocked", f"{what} denied for {scope.user}", f"requester grants: {', '.join(sorted(scope.grants)) or 'none'}",
                    [RULE_TAGS["requester-scoped-identity"]], rule=violation.rule, enforcement=violation.detail,
                    disposition="The agent acts with the requester's grants, not the service account's. Nothing ran.",
                    identity=f"requester: {scope.user}")

    # ---- agent actions ---------------------------------------------------
    def read_doc(self, doc_id: str, text: str, tools: list[str], persona: str = DEFAULT_PERSONA) -> dict:
        scope = self.scope_for(persona)
        try:
            enforce_requester_scope(scope, "read:documents")
        except GuardrailViolation as violation:
            self._deny(scope, violation, "reader.denied", doc_id, "Document read")
            raise Forbidden(str(violation)) from violation
        try:
            reader = ReaderAgent(self.audit, registered_tools=list(tools))
            result = reader.read(doc_id, text)
        except GuardrailViolation as violation:
            return self._event(
                "blocked", "Reader refused to start: write-capable tool registered",
                f"reader-agent · {doc_id} · tools: {', '.join(tools)}", [RULE_TAGS["untrusted-doc-isolation"]],
                rule=violation.rule, enforcement=violation.detail,
                disposition="No document was read. Reading and acting must be separate passes with separate privileges.",
                identity=f"reader-agent v0.4.2 · requester: {scope.user} · scope: {', '.join(tools)}",
            )
        if result["quarantined"]:
            paragraphs = [p.strip() for p in text.split("\n\n") if p.strip() and scan_for_injection(p)]
            return self._event(
                "blocked", f"Prompt injection blocked in {doc_id}",
                f"reader-agent · patterns: {', '.join(result['injection_patterns'])}", ["LLM01"],
                rule="untrusted-doc-isolation",
                enforcement="The extraction context registers zero write-capable tools. The instruction was parsed as document text and had no reachable path to a state change — there was nothing for it to call.",
                disposition="Document quarantined. Extracted facts retained; risk rating left unset; routed to human review.",
                identity=f"reader-agent v0.4.2 · requester: {scope.user} · scope: read:documents",
                payload="\n\n".join(paragraphs) or text[:400],
            )
        extracted = result.get("extracted") or {}
        return self._event(
            "allowed", f"Document read cleanly: {doc_id}", "reader-agent · no injection patterns · facts extracted",
            [], identity=f"reader-agent v0.4.2 · requester: {scope.user} · scope: read:documents",
            disposition=f"Extracted {len(extracted)} field(s): {', '.join(list(extracted)[:6]) or 'none'}.",
        )

    def llm_available(self) -> bool:
        return ClaudeDrafter is not None and importlib.util.find_spec("anthropic") is not None

    def _drafter_instance(self):
        if ClaudeDrafter is None:
            raise ValueError("LLM mode is not built into this checkout")
        if self._drafter is None:
            self._drafter = ClaudeDrafter()
        return self._drafter

    def answer(self, question: str, control_ids: list[str], qid: str | None = None,
               persona: str = DEFAULT_PERSONA, llm: bool = False) -> dict:
        if not qid:
            self.seq += 1
            qid = f"Q-{self.seq}"
        scope = self.scope_for(persona)
        kwargs = {"drafter": self._drafter_instance()} if llm else {}
        agent = AnswerAgent(self.store, self.audit, scope, allowlist=frozenset({"read:evidence"}), **kwargs)
        draft = agent.draft(qid, question, list(control_ids))
        mode = "claude-opus-5 draft · guardrails validated" if llm else "deterministic draft"
        gated = draft.status == "DECLINED" and any(
            r.classification != "publishable" for cid in control_ids for r in self.store.query(control_id=cid))
        item = dict(question_id=qid, question=question, answer=draft.answer, evidence_ids=list(draft.evidence_ids), gated=gated,
                    status=draft.status, reason=draft.reason, citations=self._citations(draft.evidence_ids),
                    control_ids=list(control_ids), mode=mode, requester=scope.user,
                    decision=None, approver=None, signature=None, signed_at=None)
        self.queue.insert(0, item)
        self._journal("draft", item)
        who = f"answer-agent · requester: {scope.user} · {mode}"
        if draft.status == "READY":
            self._event("allowed", f"Questionnaire {qid} drafted with {len(draft.evidence_ids)} citation(s)",
                        f"answer-agent · {question}", ["LLM" if llm else ""][:0] + (["grounded"] if llm else []),
                        enforcement="citation-required · egress-classification-gate · tool-allowlist · max-steps · requester-scoped-identity all passed",
                        disposition="Draft only. Nothing reaches the customer until a named human approves it.",
                        identity=who)
        elif draft.status == "DECLINED":
            self._event("declined", f"Agent declined {qid}: no evidence for the requested controls",
                        f"answer-agent · {question}", ["grounding"], rule="citation-required",
                        enforcement="No evidence record exists for the requested controls, so there is nothing to cite.",
                        disposition="Routed to the control owner. Silence in the evidence store is not evidence of absence — the agent does not infer from it.",
                        identity=who)
        else:
            rule = draft.reason.split(":")[0].strip() or "guardrail"
            self._event("blocked", f"Draft for {qid} rejected by {rule}", f"answer-agent · {question}",
                        [RULE_TAGS.get(rule, "guardrail")], rule=rule, enforcement=draft.reason,
                        disposition="Blocked before reaching the approval queue, so a reviewer never has to catch it.",
                        identity=who)
        return item

    def _citations(self, evidence_ids: list[str]) -> list[dict]:
        now = datetime.now(timezone.utc)
        out = []
        for eid in evidence_ids:
            rec = self.store.get(eid)
            if not rec:
                continue
            age_h = (now - parse_iso(rec.collected_at)).total_seconds() / 3600
            slas = [self.catalog[c].freshness_sla_hours for c in rec.control_ids if c in self.catalog]
            out.append(dict(id=rec.id, source=rec.source, kind=rec.kind, classification=rec.classification,
                            age=_age(rec.collected_at, now), stale=bool(slas) and age_h > min(slas),
                            sla=f"{min(slas) // 24}d" if slas and min(slas) >= 48 else (f"{min(slas)}h" if slas else "")))
        return out

    # ---- human actions ---------------------------------------------------
    def _sign(self, item: dict, decision: str, approver: str, ts: str) -> str:
        message = canonical_json({
            "question_id": item["question_id"],
            "answer_sha256": hashlib.sha256(item["answer"].encode("utf-8")).hexdigest(),
            "decision": decision, "approver": approver, "ts": ts,
        })
        return hmac.new(self.key, message.encode("utf-8"), hashlib.sha256).hexdigest()

    def approvals_verified(self) -> bool:
        return all(
            hmac.compare_digest(self._sign(q, q["decision"], q["approver"], q["signed_at"]), q["signature"] or "")
            for q in self.queue if q.get("decision")
        )

    def decide(self, qid: str, decision: str, persona: str = DEFAULT_PERSONA) -> None:
        scope = self.scope_for(persona)
        item = next((q for q in self.queue if q["question_id"] == qid), None)
        if item is None:
            raise ValueError(f"unknown question {qid}")
        if item["decision"]:
            raise ValueError(f"{qid} already decided")
        actions = {"approve": ("approval.approved", "approved and sent to customer"),
                   "reject": ("approval.returned", "returned to the agent for redraft"),
                   "assign": ("approval.assigned", "routed to the incident response owner")}
        if decision not in actions:
            raise ValueError(f"unknown decision {decision}")
        try:
            enforce_requester_scope(scope, "approve:questionnaire")
        except GuardrailViolation as violation:
            self._deny(scope, violation, "approval.denied", qid, f"Decision on {qid}")
            raise Forbidden(str(violation)) from violation
        action, verb = actions[decision]
        approver = scope.user
        ts = now_iso()
        signature = self._sign(item, decision, approver, ts)
        stale = any(c["stale"] for c in item["citations"])
        detail = f"sig={signature[:16]}"
        if decision == "approve" and stale:
            detail = "exception recorded: approved with a stale citation · " + detail
        self.audit.record(actor=approver, action=action, subject=qid, approver=approver, detail=detail)
        item.update(decision=decision, approver=approver, signature=signature, signed_at=ts)
        self._journal("decision", {"question_id": qid, "decision": decision, "approver": approver, "signature": signature, "ts": ts})
        self._event("allowed", f"{qid} {verb}", f"human decision · {approver} · HMAC-SHA256 {signature[:16]}…"
                    + (" · exception: stale citation" if decision == "approve" and stale else ""), [],
                    identity=f"approver: {approver} · drafted by answer-agent",
                    enforcement="Signed over (question_id, sha256(answer), decision, approver, ts) with the server's approval key. The approval cannot be edited or re-attributed without breaking the signature.")

    def tamper(self) -> None:
        path = self.data / "evidence.jsonl"
        lines = path.read_text().splitlines()
        index = min(3, len(lines) - 1)
        rec = json.loads(lines[index])
        rec["payload"]["result"] = "fail" if rec["payload"].get("result") == "pass" else "pass"
        lines[index] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n")
        self._open()
        self.audit.record(actor="demo-operator", action="evidence.tampered", subject=rec["id"],
                          detail="payload.result edited on disk; digest not recomputed")
        self._event("blocked", f"Ledger integrity failure detected at {rec['id']}",
                    "verify_chain() · recomputed digest does not match the stored one", ["integrity"], rule="hash-chain",
                    enforcement="Each record's SHA-256 covers its content plus the previous record's digest. Editing one byte on disk breaks the chain from that record forward.",
                    disposition="Evidence from this store is untrusted until restored from the collector of record. Reset the demo to restore it.")

    # ---- read model -------------------------------------------------------
    def _rule_counts(self) -> dict:
        counts = {r: 0 for r in RULE_TAGS}
        for e in self.events:
            if e["rule"] in counts and e["verdict"] in ("blocked", "escalated"):
                counts[e["rule"]] += 1
        return counts

    def state(self, persona: str = DEFAULT_PERSONA) -> dict:
        now = datetime.now(timezone.utc)
        records = self.store.all()
        fresh = 0
        for r in records:
            slas = [self.catalog[c].freshness_sla_hours for c in r.control_ids if c in self.catalog]
            age_h = (now - parse_iso(r.collected_at)).total_seconds() / 3600
            if slas and age_h <= min(slas):
                fresh += 1
        evidence = [dict(id=r.id, source=r.source, kind=r.kind, classification=r.classification,
                         digest=r.sha256[:6], age=_age(r.collected_at, now)) for r in reversed(records[-8:])]
        p = PERSONAS.get(persona, PERSONAS[DEFAULT_PERSONA])
        results = {r.control_id: r for r in self.engine.evaluate(now)}

        def failing_summary(control):
            failing = [r for r in self.store.query(control_id=control.id)
                       if isinstance(r.payload, dict) and r.payload.get("result") == "fail"]
            return failing[-1].payload.get("summary") if failing else None

        controls = [dict(id=c.id, name=c.name, state=results[c.id].state, reason=results[c.id].reason,
                         evidence=len(results[c.id].evidence_ids), sla_hours=c.freshness_sla_hours,
                         spec=c.hipaa_spec, frameworks=c.mappings,
                         failing_summary=failing_summary(c) if results[c.id].state == "FAIL" else None)
                    for c in self.catalog.values() if c.id in results]
        return dict(
            generated_at=now_iso(),
            identity=dict(persona=persona, user=p["user"], grants=p["grants"], label=p["label"]),
            personas=[dict(id=k, label=v["label"], user=v["user"], grants=v["grants"]) for k, v in PERSONAS.items()],
            llm_available=self.llm_available(),
            summary=self.engine.summary(),
            frameworks=FRAMEWORKS,
            posture={fw: self.engine.posture(fw) for fw in FRAMEWORKS},
            evidence=evidence, evidence_total=len(records), evidence_fresh=fresh,
            chain_intact=self.store.verify_chain(),
            approvals_verified=self.approvals_verified(),
            events=self.events, queue=self.queue, rules=self._rule_counts(),
            audit=[asdict(e) for e in reversed(self.audit.all())][:40],
            catalog=[dict(id=c.id, name=c.name) for c in self.catalog.values()],
            controls=controls,
        )


class Handler(BaseHTTPRequestHandler):
    app: App

    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _persona(self) -> str:
        return self.headers.get(IDENTITY_HEADER) or DEFAULT_PERSONA

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            body = PAGE.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/state":
            persona = self._persona()
            if persona not in PERSONAS:
                return self._json(400, {"error": f"unknown persona {persona!r}"})
            with self.app.lock:
                self._json(200, self.app.state(persona))
        else:
            self._json(404, {"error": "not found"})

    def do_HEAD(self) -> None:  # noqa: N802 — readiness probes
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return self._json(400, {"error": "body must be JSON"})
        persona = self._persona()
        if persona not in PERSONAS:
            return self._json(400, {"error": f"unknown persona {persona!r}"})
        app = self.app
        with app.lock:
            try:
                if path == "/api/read-doc":
                    example = body.get("example")
                    if example == "injected":
                        doc_id, text = "northwind-soc2-2025.pdf p.14", (EXAMPLES / "vendor-soc2-excerpt.txt").read_text()
                    elif example == "clean":
                        doc_id, text = "contoso-soc2-2025.pdf p.9", (EXAMPLES / "vendor-clean-excerpt.txt").read_text()
                    else:
                        doc_id, text = (body.get("doc_id") or "pasted-document.txt"), body.get("text", "")
                        if not text.strip():
                            raise ValueError("paste some document text first")
                    app.read_doc(doc_id, text, body.get("tools") or READER_TOOLS, persona)
                elif path == "/api/answer":
                    question = (body.get("question") or "").strip()
                    if not question:
                        raise ValueError("enter a question first")
                    if body.get("llm") and not app.llm_available():
                        raise ValueError("LLM mode needs the anthropic SDK: pip install anthropic")
                    app.answer(question, body.get("control_ids") or [], persona=persona, llm=bool(body.get("llm")))
                elif path == "/api/decide":
                    app.decide(body["question_id"], body["decision"], persona)
                elif path == "/api/tamper":
                    app.tamper()
                elif path == "/api/reseed":
                    app.reseed()
                else:
                    return self._json(404, {"error": "not found"})
                self._json(200, app.state(persona))
            except Forbidden as err:
                self._json(403, {"error": str(err), "state": app.state(persona)})
            except (KeyError, ValueError) as err:
                self._json(400, {"error": str(err)})

    def log_message(self, fmt, *args) -> None:  # quieter than the default
        try:
            line = fmt % args
        except TypeError:
            line = " ".join(str(a) for a in args)
        if "/api/state" not in line:
            print(f"{self.address_string()} {line}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="attest.server", description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--data", type=Path, default=ROOT / "data")
    parser.add_argument("--keep", action="store_true", help="keep existing data and replay the journal instead of reseeding")
    args = parser.parse_args(argv)
    Handler.app = App(args.data, reset=not args.keep)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Attest running at http://{args.host}:{args.port}  (data: {args.data})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
