"""attest.service — the domain layer of the real tool, on relational storage.

Everything the PoC's App did, but: identities come from auth (not a header),
the feed is persisted as guardrail entries in the audit log, drafts and
decisions live in the drafts table, control evaluations are snapshotted for
history, and collectors run through the registry with run records.
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import secrets
import threading
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import text as sql_text

from attest.agent import AnswerAgent, ReaderAgent
from attest.auth import SYSTEM, Identity
from attest.config import Config
from attest.controls import FRAMEWORKS, ControlEngine, default_catalog
from attest.db import get_setting, session_scope, set_setting
from attest.guardrails import GuardrailViolation, enforce_requester_scope, scan_for_injection
from attest.sources import FAMILIES, JOIN, sources_by_family
from attest.store_sql import AcceptanceStore, DraftStore, RunStore, SnapshotStore, SqlAuditLog, SqlEvidenceStore
from attest.util import canonical_json, now_iso, parse_iso

try:
    from attest.llm import ClaudeDrafter
except ImportError:  # pragma: no cover
    ClaudeDrafter = None

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
READER_TOOLS = ["read:documents"]
RULE_TAGS = {
    "untrusted-doc-isolation": "LLM01", "tool-allowlist": "LLM06", "max-steps": "LLM06",
    "egress-classification-gate": "LLM02", "citation-required": "grounding",
    "requester-scoped-identity": "authz", "hash-chain": "integrity", "hris-idp-join": "access",
}
FEED_PREFIX = "guardrail."
FEED_LIMIT = 200


def _age(collected_at: str, now: datetime) -> str:
    hours = (now - parse_iso(collected_at)).total_seconds() / 3600
    return f"{int(hours)}h" if hours < 48 else f"{int(hours // 24)}d"


class Forbidden(Exception):
    """A requester tried something their grants do not cover."""


class Service:
    def __init__(self, cfg: Config, engine):
        self.cfg = cfg
        self.engine = engine
        self.lock = threading.Lock()
        self.store = SqlEvidenceStore(engine)
        self.audit = SqlAuditLog(engine)
        self.snapshots = SnapshotStore(engine)
        self.runs = RunStore(engine)
        self.drafts = DraftStore(engine)
        self.acceptances = AcceptanceStore(engine)
        catalog = default_catalog()
        if cfg.sla_overrides:  # attest.toml can tighten or loosen a control's freshness SLA
            catalog = [replace(c, freshness_sla_hours=cfg.sla_overrides.get(c.id, c.freshness_sla_hours)) for c in catalog]
        self.catalog = {c.id: c for c in catalog}
        self.controls = ControlEngine(list(self.catalog.values()), self.store)
        self._drafter = None
        self.key = self._approval_key()

    # ---- installation-level secrets --------------------------------------
    def _approval_key(self) -> bytes:
        with session_scope(self.engine) as s:
            current = get_setting(s, "approval_key")
            if not current:
                current = {"hex": secrets.token_hex(32), "created_at": now_iso()}
                set_setting(s, "approval_key", current)
            return bytes.fromhex(current["hex"])

    def sign_bytes(self, data: bytes) -> str:
        """HMAC-SHA256 with this installation's approval key (packages, manifests, decisions)."""
        return hmac.new(self.key, data, hashlib.sha256).hexdigest()

    # ---- feed: persisted as guardrail entries in the audit log -----------
    def _event(self, verdict: str, title: str, sub: str, tags=(), rule=None, enforcement="", disposition="",
               identity="", payload=None, actor: str = "attest") -> dict:
        detail = json.dumps(dict(sub=sub, tags=list(tags), enforcement=enforcement, disposition=disposition,
                                 identity=identity, payload=payload), sort_keys=True)
        entry = self.audit.record(actor=actor, action=f"{FEED_PREFIX}{verdict}", subject=title, detail=detail, rule=rule)
        return self._entry_to_event(entry)

    @staticmethod
    def _entry_to_event(entry) -> dict:
        try:
            extra = json.loads(entry.detail or "{}")
        except json.JSONDecodeError:
            extra = {"sub": entry.detail}
        return dict(ts=entry.ts, verdict=entry.action[len(FEED_PREFIX):], title=entry.subject, rule=entry.rule,
                    sub=extra.get("sub", ""), tags=extra.get("tags", []), enforcement=extra.get("enforcement", ""),
                    disposition=extra.get("disposition", ""), identity=extra.get("identity", ""), payload=extra.get("payload"))

    def events(self, limit: int = FEED_LIMIT) -> list[dict]:
        return [self._entry_to_event(e) for e in self.audit.query(action_prefix=FEED_PREFIX, limit=limit)]

    def _rule_counts(self) -> dict:
        counts = {r: 0 for r in RULE_TAGS}
        for e in self.events():
            if e["rule"] in counts and e["verdict"] in ("blocked", "escalated"):
                counts[e["rule"]] += 1
        return counts

    def _deny(self, identity: Identity, violation: GuardrailViolation, action: str, subject: str, what: str) -> None:
        self.audit.record(actor=identity.email, action=action, subject=subject, rule=violation.rule, detail=violation.detail)
        self._event("blocked", f"{what} denied for {identity.email}",
                    f"role: {identity.role} · grants: {', '.join(sorted(identity.grants)) or 'none'}",
                    [RULE_TAGS["requester-scoped-identity"]], rule=violation.rule, enforcement=violation.detail,
                    disposition="The agent acts with the requester's grants, not the service account's. Nothing ran.",
                    identity=f"requester: {identity.email} ({identity.role}, via {identity.via})", actor=identity.email)

    # ---- agent actions ----------------------------------------------------
    def read_doc(self, identity: Identity, doc_id: str, text: str, tools: list[str] | None = None) -> dict:
        tools = list(tools or READER_TOOLS)
        scope = identity.scope()
        try:
            enforce_requester_scope(scope, "read:documents")
        except GuardrailViolation as violation:
            self._deny(identity, violation, "reader.denied", doc_id, "Document read")
            raise Forbidden(str(violation)) from violation
        who = f"reader-agent v0.4.2 · requester: {identity.email} · scope: {', '.join(tools)}"
        try:
            reader = ReaderAgent(self.audit, registered_tools=tools)
            result = reader.read(doc_id, text)
        except GuardrailViolation as violation:
            return self._event("blocked", "Reader refused to start: write-capable tool registered",
                               f"reader-agent · {doc_id} · tools: {', '.join(tools)}", [RULE_TAGS["untrusted-doc-isolation"]],
                               rule=violation.rule, enforcement=violation.detail,
                               disposition="No document was read. Reading and acting must be separate passes with separate privileges.",
                               identity=who, actor=identity.email)
        if result["quarantined"]:
            paragraphs = [p.strip() for p in text.split("\n\n") if p.strip() and scan_for_injection(p)]
            return self._event("blocked", f"Prompt injection blocked in {doc_id}",
                               f"reader-agent · patterns: {', '.join(result['injection_patterns'])}", ["LLM01"],
                               rule="untrusted-doc-isolation",
                               enforcement="The extraction context registers zero write-capable tools. The instruction was parsed as document text and had no reachable path to a state change — there was nothing for it to call.",
                               disposition="Document quarantined. Extracted facts retained; risk rating left unset; routed to human review.",
                               identity=who, payload="\n\n".join(paragraphs) or text[:400], actor=identity.email)
        extracted = result.get("extracted") or {}
        return self._event("allowed", f"Document read cleanly: {doc_id}", "reader-agent · no injection patterns · facts extracted",
                           [], identity=who, actor=identity.email,
                           disposition=f"Extracted {len(extracted)} field(s): {', '.join(list(extracted)[:6]) or 'none'}.")

    def llm_available(self) -> bool:
        return self.cfg.llm.enabled and ClaudeDrafter is not None and importlib.util.find_spec("anthropic") is not None

    def _drafter_instance(self):
        if not self.llm_available():
            raise ValueError("LLM drafting is disabled — set [llm].enabled = true and install attest[llm]")
        if self._drafter is None:
            self._drafter = ClaudeDrafter(model=self.cfg.llm.model)
        return self._drafter

    def answer(self, identity: Identity, question: str, control_ids: list[str], qid: str | None = None, llm: bool = False,
               questionnaire_id: str | None = None, ref: str | None = None) -> dict:
        scope = identity.scope()
        with self.lock:
            qid = qid or self.drafts.next_question_id()
        kwargs = {"drafter": self._drafter_instance()} if llm else {}
        agent = AnswerAgent(self.store, self.audit, scope, allowlist=frozenset({"read:evidence"}), **kwargs)
        draft = agent.draft(qid, question, list(control_ids))
        mode = f"{self.cfg.llm.model} draft · guardrails validated" if llm else "deterministic draft"
        fields = dict(question_id=qid, question=question, control_ids=list(control_ids), status=draft.status,
                      answer=draft.answer, reason=draft.reason, citations=self._citations(draft.evidence_ids),
                      mode=mode, model_version=agent.model_version, created_at=now_iso(), created_by=identity.email)
        if questionnaire_id:
            fields["questionnaire_id"] = questionnaire_id
        if ref:
            fields["ref"] = ref
        row = self.drafts.create(fields)
        who = f"answer-agent · requester: {identity.email} · {mode}"
        if draft.status == "READY":
            self._event("allowed", f"Questionnaire {qid} drafted with {len(draft.evidence_ids)} citation(s)", f"answer-agent · {question}",
                        ["grounded"] if llm else [],
                        enforcement="citation-required · egress-classification-gate · tool-allowlist · max-steps · requester-scoped-identity all passed",
                        disposition="Draft only. Nothing reaches the customer until a named human approves it.", identity=who, actor=identity.email)
        elif draft.status == "DECLINED":
            self._event("declined", f"Agent declined {qid}: no evidence for the requested controls", f"answer-agent · {question}",
                        ["grounding"], rule="citation-required",
                        enforcement="No evidence record exists for the requested controls, so there is nothing to cite.",
                        disposition="Routed to the control owner. Silence in the evidence store is not evidence of absence — the agent does not infer from it.",
                        identity=who, actor=identity.email)
        else:
            rule = draft.reason.split(":")[0].strip() or "guardrail"
            self._event("blocked", f"Draft for {qid} rejected by {rule}", f"answer-agent · {question}", [RULE_TAGS.get(rule, "guardrail")],
                        rule=rule, enforcement=draft.reason,
                        disposition="Blocked before reaching the approval queue, so a reviewer never has to catch it.", identity=who, actor=identity.email)
        return self._queue_item(row)

    def _citations(self, evidence_ids: list[str]) -> list[dict]:
        now = datetime.now(timezone.utc)
        out = []
        for eid in evidence_ids:
            rec = self.store.get(eid)
            if not rec:
                continue
            age_h = (now - parse_iso(rec.collected_at)).total_seconds() / 3600
            slas = [self.catalog[c].freshness_sla_hours for c in rec.control_ids if c in self.catalog]
            out.append(dict(id=rec.id, source=rec.source, kind=rec.kind, classification=rec.classification, collected_at=rec.collected_at,
                            age=_age(rec.collected_at, now), stale=bool(slas) and age_h > min(slas),
                            sla=f"{min(slas) // 24}d" if slas and min(slas) >= 48 else (f"{min(slas)}h" if slas else "")))
        return out

    def _queue_item(self, row: dict) -> dict:
        """What the console renders for one draft."""
        gated = row["status"] == "DECLINED" and any(
            r.classification != "publishable" for cid in row.get("control_ids", []) for r in self.store.query(control_id=cid))
        return dict(question_id=row["question_id"], question=row["question"], answer=row.get("answer", ""), ref=row.get("ref"),
                    evidence_ids=[c["id"] for c in row.get("citations", [])], gated=gated, status=row["status"],
                    reason=row.get("reason", ""), citations=row.get("citations", []), control_ids=row.get("control_ids", []),
                    mode=row.get("mode", ""), requester=row.get("created_by"), created_at=row.get("created_at"),
                    decision=row.get("decision"), approver=row.get("approver"), signature=row.get("signature"), signed_at=row.get("decided_at"))

    def queue(self, limit: int | None = None) -> list[dict]:
        return [self._queue_item(r) for r in self.drafts.list(limit=limit)]

    # ---- human decisions ------------------------------------------------
    def _sign(self, question_id: str, answer: str, decision: str, approver: str, ts: str) -> str:
        message = canonical_json({"question_id": question_id, "answer_sha256": hashlib.sha256(answer.encode("utf-8")).hexdigest(),
                                  "decision": decision, "approver": approver, "ts": ts})
        return hmac.new(self.key, message.encode("utf-8"), hashlib.sha256).hexdigest()

    def approvals_verified(self) -> bool:
        return all(hmac.compare_digest(self._sign(q["question_id"], q["answer"], q["decision"], q["approver"], q["signed_at"]), q["signature"] or "")
                   for q in self.queue() if q.get("decision"))

    def decide(self, identity: Identity, qid: str, decision: str) -> dict:
        row = self.drafts.get(qid)
        if row is None:
            raise ValueError(f"unknown question {qid}")
        if row.get("decision"):
            raise ValueError(f"{qid} already decided")
        actions = {"approve": ("approval.approved", "approved and sent to customer"),
                   "reject": ("approval.returned", "returned to the agent for redraft"),
                   "assign": ("approval.assigned", "routed to the incident response owner")}
        if decision not in actions:
            raise ValueError(f"unknown decision {decision}")
        try:
            enforce_requester_scope(identity.scope(), "approve:questionnaire")
        except GuardrailViolation as violation:
            self._deny(identity, violation, "approval.denied", qid, f"Decision on {qid}")
            raise Forbidden(str(violation)) from violation
        action, verb = actions[decision]
        ts = now_iso()
        signature = self._sign(qid, row.get("answer", ""), decision, identity.email, ts)
        stale = any(c.get("stale") for c in row.get("citations", []))
        detail = f"sig={signature[:16]}"
        if decision == "approve" and stale:
            detail = "exception recorded: approved with a stale citation · " + detail
        self.audit.record(actor=identity.email, action=action, subject=qid, approver=identity.email, detail=detail)
        updated = self.drafts.decide(qid, decision, identity.email, signature, ts)
        self._event("allowed", f"{qid} {verb}", f"human decision · {identity.email} · HMAC-SHA256 {signature[:16]}…"
                    + (" · exception: stale citation" if decision == "approve" and stale else ""), [],
                    identity=f"approver: {identity.email} ({identity.role}) · drafted by answer-agent",
                    enforcement="Signed over (question_id, sha256(answer), decision, approver, ts) with this installation's approval key. The approval cannot be edited or re-attributed without breaking the signature.",
                    actor=identity.email)
        return self._queue_item(updated)

    # ---- evaluation & history ------------------------------------------
    def evaluate(self, trigger: str = "manual", record: bool = True) -> dict:
        results = self.controls.evaluate()
        current = {r.control_id: r for r in results}
        if record:
            previous = {cid: snap.get("state") for cid, snap in self.snapshots.latest().items()}
            self.snapshots.record(results, trigger=trigger)
            if previous:  # nothing to compare on the very first evaluation
                self._notify_transitions(previous, current)
        return current

    # ---- notifications: a new FAIL / DEGRADED / finding reaches an owner ----
    def _notifier(self):
        try:
            from attest.notify import Notifier
            from attest.store_sql import NotificationStore
        except ImportError:
            return None
        return Notifier(self.cfg, NotificationStore(self.engine))

    def _notify_transitions(self, previous: dict, current: dict) -> None:
        try:
            from attest.notify import diff_states
        except ImportError:
            return
        events = diff_states(previous, {c: r.state for c, r in current.items()}, {c: r.reason for c, r in current.items()})
        if events:
            self._dispatch(events)

    def _dispatch(self, events) -> None:
        notifier = self._notifier()
        if notifier is None:
            return
        try:
            notifier.dispatch(events)
        except Exception as e:  # delivery must never break evaluation; it is recorded, not raised
            self.audit.record(actor="notifier", action="notify.error", subject="dispatch", detail=str(e))

    def notifications(self, limit: int = 50) -> list[dict]:
        try:
            from attest.store_sql import NotificationStore
        except ImportError:
            return []
        return NotificationStore(self.engine).recent(limit)

    def history_summary(self, days: int = 90) -> dict:
        """Observation-window view: how each control behaved over the last N evaluations."""
        now = datetime.now(timezone.utc)
        since = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        out = {}
        for cid in self.catalog:
            rows = self.snapshots.history(cid, since=since, limit=None)  # newest first
            if not rows:
                out[cid] = dict(evaluations=0, current=None, pass_pct=None, transitions=0, timeline=[])
                continue
            chron = list(reversed(rows))
            states = [r["state"] for r in chron]
            transitions = sum(1 for a, b in zip(states, states[1:]) if a != b)
            streak_since = chron[-1]["evaluated_at"]
            for r in reversed(chron):
                if r["state"] != states[-1]:
                    break
                streak_since = r["evaluated_at"]
            out[cid] = dict(current=states[-1], evaluations=len(states), pass_pct=round(100 * states.count("PASS") / len(states), 1),
                            transitions=transitions, since=streak_since, first=chron[0]["evaluated_at"], last=chron[-1]["evaluated_at"],
                            timeline=[dict(t=r["evaluated_at"], s=r["state"]) for r in chron][-60:])
        return dict(days=days, since=since, controls=out)

    # ---- questionnaires and packages -------------------------------------
    def questionnaires(self) -> list[dict]:
        from attest.store_sql import QuestionnaireStore
        return QuestionnaireStore(self.engine).list()

    def import_questionnaire(self, identity: Identity, path: Path, name: str | None = None) -> dict:
        from attest.questionnaires import parse_questionnaire
        from attest.store_sql import QuestionnaireStore
        identity.require("read:evidence")
        rows = parse_questionnaire(path)
        store = QuestionnaireStore(self.engine)
        qn = store.create(name or path.stem, path.name, identity.email, len(rows))
        drafts = [self.answer(identity, r["question"], list(r.get("control_ids") or []), questionnaire_id=qn["id"], ref=r.get("ref")) for r in rows]
        self.audit.record(actor=identity.email, action="questionnaire.imported", subject=qn["id"], detail=f"{len(rows)} questions from {path.name}")
        return dict(questionnaire=qn, drafts=drafts)

    def questionnaire_rows(self, qn_id: str) -> list[dict]:
        return [self._queue_item(r) for r in self.drafts.list_for_questionnaire(qn_id)]

    def export_questionnaire(self, identity: Identity, qn_id: str, out: Path, fmt: str | None = None) -> Path:
        from attest.questionnaires import export_questionnaire
        from attest.store_sql import QuestionnaireStore
        identity.require("read:evidence")
        store = QuestionnaireStore(self.engine)
        if store.get(qn_id) is None:
            raise ValueError(f"unknown questionnaire {qn_id}")
        rows = self.questionnaire_rows(qn_id)
        pending = [r["question_id"] for r in rows if r["status"] == "READY" and not r.get("decision")]
        export_questionnaire(rows, out, fmt)
        store.set_status(qn_id, "exported")
        self.audit.record(actor=identity.email, action="questionnaire.exported", subject=qn_id,
                          detail=f"{len(rows)} rows → {out.name}" + (f" · {len(pending)} undecided" if pending else ""))
        return out

    def build_package(self, identity: Identity, out: Path, framework: str | None = None, since: str | None = None,
                      include_restricted: bool = False) -> dict:
        from attest.packages import build_package
        from attest.store_sql import PackageStore
        identity.require("read:evidence")
        if include_restricted:
            identity.require("manage:acceptances")  # engineers and admins only; auditors get the publishable+internal set
        if framework and framework not in FRAMEWORKS:
            raise ValueError(f"unknown framework {framework}")
        out.parent.mkdir(parents=True, exist_ok=True)
        manifest = build_package(self, out, framework=framework, since=since, include_restricted=include_restricted, created_by=identity.email)
        digest = hashlib.sha256(out.read_bytes()).hexdigest()
        PackageStore(self.engine).record(identity.email, framework, since, str(out), digest, manifest)
        self.audit.record(actor=identity.email, action="package.built", subject=out.name, detail=f"framework={framework or 'all'} since={since or '-'} sha256={digest[:16]}")
        return dict(manifest=manifest, path=str(out), sha256=digest)

    def history(self, control_id: str, since: str | None = None, limit: int | None = 200) -> list[dict]:
        if control_id not in self.catalog:
            raise ValueError(f"unknown control {control_id}")
        return self.snapshots.history(control_id, since=since, limit=limit)

    # ---- collectors ------------------------------------------------------
    def run_source(self, source_id: str, identity: Identity = SYSTEM, trigger: str = "manual") -> dict:
        from attest.collectors.registry import run_source
        identity.require("run:collectors")
        before = self.store.count()
        result = run_source(self.cfg, source_id, self.store, self.audit, runs=self.runs, trigger=trigger, started_by=identity.email)
        if self.cfg.sources[source_id].type == "hris-idp-join" and result.get("status") == "ok":
            newest = self.store.query(kind=JOIN["output"])
            if newest:
                self._join_event(newest[-1], trigger, actor=identity.email)
        self.evaluate(trigger="collector")
        result["new_records"] = self.store.count() - before
        return result

    def import_file(self, identity: Identity, path: Path, mapping: str | None = None, source: str | None = None) -> dict:
        from attest.importers import import_file
        identity.require("write:evidence:import")
        run_id = self.runs.start(source or f"import:{path.name}", trigger="import", started_by=identity.email)
        try:
            res = import_file(self.store, path, mapping=mapping, source=source, run_id=run_id)
        except Exception as e:
            self.runs.finish(run_id, "error", 0, str(e))
            self.audit.record(actor=identity.email, action="import.error", subject=path.name, detail=str(e))
            raise
        self.runs.finish(run_id, "ok", res.records)
        self.audit.record(actor=identity.email, action="import.ok", subject=path.name,
                          detail=f"{res.records} records · kinds: {', '.join(res.kinds)}")
        self.evaluate(trigger="import")
        return dict(records=res.records, kinds=res.kinds, warnings=res.warnings, run_id=run_id)

    def _join_event(self, rec, trigger: str, actor: str = "join-collector") -> None:
        failed = rec.payload.get("result") == "fail"
        orphans = rec.payload.get("orphans", [])
        self.audit.record(actor="join-collector", action="join.finding" if failed else "join.pass",
                          subject=orphans[0]["email"] if orphans else "hris-idp-join", detail=rec.payload.get("summary", ""))
        if failed and orphans:
            o = orphans[0]
            try:
                from attest.notify import NotifyEvent
                self._dispatch([NotifyEvent(kind="finding", control_id=JOIN["control"],
                                            title=f"Leaver still active {o.get('days_open', '?')} days after termination",
                                            summary=rec.payload.get("summary", ""), evidence_ids=[rec.id])])
            except ImportError:
                pass
            self._event("finding", f"Leaver still has an active IdP account {o.get('days_open', '?')} days after termination",
                        f"hris-idp-join · {o.get('name')} <{o.get('email')}> · terminated {o.get('terminated')} · IdP {o.get('idp_status')}",
                        [RULE_TAGS["hris-idp-join"]], rule="hris-idp-join",
                        enforcement="The HR roster was joined against the identity provider's user list. A terminated employee with an active account is an access-control failure regardless of what the last access review signed off.",
                        disposition="CTL-ACCESS-02 is now FAIL — SOC 2 CC6.2, ISO/IEC A.5.18, HIPAA §164.308(a)(3)(ii)(C). Deprovision the account and re-run the join.",
                        identity=f"join-collector · inputs: hris.roster × idp.users · trigger: {trigger}", actor=actor)
        else:
            self._event("allowed", "Leaver join clean: every terminated employee was deprovisioned inside the SLA",
                        f"hris-idp-join · {rec.payload.get('summary', '')}", [RULE_TAGS["hris-idp-join"]], rule="hris-idp-join",
                        disposition="CTL-ACCESS-02 holds on evidence, not on the last review's signature.",
                        identity=f"join-collector · inputs: hris.roster × idp.users · trigger: {trigger}", actor=actor)

    def run_join(self, identity: Identity = SYSTEM, trigger: str = "manual") -> dict:
        from attest.collectors.joiner_leaver import run_join
        identity.require("run:collectors")
        rec = run_join(self.store)
        self._join_event(rec, trigger, actor=identity.email)
        self.evaluate(trigger="collector")
        return rec.payload

    # ---- gate --------------------------------------------------------------
    def gate(self, today: str | None = None, strict: bool = False) -> dict:
        today = today or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        accepted = {a["control_id"]: a for a in self.acceptances.active(today)}
        for a in self.cfg.acceptances:  # file-level acceptances count too
            if a.expires >= today and a.control not in accepted:
                accepted[a.control] = dict(control_id=a.control, owner=a.owner, reason=a.reason, expires=a.expires, source="attest.toml")
        rows, failing = [], []
        for cid, r in self.evaluate(trigger="gate", record=False).items():
            verdict = r.state
            if r.state == "FAIL" and cid in accepted:
                verdict = "ACCEPTED"
            elif r.state == "FAIL" or (strict and r.state == "DEGRADED"):
                failing.append(cid)
            rows.append(dict(control_id=cid, state=r.state, verdict=verdict, reason=r.reason, acceptance=accepted.get(cid)))
        return dict(passed=not failing, failing=failing, rows=rows, strict=strict, today=today)

    # ---- sandbox-only demo operations ----------------------------------
    def _require_sandbox(self) -> None:
        if not self.cfg.sandbox:
            raise Forbidden("demo operations are only available in sandbox mode")

    def reseed(self) -> None:
        self._require_sandbox()
        from attest.seed import seed_into
        with session_scope(self.engine) as s:
            for table in ("evidence", "audit", "drafts", "control_snapshots", "collector_runs"):
                s.execute(sql_text(f"DELETE FROM {table}"))
        seed_into(self.store, self.audit)
        self._warmup()
        self.evaluate(trigger="seed")

    def _warmup(self) -> None:
        demo = self._demo_identity()
        self.answer(demo, "Have you experienced a reportable breach in the last 24 months?", [], qid="Q-4474")
        self.answer(demo, "Describe your cadence for reviewing privileged access.", ["CTL-PRIV-01"], qid="Q-4472")
        self.answer(demo, "Is customer PHI encrypted at rest and in transit?", ["CTL-CRYPTO-01", "CTL-CRYPTO-02"], qid="Q-4471")
        self.read_doc(demo, "contoso-soc2-2025.pdf p.9", (EXAMPLES / "vendor-clean-excerpt.txt").read_text(), READER_TOOLS)
        self.read_doc(demo, "northwind-soc2-2025.pdf p.14", (EXAMPLES / "vendor-soc2-excerpt.txt").read_text(), READER_TOOLS)

    @staticmethod
    def _demo_identity() -> Identity:
        from attest.auth import ROLE_GRANTS
        return Identity(user_id=0, email="s.vemula@attest.internal", name="Security engineer", role="engineer", via="system",
                        grants=ROLE_GRANTS["engineer"])

    def tamper(self) -> dict:
        self._require_sandbox()
        rows = self.store.all()
        target = rows[min(3, len(rows) - 1)]
        payload = dict(target.payload)
        payload["result"] = "fail" if payload.get("result") == "pass" else "pass"
        with session_scope(self.engine) as s:  # deliberately bypasses the store: there is no update path
            s.execute(sql_text("UPDATE evidence SET payload = :p WHERE id = :id"), {"p": json.dumps(payload), "id": target.id})
        self.audit.record(actor="demo-operator", action="evidence.tampered", subject=target.id,
                          detail="payload.result edited in the database; digest not recomputed")
        return self._event("blocked", f"Ledger integrity failure detected at {target.id}",
                           "verify_chain() · recomputed digest does not match the stored one", ["integrity"], rule="hash-chain",
                           enforcement="Each record's SHA-256 covers its content plus the previous record's digest. Editing one row breaks the chain from that record forward.",
                           disposition="Evidence from this store is untrusted until restored from the collector of record. Reset the sandbox to restore it.")

    def terminate_user(self, identity: Identity) -> dict:
        self._require_sandbox()
        rosters = self.store.query(kind="hris.roster")
        idps = self.store.query(kind="idp.users")
        if not rosters or not idps:
            raise ValueError("the store has no HRIS roster / IdP user list to join")
        roster = rosters[-1]
        employees = [dict(e) for e in roster.payload.get("employees", [])]
        active = {u.get("email") for u in idps[-1].payload.get("users", []) if u.get("status") == "active"}
        victim = next((e for e in employees if not e.get("terminated") and e.get("email") in active), None)
        if victim is None:
            raise ValueError("every active employee has already been terminated in this demo — reset to start over")
        when = (datetime.now(timezone.utc) - timedelta(days=9)).strftime("%Y-%m-%d")
        victim["terminated"] = when
        terminated = sum(1 for e in employees if e.get("terminated"))
        self.store.append(source="hris", kind="hris.roster", control_ids=list(roster.control_ids), classification="internal",
                          payload={"summary": f"HRIS roster: {len(employees)} employees, {terminated} terminated (latest: {victim.get('name')} on {when})",
                                   "result": "pass", "employees": employees})
        self.audit.record(actor=identity.email, action="hris.termination", subject=victim.get("email", "?"), detail=f"terminated {when}; IdP account left active")
        return self.run_join(identity, trigger="hris.termination")

    # ---- read model --------------------------------------------------------
    def _sources_view(self, results: dict, now: datetime) -> tuple[list, dict]:
        records = self.store.all()
        by_source: dict[str, list] = {}
        for r in records:
            by_source.setdefault(r.source, []).append(r)
        rank = {"FAIL": 0, "DEGRADED": 1, "PASS": 2}
        last_runs = self.runs.latest_by_source()
        families = []
        for fid, sources in sources_by_family().items():
            rows = []
            for src in sources:
                recs = by_source.get(src.id, [])
                ctls = [c for c in self.catalog.values() if set(c.required_kinds) & set(src.kinds)]
                if set(src.kinds) & set(JOIN["inputs"]) and self.catalog[JOIN["control"]] not in ctls:
                    ctls.append(self.catalog[JOIN["control"]])
                states = [results[c.id].state for c in ctls if c.id in results]
                newest = max(recs, key=lambda r: r.collected_at) if recs else None
                rows.append(dict(id=src.id, system=src.system, proves=src.proves, kinds=list(src.kinds), records=len(recs),
                                 newest_age=_age(newest.collected_at, now) if newest else None, controls=[c.id for c in ctls],
                                 state=min(states, key=lambda x: rank[x]) if states else None,
                                 last_run=last_runs.get(src.id)))
            families.append(dict(id=fid, name=FAMILIES[fid], sources=rows))
        latest = None
        join_recs = [r for r in records if r.kind == JOIN["output"]]
        if join_recs:
            r = join_recs[-1]
            latest = dict(id=r.id, result=r.payload.get("result"), summary=r.payload.get("summary"), orphans=r.payload.get("orphans", []),
                          checked=r.payload.get("checked"), sla_hours=r.payload.get("sla_hours"), age=_age(r.collected_at, now))
        return families, dict(JOIN, inputs=list(JOIN["inputs"]), latest=latest)

    def configured_sources(self) -> list[dict]:
        last = self.runs.latest_by_source()
        return [dict(id=s.id, type=s.type, schedule=s.schedule, enabled=s.enabled, params={k: v for k, v in s.params.items() if k != "token"},
                     last_run=last.get(s.id)) for s in self.cfg.sources.values()]

    def state(self, identity: Identity) -> dict:
        now = datetime.now(timezone.utc)
        records = self.store.all()
        fresh = 0
        for r in records:
            slas = [self.catalog[c].freshness_sla_hours for c in r.control_ids if c in self.catalog]
            if slas and (now - parse_iso(r.collected_at)).total_seconds() / 3600 <= min(slas):
                fresh += 1
        evidence = [dict(id=r.id, source=r.source, kind=r.kind, classification=r.classification, digest=r.sha256[:6],
                         age=_age(r.collected_at, now)) for r in reversed(records[-12:])]
        results = self.evaluate(trigger="state", record=False)

        def failing_summary(control):
            failing = [r for r in self.store.query(control_id=control.id) if isinstance(r.payload, dict) and r.payload.get("result") == "fail"]
            return failing[-1].payload.get("summary") if failing else None

        controls = [dict(id=c.id, name=c.name, state=results[c.id].state, reason=results[c.id].reason, evidence=len(results[c.id].evidence_ids),
                         sla_hours=c.freshness_sla_hours, spec=c.hipaa_spec, frameworks=c.mappings,
                         failing_summary=failing_summary(c) if results[c.id].state == "FAIL" else None)
                    for c in self.catalog.values() if c.id in results]
        sources, join = self._sources_view(results, now)
        audit = [asdict(e) for e in self.audit.query(limit=200) if not e.action.startswith(FEED_PREFIX)][:40]
        return dict(
            generated_at=now_iso(), mode=self.cfg.server.mode,
            identity=dict(user=identity.email, name=identity.name, role=identity.role, grants=sorted(identity.grants), via=identity.via),
            llm_available=self.llm_available(),
            summary=self.controls.summary(), frameworks=FRAMEWORKS, posture={fw: self.controls.posture(fw) for fw in FRAMEWORKS},
            evidence=evidence, evidence_total=len(records), evidence_fresh=fresh,
            chain_intact=self.store.verify_chain(), approvals_verified=self.approvals_verified(),
            events=self.events(), queue=self.queue(), rules=self._rule_counts(), audit=audit,
            catalog=[dict(id=c.id, name=c.name) for c in self.catalog.values()], controls=controls,
            sources=sources, join=join, configured_sources=self.configured_sources(),
            acceptances=self.acceptances.active(now.strftime("%Y-%m-%d")),
            questionnaires=self._safe(self.questionnaires, []), notifications=self._safe(lambda: self.notifications(20), []),
        )

    @staticmethod
    def _safe(fn, default):
        """Optional read-model parts survive a module that has not shipped yet."""
        try:
            return fn()
        except (ImportError, AttributeError):
            return default
