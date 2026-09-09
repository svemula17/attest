"""Agents for the attest pipeline.  Deterministic by default; no LLM calls
unless a drafter is injected.

:class:`AnswerAgent` composes an answer to a compliance question purely from
evidence records, so the whole guardrail pipeline can be exercised offline:

    query (budgeted, allowlisted, requester-scoped)
      -> claims (one per record, each citing exactly that record)
      -> citation_required
      -> egress_classification_gate
      -> Draft(READY | BLOCKED | DECLINED)
      -> one AuditLog entry, whatever the outcome

With an optional ``drafter`` (see :mod:`attest.llm`) the *claims* step is
delegated to a model, and the same guardrails validate what it returns: the
egress gate runs on the records before they are shown to the model, every
claim must cite ids that resolve in the store, and the egress gate runs
again on the records those citations resolve to.

:class:`ReaderAgent` ingests untrusted documents.  It is constructed with the
tools it is allowed to hold, refuses to exist if any of them can write, scans
each document for injection patterns and quarantines anything suspicious.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .guardrails import (
    Claim,
    GuardrailViolation,
    RequesterScope,
    StepBudget,
    citation_required,
    egress_classification_gate,
    enforce_requester_scope,
    enforce_tool_allowlist,
    scan_for_injection,
    untrusted_doc_isolation,
)

__all__ = [
    "Draft",
    "AnswerAgent",
    "ReaderAgent",
    "EVIDENCE_QUERY_TOOL",
    "EGRESS_MAX_CLASSIFICATION",
    "DECLINED_NO_EVIDENCE",
    "DECLINED_NO_MODEL_SUPPORT",
    "LLM_ERROR_RULE",
]

#: The single tool the answer agent uses.  It must be present in both the
#: static allowlist and the requester's grants for a draft to proceed.
EVIDENCE_QUERY_TOOL = "read:evidence"

#: Answers leave the system, so only publishable evidence may be used.
EGRESS_MAX_CLASSIFICATION = "publishable"

#: Reason recorded on a Draft when no evidence exists for the asked controls.
DECLINED_NO_EVIDENCE = "no evidence for requested controls; not inferring from absence"

#: Reason recorded when a drafter model returns zero claims for real evidence.
DECLINED_NO_MODEL_SUPPORT = "model found no supporting evidence; not inferring from absence"

#: Audit rule / reason prefix when the drafter itself fails (transport, refusal, bad shape).
LLM_ERROR_RULE = "llm-error"


@dataclass
class Draft:
    question_id: str
    question: str
    answer: str
    evidence_ids: list[str]
    status: str  # "READY" | "BLOCKED" | "DECLINED"
    reason: str = ""


def _sentence_for(record) -> str:
    """The one deterministic sentence an answer contains per evidence record."""
    payload = getattr(record, "payload", None) or {}
    summary = payload.get("summary", "evidence on file")
    return f"{record.kind}: {summary} [{record.id}]"


class _DrafterFailure(Exception):
    """Internal: the injected drafter raised or returned something unusable."""


class AnswerAgent:
    """Composes answers from evidence only.  Declines rather than infers.

    Pass ``drafter`` (e.g. :class:`attest.llm.ClaudeDrafter`) to have a model
    write the claims; the guardrails still decide whether they ship.
    """

    def __init__(
        self,
        store,
        audit,
        scope: RequesterScope,
        allowlist: frozenset[str],
        model_version: str = "answer-agent v0.4.2",
        max_steps: int = 12,
        drafter=None,
    ):
        self.store = store
        self.audit = audit
        self.scope = scope
        self.allowlist = frozenset(allowlist)
        self.drafter = drafter
        # A drafter names the model that actually wrote the words; audit as that.
        self.model_version = getattr(drafter, "model_version", None) or model_version
        self.max_steps = max_steps

    # -- helpers ------------------------------------------------------------

    def _collect(self, control_ids: list[str], budget: StepBudget) -> list:
        """One budgeted, allowlisted, requester-scoped query per control id.

        Records are de-duplicated by id and kept in first-seen order so the
        resulting answer is deterministic for a given store.
        """
        records: list = []
        seen: set[str] = set()
        for control_id in control_ids:
            enforce_tool_allowlist(EVIDENCE_QUERY_TOOL, self.allowlist)
            enforce_requester_scope(self.scope, EVIDENCE_QUERY_TOOL)
            budget.tick(EVIDENCE_QUERY_TOOL)
            found = self.store.query(
                control_id=control_id, max_classification=EGRESS_MAX_CLASSIFICATION
            )
            for record in found:
                if record.id not in seen:
                    seen.add(record.id)
                    records.append(record)
        return records

    def _model_claims(self, question: str, records: list) -> list[Claim]:
        """Ask the injected drafter for claims.  Any failure becomes an llm-error."""
        try:
            claims = self.drafter.draft(question, records)
        except GuardrailViolation:
            raise
        except Exception as exc:  # noqa: BLE001 - the model is untrusted; fail closed
            raise _DrafterFailure(str(exc) or exc.__class__.__name__) from exc
        return [Claim(text=str(c.text), evidence_ids=list(c.evidence_ids)) for c in claims]

    def _cited_records(self, claims: list[Claim]) -> list:
        """Resolve every cited id through the store, de-duplicated, first-seen order."""
        cited: list = []
        seen: set[str] = set()
        for claim in claims:
            for evidence_id in claim.evidence_ids:
                if evidence_id in seen:
                    continue
                seen.add(evidence_id)
                record = self.store.get(evidence_id)
                if record is not None:
                    cited.append(record)
        return cited

    def _audit(self, draft: Draft, rule: str | None, detail: str) -> None:
        self.audit.record(
            actor=self.model_version,
            action=f"draft.{draft.status.lower()}",
            subject=draft.question_id,
            model_version=self.model_version,
            approver=None,
            rule=rule,
            detail=detail,
        )

    # -- public API ---------------------------------------------------------

    def draft(self, question_id: str, question: str, control_ids: list[str]) -> Draft:
        budget = StepBudget(self.max_steps)
        control_ids = list(control_ids)
        rule: str | None = None
        detail: str

        try:
            records = self._collect(control_ids, budget)

            if not records:
                draft = Draft(
                    question_id=question_id,
                    question=question,
                    answer="",
                    evidence_ids=[],
                    status="DECLINED",
                    reason=DECLINED_NO_EVIDENCE,
                )
                detail = f"controls={control_ids}; steps={budget.steps}"
            elif self.drafter is None:
                claims = [Claim(text=_sentence_for(r), evidence_ids=[r.id]) for r in records]
                citation_required(claims, self.store)
                egress_classification_gate(records, max_classification=EGRESS_MAX_CLASSIFICATION)
                draft = Draft(
                    question_id=question_id,
                    question=question,
                    answer=" ".join(claim.text for claim in claims),
                    evidence_ids=[r.id for r in records],
                    status="READY",
                    reason="",
                )
                detail = (
                    f"controls={control_ids}; evidence={draft.evidence_ids}; "
                    f"steps={budget.steps}"
                )
            else:
                # Records leave the system when shown to the model: gate them first.
                egress_classification_gate(records, max_classification=EGRESS_MAX_CLASSIFICATION)
                claims = self._model_claims(question, records)
                if not claims:
                    draft = Draft(
                        question_id=question_id,
                        question=question,
                        answer="",
                        evidence_ids=[],
                        status="DECLINED",
                        reason=DECLINED_NO_MODEL_SUPPORT,
                    )
                    detail = (
                        f"controls={control_ids}; offered={[r.id for r in records]}; "
                        f"steps={budget.steps}"
                    )
                else:
                    citation_required(claims, self.store)
                    cited = self._cited_records(claims)
                    egress_classification_gate(cited, max_classification=EGRESS_MAX_CLASSIFICATION)
                    draft = Draft(
                        question_id=question_id,
                        question=question,
                        answer=" ".join(claim.text for claim in claims),
                        evidence_ids=[r.id for r in cited],
                        status="READY",
                        reason="",
                    )
                    detail = (
                        f"controls={control_ids}; evidence={draft.evidence_ids}; "
                        f"offered={[r.id for r in records]}; steps={budget.steps}"
                    )
        except _DrafterFailure as failure:
            rule = LLM_ERROR_RULE
            detail = f"{failure}; controls={control_ids}; steps={budget.steps}"
            draft = Draft(
                question_id=question_id,
                question=question,
                answer="",
                evidence_ids=[],
                status="BLOCKED",
                reason=f"{LLM_ERROR_RULE}: {failure}",
            )
        except GuardrailViolation as violation:
            rule = violation.rule
            detail = f"{violation.detail}; controls={control_ids}; steps={budget.steps}"
            draft = Draft(
                question_id=question_id,
                question=question,
                answer="",
                evidence_ids=[],
                status="BLOCKED",
                reason=violation.rule,
            )

        self._audit(draft, rule, detail)
        return draft


_CONTROL_ID_RE = re.compile(r"\bCTL-[A-Z0-9]+-\d+\b")
_SOC2_CRITERIA_RE = re.compile(r"\b(?:CC|A|C|PI|P)\d{1,2}\.\d{1,2}\b")


class ReaderAgent:
    """Reads untrusted documents with read-only tools and quarantines on detection.

    Construction fails with ``GuardrailViolation("untrusted-doc-isolation")``
    if any registered tool can write; the check is repeated on every read in
    case the tool list was mutated afterwards.
    """

    def __init__(self, audit, registered_tools: list[str], model_version: str = "reader-agent v0.4.2"):
        self.audit = audit
        self.registered_tools = list(registered_tools)
        self.model_version = model_version
        self._assert_isolated(subject="<construction>")

    def _assert_isolated(self, subject: str) -> None:
        try:
            untrusted_doc_isolation(self.registered_tools)
        except GuardrailViolation as violation:
            self.audit.record(
                actor=self.model_version,
                action="reader.misconfigured",
                subject=subject,
                model_version=self.model_version,
                approver=None,
                rule=violation.rule,
                detail=violation.detail,
            )
            raise

    @staticmethod
    def _extract(text: str) -> dict:
        """Structural, non-interpretive extraction from a clean document."""
        return {
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "chars": len(text),
            "words": len(text.split()),
            "lines": text.count("\n") + 1 if text else 0,
            "control_ids": sorted(set(_CONTROL_ID_RE.findall(text))),
            "soc2_criteria": sorted(set(_SOC2_CRITERIA_RE.findall(text))),
        }

    def read(self, doc_id: str, text: str) -> dict:
        self._assert_isolated(subject=doc_id)

        patterns = scan_for_injection(text)
        quarantined = bool(patterns)
        extracted = {} if quarantined else self._extract(text)

        self.audit.record(
            actor=self.model_version,
            action="doc.quarantined" if quarantined else "doc.read",
            subject=doc_id,
            model_version=self.model_version,
            approver=None,
            rule="injection-scan" if quarantined else None,
            detail=(
                "injection patterns: " + ", ".join(patterns)
                if quarantined
                else f"clean; {extracted['chars']} chars"
            ),
        )
        return {
            "doc_id": doc_id,
            "injection_patterns": patterns,
            "quarantined": quarantined,
            "extracted": extracted,
        }
