"""Tests for attest.llm and the AnswerAgent LLM seam.

No network.  A FakeClient stands in for ``anthropic.Anthropic()`` and returns
a canned response object shaped like the SDK's Message: ``stop_reason``,
``stop_details`` and a ``content`` list of blocks with ``.type`` / ``.text``.
"""
from __future__ import annotations

import dataclasses
import json
import os
import sys
from types import SimpleNamespace

import pytest

from attest.agent import (
    DECLINED_NO_EVIDENCE,
    DECLINED_NO_MODEL_SUPPORT,
    EVIDENCE_QUERY_TOOL,
    AnswerAgent,
)
from attest.guardrails import Claim, RequesterScope
from attest.llm import CLAIMS_SCHEMA, SYSTEM_PROMPT, ClaudeDrafter, LLMDraftError, LLMRefusal

CLASSIFICATION_ORDER = ["publishable", "internal", "restricted"]


# --------------------------------------------------------------------------- #
# fakes
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class FakeRecord:
    id: str
    classification: str
    kind: str
    payload: dict
    control_ids: list
    source: str = "aws-config"


class FakeStore:
    def __init__(self, records, leak=False):
        self._records = list(records)
        self.leak = leak
        self.queries = []

    def get(self, record_id):
        return next((r for r in self._records if r.id == record_id), None)

    def query(self, control_id=None, kind=None, max_classification=None):
        self.queries.append({"control_id": control_id, "max_classification": max_classification})
        out = [r for r in self._records if control_id is None or control_id in r.control_ids]
        if max_classification is not None and not self.leak:
            allowed = CLASSIFICATION_ORDER[: CLASSIFICATION_ORDER.index(max_classification) + 1]
            out = [r for r in out if r.classification in allowed]
        return out


class FakeAudit:
    def __init__(self):
        self.entries = []

    def record(self, actor, action, subject, model_version=None, approver=None, rule=None, detail=""):
        entry = dict(actor=actor, action=action, subject=subject, model_version=model_version,
                     approver=approver, rule=rule, detail=detail)
        self.entries.append(entry)
        return entry


def canned_response(data=None, *, stop_reason="end_turn", stop_details=None, text=None):
    """Mirror the SDK Message shape the drafter reads."""
    body = text if text is not None else json.dumps(data if data is not None else {"claims": []})
    return SimpleNamespace(
        model="claude-opus-5",
        stop_reason=stop_reason,
        stop_details=stop_details,
        content=[SimpleNamespace(type="text", text=body)],
    )


class FakeMessages:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.response


class FakeClient:
    def __init__(self, response=None, error=None):
        self.messages = FakeMessages(response, error)

    @property
    def calls(self):
        return self.messages.calls


EV1 = FakeRecord("EV-0001", "publishable", "kms.key.rotation", {"summary": "CMKs rotate every 365 days"}, ["CTL-CRYPTO-01"])
EV2 = FakeRecord("EV-0002", "publishable", "tls.policy", {"summary": "TLS 1.2+ enforced on all listeners"}, ["CTL-CRYPTO-02"])
EV3 = FakeRecord("EV-0003", "restricted", "pentest.report", {"summary": "critical finding open"}, ["CTL-CRYPTO-01"])

ALLOWLIST = frozenset({EVIDENCE_QUERY_TOOL})
SCOPE = RequesterScope("alice@example.com", frozenset({EVIDENCE_QUERY_TOOL}))
CONTROLS = ["CTL-CRYPTO-01", "CTL-CRYPTO-02"]
QUESTION = "How is customer data protected at rest and in transit?"


def make_agent(store, client=None, drafter=None, **kw):
    audit = FakeAudit()
    if drafter is None and client is not None:
        drafter = ClaudeDrafter(client=client)
    agent = AnswerAgent(store, audit, SCOPE, ALLOWLIST, drafter=drafter, **kw)
    return agent, audit


# --------------------------------------------------------------------------- #
# ClaudeDrafter: SDK call shape and response parsing
# --------------------------------------------------------------------------- #


def test_drafter_call_shape_matches_documented_structured_output():
    client = FakeClient(canned_response({"claims": [{"text": "x", "evidence_ids": ["EV-0001"]}]}))
    drafter = ClaudeDrafter(client=client)

    claims = drafter.draft(QUESTION, [EV1, EV2])

    assert claims == [Claim(text="x", evidence_ids=["EV-0001"])]
    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["model"] == "claude-opus-5"
    assert call["thinking"] == {"type": "adaptive"}
    assert call["system"] == SYSTEM_PROMPT
    assert call["output_config"] == {"format": {"type": "json_schema", "schema": CLAIMS_SCHEMA}}
    assert isinstance(call["max_tokens"], int) and call["max_tokens"] > 0
    assert call["messages"][0]["role"] == "user"
    user_text = call["messages"][0]["content"]
    assert QUESTION in user_text
    assert "EV-0001" in user_text and "EV-0002" in user_text
    assert "CMKs rotate every 365 days" in user_text
    assert "critical finding" not in user_text  # EV-0003 was never offered


def test_drafter_model_version_names_the_model():
    assert ClaudeDrafter(client=FakeClient()).model_version == "answer-agent v0.5.0 · claude-opus-5"
    assert ClaudeDrafter(client=FakeClient(), model="claude-sonnet-5").model_version.endswith("claude-sonnet-5")


def test_drafter_without_sdk_raises_clear_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "anthropic", None)  # makes `import anthropic` raise ImportError
    drafter = ClaudeDrafter()
    with pytest.raises(RuntimeError, match=r"install anthropic: pip install anthropic"):
        drafter.draft(QUESTION, [EV1])


def test_drafter_refusal_raises_llm_refusal_with_category():
    details = SimpleNamespace(category="cyber", explanation="declined to answer")
    drafter = ClaudeDrafter(client=FakeClient(canned_response(stop_reason="refusal", stop_details=details)))
    with pytest.raises(LLMRefusal) as info:
        drafter.draft(QUESTION, [EV1])
    assert info.value.category == "cyber"
    assert "refused" in str(info.value) and "cyber" in str(info.value)


def test_drafter_truncation_and_bad_json_are_errors():
    with pytest.raises(LLMDraftError, match="max_tokens"):
        ClaudeDrafter(client=FakeClient(canned_response(stop_reason="max_tokens"))).draft(QUESTION, [EV1])
    with pytest.raises(LLMDraftError, match="not valid JSON"):
        ClaudeDrafter(client=FakeClient(canned_response(text="{not json"))).draft(QUESTION, [EV1])
    with pytest.raises(LLMDraftError, match="claims"):
        ClaudeDrafter(client=FakeClient(canned_response({"answer": "free text"}))).draft(QUESTION, [EV1])
    with pytest.raises(LLMDraftError, match="evidence_ids"):
        ClaudeDrafter(client=FakeClient(canned_response({"claims": [{"text": "x", "evidence_ids": "EV-0001"}]}))).draft(QUESTION, [EV1])


# --------------------------------------------------------------------------- #
# AnswerAgent in LLM mode: the same guardrails validate the model's output
# --------------------------------------------------------------------------- #


def test_llm_ready_path_when_model_cites_real_ids():
    client = FakeClient(canned_response({"claims": [
        {"text": "Customer data at rest is encrypted with KMS keys that rotate every 365 days.", "evidence_ids": ["EV-0001"]},
        {"text": "All connections require TLS 1.2 or higher.", "evidence_ids": ["EV-0002"]},
    ]}))
    store = FakeStore([EV1, EV2, EV3])
    agent, audit = make_agent(store, client=client)

    draft = agent.draft("Q-1", QUESTION, CONTROLS)

    assert draft.status == "READY"
    assert draft.reason == ""
    assert draft.answer == (
        "Customer data at rest is encrypted with KMS keys that rotate every 365 days. "
        "All connections require TLS 1.2 or higher."
    )
    assert draft.evidence_ids == ["EV-0001", "EV-0002"]
    # collection is unchanged: one publishable query per control
    assert [q["control_id"] for q in store.queries] == CONTROLS
    assert all(q["max_classification"] == "publishable" for q in store.queries)
    # audited as the model that wrote it
    assert len(audit.entries) == 1
    entry = audit.entries[0]
    assert entry["action"] == "draft.ready"
    assert entry["actor"] == "answer-agent v0.5.0 · claude-opus-5"
    assert entry["model_version"] == "answer-agent v0.5.0 · claude-opus-5"
    assert entry["rule"] is None
    assert "EV-0001" in entry["detail"] and "EV-0002" in entry["detail"]


def test_llm_blocked_when_model_cites_unknown_id():
    client = FakeClient(canned_response({"claims": [
        {"text": "Keys rotate annually.", "evidence_ids": ["EV-0001"]},
        {"text": "We hold ISO 27001 certification.", "evidence_ids": ["EV-9999"]},
    ]}))
    agent, audit = make_agent(FakeStore([EV1, EV2]), client=client)

    draft = agent.draft("Q-2", QUESTION, CONTROLS)

    assert draft.status == "BLOCKED"
    assert draft.reason == "citation-required"
    assert draft.answer == ""
    assert draft.evidence_ids == []
    assert audit.entries[0]["action"] == "draft.blocked"
    assert audit.entries[0]["rule"] == "citation-required"
    assert "EV-9999" in audit.entries[0]["detail"]


def test_llm_blocked_when_model_cites_uncited_claim():
    client = FakeClient(canned_response({"claims": [{"text": "Everything is encrypted.", "evidence_ids": []}]}))
    agent, _ = make_agent(FakeStore([EV1]), client=client)
    draft = agent.draft("Q-2b", QUESTION, ["CTL-CRYPTO-01"])
    assert draft.status == "BLOCKED"
    assert draft.reason == "citation-required"


def test_llm_blocked_when_model_cites_restricted_record_that_exists():
    # EV-0003 is in the store (get() resolves it) but restricted, and was never
    # offered to the model.  citation_required passes; the egress gate must not.
    client = FakeClient(canned_response({"claims": [
        {"text": "Keys rotate annually.", "evidence_ids": ["EV-0001"]},
        {"text": "A penetration test found a critical issue.", "evidence_ids": ["EV-0003"]},
    ]}))
    store = FakeStore([EV1, EV3])
    agent, audit = make_agent(store, client=client)

    draft = agent.draft("Q-3", QUESTION, ["CTL-CRYPTO-01"])

    assert draft.status == "BLOCKED"
    assert draft.reason == "egress-classification-gate"
    assert draft.answer == ""
    assert "critical" not in draft.answer
    assert audit.entries[0]["rule"] == "egress-classification-gate"
    assert "EV-0003" in audit.entries[0]["detail"]


def test_llm_gate_runs_before_records_reach_the_model():
    # A leaking store hands back a restricted record; it must be blocked before
    # any of it is sent to the API.
    client = FakeClient(canned_response({"claims": [{"text": "x", "evidence_ids": ["EV-0001"]}]}))
    agent, audit = make_agent(FakeStore([EV1, EV3], leak=True), client=client)

    draft = agent.draft("Q-3b", QUESTION, ["CTL-CRYPTO-01"])

    assert draft.status == "BLOCKED"
    assert draft.reason == "egress-classification-gate"
    assert client.calls == []  # never reached the model
    assert audit.entries[0]["rule"] == "egress-classification-gate"


def test_llm_declined_when_model_returns_zero_claims():
    client = FakeClient(canned_response({"claims": []}))
    agent, audit = make_agent(FakeStore([EV1, EV2]), client=client)

    draft = agent.draft("Q-4", "Do you have a bug bounty programme?", CONTROLS)

    assert draft.status == "DECLINED"
    assert draft.reason == DECLINED_NO_MODEL_SUPPORT
    assert draft.reason == "model found no supporting evidence; not inferring from absence"
    assert draft.answer == ""
    assert draft.evidence_ids == []
    assert len(client.calls) == 1
    assert audit.entries[0]["action"] == "draft.declined"
    assert audit.entries[0]["rule"] is None


def test_llm_declined_on_zero_evidence_without_calling_the_model():
    client = FakeClient(canned_response({"claims": [{"text": "x", "evidence_ids": ["EV-0001"]}]}))
    agent, audit = make_agent(FakeStore([EV1]), client=client)
    draft = agent.draft("Q-4b", QUESTION, ["CTL-VENDOR-01"])
    assert draft.status == "DECLINED"
    assert draft.reason == DECLINED_NO_EVIDENCE
    assert client.calls == []
    assert audit.entries[0]["action"] == "draft.declined"


def test_llm_error_when_drafter_raises():
    class Boom(Exception):
        pass

    class ExplodingDrafter:
        model_version = "answer-agent v0.5.0 · claude-opus-5"

        def draft(self, question, records):
            raise Boom("connection reset")

    agent, audit = make_agent(FakeStore([EV1]), drafter=ExplodingDrafter())

    draft = agent.draft("Q-5", QUESTION, ["CTL-CRYPTO-01"])

    assert draft.status == "BLOCKED"
    assert draft.reason == "llm-error: connection reset"
    assert draft.answer == "" and draft.evidence_ids == []
    assert len(audit.entries) == 1
    assert audit.entries[0]["action"] == "draft.blocked"
    assert audit.entries[0]["rule"] == "llm-error"
    assert "connection reset" in audit.entries[0]["detail"]


def test_llm_error_when_sdk_call_raises():
    client = FakeClient(error=TimeoutError("read timed out"))
    agent, audit = make_agent(FakeStore([EV1]), client=client)
    draft = agent.draft("Q-5b", QUESTION, ["CTL-CRYPTO-01"])
    assert draft.status == "BLOCKED"
    assert draft.reason == "llm-error: read timed out"
    assert audit.entries[0]["rule"] == "llm-error"


def test_llm_refusal_is_blocked_with_clear_reason():
    details = SimpleNamespace(category="cyber", explanation="cannot help with that")
    client = FakeClient(canned_response(stop_reason="refusal", stop_details=details))
    agent, audit = make_agent(FakeStore([EV1]), client=client)

    draft = agent.draft("Q-6", QUESTION, ["CTL-CRYPTO-01"])

    assert draft.status == "BLOCKED"
    assert draft.reason.startswith("llm-error: model refused (category=cyber)")
    assert "cannot help with that" in draft.reason
    assert draft.answer == ""
    assert audit.entries[0]["rule"] == "llm-error"
    assert "refused" in audit.entries[0]["detail"]


def test_llm_refusal_without_stop_details_still_handled():
    client = FakeClient(canned_response(stop_reason="refusal", stop_details=None))
    agent, _ = make_agent(FakeStore([EV1]), client=client)
    draft = agent.draft("Q-6b", QUESTION, ["CTL-CRYPTO-01"])
    assert draft.status == "BLOCKED"
    assert draft.reason == "llm-error: model refused (category=unspecified)"


def test_llm_malformed_output_is_blocked_not_shipped():
    client = FakeClient(canned_response(text="Sure! Here is your answer: keys rotate yearly."))
    agent, audit = make_agent(FakeStore([EV1]), client=client)
    draft = agent.draft("Q-7", QUESTION, ["CTL-CRYPTO-01"])
    assert draft.status == "BLOCKED"
    assert draft.reason.startswith("llm-error: response was not valid JSON")
    assert audit.entries[0]["rule"] == "llm-error"


def test_llm_cited_ids_deduplicated_in_first_seen_order():
    client = FakeClient(canned_response({"claims": [
        {"text": "TLS everywhere.", "evidence_ids": ["EV-0002"]},
        {"text": "Keys rotate; TLS everywhere.", "evidence_ids": ["EV-0001", "EV-0002"]},
    ]}))
    agent, _ = make_agent(FakeStore([EV1, EV2]), client=client)
    draft = agent.draft("Q-8", QUESTION, CONTROLS)
    assert draft.status == "READY"
    assert draft.evidence_ids == ["EV-0002", "EV-0001"]


# --------------------------------------------------------------------------- #
# Deterministic path unchanged
# --------------------------------------------------------------------------- #


def test_default_agent_has_no_drafter_and_keeps_deterministic_output():
    store = FakeStore([EV1, EV2, EV3])
    agent, audit = make_agent(store)  # no client, no drafter
    assert agent.drafter is None

    draft = agent.draft("Q-9", QUESTION, CONTROLS)

    assert draft.status == "READY"
    assert draft.answer == (
        "kms.key.rotation: CMKs rotate every 365 days [EV-0001] "
        "tls.policy: TLS 1.2+ enforced on all listeners [EV-0002]"
    )
    assert draft.evidence_ids == ["EV-0001", "EV-0002"]
    assert audit.entries[0]["actor"] == "answer-agent v0.4.2"
    assert audit.entries[0]["model_version"] == "answer-agent v0.4.2"


def test_explicit_model_version_kept_when_no_drafter():
    agent, audit = make_agent(FakeStore([EV1]), model_version="answer-agent v9.9.9")
    agent.draft("Q-10", QUESTION, ["CTL-CRYPTO-01"])
    assert audit.entries[0]["model_version"] == "answer-agent v9.9.9"


# --------------------------------------------------------------------------- #
# Live integration (opt-in)
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(os.environ.get("ATTEST_LIVE_LLM") != "1", reason="set ATTEST_LIVE_LLM=1 to call the real API")
def test_live_claude_drafts_from_real_evidence_store(tmp_path):
    from attest.audit import AuditLog
    from attest.evidence import EvidenceStore

    store = EvidenceStore(tmp_path / "evidence.jsonl")
    store.append("aws-config", "kms.key.rotation", ["CTL-CRYPTO-01"], "publishable",
                 {"summary": "All customer-managed KMS keys rotate automatically every 365 days", "result": "pass"})
    store.append("aws-config", "tls.policy", ["CTL-CRYPTO-02"], "publishable",
                 {"summary": "Load balancers enforce TLS 1.2 or higher; TLS 1.0/1.1 disabled", "result": "pass"})
    store.append("security", "pentest.report", ["CTL-CRYPTO-01"], "restricted",
                 {"summary": "one critical finding open"})
    audit = AuditLog(tmp_path / "audit.jsonl")

    agent = AnswerAgent(store, audit, SCOPE, ALLOWLIST, drafter=ClaudeDrafter())
    draft = agent.draft("Q-LIVE", QUESTION, CONTROLS)

    assert draft.status in {"READY", "DECLINED"}, draft.reason
    if draft.status == "READY":
        assert draft.answer
        assert draft.evidence_ids
        assert all(store.get(eid) is not None for eid in draft.evidence_ids)
        assert all(store.get(eid).classification == "publishable" for eid in draft.evidence_ids)
        assert "EV-0003" not in draft.evidence_ids
    entries = audit.all()
    assert len(entries) == 1
    assert entries[0].model_version == "answer-agent v0.5.0 · claude-opus-5"



# ---- server-side refusal fallbacks ------------------------------------------
class _BetaMessages(FakeMessages):
    pass


class FakeBetaClient(FakeClient):
    """A client whose beta namespace supports the fallbacks parameter."""

    def __init__(self, response=None, error=None):
        super().__init__(response, error)
        self.beta = type("Beta", (), {})()
        self.beta.messages = _BetaMessages(response, error)


class FakeOldBetaClient(FakeClient):
    """A client whose beta namespace exists but rejects unknown kwargs (older SDK)."""

    def __init__(self, response=None, error=None):
        super().__init__(response, error)
        self.beta = type("Beta", (), {})()

        def create(**kwargs):
            raise TypeError("create() got an unexpected keyword argument 'fallbacks'")
        self.beta.messages = type("M", (), {"create": staticmethod(create)})()


def test_beta_client_gets_fallbacks_default():
    from attest.llm import ClaudeDrafter, FALLBACK_BETA
    client = FakeBetaClient(response=canned_response({"claims": [{"text": "Keys rotate yearly.", "evidence_ids": ["EV-0001"]}]}))
    ClaudeDrafter(client=client).draft("q", [EV1])
    assert client.messages.calls == []                      # plain endpoint untouched
    call = client.beta.messages.calls[0]
    assert call["fallbacks"] == "default" and call["betas"] == [FALLBACK_BETA]
    assert call["model"] == "claude-opus-5"


def test_old_sdk_without_fallbacks_still_works():
    from attest.llm import ClaudeDrafter
    client = FakeOldBetaClient(response=canned_response({"claims": [{"text": "Keys rotate yearly.", "evidence_ids": ["EV-0001"]}]}))
    claims = ClaudeDrafter(client=client).draft("q", [EV1])
    assert claims and client.messages.calls and "fallbacks" not in client.messages.calls[0]
