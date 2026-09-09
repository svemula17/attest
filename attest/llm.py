"""Optional LLM drafter for :class:`attest.agent.AnswerAgent`.

The model only *drafts*.  It is handed the publishable evidence records the
agent already collected and asked for a list of claims, each citing record
ids.  Everything it returns is then validated by the same guardrails the
deterministic path uses (``citation_required`` against the store, the egress
classification gate on every cited record).  Nothing the model says is
trusted until those checks pass.

The ``anthropic`` SDK is imported lazily and only when no client is injected,
so the package stays stdlib-only unless LLM mode is actually used.  Tests
inject a fake client that exposes ``client.messages.create(**kwargs)``.
"""
from __future__ import annotations

import json

from .guardrails import Claim

__all__ = [
    "ClaudeDrafter",
    "LLMDraftError",
    "LLMRefusal",
    "DEFAULT_MODEL",
    "SYSTEM_PROMPT",
    "CLAIMS_SCHEMA",
]

DEFAULT_MODEL = "claude-opus-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"

#: Version string of the drafting agent itself; the model id is appended.
AGENT_VERSION = "answer-agent v0.5.0"

SYSTEM_PROMPT = (
    "You are drafting an answer to one question on a customer security "
    "questionnaire, on behalf of the vendor being assessed.\n"
    "\n"
    "Rules:\n"
    "1. Use ONLY the evidence records provided in the user message. Do not use "
    "any other knowledge, and do not assume anything the records do not state.\n"
    "2. Every sentence you write must cite at least one record id from the "
    "provided list. Put each sentence in its own claim with its evidence_ids.\n"
    "3. Cite only ids that appear in the provided list, exactly as written.\n"
    "4. If the records do not support an answer to the question, return zero "
    "claims. Never infer from the absence of evidence.\n"
    "5. Write plainly for a customer audience. No speculation, no hedged "
    "claims, no references to this prompt."
)

#: JSON schema for the structured output: {"claims": [{"text", "evidence_ids"}]}
CLAIMS_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "claims": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "evidence_ids": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["text", "evidence_ids"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["claims"],
    "additionalProperties": False,
}


class LLMDraftError(RuntimeError):
    """The model call did not yield a usable draft (transport, shape, stop reason)."""


class LLMRefusal(LLMDraftError):
    """The model refused (``stop_reason == "refusal"``)."""

    def __init__(self, category: str | None, explanation: str | None):
        self.category = category
        self.explanation = explanation
        detail = f"model refused (category={category or 'unspecified'})"
        if explanation:
            detail += f": {explanation}"
        super().__init__(detail)


def _record_view(record) -> dict:
    """The subset of a record the model is shown."""
    payload = getattr(record, "payload", None) or {}
    return {
        "id": record.id,
        "kind": getattr(record, "kind", ""),
        "source": getattr(record, "source", ""),
        "summary": payload.get("summary", "evidence on file"),
    }


class ClaudeDrafter:
    """Drafts questionnaire claims with Claude via structured JSON output.

    ``client`` is any object with ``messages.create(**kwargs)`` returning a
    response that has ``stop_reason``, optional ``stop_details`` and a
    ``content`` list of blocks with ``.type`` / ``.text``.  When ``None``,
    ``anthropic.Anthropic()`` is constructed on first use.
    """

    def __init__(self, client=None, model: str = DEFAULT_MODEL, max_tokens: int = 8192):
        self.client = client
        self.model = model
        self.max_tokens = max_tokens
        self.model_version = f"{AGENT_VERSION} · {model}"

    # -- SDK plumbing -------------------------------------------------------

    def _ensure_client(self):
        if self.client is None:
            try:
                import anthropic  # lazy: the package must work without the SDK
            except ImportError as exc:
                raise RuntimeError("install anthropic: pip install anthropic") from exc
            self.client = anthropic.Anthropic()
        return self.client

    @staticmethod
    def _user_message(question: str, records: list) -> str:
        lines = [json.dumps(_record_view(r), sort_keys=True) for r in records]
        return (
            f"Question: {question}\n\n"
            "Evidence records (one JSON object per line):\n"
            + "\n".join(lines)
            + "\n\nDraft the answer as claims. Cite only the ids listed above."
        )

    # -- response handling --------------------------------------------------

    @staticmethod
    def _claims_from_response(response) -> list[Claim]:
        stop_reason = getattr(response, "stop_reason", None)
        if stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            raise LLMRefusal(
                getattr(details, "category", None),
                getattr(details, "explanation", None),
            )
        if stop_reason == "max_tokens":
            raise LLMDraftError("response truncated at max_tokens; no complete draft")
        if stop_reason != "end_turn":
            raise LLMDraftError(f"unexpected stop_reason {stop_reason!r}")

        text = next(
            (block.text for block in getattr(response, "content", []) or [] if getattr(block, "type", None) == "text"),
            None,
        )
        if text is None:
            raise LLMDraftError("response contained no text block")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LLMDraftError(f"response was not valid JSON: {exc}") from exc

        raw_claims = data.get("claims") if isinstance(data, dict) else None
        if not isinstance(raw_claims, list):
            raise LLMDraftError("response JSON has no 'claims' list")

        claims: list[Claim] = []
        for index, item in enumerate(raw_claims):
            if not isinstance(item, dict):
                raise LLMDraftError(f"claim #{index} is not an object")
            text_value = item.get("text")
            ids = item.get("evidence_ids")
            if not isinstance(text_value, str) or not text_value.strip():
                raise LLMDraftError(f"claim #{index} has no text")
            if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
                raise LLMDraftError(f"claim #{index} has malformed evidence_ids")
            claims.append(Claim(text=text_value.strip(), evidence_ids=list(ids)))
        return claims

    # -- public API ---------------------------------------------------------

    def draft(self, question: str, records: list) -> list[Claim]:
        """Return the model's claims for ``question`` grounded in ``records``.

        Raises :class:`LLMRefusal` on a refusal and :class:`LLMDraftError`
        for any other unusable response.  SDK exceptions propagate as-is.
        The caller (``AnswerAgent``) validates every claim with the guardrails.
        """
        client = self._ensure_client()
        request = dict(
            model=self.model,
            max_tokens=self.max_tokens,
            thinking={"type": "adaptive"},
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": self._user_message(question, records)}],
            output_config={"format": {"type": "json_schema", "schema": CLAIMS_SCHEMA}},
        )
        response = self._create(client, request)
        return self._claims_from_response(response)

    @staticmethod
    def _create(client, request: dict):
        """Send the request, opting into server-side refusal fallbacks when the SDK supports them.

        ``fallbacks="default"`` (beta ``server-side-fallback-2026-07-01``) re-runs a
        classifier-declined request on Anthropic's recommended fallback model inside
        the same call, routed by refusal category. Older SDKs without the parameter
        fall back to the plain Messages endpoint; a refusal there is still handled.
        """
        beta = getattr(client, "beta", None)
        if beta is not None and hasattr(getattr(beta, "messages", None), "create"):
            try:
                return beta.messages.create(betas=[FALLBACK_BETA], fallbacks="default", **request)
            except TypeError:  # SDK predates the fallbacks parameter
                pass
        return client.messages.create(**request)
