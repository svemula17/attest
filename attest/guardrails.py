"""Guardrails for the attest pipeline.

Every check in this module is a pure, deterministic function (or a tiny
stateful object in the case of :class:`StepBudget`) that raises
:class:`GuardrailViolation` when a rule is broken and returns ``None``
otherwise.  Callers decide what to do with a violation; the guardrails
themselves never swallow it.

Rules (the ``rule`` attribute on the raised exception):

* ``untrusted-doc-isolation``  - a reader of untrusted documents holds a
  write-capable tool.
* ``tool-allowlist``           - a tool outside the static allowlist was requested.
* ``citation-required``        - a claim has no evidence, or cites an unknown id.
* ``egress-classification-gate`` - a record more sensitive than the egress
  ceiling was about to leave the system.
* ``max-steps``                - the per-task step budget is exhausted.
* ``requester-scoped-identity`` - the requester is not granted the tool.

Injection *detection* (:func:`scan_for_injection`) is for logging and
quarantine decisions only; isolation is the control that actually prevents
harm, because a detector can always be evaded.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

__all__ = [
    "GuardrailViolation",
    "WRITE_TOOL_PREFIXES",
    "INJECTION_PATTERNS",
    "untrusted_doc_isolation",
    "scan_for_injection",
    "enforce_tool_allowlist",
    "Claim",
    "citation_required",
    "egress_classification_gate",
    "classification_order",
    "StepBudget",
    "RequesterScope",
    "enforce_requester_scope",
]


class GuardrailViolation(Exception):
    """Raised when a guardrail rule is broken.

    ``rule`` is the machine-readable rule name; ``detail`` is a human-readable
    explanation.  ``str(exc)`` is always ``f"{rule}: {detail}"``.
    """

    def __init__(self, rule: str, detail: str):
        self.rule = rule
        self.detail = detail
        super().__init__(f"{rule}: {detail}")

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"GuardrailViolation(rule={self.rule!r}, detail={self.detail!r})"


# --------------------------------------------------------------------------- #
# Untrusted document isolation
# --------------------------------------------------------------------------- #

WRITE_TOOL_PREFIXES = ("write:", "update:", "delete:", "approve:", "send:")


def untrusted_doc_isolation(registered_tools: Iterable[str]) -> None:
    """A component that reads untrusted documents must hold no write-capable tool.

    Raises ``GuardrailViolation("untrusted-doc-isolation", ...)`` if any
    registered tool name starts with one of :data:`WRITE_TOOL_PREFIXES`
    (case-insensitive, surrounding whitespace ignored).
    """
    offending = sorted(
        {
            str(tool)
            for tool in registered_tools
            if str(tool).strip().lower().startswith(WRITE_TOOL_PREFIXES)
        }
    )
    if offending:
        raise GuardrailViolation(
            "untrusted-doc-isolation",
            "reader of untrusted documents holds write-capable tool(s): "
            + ", ".join(offending),
        )


# --------------------------------------------------------------------------- #
# Injection scanning (detection only)
# --------------------------------------------------------------------------- #

# Ordered so scan results are deterministic.  All patterns are case-insensitive.
INJECTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "ignore-prior-instructions": re.compile(
        r"\b(?:ignore|disregard)\s+(?:all\s+|any\s+)?(?:prior|previous|above|earlier)\s+instructions\b",
        re.IGNORECASE,
    ),
    "authority-claim": re.compile(
        r"\bpre-?approved\b"
        r"|\bdelegated\s+approval\s+authority\b"
        r"|\bsystem\s+override\b"
        r"|\bsecurity\s+team\s+has\b",
        re.IGNORECASE,
    ),
    "hidden-html-comment": re.compile(r"<!--.*?-->", re.IGNORECASE | re.DOTALL),
    "exfiltration": re.compile(
        r"\b(?:append|include|output)\s+the\s+(?:contents|entire)\b"
        r"[^\n]*?\b(?:store|database|prompt)\b",
        re.IGNORECASE,
    ),
    "state-mutation": re.compile(
        r"\bmark(?:ed|s|ing)?\b[^\n]*?\b(?:as\s+)?(?:complete|completed|remediated|low)\b"
        r"|\bset\s+\w+ ?= ?\w+",
        re.IGNORECASE,
    ),
}


def scan_for_injection(text: str) -> list[str]:
    """Return the names of every injection pattern that matches ``text``.

    The result is ordered as in :data:`INJECTION_PATTERNS` and contains no
    duplicates.  An empty list means nothing was detected - which is *not*
    proof that the text is safe; isolation remains the control.
    """
    if not text:
        return []
    return [name for name, pattern in INJECTION_PATTERNS.items() if pattern.search(text)]


# --------------------------------------------------------------------------- #
# Tool allowlist
# --------------------------------------------------------------------------- #


def enforce_tool_allowlist(requested_tool: str, allowlist: frozenset[str]) -> None:
    """Raise ``GuardrailViolation("tool-allowlist", ...)`` unless the tool is allowlisted."""
    if requested_tool not in allowlist:
        raise GuardrailViolation(
            "tool-allowlist",
            f"tool {requested_tool!r} is not in the allowlist "
            f"[{', '.join(sorted(allowlist)) or 'empty'}]",
        )


# --------------------------------------------------------------------------- #
# Citations
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Claim:
    text: str
    evidence_ids: list[str]


def citation_required(claims: list[Claim], store) -> None:
    """Every claim must cite at least one evidence id that resolves in ``store``.

    ``store`` only needs a ``get(record_id)`` method returning ``None`` for
    unknown ids.  Raises ``GuardrailViolation("citation-required", ...)``.
    """
    for index, claim in enumerate(claims):
        if not claim.evidence_ids:
            raise GuardrailViolation(
                "citation-required",
                f"claim #{index} has no evidence ids: {claim.text!r}",
            )
        for evidence_id in claim.evidence_ids:
            if store.get(evidence_id) is None:
                raise GuardrailViolation(
                    "citation-required",
                    f"claim #{index} cites unknown evidence id {evidence_id!r}",
                )


# --------------------------------------------------------------------------- #
# Egress classification gate
# --------------------------------------------------------------------------- #

_FALLBACK_CLASSIFICATION_ORDER = ["publishable", "internal", "restricted"]


def classification_order() -> list[str]:
    """Ascending-sensitivity classification labels.

    Imported lazily from :mod:`attest.evidence` so this module has no hard
    dependency on it; falls back to the contract's literal list.
    """
    try:
        from .evidence import CLASSIFICATION_ORDER  # type: ignore[import-not-found]
    except Exception:  # ImportError, or a partially-written module
        return list(_FALLBACK_CLASSIFICATION_ORDER)
    order = list(CLASSIFICATION_ORDER)
    return order or list(_FALLBACK_CLASSIFICATION_ORDER)


def egress_classification_gate(records, max_classification: str = "publishable") -> None:
    """No record more sensitive than ``max_classification`` may leave the system.

    Raises ``GuardrailViolation("egress-classification-gate", ...)`` for the
    first offending record.  A record whose classification is not a known
    label is treated as *above* the ceiling (fail closed).  An unknown
    ``max_classification`` is a configuration error and raises ``ValueError``.
    """
    order = classification_order()
    if max_classification not in order:
        raise ValueError(
            f"unknown max_classification {max_classification!r}; expected one of {order}"
        )
    ceiling = order.index(max_classification)
    for record in records:
        label = getattr(record, "classification", None)
        record_id = getattr(record, "id", "<no id>")
        if label not in order:
            raise GuardrailViolation(
                "egress-classification-gate",
                f"record {record_id} has unknown classification {label!r}; "
                f"refusing egress above {max_classification!r}",
            )
        if order.index(label) > ceiling:
            raise GuardrailViolation(
                "egress-classification-gate",
                f"record {record_id} is classified {label!r}, "
                f"above the egress ceiling {max_classification!r}",
            )


# --------------------------------------------------------------------------- #
# Step budget
# --------------------------------------------------------------------------- #


class StepBudget:
    """A hard cap on tool invocations for one task.

    The cap is fixed at construction: ``max_steps`` is a read-only property
    with no setter, and the instance uses ``__slots__`` so no attribute can
    be smuggled in via ``__dict__``.
    """

    __slots__ = ("_max_steps", "_steps", "_history")

    def __init__(self, max_steps: int = 12):
        if isinstance(max_steps, bool) or not isinstance(max_steps, int) or max_steps < 1:
            raise ValueError(f"max_steps must be a positive integer, got {max_steps!r}")
        self._max_steps = max_steps
        self._steps = 0
        self._history: list[str] = []

    @property
    def max_steps(self) -> int:
        return self._max_steps

    @property
    def steps(self) -> int:
        """Steps consumed so far."""
        return self._steps

    @property
    def remaining(self) -> int:
        return self._max_steps - self._steps

    @property
    def history(self) -> tuple[str, ...]:
        """Tools ticked so far, in order."""
        return tuple(self._history)

    def tick(self, tool: str) -> int:
        """Consume one step for ``tool`` and return the new step count.

        Raises ``GuardrailViolation("max-steps", ...)`` when the budget is
        already exhausted; the refused step is *not* counted.
        """
        if self._steps >= self._max_steps:
            raise GuardrailViolation(
                "max-steps",
                f"step budget of {self._max_steps} exhausted; refused step "
                f"{self._steps + 1} for tool {tool!r}",
            )
        self._steps += 1
        self._history.append(str(tool))
        return self._steps

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"StepBudget(steps={self._steps}, max_steps={self._max_steps})"


# --------------------------------------------------------------------------- #
# Requester-scoped identity
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RequesterScope:
    user: str
    grants: frozenset[str]

    def __post_init__(self) -> None:
        # Accept any iterable of tool names but always store a frozenset.
        if not isinstance(self.grants, frozenset):
            object.__setattr__(self, "grants", frozenset(self.grants))


def enforce_requester_scope(scope: RequesterScope, requested_tool: str) -> None:
    """The agent acts *as the requester*: it may only use tools the requester holds.

    Raises ``GuardrailViolation("requester-scoped-identity", ...)``.
    """
    if requested_tool not in scope.grants:
        raise GuardrailViolation(
            "requester-scoped-identity",
            f"requester {scope.user!r} is not granted tool {requested_tool!r}",
        )
