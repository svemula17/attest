"""Control catalog and evaluation engine (Agent B).

A :class:`Control` names the evidence *kinds* that must all be present and
fresh for the control to be considered operating, plus its citations into each
supported framework.  :class:`ControlEngine` evaluates a catalog against an
``EvidenceStore`` (see ``attest/evidence.py``) and reports per-control results,
per-framework posture rows, and roll-up counts.

State rules (from CONTRACT.md):

* all required kinds present and within the freshness SLA  -> ``PASS``
* all present, but at least one outside the SLA             -> ``DEGRADED``
* any required kind missing, or the newest record for a kind
  carries ``{"result": "fail"}`` in its payload              -> ``FAIL``

For each (control, kind) pair only the *newest* record whose ``control_ids``
contains the control id is considered, so a later passing record supersedes an
earlier failing one and vice versa.  A failing record always yields ``FAIL``
even when it is also stale.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable

__all__ = [
    "PASS",
    "DEGRADED",
    "FAIL",
    "FRAMEWORKS",
    "Control",
    "ControlResult",
    "ControlEngine",
    "default_catalog",
]

PASS = "PASS"
DEGRADED = "DEGRADED"
FAIL = "FAIL"

FRAMEWORKS = {
    "soc2": "SOC 2 Type II",
    "iso27001": "ISO/IEC 27001:2022",
    "hipaa": "HIPAA Security Rule (45 CFR 164)",
}


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Control:
    """A single internal control and its framework citations.

    ``mappings`` keys are framework ids from :data:`FRAMEWORKS`; values are the
    framework's own clause / criterion identifiers.  ``hipaa_spec`` records
    whether the cited HIPAA implementation specification is "required" or
    "addressable" (45 CFR 164.306(d)); it is ``None`` for controls that do not
    map to HIPAA.
    """

    id: str
    name: str
    required_kinds: list[str]
    freshness_sla_hours: int
    mappings: dict[str, list[str]]
    hipaa_spec: str | None = None


@dataclass(frozen=True)
class ControlResult:
    control_id: str
    state: str  # PASS | DEGRADED | FAIL
    evidence_ids: list[str]  # newest record per present required kind
    reason: str  # human-readable explanation


# --------------------------------------------------------------------------- #
# Timestamp handling (lazy import of attest.util with a local fallback)
# --------------------------------------------------------------------------- #
def _fallback_parse_iso(value: str) -> datetime:
    """Parse ISO 8601 UTC strings such as ``2026-09-09T14:02:11Z``."""
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


_parse_iso_impl: Callable[[str], datetime] | None = None


def _parse_iso(value: str) -> datetime:
    """Return an aware UTC datetime, preferring ``attest.util.parse_iso``."""
    global _parse_iso_impl
    if _parse_iso_impl is None:
        try:
            from attest.util import parse_iso as impl  # type: ignore[import-not-found]
        except ImportError:
            impl = _fallback_parse_iso
        _parse_iso_impl = impl
    return _as_utc(_parse_iso_impl(value))


def _as_utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _resolve_now(now: datetime | None) -> datetime:
    return datetime.now(timezone.utc) if now is None else _as_utc(now)


# --------------------------------------------------------------------------- #
# Catalog
# --------------------------------------------------------------------------- #
def default_catalog() -> list[Control]:
    """Return the built-in control catalog with SOC 2 / ISO 27001 / HIPAA citations.

    SOC 2 ids are Trust Services Criteria (2017, 2022 points of focus).
    ISO ids are ISO/IEC 27001:2022 Annex A controls, except risk assessment,
    which is main-clause 6.1.2 and is written ``Cl.6.1.2``.  HIPAA ids are
    45 CFR Part 164 Security Rule sections.
    """
    return [
        Control(
            id="CTL-ACCESS-01",
            name="Logical access security",
            required_kinds=["iam.least-privilege", "sso.enforced"],
            freshness_sla_hours=24,
            mappings={
                "soc2": ["CC6.1"],
                "iso27001": ["A.5.15"],
                "hipaa": ["164.312(a)(1)"],
            },
            hipaa_spec="required",
        ),
        Control(
            id="CTL-PRIV-01",
            name="Privileged access review",
            required_kinds=["access-review.quarterly"],
            freshness_sla_hours=720,  # 30 days
            mappings={
                "soc2": ["CC6.3"],
                "iso27001": ["A.8.2"],
                "hipaa": ["164.308(a)(4)(ii)(C)"],
            },
            hipaa_spec="addressable",
        ),
        Control(
            id="CTL-CRYPTO-01",
            name="Encryption at rest",
            required_kinds=["kms.key.rotation", "storage.encrypted"],
            freshness_sla_hours=24,
            mappings={
                "soc2": ["CC6.1"],
                "iso27001": ["A.8.24"],
                "hipaa": ["164.312(a)(2)(iv)"],
            },
            hipaa_spec="addressable",
        ),
        Control(
            id="CTL-CRYPTO-02",
            name="Encryption in transit",
            required_kinds=["tls.policy"],
            freshness_sla_hours=24,
            mappings={
                "soc2": ["CC6.7"],
                "iso27001": ["A.8.24"],
                "hipaa": ["164.312(e)(1)"],
            },
            hipaa_spec="required",
        ),
        Control(
            id="CTL-LOG-01",
            name="Audit logging",
            required_kinds=["cloudtrail.enabled", "log.integrity"],
            freshness_sla_hours=24,
            mappings={
                "soc2": ["CC7.2"],
                "iso27001": ["A.8.15"],
                "hipaa": ["164.312(b)"],
            },
            hipaa_spec="required",
        ),
        Control(
            id="CTL-CHANGE-01",
            name="Change management",
            required_kinds=["pr.review-required", "ci.policy-gate"],
            freshness_sla_hours=168,  # 7 days
            mappings={
                "soc2": ["CC8.1"],
                "iso27001": ["A.8.32"],
            },
        ),
        Control(
            id="CTL-VENDOR-01",
            name="Subprocessor agreements",
            required_kinds=["baa.executed"],
            freshness_sla_hours=720,  # 30 days
            mappings={
                "soc2": ["CC9.2"],
                "iso27001": ["A.5.19"],
                "hipaa": ["164.314(a)"],
            },
            hipaa_spec="required",
        ),
        Control(
            id="CTL-RISK-01",
            name="Risk analysis",
            required_kinds=["risk.assessment"],
            freshness_sla_hours=8760,  # 365 days
            mappings={
                "soc2": ["CC3.2"],
                "iso27001": ["Cl.6.1.2"],
                "hipaa": ["164.308(a)(1)(ii)(A)"],
            },
            hipaa_spec="required",
        ),
        Control(
            id="CTL-MON-01",
            name="Anomaly monitoring",
            required_kinds=["siem.alerting"],
            freshness_sla_hours=24,
            mappings={
                "soc2": ["CC7.2"],
                "iso27001": ["A.8.16"],
                "hipaa": ["164.308(a)(1)(ii)(D)"],
            },
            hipaa_spec="required",
        ),
        Control(
            id="CTL-NET-01",
            name="Boundary protection",
            required_kinds=["sg.no-open-ingress", "waf.enabled"],
            freshness_sla_hours=24,
            mappings={
                "soc2": ["CC6.6"],
                "iso27001": ["A.8.20"],
            },
        ),
    ]


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
def _payload_failed(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    result = payload.get("result")
    return isinstance(result, str) and result.strip().lower() == "fail"


def _newest(records: Iterable[Any]) -> Any | None:
    """Pick the record with the latest ``collected_at`` (ties broken by id)."""
    best = None
    best_key: tuple[datetime, str] | None = None
    for record in records:
        key = (_parse_iso(record.collected_at), str(record.id))
        if best_key is None or key > best_key:
            best, best_key = record, key
    return best


def _quoted(items: Iterable[str]) -> str:
    return ", ".join(f"'{item}'" for item in items)


def _hours(delta: timedelta) -> str:
    return f"{delta.total_seconds() / 3600:.1f}h"


class ControlEngine:
    """Evaluate a control catalog against an evidence store.

    ``store`` only needs ``query(control_id=...)`` returning records with
    ``id``, ``kind``, ``control_ids``, ``collected_at`` and ``payload``.
    """

    def __init__(self, catalog: list[Control], store: Any):
        catalog = list(catalog)
        seen: set[str] = set()
        for control in catalog:
            if control.id in seen:
                raise ValueError(f"duplicate control id in catalog: {control.id}")
            if not control.required_kinds:
                raise ValueError(f"control {control.id} declares no required evidence kinds")
            if control.freshness_sla_hours <= 0:
                raise ValueError(f"control {control.id} has a non-positive freshness SLA")
            seen.add(control.id)
        self.catalog = catalog
        self.store = store

    # -- evaluation -------------------------------------------------------- #
    def evaluate(self, now: datetime | None = None) -> list[ControlResult]:
        moment = _resolve_now(now)
        return [self._evaluate_control(control, moment) for control in self.catalog]

    def _records_for(self, control: Control) -> list[Any]:
        records = self.store.query(control_id=control.id)
        # Defensive: only trust records that actually cite this control.
        return [r for r in records if control.id in (r.control_ids or [])]

    def _evaluate_control(self, control: Control, now: datetime) -> ControlResult:
        records = self._records_for(control)
        sla = timedelta(hours=control.freshness_sla_hours)

        evidence_ids: list[str] = []
        missing: list[str] = []
        failing: list[tuple[str, str]] = []  # (record id, kind)
        stale: list[tuple[str, str, timedelta]] = []  # (kind, record id, age)

        for kind in control.required_kinds:
            newest = _newest(r for r in records if r.kind == kind)
            if newest is None:
                missing.append(kind)
                continue
            evidence_ids.append(newest.id)
            if _payload_failed(newest.payload):
                failing.append((newest.id, kind))
                continue
            age = now - _parse_iso(newest.collected_at)
            if age > sla:
                stale.append((kind, newest.id, age))

        if missing or failing:
            sentences: list[str] = []
            if missing:
                noun = "kind" if len(missing) == 1 else "kinds"
                sentences.append(
                    f"No evidence of {noun} {_quoted(missing)} cites control {control.id}."
                )
            for record_id, kind in failing:
                sentences.append(
                    f"Evidence record {record_id} (kind '{kind}') reports result=fail "
                    f"for {control.id}."
                )
            return ControlResult(control.id, FAIL, evidence_ids, " ".join(sentences))

        if stale:
            sentences = [
                f"Evidence for kind '{kind}' ({record_id}) is stale: collected "
                f"{_hours(age)} ago, exceeding the {control.freshness_sla_hours}h SLA "
                f"for {control.id}."
                for kind, record_id, age in stale
            ]
            return ControlResult(control.id, DEGRADED, evidence_ids, " ".join(sentences))

        count = len(control.required_kinds)
        noun = "kind" if count == 1 else "kinds"
        reason = (
            f"All {count} required evidence {noun} for {control.id} are present and "
            f"within the {control.freshness_sla_hours}h freshness SLA "
            f"({', '.join(evidence_ids)})."
        )
        return ControlResult(control.id, PASS, evidence_ids, reason)

    # -- framework views --------------------------------------------------- #
    def _known_frameworks(self) -> list[str]:
        known = list(FRAMEWORKS)
        for control in self.catalog:
            for framework in control.mappings:
                if framework not in known:
                    known.append(framework)
        return known

    def _posture_rows(self, framework: str, results: list[ControlResult]) -> list[dict]:
        by_id = {r.control_id: r for r in results}
        rows: list[dict] = []
        for control in self.catalog:
            result = by_id[control.id]
            for framework_id in control.mappings.get(framework, []):
                rows.append(
                    {
                        "framework_id": framework_id,
                        "control_id": control.id,
                        "name": control.name,
                        "state": result.state,
                        "evidence_ids": list(result.evidence_ids),
                        "spec": control.hipaa_spec or None,
                    }
                )
        return rows

    def posture(self, framework: str, now: datetime | None = None) -> list[dict]:
        """One row per (control, framework citation) for ``framework``."""
        if framework not in self._known_frameworks():
            raise ValueError(
                f"unknown framework {framework!r}; expected one of "
                f"{', '.join(self._known_frameworks())}"
            )
        return self._posture_rows(framework, self.evaluate(now))

    def summary(self, now: datetime | None = None) -> dict:
        moment = _resolve_now(now)  # resolve once so all views share one clock
        results = self.evaluate(moment)
        counts = Counter(r.state for r in results)
        by_framework: dict[str, dict[str, int]] = {}
        for framework in self._known_frameworks():
            rows = self._posture_rows(framework, results)
            row_counts = Counter(row["state"] for row in rows)
            by_framework[framework] = {
                "pass": row_counts[PASS],
                "degraded": row_counts[DEGRADED],
                "fail": row_counts[FAIL],
                "total": len(rows),
            }
        return {
            "total": len(results),
            "pass": counts[PASS],
            "degraded": counts[DEGRADED],
            "fail": counts[FAIL],
            "by_framework": by_framework,
        }
