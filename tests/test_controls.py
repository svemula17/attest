"""Tests for attest.controls (Agent B).

Uses an in-memory, duck-typed evidence store so the suite does not depend on
attest.evidence / attest.util, which are written by another agent.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import pytest

from attest.controls import (
    DEGRADED,
    FAIL,
    FRAMEWORKS,
    PASS,
    Control,
    ControlEngine,
    ControlResult,
    default_catalog,
)

NOW = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)
CLASSIFICATION_ORDER = ["publishable", "internal", "restricted"]
EXPECTED_IDS = [
    "CTL-ACCESS-01", "CTL-PRIV-01", "CTL-CRYPTO-01", "CTL-CRYPTO-02", "CTL-LOG-01",
    "CTL-CHANGE-01", "CTL-VENDOR-01", "CTL-RISK-01", "CTL-MON-01", "CTL-NET-01",
]


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hours_ago(hours: float) -> str:
    return iso(NOW - timedelta(hours=hours))


# --------------------------------------------------------------------------- #
# Minimal stand-in for attest.evidence.EvidenceStore
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class StubRecord:
    id: str
    source: str
    kind: str
    control_ids: list[str]
    classification: str
    collected_at: str
    payload: dict = field(default_factory=dict)
    sha256: str = ""
    prev_sha256: str | None = None


class StubStore:
    def __init__(self) -> None:
        self._records: list[StubRecord] = []

    def append(self, source, kind, control_ids, classification, payload, collected_at=None):
        record = StubRecord(
            id=f"EV-{len(self._records) + 1:04d}",
            source=source,
            kind=kind,
            control_ids=list(control_ids),
            classification=classification,
            collected_at=collected_at or iso(NOW),
            payload=dict(payload),
        )
        self._records.append(record)
        return record

    def all(self):
        return list(self._records)

    def get(self, record_id):
        return next((r for r in self._records if r.id == record_id), None)

    def query(self, control_id=None, kind=None, max_classification=None):
        out = self._records
        if control_id is not None:
            out = [r for r in out if control_id in r.control_ids]
        if kind is not None:
            out = [r for r in out if r.kind == kind]
        if max_classification is not None:
            limit = CLASSIFICATION_ORDER.index(max_classification)
            out = [r for r in out if CLASSIFICATION_ORDER.index(r.classification) <= limit]
        return list(out)


def seed_all_pass(store, catalog, *, age_hours=1, skip=()):
    """One fresh passing record per (control, kind), except pairs listed in skip."""
    for control in catalog:
        for kind in control.required_kinds:
            if (control.id, kind) in skip:
                continue
            store.append("test", kind, [control.id], "publishable",
                         {"result": "pass"}, collected_at=hours_ago(age_hours))


def by_id(results: list[ControlResult]) -> dict[str, ControlResult]:
    return {r.control_id: r for r in results}


@pytest.fixture
def catalog():
    return default_catalog()


@pytest.fixture
def store():
    return StubStore()


# --------------------------------------------------------------------------- #
# Catalog
# --------------------------------------------------------------------------- #
def test_default_catalog_shape_and_citations(catalog):
    ids = [c.id for c in catalog]
    assert len(ids) >= 10
    assert len(set(ids)) == len(ids)
    for expected in EXPECTED_IDS:
        assert expected in ids
    for control in catalog:
        assert isinstance(control, Control)
        assert control.required_kinds
        assert control.freshness_sla_hours > 0
        assert "soc2" in control.mappings and "iso27001" in control.mappings
        assert control.hipaa_spec in (None, "required", "addressable")
        assert ("hipaa" in control.mappings) == (control.hipaa_spec is not None)
        assert set(control.mappings) <= set(FRAMEWORKS)

    controls = {c.id: c for c in catalog}
    vendor = controls["CTL-VENDOR-01"]
    assert vendor.required_kinds == ["baa.executed"]
    assert vendor.freshness_sla_hours == 720
    assert vendor.mappings == {"soc2": ["CC9.2"], "iso27001": ["A.5.19"], "hipaa": ["164.314(a)"]}
    assert vendor.hipaa_spec == "required"

    risk = controls["CTL-RISK-01"]
    assert risk.mappings["iso27001"] == ["Cl.6.1.2"]
    assert risk.mappings["hipaa"] == ["164.308(a)(1)(ii)(A)"]
    assert risk.freshness_sla_hours == 8760

    assert controls["CTL-PRIV-01"].hipaa_spec == "addressable"
    assert controls["CTL-CRYPTO-01"].hipaa_spec == "addressable"
    assert controls["CTL-CHANGE-01"].hipaa_spec is None
    assert controls["CTL-NET-01"].mappings == {"soc2": ["CC6.6"], "iso27001": ["A.8.20"]}


# --------------------------------------------------------------------------- #
# State rules
# --------------------------------------------------------------------------- #
def test_all_controls_pass_with_fresh_evidence(catalog, store):
    seed_all_pass(store, catalog)
    results = ControlEngine(catalog, store).evaluate(now=NOW)
    assert len(results) == len(catalog)
    assert all(r.state == PASS for r in results)
    crypto = by_id(results)["CTL-CRYPTO-01"]
    assert len(crypto.evidence_ids) == 2
    assert all(store.get(eid) is not None for eid in crypto.evidence_ids)
    assert "CTL-CRYPTO-01" in crypto.reason and "24h" in crypto.reason


def test_stale_evidence_is_degraded(catalog, store):
    seed_all_pass(store, catalog, skip={("CTL-CRYPTO-01", "kms.key.rotation")})
    stale = store.append("aws-config", "kms.key.rotation", ["CTL-CRYPTO-01"], "internal",
                         {"result": "pass"}, collected_at=hours_ago(30))
    results = by_id(ControlEngine(catalog, store).evaluate(now=NOW))
    assert results["CTL-CRYPTO-01"].state == DEGRADED
    assert stale.id in results["CTL-CRYPTO-01"].evidence_ids
    assert "kms.key.rotation" in results["CTL-CRYPTO-01"].reason
    assert stale.id in results["CTL-CRYPTO-01"].reason
    assert "stale" in results["CTL-CRYPTO-01"].reason.lower()
    # Everything else is untouched.
    assert all(r.state == PASS for cid, r in results.items() if cid != "CTL-CRYPTO-01")


def test_missing_required_kind_is_fail(catalog, store):
    seed_all_pass(store, catalog, skip={("CTL-NET-01", "waf.enabled")})
    result = by_id(ControlEngine(catalog, store).evaluate(now=NOW))["CTL-NET-01"]
    assert result.state == FAIL
    assert "waf.enabled" in result.reason
    assert "CTL-NET-01" in result.reason
    # Only the present kind contributes an evidence id.
    assert len(result.evidence_ids) == 1
    assert store.get(result.evidence_ids[0]).kind == "sg.no-open-ingress"


def test_failing_payload_beats_stale(catalog, store):
    seed_all_pass(store, catalog, skip={("CTL-CRYPTO-02", "tls.policy")})
    bad = store.append("aws-config", "tls.policy", ["CTL-CRYPTO-02"], "publishable",
                       {"result": "fail", "min_version": "TLS1.0"}, collected_at=hours_ago(72))
    result = by_id(ControlEngine(catalog, store).evaluate(now=NOW))["CTL-CRYPTO-02"]
    assert result.state == FAIL  # not DEGRADED, even though the record is 72h old
    assert bad.id in result.reason
    assert "fail" in result.reason.lower()
    assert result.evidence_ids == [bad.id]


def test_newest_record_per_kind_wins(catalog, store):
    seed_all_pass(store, catalog, skip={("CTL-MON-01", "siem.alerting")})
    older_fail = store.append("siem", "siem.alerting", ["CTL-MON-01"], "internal",
                              {"result": "fail"}, collected_at=hours_ago(5))
    newer_pass = store.append("siem", "siem.alerting", ["CTL-MON-01"], "internal",
                              {"result": "pass"}, collected_at=hours_ago(1))
    result = by_id(ControlEngine(catalog, store).evaluate(now=NOW))["CTL-MON-01"]
    assert result.state == PASS
    assert result.evidence_ids == [newer_pass.id]
    assert older_fail.id not in result.evidence_ids

    # And a newer failure supersedes an older pass.
    newest_fail = store.append("siem", "siem.alerting", ["CTL-MON-01"], "internal",
                               {"result": "fail"}, collected_at=hours_ago(0.5))
    result = by_id(ControlEngine(catalog, store).evaluate(now=NOW))["CTL-MON-01"]
    assert result.state == FAIL
    assert result.evidence_ids == [newest_fail.id]


def test_records_citing_other_controls_do_not_count(catalog, store):
    seed_all_pass(store, catalog, skip={("CTL-VENDOR-01", "baa.executed")})
    # Right kind, wrong control id: must not satisfy CTL-VENDOR-01.
    store.append("vendor-registry", "baa.executed", ["CTL-OTHER-99"], "publishable",
                 {"result": "pass"}, collected_at=hours_ago(1))
    result = by_id(ControlEngine(catalog, store).evaluate(now=NOW))["CTL-VENDOR-01"]
    assert result.state == FAIL
    assert result.evidence_ids == []


def test_evaluate_defaults_to_current_time(catalog, store):
    recent = iso(datetime.now(timezone.utc) - timedelta(minutes=1))
    for control in catalog:
        for kind in control.required_kinds:
            store.append("test", kind, [control.id], "publishable",
                         {"result": "pass"}, collected_at=recent)
    assert all(r.state == PASS for r in ControlEngine(catalog, store).evaluate())


# --------------------------------------------------------------------------- #
# Framework views
# --------------------------------------------------------------------------- #
def test_posture_rows_include_hipaa_spec(catalog, store):
    seed_all_pass(store, catalog)
    engine = ControlEngine(catalog, store)
    rows = engine.posture("hipaa", now=NOW)
    hipaa_controls = [c for c in catalog if "hipaa" in c.mappings]
    assert len(rows) == sum(len(c.mappings["hipaa"]) for c in hipaa_controls)
    for row in rows:
        assert set(row) == {"framework_id", "control_id", "name", "state", "evidence_ids", "spec"}
        assert row["spec"] in ("required", "addressable")
        assert row["state"] == PASS
        assert row["evidence_ids"]
    spec_by_control = {row["control_id"]: row["spec"] for row in rows}
    assert spec_by_control["CTL-ACCESS-01"] == "required"
    assert spec_by_control["CTL-CRYPTO-01"] == "addressable"
    assert spec_by_control["CTL-PRIV-01"] == "addressable"
    assert "CTL-CHANGE-01" not in spec_by_control
    assert "CTL-NET-01" not in spec_by_control

    # One row per (control, framework_id): CC6.1 (ACCESS-01, CRYPTO-01, SECRETS-01)
    # and CC7.2 (LOG-01, MON-01, DETECT-01) are each cited three times.
    soc2_ids = [row["framework_id"] for row in engine.posture("soc2", now=NOW)]
    assert soc2_ids.count("CC6.1") == 3
    assert soc2_ids.count("CC7.2") == 3
    assert len(soc2_ids) == sum(len(c.mappings["soc2"]) for c in catalog)


def test_posture_rejects_unknown_framework(catalog, store):
    with pytest.raises(ValueError):
        ControlEngine(catalog, store).posture("pci-dss", now=NOW)


def test_summary_counts_add_up(catalog, store):
    seed_all_pass(store, catalog, skip={
        ("CTL-CRYPTO-01", "kms.key.rotation"),  # will be stale -> DEGRADED
        ("CTL-NET-01", "waf.enabled"),          # missing -> FAIL
        ("CTL-CRYPTO-02", "tls.policy"),        # result fail -> FAIL
    })
    store.append("aws-config", "kms.key.rotation", ["CTL-CRYPTO-01"], "internal",
                 {"result": "pass"}, collected_at=hours_ago(30))
    store.append("aws-config", "tls.policy", ["CTL-CRYPTO-02"], "publishable",
                 {"result": "fail"}, collected_at=hours_ago(1))
    engine = ControlEngine(catalog, store)
    summary = engine.summary(now=NOW)

    assert summary["total"] == len(catalog)
    assert summary["degraded"] == 1
    assert summary["fail"] == 2
    assert summary["pass"] == len(catalog) - 3
    assert summary["pass"] + summary["degraded"] + summary["fail"] == summary["total"]

    assert set(summary["by_framework"]) == set(FRAMEWORKS)
    for framework, counts in summary["by_framework"].items():
        rows = engine.posture(framework, now=NOW)
        assert counts["total"] == len(rows)
        assert counts["pass"] == sum(row["state"] == PASS for row in rows)
        assert counts["pass"] + counts["degraded"] + counts["fail"] == counts["total"]
    # CTL-NET-01 has no HIPAA mapping, so only the TLS failure shows there.
    assert summary["by_framework"]["hipaa"]["fail"] == 1
    assert summary["by_framework"]["soc2"]["fail"] == 2


def test_single_gap_fails_three_frameworks(catalog, store):
    """One missing BAA record makes CC9.2, A.5.19 and 164.314(a) all FAIL."""
    seed_all_pass(store, catalog, skip={("CTL-VENDOR-01", "baa.executed")})
    engine = ControlEngine(catalog, store)

    def row(framework, framework_id):
        matches = [r for r in engine.posture(framework, now=NOW) if r["framework_id"] == framework_id]
        assert len(matches) == 1, f"{framework}:{framework_id}"
        return matches[0]

    for framework, framework_id in (("soc2", "CC9.2"), ("iso27001", "A.5.19"), ("hipaa", "164.314(a)")):
        r = row(framework, framework_id)
        assert r["state"] == FAIL
        assert r["control_id"] == "CTL-VENDOR-01"
        assert r["evidence_ids"] == []
    assert row("hipaa", "164.314(a)")["spec"] == "required"

    # Nothing else is affected in any framework.
    for framework in FRAMEWORKS:
        others = [r for r in engine.posture(framework, now=NOW) if r["control_id"] != "CTL-VENDOR-01"]
        assert all(r["state"] == PASS for r in others)
    summary = engine.summary(now=NOW)
    assert summary["fail"] == 1
    assert all(counts["fail"] == 1 for counts in summary["by_framework"].values())
