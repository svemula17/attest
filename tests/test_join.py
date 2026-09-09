"""HRIS × IdP join — the check that makes an access review real."""
from datetime import datetime, timezone

import pytest

from attest.collectors.joiner_leaver import run_join
from attest.evidence import EvidenceStore

NOW = datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc)


def _store(tmp_path, employees, users):
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    store.append(source="hris", kind="hris.roster", control_ids=["CTL-ACCESS-02"], classification="internal",
                 payload={"summary": "roster", "result": "pass", "employees": employees})
    store.append(source="okta", kind="idp.users", control_ids=["CTL-ACCESS-02"], classification="internal",
                 payload={"summary": "users", "result": "pass", "users": users})
    return store


def test_active_account_after_termination_is_an_orphan(tmp_path):
    store = _store(tmp_path,
                   [{"id": "1", "name": "Ada", "email": "ada@x", "hired": "2020-01-01", "terminated": "2026-08-31"}],
                   [{"email": "ada@x", "status": "active", "deprovisioned_at": None}])
    rec = run_join(store, now=NOW)
    assert rec.payload["result"] == "fail" and rec.kind == "access.leaver-deprovisioned"
    orphan = rec.payload["orphans"][0]
    assert orphan["email"] == "ada@x" and orphan["days_open"] == 9 and orphan["idp_status"] == "active"
    assert "Ada" in rec.payload["summary"] and rec.control_ids == ["CTL-ACCESS-02"]


def test_deprovisioned_inside_sla_passes(tmp_path):
    store = _store(tmp_path,
                   [{"id": "1", "name": "Ada", "email": "ada@x", "hired": "2020-01-01", "terminated": "2026-08-31"}],
                   [{"email": "ada@x", "status": "deprovisioned", "deprovisioned_at": "2026-08-31T03:00:00Z"}])
    rec = run_join(store, now=NOW)
    assert rec.payload["result"] == "pass" and rec.payload["checked"] == 1 and rec.payload["orphans"] == []


def test_deprovisioned_five_days_late_fails(tmp_path):
    store = _store(tmp_path,
                   [{"id": "1", "name": "Ada", "email": "ada@x", "hired": "2020-01-01", "terminated": "2026-08-31"}],
                   [{"email": "ada@x", "status": "deprovisioned", "deprovisioned_at": "2026-09-05T03:00:00Z"}])
    assert run_join(store, now=NOW).payload["result"] == "fail"


def test_current_employees_are_ignored(tmp_path):
    store = _store(tmp_path,
                   [{"id": "1", "name": "Ada", "email": "ada@x", "hired": "2020-01-01", "terminated": None}],
                   [{"email": "ada@x", "status": "active", "deprovisioned_at": None}])
    rec = run_join(store, now=NOW)
    assert rec.payload["result"] == "pass" and rec.payload["checked"] == 0


def test_missing_inputs_raise(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    with pytest.raises(ValueError):
        run_join(store, now=NOW)


def test_newest_roster_wins(tmp_path):
    store = _store(tmp_path,
                   [{"id": "1", "name": "Ada", "email": "ada@x", "hired": "2020-01-01", "terminated": None}],
                   [{"email": "ada@x", "status": "active", "deprovisioned_at": None}])
    assert run_join(store, now=NOW).payload["result"] == "pass"
    store.append(source="hris", kind="hris.roster", control_ids=["CTL-ACCESS-02"], classification="internal",
                 payload={"summary": "roster v2", "result": "pass",
                          "employees": [{"id": "1", "name": "Ada", "email": "ada@x", "hired": "2020-01-01", "terminated": "2026-09-01"}]})
    assert run_join(store, now=NOW).payload["result"] == "fail"
