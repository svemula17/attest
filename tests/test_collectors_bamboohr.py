"""BambooHR roster collector over httpx.MockTransport (no network)."""
import base64
import json
from datetime import date

import httpx
import pytest

from attest.audit import AuditLog
from attest.collectors import bamboohr
from attest.collectors.bamboohr import collect, describe
from attest.collectors.joiner_leaver import run_join
from attest.collectors.registry import CollectContext
from attest.config import Config, SourceConfig
from attest.evidence import EvidenceStore

TODAY = date(2026, 9, 11)

ROSTER = [
    {"id": "1", "displayName": "Priya Natarajan", "workEmail": "Priya.Natarajan@Example.com", "hireDate": "2022-03-14",
     "terminationDate": "0000-00-00", "status": "Active", "employmentHistoryStatus": "Full-Time"},
    {"id": "2", "displayName": "Kenji Watanabe", "workEmail": "kenji@example.com", "hireDate": "2020-01-06",
     "terminationDate": "2026-08-29", "status": "Inactive", "employmentHistoryStatus": "Full-Time"},
    {"id": "3", "displayName": "Future Leaver", "workEmail": "future@example.com", "hireDate": "2021-05-03",
     "terminationDate": "2026-10-01", "status": "Active", "employmentHistoryStatus": "Part-Time"},
    {"id": "4", "displayName": "No Mailbox", "workEmail": "", "hireDate": "2023-02-01",
     "terminationDate": "", "status": "Active"},
    {"id": "5", "displayName": "Con Tractor", "workEmail": "con@agency.example", "hireDate": "2024-07-01",
     "terminationDate": "0000-00-00", "status": "Active", "employmentHistoryStatus": "Contractor"},
    {"id": "6", "displayName": "Inactive No Date", "workEmail": "gone@example.com", "hireDate": "0000-00-00",
     "terminationDate": None, "status": "Inactive"},
]


def make_ctx(tmp_path, params, source_id="bamboo"):
    store = EvidenceStore(tmp_path / "data" / "evidence.jsonl")
    audit = AuditLog(tmp_path / "data" / "audit.jsonl")
    return CollectContext(store=store, audit=audit, source=SourceConfig(id=source_id, type="bamboohr", params=params), config=Config())


class FakeBamboo:
    def __init__(self, employees=ROSTER, status=200, key="k3y"):
        self.employees, self.status, self.key = employees, status, key
        self.calls: list[httpx.Request] = []

    def transport(self):
        return httpx.MockTransport(self)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        expected = "Basic " + base64.b64encode(f"{self.key}:x".encode()).decode()
        if request.headers.get("Authorization") != expected:
            return httpx.Response(401, request=request)
        if self.status != 200:
            return httpx.Response(self.status, json={"message": "nope"}, request=request)
        body = json.loads(request.content)
        return httpx.Response(200, json={"title": body["title"], "fields": [{"id": f} for f in body["fields"]],
                                         "employees": self.employees}, request=request)


@pytest.fixture(autouse=True)
def key_env(monkeypatch):
    monkeypatch.setenv("BAMBOO_KEY", "k3y")


def test_roster_record_shape_dates_and_contract_fields(tmp_path):
    fake = FakeBamboo()
    ctx = make_ctx(tmp_path, {"subdomain": "acme", "token_env": "BAMBOO_KEY"})
    out = collect(ctx, transport=fake.transport(), today=TODAY)
    assert out.records == 1 and out.summary == "HRIS roster: 4 employees, 1 terminated in the period"
    [rec] = ctx.store.all()
    assert rec.kind == "hris.roster" and rec.source == "hris" and rec.classification == "internal"
    assert rec.control_ids == ["CTL-ACCESS-02"]
    assert rec.payload["result"] == "pass" and rec.payload["summary"] == out.summary
    assert rec.payload["employees"] == [
        {"id": "1", "name": "Priya Natarajan", "email": "priya.natarajan@example.com", "hired": "2022-03-14", "terminated": None},
        {"id": "2", "name": "Kenji Watanabe", "email": "kenji@example.com", "hired": "2020-01-06", "terminated": "2026-08-29"},
        {"id": "3", "name": "Future Leaver", "email": "future@example.com", "hired": "2021-05-03", "terminated": None},
        {"id": "6", "name": "Inactive No Date", "email": "gone@example.com", "hired": None, "terminated": None},
    ]
    assert rec.payload["skipped"] == 1 and rec.payload["contractors_excluded"] == 1
    assert rec.payload["as_of"] == "2026-09-11" and rec.payload["collected_by"] == "bamboo"
    assert ctx.store.verify_chain()
    # the request: POST to the custom-report endpoint, basic auth key:x, the documented fields
    [req] = fake.calls
    assert req.method == "POST"
    assert str(req.url) == "https://api.bamboohr.com/api/gateway.php/acme/v1/reports/custom?format=JSON"
    body = json.loads(req.content)
    assert body["title"] == "attest"
    assert body["fields"][:6] == ["id", "displayName", "workEmail", "hireDate", "terminationDate", "status"]
    assert req.headers["Accept"] == "application/json"


def test_include_contractors_keeps_them(tmp_path):
    ctx = make_ctx(tmp_path, {"subdomain": "acme", "token_env": "BAMBOO_KEY", "include_contractors": True})
    out = collect(ctx, transport=FakeBamboo().transport(), today=TODAY)
    assert out.summary == "HRIS roster: 5 employees, 1 terminated in the period"
    [rec] = ctx.store.all()
    assert "con@agency.example" in [e["email"] for e in rec.payload["employees"]]
    assert rec.payload["contractors_excluded"] == 0


def test_contractor_filter_only_applies_when_the_field_is_present(tmp_path):
    roster = [{"id": "9", "displayName": "X", "workEmail": "x@example.com", "hireDate": "2024-01-01",
               "terminationDate": "0000-00-00", "status": "Active"}]
    ctx = make_ctx(tmp_path, {"subdomain": "acme", "token_env": "BAMBOO_KEY"})
    collect(ctx, transport=FakeBamboo(roster).transport(), today=TODAY)
    assert len(ctx.store.all()[0].payload["employees"]) == 1


def test_termination_today_counts_future_does_not(tmp_path):
    roster = [
        {"id": "1", "displayName": "Today", "workEmail": "t@example.com", "hireDate": "2024-01-01", "terminationDate": "2026-09-11", "status": "Active"},
        {"id": "2", "displayName": "Tomorrow", "workEmail": "m@example.com", "hireDate": "2024-01-01", "terminationDate": "2026-09-12", "status": "Inactive"},
    ]
    ctx = make_ctx(tmp_path, {"subdomain": "acme", "token_env": "BAMBOO_KEY"})
    collect(ctx, transport=FakeBamboo(roster).transport(), today=TODAY)
    emps = {e["id"]: e for e in ctx.store.all()[0].payload["employees"]}
    assert emps["1"]["terminated"] == "2026-09-11" and emps["2"]["terminated"] is None


def test_bad_date_is_an_error_naming_the_employee(tmp_path):
    roster = [{"id": "42", "displayName": "X", "workEmail": "x@example.com", "hireDate": "03/14/2022", "terminationDate": "", "status": "Active"}]
    ctx = make_ctx(tmp_path, {"subdomain": "acme", "token_env": "BAMBOO_KEY"})
    with pytest.raises(ValueError, match="employee 42: hireDate '03/14/2022'"):
        collect(ctx, transport=FakeBamboo(roster).transport(), today=TODAY)
    assert ctx.store.all() == []


def test_401_is_a_permission_error_and_5xx_a_runtime_error(tmp_path, monkeypatch):
    monkeypatch.setenv("BAMBOO_KEY", "wrong")
    ctx = make_ctx(tmp_path, {"subdomain": "acme", "token_env": "BAMBOO_KEY"})
    with pytest.raises(PermissionError, match="401"):
        collect(ctx, transport=FakeBamboo().transport(), today=TODAY)
    monkeypatch.setenv("BAMBOO_KEY", "k3y")
    with pytest.raises(RuntimeError, match="503"):
        collect(ctx, transport=FakeBamboo(status=503).transport(), today=TODAY)
    assert ctx.store.all() == []


def test_missing_params_fail_before_any_request(tmp_path, monkeypatch):
    fake = FakeBamboo()
    with pytest.raises(ValueError, match="needs params.subdomain"):
        collect(make_ctx(tmp_path, {"token_env": "BAMBOO_KEY"}), transport=fake.transport())
    with pytest.raises(PermissionError, match="token_env"):
        collect(make_ctx(tmp_path, {"subdomain": "acme"}), transport=fake.transport())
    monkeypatch.delenv("BAMBOO_KEY")
    with pytest.raises(PermissionError, match="BAMBOO_KEY"):
        collect(make_ctx(tmp_path, {"subdomain": "acme", "token_env": "BAMBOO_KEY"}), transport=fake.transport())
    assert fake.calls == []


def test_roster_feeds_the_hris_idp_join(tmp_path):
    ctx = make_ctx(tmp_path, {"subdomain": "acme", "token_env": "BAMBOO_KEY"})
    collect(ctx, transport=FakeBamboo().transport(), today=TODAY)
    ctx.store.append(source="okta", kind="idp.users", control_ids=["CTL-ACCESS-02"], classification="internal",
                     payload={"summary": "idp", "result": "pass",
                              "users": [{"email": "kenji@example.com", "status": "active", "deprovisioned_at": None}]})
    rec = run_join(ctx.store)
    assert rec.payload["result"] == "fail" and rec.payload["orphans"][0]["email"] == "kenji@example.com"


def test_describe_and_type():
    assert bamboohr.TYPE == "bamboohr"
    d = describe()
    assert d["kinds"] == ["hris.roster"] and d["control_ids"] == ["CTL-ACCESS-02"] and d["classification"] == "internal"
    assert set(d["params"]) == {"subdomain", "token_env", "include_contractors"} and d["secrets"] == ["token_env"]
