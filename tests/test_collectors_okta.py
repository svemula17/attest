"""Okta collector against an httpx.MockTransport that speaks Okta's pagination and error conventions."""
import re

import httpx
import pytest

from attest.audit import AuditLog
from attest.collectors import okta
from attest.collectors.joiner_leaver import run_join
from attest.collectors.registry import CollectContext
from attest.config import Config, SourceConfig
from attest.evidence import EvidenceStore
from attest.sources import source_for_kind
from attest.util import parse_iso

ORG = "https://acme.okta.com"
TOKEN = "00sekrit"


def user(uid, login, status, changed=None):
    return {"id": uid, "status": status, "statusChanged": changed, "profile": {"login": login, "email": login}}


PAGE1 = [user("u1", "Alice@acme.com", "ACTIVE"), user("u2", "bob@acme.com", "ACTIVE"),
         user("u3", "carol@acme.com", "STAGED"), user("u4", "dan@acme.com", "SUSPENDED", "2026-08-20T08:00:00.000Z")]
PAGE2 = [user("u5", "erin@acme.com", "LOCKED_OUT")]
DEPROVISIONED = [user("u9", "kenji@acme.com", "DEPROVISIONED", "2026-08-01T09:15:30.123Z")]
FACTORS = {"u1": [{"factorType": "push", "status": "ACTIVE"}], "u2": [{"factorType": "sms", "status": "PENDING_ACTIVATION"}]}
POLICIES = [{"id": "p1", "name": "Default Policy", "status": "ACTIVE", "type": "OKTA_SIGN_ON"},
            {"id": "p2", "name": "Legacy", "status": "INACTIVE", "type": "OKTA_SIGN_ON"}]
RULES = {"p1": [{"id": "r1", "name": "Require MFA", "status": "ACTIVE", "actions": {"signon": {"access": "ALLOW", "requireFactor": True}}}]}


class FakeOkta:
    def __init__(self, pages=(PAGE1, PAGE2), deprovisioned=DEPROVISIONED, factors=FACTORS, policies=POLICIES, rules=RULES):
        self.pages, self.deprovisioned, self.factors, self.policies, self.rules = pages, deprovisioned, factors, policies, rules
        self.requests: list[httpx.Request] = []
        self.fail_path, self.fail_status, self.fail_body, self.fail_headers = None, None, None, {}

    def fail_once(self, path, status, body=None, headers=None):
        self.fail_path, self.fail_status, self.fail_body, self.fail_headers = path, status, body or {}, headers or {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.headers["Authorization"] == f"SSWS {TOKEN}"
        path, q = request.url.path, dict(request.url.params)
        if path == self.fail_path:
            self.fail_path = None
            return httpx.Response(self.fail_status, json=self.fail_body, headers=self.fail_headers)
        if path == "/api/v1/users":
            assert q.get("limit") == "200"
            if q.get("filter") == 'status eq "DEPROVISIONED"':
                return httpx.Response(200, json=self.deprovisioned)
            assert "filter" not in q
            if "after" not in q:
                link = f'<{ORG}/api/v1/users?limit=200>; rel="self", <{ORG}/api/v1/users?after=u4&limit=200>; rel="next"'
                return httpx.Response(200, json=self.pages[0], headers={"Link": link})
            assert q["after"] == "u4"
            return httpx.Response(200, json=self.pages[1])
        if m := re.fullmatch(r"/api/v1/users/(\w+)/factors", path):
            return httpx.Response(200, json=self.factors.get(m.group(1), []))
        if path == "/api/v1/policies":
            assert q == {"type": "OKTA_SIGN_ON"}
            return httpx.Response(200, json=self.policies)
        if m := re.fullmatch(r"/api/v1/policies/(\w+)/rules", path):
            return httpx.Response(200, json=self.rules.get(m.group(1), []))
        raise AssertionError(f"unexpected {request.method} {request.url}")

    def paths(self):
        return [f"{r.url.path}?{r.url.query.decode()}" if r.url.query else r.url.path for r in self.requests]

    @property
    def transport(self):
        return httpx.MockTransport(self.handler)


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("OKTA_TOKEN", TOKEN)
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    audit = AuditLog(tmp_path / "audit.jsonl")
    src = SourceConfig(id="okta-prod", type="okta", params={"org_url": ORG + "/", "token_env": "OKTA_TOKEN"})
    return CollectContext(store=store, audit=audit, source=src, config=Config())


def run(ctx, fake):
    result = okta.collect(ctx, transport=fake.transport)
    return result, {r.kind: r for r in ctx.store.all()}


# -- idp.users -------------------------------------------------------------------------

def test_users_record_is_the_join_input(ctx):
    fake = FakeOkta()
    result, records = run(ctx, fake)
    users = records["idp.users"]
    assert users.source == "okta" and users.classification == "internal" and users.control_ids == ["CTL-ACCESS-02"]
    assert users.payload["summary"] == "IdP users: 4 active, 2 deprovisioned"
    assert users.payload["collected_by"] == "okta-prod" and users.payload["raw"] == {"active": 4, "deprovisioned": 2, "org": ORG}
    rows = {u["email"]: u for u in users.payload["users"]}
    assert set(rows) == {"alice@acme.com", "bob@acme.com", "carol@acme.com", "dan@acme.com", "erin@acme.com", "kenji@acme.com"}
    assert rows["alice@acme.com"] == {"email": "alice@acme.com", "status": "active", "deprovisioned_at": None, "okta_status": "ACTIVE"}
    assert rows["carol@acme.com"]["status"] == "active" and rows["erin@acme.com"]["status"] == "active"   # STAGED, LOCKED_OUT
    assert rows["dan@acme.com"] == {"email": "dan@acme.com", "status": "deprovisioned", "deprovisioned_at": "2026-08-20T08:00:00Z", "okta_status": "SUSPENDED"}
    assert rows["kenji@acme.com"]["deprovisioned_at"] == "2026-08-01T09:15:30Z"     # millisecond form normalised for the join
    parse_iso(rows["kenji@acme.com"]["deprovisioned_at"])
    # both pages of the default listing plus the deprovisioned pass
    assert fake.paths()[:3] == ["/api/v1/users?limit=200", "/api/v1/users?after=u4&limit=200",
                                "/api/v1/users?limit=200&filter=status+eq+%22DEPROVISIONED%22"]
    assert result.records == 3


def test_users_record_joins_against_an_hr_roster(ctx):
    run(ctx, FakeOkta())
    ctx.store.append(source="hris", kind="hris.roster", control_ids=["CTL-ACCESS-02"], classification="internal", payload={
        "summary": "roster", "result": "pass", "employees": [
            {"employee_id": "1", "name": "Kenji Watanabe", "email": "kenji@acme.com", "hired": "2020-01-01", "terminated": "2026-08-01"},
            {"employee_id": "2", "name": "Dan Ortiz", "email": "dan@acme.com", "hired": "2021-01-01", "terminated": "2026-08-10"},
            {"employee_id": "3", "name": "Alice Ng", "email": "alice@acme.com", "hired": "2022-01-01", "terminated": ""},
        ]})
    finding = run_join(ctx.store, sla_hours=24)
    assert finding.payload["result"] == "fail" and finding.payload["checked"] == 2
    assert [o["email"] for o in finding.payload["orphans"]] == ["dan@acme.com"]     # suspended 10 days after leaving
    assert finding.payload["orphans"][0]["idp_status"] == "deprovisioned"


# -- idp.mfa-enrollment ----------------------------------------------------------------

def test_mfa_enrollment_checks_only_active_users_and_names_the_unenrolled(ctx):
    fake = FakeOkta()
    _, records = run(ctx, fake)
    mfa = records["idp.mfa-enrollment"]
    assert mfa.source == "okta" and mfa.classification == "publishable"
    assert mfa.payload["result"] == "fail" and mfa.payload["summary"] == "MFA enrolled on 1/2 active users"
    assert mfa.payload["unenrolled"] == ["bob@acme.com"]     # a PENDING_ACTIVATION factor is not enrollment
    assert mfa.payload["raw"] == {"active": 2, "checked": 2, "enrolled": 1, "unenrolled": 1, "capped": False}
    factor_calls = [p for p in fake.paths() if p.endswith("/factors")]
    assert factor_calls == ["/api/v1/users/u1/factors", "/api/v1/users/u2/factors"]   # not STAGED u3, SUSPENDED u4, LOCKED_OUT u5


def test_mfa_enrollment_passes_and_max_users_caps_the_lookups(ctx):
    fake = FakeOkta(factors={**FACTORS, "u2": [{"factorType": "token:software:totp", "status": "ACTIVE"}]})
    _, records = run(ctx, fake)
    assert records["idp.mfa-enrollment"].payload["result"] == "pass"
    assert records["idp.mfa-enrollment"].payload["summary"] == "MFA enrolled on 2/2 active users"

    ctx.source.params["max_users"] = 1
    fake = FakeOkta()
    _, records = run(ctx, fake)
    mfa = records["idp.mfa-enrollment"].payload
    assert mfa["result"] == "pass" and mfa["summary"] == "MFA enrolled on 1/1 active users (first 1 of 2 checked; raise params.max_users)"
    assert mfa["raw"]["capped"] is True
    assert [p for p in fake.paths() if p.endswith("/factors")] == ["/api/v1/users/u1/factors"]


# -- sso.enforced ----------------------------------------------------------------------

def test_sso_enforced_names_the_policy_and_rule(ctx):
    fake = FakeOkta()
    result, records = run(ctx, fake)
    sso = records["sso.enforced"]
    assert sso.source == "okta" and sso.control_ids == ["CTL-ACCESS-01"] and sso.classification == "publishable"
    assert sso.payload["result"] == "pass"
    assert sso.payload["summary"] == 'MFA required by sign-on policy "Default Policy" rule "Require MFA"'
    assert sso.payload["raw"] == {"policies": 1, "enforcing_rules": 1, "enforcing": [{"policy": "Default Policy", "rule": "Require MFA"}]}
    assert "/api/v1/policies/p2/rules" not in fake.paths()      # inactive policy: rules never fetched
    assert result.summary == "okta acme.okta.com: 3 records; 4 active users, 1/2 MFA-enrolled, sso pass"


def test_sso_enforced_fails_without_a_factor_requiring_allow_rule(ctx):
    rules = {"p1": [
        {"id": "r0", "name": "Deny with factor", "status": "ACTIVE", "actions": {"signon": {"access": "DENY", "requireFactor": True}}},
        {"id": "r1", "name": "Inactive MFA", "status": "INACTIVE", "actions": {"signon": {"access": "ALLOW", "requireFactor": True}}},
        {"id": "r2", "name": "Password only", "status": "ACTIVE", "actions": {"signon": {"access": "ALLOW", "requireFactor": False}}},
    ]}
    _, records = run(ctx, FakeOkta(rules=rules))
    sso = records["sso.enforced"].payload
    assert sso["result"] == "fail"
    assert sso["summary"] == "no active sign-on policy rule requires a factor (1 active policies checked)"

    rules["p1"].append({"id": "r3", "name": "2FA mode", "status": "ACTIVE", "actions": {"signon": {"access": "ALLOW", "factorMode": "2FA"}}})
    _, records = run(ctx, FakeOkta(rules=rules))
    assert records["sso.enforced"].payload["result"] == "pass" and '"2FA mode"' in records["sso.enforced"].payload["summary"]


# -- auth, params and errors -----------------------------------------------------------

def test_401_is_a_permission_error_with_the_scope_hint(ctx):
    fake = FakeOkta()
    fake.fail_once("/api/v1/users", 401, {"errorCode": "E0000011", "errorSummary": "Invalid token provided"})
    with pytest.raises(PermissionError) as exc:
        okta.collect(ctx, transport=fake.transport)
    message = str(exc.value)
    assert "Okta returned 401 for GET /api/v1/users" in message
    assert "okta.users.read" in message and "okta.policies.read" in message and "Invalid token provided" in message
    assert ctx.store.all() == []

    fake = FakeOkta()
    fake.fail_once("/api/v1/policies", 403)
    with pytest.raises(PermissionError, match="403 for GET /api/v1/policies"):
        okta.collect(ctx, transport=fake.transport)

    fake = FakeOkta()
    fake.fail_once("/api/v1/users/u1/factors", 500, {"errorSummary": "boom"})
    with pytest.raises(RuntimeError, match="500 for GET /api/v1/users/u1/factors; Okta said: boom"):
        okta.collect(ctx, transport=fake.transport)


def test_rate_limit_is_retried_once(ctx, monkeypatch):
    waits = []
    monkeypatch.setattr(okta, "_sleep", waits.append)
    fake = FakeOkta()
    fake.fail_once("/api/v1/users", 429, {"errorSummary": "API call exceeded rate limit"}, {"X-Rate-Limit-Reset": "0"})
    result, _ = run(ctx, fake)
    assert result.records == 3 and waits == [1.0]
    assert fake.paths()[:2] == ["/api/v1/users?limit=200", "/api/v1/users?limit=200"]


def test_token_comes_from_the_named_environment_variable(ctx, monkeypatch):
    monkeypatch.delenv("OKTA_TOKEN")
    with pytest.raises(PermissionError, match="OKTA_TOKEN"):
        okta.collect(ctx, transport=FakeOkta().transport)
    ctx.source.params.pop("token_env")
    with pytest.raises(PermissionError, match="token_env"):
        okta.collect(ctx, transport=FakeOkta().transport)


def test_org_url_must_be_https(ctx):
    ctx.source.params["org_url"] = "acme.okta.com"
    with pytest.raises(ValueError, match="needs params.org_url"):
        okta.collect(ctx, transport=FakeOkta().transport)


def test_describe_lists_scopes_and_catalog_kinds():
    info = okta.describe()
    assert info["type"] == okta.TYPE == "okta"
    assert set(info["params"]) == {"org_url", "token_env", "max_users"}
    assert info["scopes"] == ["okta.users.read", "okta.policies.read"]
    assert info["kinds"] == ["idp.users", "idp.mfa-enrollment", "sso.enforced"]
    assert all(source_for_kind(k).id == "okta" for k in info["kinds"])
