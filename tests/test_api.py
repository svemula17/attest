"""HTTP surface, end to end, in sandbox mode on a temp SQLite database."""
import io

import pytest
from fastapi.testclient import TestClient

from attest.api import DEMO_USERS, create_app
from attest.config import default_config_toml, parse_config

ENGINEER, AUDITOR = "s.vemula@attest.internal", "j.okafor@auditfirm.example"


@pytest.fixture
def client(tmp_path):
    cfg_path = tmp_path / "attest.toml"
    cfg_path.write_text(default_config_toml(mode="sandbox", storage_url=f"sqlite:///{tmp_path/'attest.db'}"))
    cfg = parse_config(cfg_path.read_text(), path=cfg_path)
    with TestClient(create_app(cfg)) as c:
        yield c


def login(c, email, password="attest"):
    r = c.post("/api/auth/login", json={"email": email, "password": password}); assert r.status_code == 200, r.text
    return r.json()


def test_health_and_anonymous_sandbox_identity(client):
    h = client.get("/api/health").json()
    assert h["ok"] and h["mode"] == "sandbox" and h["evidence"] > 40 and h["chain_intact"]
    me = client.get("/api/auth/me").json()
    assert me["user"] == ENGINEER and me["via"] == "sandbox"
    assert client.get("/").status_code == 200 and "Attest" in client.get("/").text


def test_state_matches_console_contract(client):
    s = client.get("/api/state").json()
    for key in ("summary", "posture", "controls", "events", "queue", "audit", "sources", "join", "configured_sources", "identity", "mode"):
        assert key in s
    assert s["summary"]["fail"] == 1 and s["identity"]["role"] == "engineer" and s["chain_intact"] and s["approvals_verified"]
    assert {q["question_id"] for q in s["queue"]} >= {"Q-4471", "Q-4472", "Q-4474"}
    assert s["events"][0]["verdict"] == "blocked"  # the warm-up injection lands on top


def test_login_logout_and_roles(client):
    login(client, AUDITOR)
    assert client.get("/api/auth/me").json()["role"] == "auditor"
    r = client.post("/api/decide", json={"question_id": "Q-4471", "decision": "approve"})
    assert r.status_code == 403 and "approve:questionnaire" in r.json()["error"] and r.json()["state"]["events"][0]["verdict"] == "blocked"
    client.post("/api/auth/logout")
    login(client, ENGINEER)
    r = client.post("/api/decide", json={"question_id": "Q-4471", "decision": "approve"})
    assert r.status_code == 200
    q = next(x for x in r.json()["queue"] if x["question_id"] == "Q-4471")
    assert q["decision"] == "approve" and q["approver"] == ENGINEER and len(q["signature"]) == 64
    assert r.json()["approvals_verified"]
    assert client.post("/api/auth/login", json={"email": ENGINEER, "password": "wrong"}).status_code == 401


def test_answer_declines_and_blocks(client):
    login(client, ENGINEER)
    r = client.post("/api/answer", json={"question": "Any breaches?", "control_ids": []}).json()
    assert r["queue"][0]["status"] == "DECLINED"
    r = client.post("/api/answer", json={"question": "Everything?", "control_ids": [c["id"] for c in r["catalog"]] + ["CTL-X-01", "CTL-X-02", "CTL-X-03"]}).json()
    assert r["queue"][0]["status"] == "BLOCKED" and "max-steps" in r["queue"][0]["reason"]


def test_read_doc_examples_and_misconfigured_reader(client):
    r = client.post("/api/read-doc", json={"example": "injected"}).json()
    assert r["events"][0]["verdict"] == "blocked" and r["events"][0]["payload"]
    r = client.post("/api/read-doc", json={"example": "injected", "tools": ["read:documents", "write:evidence"]}).json()
    assert "refused to start" in r["events"][0]["title"]
    assert client.post("/api/read-doc", json={"text": "   "}).status_code == 400


def test_api_key_flow_and_admin_endpoints(client, tmp_path):
    login(client, ENGINEER)
    assert client.get("/api/users").status_code == 403  # engineer cannot manage users
    from attest.auth import create_api_key, create_user
    engine = client.app.state.engine
    create_user(engine, "admin@example.com", "admin", password="pw")
    login(client, "admin@example.com", "pw")
    r = client.post("/api/users", json={"email": "ci@example.com", "role": "service"}); assert r.status_code == 201
    r = client.post("/api/keys", json={"email": "ci@example.com", "name": "ci"}); assert r.status_code == 201
    secret = r.json()["secret"]
    client.post("/api/auth/logout")
    anon = TestClient(client.app)  # no cookie → sandbox default identity; bearer overrides it
    me = anon.get("/api/auth/me", headers={"Authorization": f"Bearer {secret}"}).json()
    assert me["user"] == "ci@example.com" and me["via"] == "api-key"
    assert anon.get("/api/auth/me", headers={"Authorization": "Bearer atst_bogus"}).status_code == 401


def test_evidence_audit_controls_history(client):
    login(client, ENGINEER)
    ev = client.get("/api/evidence", params={"kind": "kms.key.rotation"}).json()
    assert ev and ev[0]["kind"] == "kms.key.rotation"
    assert client.get(f"/api/evidence/{ev[0]['id']}").json()["sha256"]
    assert client.get("/api/evidence/EV-9999").status_code == 404
    assert client.get("/api/audit", params={"prefix": "draft."}).json()
    assert client.post("/api/evaluate").json()["CTL-VENDOR-01"]["state"] == "FAIL"
    hist = client.get("/api/controls/CTL-VENDOR-01/history").json()
    assert hist and hist[0]["state"] == "FAIL"
    assert client.get("/api/controls/NOPE/history").status_code == 400


def test_acceptances_and_gate(client):
    login(client, ENGINEER)
    assert client.get("/api/gate").json()["passed"] is False
    r = client.post("/api/acceptances", json={"control_id": "CTL-VENDOR-01", "owner": "s.vemula", "reason": "BAA in progress", "expires": "2099-01-01"})
    assert r.status_code == 201
    g = client.get("/api/gate").json()
    assert g["passed"] and next(x for x in g["rows"] if x["control_id"] == "CTL-VENDOR-01")["verdict"] == "ACCEPTED"
    client.delete(f"/api/acceptances/{r.json()['id']}")
    assert client.get("/api/gate").json()["passed"] is False


def test_import_upload_validates_whole_file(client):
    login(client, ENGINEER)
    bad = "source,kind,control_ids,classification,collected_at,summary,result\naws-config,x.y,CTL-NET-01,secret,,oops,pass\n"
    r = client.post("/api/import", files={"file": ("bad.csv", io.BytesIO(bad.encode()), "text/csv")}, data={"mapping": "evidence"})
    assert r.status_code == 422 and r.json()["problems"]
    before = client.get("/api/health").json()["evidence"]
    good = "source,kind,control_ids,collected_at,classification,summary,result\naws-config,waf.enabled,CTL-NET-01,,publishable,WAF on,pass\n"
    r = client.post("/api/import", files={"file": ("good.csv", io.BytesIO(good.encode()), "text/csv")})
    assert r.status_code == 200 and r.json()["records"] == 1
    assert client.get("/api/health").json()["evidence"] == before + 1
    assert client.get("/api/runs").json()[0]["status"] == "ok"


def test_sources_and_demo_endpoints(client):
    login(client, ENGINEER)
    ids = {s["id"] for s in client.get("/api/sources").json()}
    assert {"hris", "idp", "leavers", "evidence"} <= ids
    s = client.post("/api/demo/terminate").json()
    assert s["join"]["latest"]["result"] == "fail" and s["events"][0]["verdict"] == "finding"
    assert next(c for c in s["controls"] if c["id"] == "CTL-ACCESS-02")["state"] == "FAIL"
    s = client.post("/api/tamper").json(); assert s["chain_intact"] is False
    s = client.post("/api/reseed").json(); assert s["chain_intact"] and s["summary"]["fail"] == 1


def test_production_mode_requires_auth(tmp_path):
    cfg_path = tmp_path / "attest.toml"
    cfg_path.write_text(default_config_toml(mode="production", storage_url=f"sqlite:///{tmp_path/'p.db'}"))
    cfg = parse_config(cfg_path.read_text(), path=cfg_path)
    with TestClient(create_app(cfg)) as c:
        assert c.get("/api/state").status_code == 401
        assert "Sign in" in c.get("/").text
        assert c.post("/api/reseed").status_code in (404, 405)
        from attest.auth import create_user
        create_user(c.app.state.engine, "a@x", "admin", password="pw")
        login(c, "a@x", "pw")
        assert c.get("/api/state").json()["evidence_total"] == 0
