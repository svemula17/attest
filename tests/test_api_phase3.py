"""Phase 2–4 surfaces on the HTTP API: history, questionnaires, packages, notifications, security, OIDC."""
import csv
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from attest.api import create_app
from attest.config import default_config_toml, parse_config

ENGINEER = "s.vemula@attest.internal"


@pytest.fixture
def client(tmp_path):
    cfg_path = tmp_path / "attest.toml"
    cfg_path.write_text(default_config_toml(mode="sandbox", storage_url=f"sqlite:///{tmp_path/'attest.db'}"))
    cfg = parse_config(cfg_path.read_text(), path=cfg_path)
    with TestClient(create_app(cfg), base_url="http://127.0.0.1:8765") as c:
        c.post("/api/auth/login", json={"email": ENGINEER, "password": "attest"}, headers={"Origin": "http://127.0.0.1:8765"})
        yield c


def hdr():
    return {"Origin": "http://127.0.0.1:8765"}


def test_history_summary_reflects_evaluations(client):
    client.post("/api/evaluate", headers=hdr()); client.post("/api/evaluate", headers=hdr())
    j = client.get("/api/history/summary?days=30").json()
    c = j["controls"]["CTL-VENDOR-01"]
    assert c["current"] == "FAIL" and c["evaluations"] >= 2 and c["pass_pct"] == 0.0 and c["timeline"][-1]["s"] == "FAIL"


def test_questionnaire_import_and_export_roundtrip(client):
    body = "ref,question,control_ids\nQ1,Is data encrypted at rest?,CTL-CRYPTO-01\nQ2,Any breaches in 24 months?,\n"
    r = client.post("/api/questionnaires", files={"file": ("northwind.csv", io.BytesIO(body.encode()), "text/csv")}, headers=hdr())
    assert r.status_code == 201, r.text
    qn = r.json()["questionnaire"]
    assert r.json()["drafted"] == 2 and qn["row_count"] == 2
    rows = client.get(f"/api/questionnaires/{qn['id']}/rows").json()
    assert {x["status"] for x in rows} == {"READY", "DECLINED"}
    out = client.get(f"/api/questionnaires/{qn['id']}/export?fmt=csv")
    assert out.status_code == 200 and "text/csv" in out.headers["content-type"]
    parsed = list(csv.DictReader(io.StringIO(out.text)))
    assert len(parsed) == 2 and any(p["answer"].startswith("NOT ANSWERED") for p in parsed)
    assert client.get("/api/questionnaires").json()[0]["status"] == "exported"
    xlsx = client.get(f"/api/questionnaires/{qn['id']}/export?fmt=xlsx")
    assert xlsx.status_code == 200 and xlsx.content[:2] == b"PK"
    bad = client.post("/api/questionnaires", files={"file": ("bad.csv", io.BytesIO(b"nothing,here\n1,2\n"), "text/csv")}, headers=hdr())
    assert bad.status_code in (400, 422)


def test_package_export_is_a_signed_zip(client):
    r = client.post("/api/package", json={"framework": "hipaa"}, headers=hdr())
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/zip")
    assert len(r.headers["x-attest-package-sha256"]) == 64
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(z.namelist())
    assert {"manifest.json", "controls.json", "controls.csv", "evidence.jsonl", "chain.json", "audit.jsonl", "README.txt"} <= names
    manifest = json.loads(z.read("manifest.json"))
    assert manifest["signature"] and manifest["framework"] == "hipaa"
    evidence = [json.loads(l) for l in z.read("evidence.jsonl").decode().splitlines() if l.strip()]
    assert evidence and all(e["classification"] != "restricted" for e in evidence)
    assert json.loads(z.read("chain.json"))["verified"] is True
    assert client.get("/api/packages").json()[0]["framework"] == "hipaa"
    assert client.post("/api/package", json={"framework": "nope"}, headers=hdr()).status_code == 400


def test_notifications_endpoint_and_state(client):
    assert client.get("/api/notifications").json() == []
    assert "notifications" in client.get("/api/state").json()


def test_security_headers_rate_limit_and_origin(client):
    r = client.get("/api/health")
    assert r.headers.get("x-content-type-options") == "nosniff" and "frame-ancestors" in r.headers.get("content-security-policy", "")
    # cookie-authenticated state change from a foreign origin is refused
    r = client.post("/api/evaluate", headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    # login brute force is throttled per IP
    codes = [client.post("/api/auth/login", json={"email": ENGINEER, "password": "wrong"}, headers=hdr()).status_code for _ in range(15)]
    assert 429 in codes


def test_auth_methods_and_oidc_absent(client):
    m = client.get("/api/auth/methods").json()
    assert m["password"] is True and m["oidc"] is False
    assert client.get("/api/auth/oidc/start").status_code == 404
