"""The OIDC sign-in routes, with the provider faked at the class boundary."""
import pytest
from fastapi.testclient import TestClient

import attest.oidc as oidc_mod
from attest.api import create_app
from attest.config import default_config_toml, parse_config

OIDC_TOML = '''
[auth.oidc]
issuer = "https://idp.example.com"
client_id = "attest-console"
role_claim = "groups"
allowed_domains = ["example.com"]
[auth.oidc.role_map]
"sec-eng" = "engineer"
"admins" = "admin"
'''


class FakeOIDC:
    """Stands in for attest.oidc.OIDC: same surface, no network."""
    claims = {"email": "Ada@Example.com", "name": "Ada L", "groups": ["sec-eng"], "nonce": "n1"}

    def __init__(self, cfg, redirect_uri, transport=None):
        self.cfg, self.redirect_uri = cfg, redirect_uri

    def start(self):
        return {"url": "https://idp.example.com/authorize?state=s1", "state": "s1", "nonce": "n1", "code_verifier": "v1"}

    def finish(self, code, code_verifier, nonce):
        assert code == "good" and code_verifier == "v1" and nonce == "n1"
        return dict(self.claims)

    def check_email(self, claims):
        email = claims["email"].lower()
        if not email.endswith("@example.com"):
            raise oidc_mod.OIDCError("domain not allowed")
        return email

    def role_for(self, claims):
        for g in claims.get("groups", []):
            if g in self.cfg.role_map:
                return self.cfg.role_map[g]
        return self.cfg.default_role


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(oidc_mod, "OIDC", FakeOIDC)
    cfg_path = tmp_path / "attest.toml"
    cfg_path.write_text(default_config_toml(mode="production", storage_url=f"sqlite:///{tmp_path/'o.db'}") + OIDC_TOML)
    cfg = parse_config(cfg_path.read_text(), path=cfg_path)
    with TestClient(create_app(cfg), base_url="http://127.0.0.1:8765", follow_redirects=False) as c:
        yield c


def test_methods_advertise_oidc(client):
    m = client.get("/api/auth/methods").json()
    assert m["oidc"] is True and m["oidc_issuer"] == "https://idp.example.com"
    assert "Sign in with SSO" in client.get("/login").text


def test_full_login_creates_the_user_with_the_mapped_role(client):
    r = client.get("/api/auth/oidc/start")
    assert r.status_code == 302 and r.headers["location"].startswith("https://idp.example.com/authorize") and "attest_oidc" in r.cookies
    r = client.get("/api/auth/oidc/callback", params={"code": "good", "state": "s1"})
    assert r.status_code == 302 and r.headers["location"] == "/" and "attest_session" in r.cookies
    me = client.get("/api/auth/me").json()
    assert me["user"] == "ada@example.com" and me["role"] == "engineer" and me["via"] == "session"
    audit = client.get("/api/audit", params={"prefix": "user."}).json()
    assert audit and audit[0]["action"] == "user.created"


def test_state_mismatch_and_bad_domain_are_refused(client, monkeypatch):
    client.get("/api/auth/oidc/start")
    assert client.get("/api/auth/oidc/callback", params={"code": "good", "state": "wrong"}).status_code == 401
    monkeypatch.setattr(FakeOIDC, "claims", {**FakeOIDC.claims, "email": "mallory@evil.example"})
    client.get("/api/auth/oidc/start")
    r = client.get("/api/auth/oidc/callback", params={"code": "good", "state": "s1"})
    assert r.status_code == 401 and "domain" in r.json()["error"]
    assert client.get("/api/auth/me").status_code == 401


def test_role_follows_the_claim_on_later_logins(client, monkeypatch):
    client.get("/api/auth/oidc/start"); client.get("/api/auth/oidc/callback", params={"code": "good", "state": "s1"})
    assert client.get("/api/auth/me").json()["role"] == "engineer"
    monkeypatch.setattr(FakeOIDC, "claims", {**FakeOIDC.claims, "groups": ["admins"]})
    client.get("/api/auth/oidc/start"); client.get("/api/auth/oidc/callback", params={"code": "good", "state": "s1"})
    assert client.get("/api/auth/me").json()["role"] == "admin"
