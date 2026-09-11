"""OIDC sign-in against a fake issuer: real RSA key, real PyJWT signatures, httpx.MockTransport for HTTP."""
import base64
import hashlib
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from attest.config import OIDCConfig
from attest.oidc import OIDC, OIDCError, pkce_challenge

ISSUER = "https://acme.okta.com/oauth2/default"
CLIENT_ID = "0oa-attest"
REDIRECT = "https://attest.example.com/auth/callback"
KID = "key-2026"


def make_key(kid):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return {"pem": pem, "jwk": jwk}


@pytest.fixture(scope="module")
def key():
    return make_key(KID)


class FakeIssuer:
    """Discovery, JWKS and token endpoints. `claims` overrides what the minted id_token says."""

    def __init__(self, key, issuer=ISSUER):
        self.key, self.issuer = key, issuer
        self.nonce = None
        self.kid = KID
        self.alg = "RS256"
        self.claims = {}
        self.jwks_keys = [key["jwk"]]
        self.token_status = 200
        self.calls = []
        self.last_token_form = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append(path)
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={"issuer": self.issuer, "authorization_endpoint": ISSUER + "/v1/authorize",
                                             "token_endpoint": ISSUER + "/v1/token", "jwks_uri": ISSUER + "/v1/keys"})
        if path.endswith("/v1/keys"):
            return httpx.Response(200, json={"keys": self.jwks_keys})
        if path.endswith("/v1/token"):
            assert request.method == "POST"
            self.last_token_form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            if self.token_status != 200:
                return httpx.Response(self.token_status, json={"error": "invalid_grant", "error_description": "code expired"})
            return httpx.Response(200, json={"id_token": self.mint(), "access_token": "at", "token_type": "Bearer"})
        raise AssertionError(f"unexpected {request.method} {request.url}")

    def mint(self):
        now = int(time.time())
        claims = {"iss": self.issuer, "aud": CLIENT_ID, "sub": "user-1", "email": "Ada@Acme.com", "nonce": self.nonce,
                  "iat": now, "exp": now + 300, "groups": ["eng"], **self.claims}
        if self.alg == "none":
            return jwt.encode(claims, None, algorithm="none", headers={"kid": self.kid})
        return jwt.encode(claims, self.key["pem"], algorithm="RS256", headers={"kid": self.kid})

    def count(self, suffix):
        return sum(1 for p in self.calls if p.endswith(suffix))


def config(**overrides):
    base = dict(issuer=ISSUER, client_id=CLIENT_ID, client_secret_env="ATTEST_OIDC_CLIENT_SECRET")
    return OIDCConfig(**{**base, **overrides})


@pytest.fixture
def issuer(key):
    return FakeIssuer(key)


@pytest.fixture
def oidc(issuer):
    return OIDC(config(), REDIRECT, transport=httpx.MockTransport(issuer.handler))


def login(oidc, issuer):
    """start() and hand the nonce to the fake issuer, as the real one learns it from the authorize request."""
    started = oidc.start()
    issuer.nonce = started["nonce"]
    return started


# -- start(): PKCE + authorization URL -------------------------------------------------

def test_pkce_challenge_is_s256_of_the_verifier():
    # RFC 7636 appendix B
    assert pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    verifier = "x" * 43
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert pkce_challenge(verifier) == expected and "=" not in pkce_challenge(verifier)


def test_start_builds_the_authorization_url_with_fresh_state_nonce_and_pkce(oidc, issuer):
    first, second = oidc.start(), oidc.start()
    assert len({first["state"], second["state"], first["nonce"], second["nonce"], first["code_verifier"], second["code_verifier"]}) == 6
    assert 43 <= len(first["code_verifier"]) <= 128
    url = urlparse(first["url"])
    assert f"{url.scheme}://{url.netloc}{url.path}" == ISSUER + "/v1/authorize"
    q = {k: v[0] for k, v in parse_qs(url.query).items()}
    assert q == {"response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT, "scope": "openid email profile",
                 "state": first["state"], "nonce": first["nonce"], "code_challenge": pkce_challenge(first["code_verifier"]),
                 "code_challenge_method": "S256"}
    assert issuer.count("openid-configuration") == 1      # discovery cached across the two starts


def test_scopes_come_from_the_config(issuer):
    oidc = OIDC(config(scopes=["openid", "email", "groups"]), REDIRECT, transport=httpx.MockTransport(issuer.handler))
    assert parse_qs(urlparse(oidc.start()["url"]).query)["scope"] == ["openid email groups"]


# -- finish(): token exchange + verification -------------------------------------------

def test_finish_returns_verified_claims_and_caches_discovery_and_jwks(oidc, issuer, monkeypatch):
    monkeypatch.setenv("ATTEST_OIDC_CLIENT_SECRET", "shh")
    started = login(oidc, issuer)
    claims = oidc.finish("auth-code", started["code_verifier"], started["nonce"])
    assert claims["sub"] == "user-1" and claims["email"] == "Ada@Acme.com" and claims["nonce"] == started["nonce"]
    assert issuer.last_token_form == {"grant_type": "authorization_code", "code": "auth-code", "client_id": CLIENT_ID,
                                      "redirect_uri": REDIRECT, "code_verifier": started["code_verifier"], "client_secret": "shh"}
    again = login(oidc, issuer)
    oidc.finish("code-2", again["code_verifier"], again["nonce"])
    assert issuer.count("openid-configuration") == 1 and issuer.count("/v1/keys") == 1 and issuer.count("/v1/token") == 2


def test_client_secret_is_omitted_when_the_env_var_is_unset(oidc, issuer, monkeypatch):
    monkeypatch.delenv("ATTEST_OIDC_CLIENT_SECRET", raising=False)
    started = login(oidc, issuer)
    oidc.finish("c", started["code_verifier"], started["nonce"])
    assert "client_secret" not in issuer.last_token_form


def test_wrong_nonce_is_rejected(oidc, issuer):
    started = login(oidc, issuer)
    with pytest.raises(OIDCError, match="nonce"):
        oidc.finish("c", started["code_verifier"], "some-other-nonce")
    with pytest.raises(OIDCError, match="nonce"):
        oidc.finish("c", started["code_verifier"], "")


def test_wrong_audience_is_rejected(oidc, issuer):
    issuer.claims = {"aud": "another-app"}
    started = login(oidc, issuer)
    with pytest.raises(OIDCError, match="(?i)audience"):
        oidc.finish("c", started["code_verifier"], started["nonce"])


def test_wrong_issuer_claim_is_rejected(oidc, issuer):
    issuer.claims = {"iss": "https://evil.example.com"}
    started = login(oidc, issuer)
    with pytest.raises(OIDCError, match="(?i)issuer"):
        oidc.finish("c", started["code_verifier"], started["nonce"])


def test_expired_token_is_rejected(oidc, issuer):
    issuer.claims = {"exp": int(time.time()) - 600}
    started = login(oidc, issuer)
    with pytest.raises(OIDCError, match="(?i)expired"):
        oidc.finish("c", started["code_verifier"], started["nonce"])


def test_unknown_kid_refetches_the_jwks_once_then_fails(oidc, issuer):
    issuer.kid = "rotated-away"
    started = login(oidc, issuer)
    with pytest.raises(OIDCError, match="rotated-away"):
        oidc.finish("c", started["code_verifier"], started["nonce"])
    assert issuer.count("/v1/keys") == 2


def test_rotated_key_is_found_on_the_refetch(issuer):
    new = make_key("key-2027")
    oidc = OIDC(config(), REDIRECT, transport=httpx.MockTransport(issuer.handler))
    started = login(oidc, issuer)
    oidc.finish("c", started["code_verifier"], started["nonce"])           # caches the 2026 JWKS
    issuer.key, issuer.kid, issuer.jwks_keys = new, "key-2027", [new["jwk"]]
    started = login(oidc, issuer)
    assert oidc.finish("c", started["code_verifier"], started["nonce"])["sub"] == "user-1"
    assert issuer.count("/v1/keys") == 2


def test_token_signed_by_another_key_is_rejected(issuer):
    impostor = make_key(KID)           # same kid, different key pair
    oidc = OIDC(config(), REDIRECT, transport=httpx.MockTransport(issuer.handler))
    started = login(oidc, issuer)
    issuer.key = impostor
    with pytest.raises(OIDCError, match="(?i)signature"):
        oidc.finish("c", started["code_verifier"], started["nonce"])


def test_alg_none_is_rejected(oidc, issuer):
    issuer.alg = "none"
    started = login(oidc, issuer)
    with pytest.raises(OIDCError, match="id_token rejected"):
        oidc.finish("c", started["code_verifier"], started["nonce"])


def test_token_endpoint_errors_and_missing_id_token(oidc, issuer):
    started = login(oidc, issuer)
    issuer.token_status = 400
    with pytest.raises(OIDCError, match="400: code expired"):
        oidc.finish("c", started["code_verifier"], started["nonce"])


def test_discovery_issuer_must_match_the_configured_issuer(key):
    issuer = FakeIssuer(key, issuer="https://acme.okta.com/oauth2/other")
    oidc = OIDC(config(), REDIRECT, transport=httpx.MockTransport(issuer.handler))
    with pytest.raises(OIDCError, match="does not match"):
        oidc.discover()


def test_discovery_failures_are_oidc_errors():
    def handler(request):
        return httpx.Response(503, text="down")
    with pytest.raises(OIDCError, match="503"):
        OIDC(config(), REDIRECT, transport=httpx.MockTransport(handler)).discover()
    with pytest.raises(OIDCError, match="needs issuer and client_id"):
        OIDC(config(client_id=""), REDIRECT)


# -- what the claims mean --------------------------------------------------------------

def test_check_email_lowercases_and_enforces_allowed_domains():
    oidc = OIDC(config(allowed_domains=["Acme.com"]), REDIRECT)
    assert oidc.check_email({"email": " Ada@Acme.com "}) == "ada@acme.com"
    assert oidc.check_email({"preferred_username": "bob@acme.com"}) == "bob@acme.com"
    with pytest.raises(OIDCError, match="not in an allowed domain"):
        oidc.check_email({"email": "eve@other.com"})
    with pytest.raises(OIDCError, match="no email"):
        oidc.check_email({"sub": "x"})
    assert OIDC(config(), REDIRECT).check_email({"email": "eve@other.com"}) == "eve@other.com"   # no allow-list: any domain


def test_role_for_picks_the_most_privileged_mapped_role():
    role_map = {"admins": "admin", "eng": "engineer", "bots": "service", "aud": "auditor", "odd": "superuser"}
    oidc = OIDC(config(role_claim="groups", role_map=role_map, default_role="auditor"), REDIRECT)
    assert oidc.role_for({"groups": ["eng", "admins"]}) == "admin"
    assert oidc.role_for({"groups": ["aud", "bots"]}) == "service"
    assert oidc.role_for({"groups": ["aud", "eng"]}) == "engineer"
    assert oidc.role_for({"groups": "eng"}) == "engineer"                 # a scalar claim works too
    assert oidc.role_for({"groups": ["nobody"]}) == "auditor"            # nothing mapped → default
    assert oidc.role_for({"groups": ["odd"]}) == "auditor"               # a mapping to an unknown role is ignored
    assert oidc.role_for({}) == "auditor"
    assert OIDC(config(default_role="engineer"), REDIRECT).role_for({"groups": ["admins"]}) == "engineer"   # no role_claim
