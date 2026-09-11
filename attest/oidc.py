"""Sign in with any OpenID Connect issuer: Authorization Code + PKCE, id_token verified locally.

    oidc = OIDC(cfg.auth.oidc, redirect_uri="https://attest.example.com/auth/callback")
    login = oidc.start()                 # send the browser to login["url"]; keep state/nonce/code_verifier in the session
    claims = oidc.finish(code, login["code_verifier"], login["nonce"])
    email, role = oidc.check_email(claims), oidc.role_for(claims)

Discovery and the JWKS are fetched once per instance. The id_token is checked for signature (RS256,
key by ``kid``), issuer, audience, expiry and nonce; any failure raises ``OIDCError`` — no partial
claims ever come back. The client secret is read from the environment variable named in the config.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
from urllib.parse import urlencode

import httpx
import jwt

from attest.config import OIDCConfig

DISCOVERY_PATH = "/.well-known/openid-configuration"
DISCOVERY_KEYS = ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri")
ROLE_ORDER = ("admin", "engineer", "service", "auditor")     # most → least privileged
LEEWAY_SECONDS = 60
REQUIRED_CLAIMS = ("iss", "aud", "exp", "iat", "sub")


class OIDCError(Exception):
    """Anything that should stop a sign-in: transport, discovery, token exchange or claim checks."""


def pkce_challenge(code_verifier: str) -> str:
    """S256: base64url(sha256(verifier)) without padding (RFC 7636 §4.2)."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class OIDC:
    def __init__(self, cfg: OIDCConfig, redirect_uri: str, transport=None):
        if not cfg.issuer or not cfg.client_id:
            raise OIDCError("[auth.oidc] needs issuer and client_id")
        self.cfg = cfg
        self.redirect_uri = redirect_uri
        self._http = httpx.Client(transport=transport, timeout=10.0, headers={"Accept": "application/json"})
        self._metadata: dict | None = None
        self._jwks: list[dict] | None = None

    # -- discovery -----------------------------------------------------------------

    def discover(self) -> dict:
        """The issuer's metadata (cached): issuer, authorization_endpoint, token_endpoint, jwks_uri."""
        if self._metadata is None:
            issuer = self.cfg.issuer.rstrip("/")
            body = self._get_json(issuer + DISCOVERY_PATH, "discovery document")
            missing = [k for k in DISCOVERY_KEYS if not isinstance(body.get(k), str) or not body[k]]
            if missing:
                raise OIDCError(f"discovery document at {issuer} lacks {', '.join(missing)}")
            if body["issuer"].rstrip("/") != issuer:
                raise OIDCError(f"discovery document issuer {body['issuer']!r} does not match configured issuer {self.cfg.issuer!r}")
            self._metadata = {k: body[k] for k in DISCOVERY_KEYS}
        return self._metadata

    # -- the two legs ----------------------------------------------------------------

    def start(self) -> dict:
        """Fresh state, nonce and PKCE verifier plus the authorization URL to send the browser to."""
        meta = self.discover()
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(64)  # 86 chars: inside RFC 7636's 43..128
        query = {
            "response_type": "code",
            "client_id": self.cfg.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.cfg.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": pkce_challenge(code_verifier),
            "code_challenge_method": "S256",
        }
        joiner = "&" if "?" in meta["authorization_endpoint"] else "?"
        return {"url": f"{meta['authorization_endpoint']}{joiner}{urlencode(query)}",
                "state": state, "nonce": nonce, "code_verifier": code_verifier}

    def finish(self, code: str, code_verifier: str, nonce: str) -> dict:
        """Exchange the code, verify the id_token, and return its claims — or raise OIDCError."""
        meta = self.discover()
        data = {"grant_type": "authorization_code", "code": code, "client_id": self.cfg.client_id,
                "redirect_uri": self.redirect_uri, "code_verifier": code_verifier}
        client_secret = os.environ.get(self.cfg.client_secret_env) if self.cfg.client_secret_env else None
        if client_secret:
            data["client_secret"] = client_secret
        try:
            resp = self._http.post(meta["token_endpoint"], data=data)
        except httpx.HTTPError as exc:
            raise OIDCError(f"token request failed: {exc}") from exc
        body = self._json_or_empty(resp)
        if resp.status_code != 200:
            detail = body.get("error_description") or body.get("error") or resp.text[:200]
            raise OIDCError(f"token endpoint returned {resp.status_code}: {detail}")
        id_token = body.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise OIDCError("token response has no id_token (is the 'openid' scope requested?)")
        claims = self._verify(id_token, meta)
        if not nonce or claims.get("nonce") != nonce:
            raise OIDCError("id_token nonce does not match this login attempt")
        return claims

    # -- what the claims mean for attest ---------------------------------------------

    def role_for(self, claims: dict) -> str:
        """Map the configured role claim through role_map; the most privileged mapped role wins."""
        if not self.cfg.role_claim:
            return self.cfg.default_role
        value = claims.get(self.cfg.role_claim)
        values = [value] if isinstance(value, str) else [v for v in value if isinstance(v, str)] if isinstance(value, list) else []
        mapped = {self.cfg.role_map[v] for v in values if v in self.cfg.role_map}
        for role in ROLE_ORDER:
            if role in mapped:
                return role
        return self.cfg.default_role

    def check_email(self, claims: dict) -> str:
        """The lowercased email from the claims, refused when its domain is not allowed."""
        email = claims.get("email") or claims.get("preferred_username") or ""
        email = email.strip().lower() if isinstance(email, str) else ""
        if "@" not in email:
            raise OIDCError("id_token carries no email (request the 'email' scope or map preferred_username)")
        if self.cfg.allowed_domains:
            domain = email.rsplit("@", 1)[1]
            if domain not in {d.strip().lower() for d in self.cfg.allowed_domains}:
                raise OIDCError(f"{email} is not in an allowed domain ({', '.join(self.cfg.allowed_domains)})")
        return email

    # -- verification ----------------------------------------------------------------

    def _verify(self, id_token: str, meta: dict) -> dict:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise OIDCError(f"malformed id_token: {exc}") from exc
        key = self._signing_key(header.get("kid"), meta["jwks_uri"])
        try:
            return jwt.decode(id_token, key=key, algorithms=["RS256"], audience=self.cfg.client_id, issuer=meta["issuer"],
                              leeway=LEEWAY_SECONDS, options={"require": list(REQUIRED_CLAIMS)})
        except jwt.PyJWTError as exc:
            raise OIDCError(f"id_token rejected: {exc}") from exc

    def _signing_key(self, kid: str | None, jwks_uri: str):
        key = self._find_key(kid, jwks_uri)
        if key is None:            # keys rotate: refetch once before giving up
            self._jwks = None
            key = self._find_key(kid, jwks_uri)
        if key is None:
            raise OIDCError(f"no RSA signing key in the JWKS matches kid {kid!r}")
        return key

    def _find_key(self, kid: str | None, jwks_uri: str):
        if self._jwks is None:
            keys = self._get_json(jwks_uri, "JWKS").get("keys")
            self._jwks = [k for k in keys if isinstance(k, dict)] if isinstance(keys, list) else []
        candidates = [k for k in self._jwks if k.get("kty") == "RSA" and k.get("use", "sig") == "sig"]
        if kid is not None:
            candidates = [k for k in candidates if k.get("kid") == kid]
        elif len(candidates) != 1:
            return None            # no kid in the header and no single key to fall back on
        for candidate in candidates:
            try:
                return jwt.PyJWK(candidate).key
            except jwt.PyJWTError:
                continue
        return None

    # -- http ------------------------------------------------------------------------

    def _get_json(self, url: str, what: str) -> dict:
        try:
            resp = self._http.get(url)
        except httpx.HTTPError as exc:
            raise OIDCError(f"{what} request failed: {exc}") from exc
        if resp.status_code != 200:
            raise OIDCError(f"{what} at {url} returned {resp.status_code}")
        body = self._json_or_empty(resp)
        if not body:
            raise OIDCError(f"{what} at {url} is not a JSON object")
        return body

    @staticmethod
    def _json_or_empty(resp: httpx.Response) -> dict:
        try:
            body = resp.json()
        except ValueError:
            return {}
        return body if isinstance(body, dict) else {}
