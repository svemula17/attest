"""Authentication and authorization.

Two credentials: a bearer API key (services, CI, the MCP server) or a signed
session cookie (people, after a local login). Both resolve to a User, and a
User's role resolves to the grants the agent layer already enforces — so the
requester-scoped-identity guardrail runs on real identities, not personas.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import select
from sqlalchemy.engine import Engine

from attest.db import ROLES, ApiKey, User, session_scope, utcnow
from attest.guardrails import RequesterScope

# Role → grants. The agent layer checks grants, never roles.
ROLE_GRANTS: dict[str, frozenset[str]] = {
    "admin":    frozenset({"read:evidence", "read:documents", "approve:questionnaire", "run:collectors", "manage:users", "manage:acceptances", "write:evidence:import"}),
    "engineer": frozenset({"read:evidence", "read:documents", "approve:questionnaire", "run:collectors", "manage:acceptances", "write:evidence:import"}),
    "auditor":  frozenset({"read:evidence"}),
    "service":  frozenset({"read:evidence", "run:collectors", "write:evidence:import"}),
}

KEY_PREFIX = "atst_"
_PBKDF2_ROUNDS = 200_000


class AuthError(Exception):
    """Raised for a missing/invalid credential (401) or a missing grant (403)."""
    def __init__(self, message: str, status: int = 401):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Identity:
    user_id: int
    email: str
    name: str
    role: str
    via: str                      # "session" | "api-key" | "system"
    grants: frozenset[str] = field(default_factory=frozenset)

    def scope(self) -> RequesterScope:
        return RequesterScope(user=self.email, grants=self.grants)

    def can(self, grant: str) -> bool:
        return grant in self.grants

    def require(self, grant: str) -> None:
        if grant not in self.grants:
            raise AuthError(f"{self.email} ({self.role}) is not granted '{grant}'", status=403)


SYSTEM = Identity(user_id=0, email="system@attest", name="system", role="admin", via="system", grants=ROLE_GRANTS["admin"])


# ---- passwords (local login) ------------------------------------------------
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), _PBKDF2_ROUNDS).hex()
    return f"pbkdf2_sha256${_PBKDF2_ROUNDS}${salt}${digest}"


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        return False
    try:
        algo, rounds, salt, digest = stored.split("$")
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds)).hex()
    return hmac.compare_digest(candidate, digest)


# ---- users -------------------------------------------------------------------
def _identity(user: User, via: str) -> Identity:
    return Identity(user_id=user.id, email=user.email, name=user.name or user.email, role=user.role, via=via,
                    grants=ROLE_GRANTS.get(user.role, frozenset()))


def create_user(engine: Engine, email: str, role: str, name: str = "", password: str | None = None) -> dict:
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}")
    email = email.strip().lower()
    with session_scope(engine) as s:
        if s.scalar(select(User).where(User.email == email)) is not None:
            raise ValueError(f"user {email} already exists")
        u = User(email=email, name=name, role=role, password_hash=hash_password(password) if password else None, created_at=utcnow())
        s.add(u); s.flush()
        return {"id": u.id, "email": u.email, "name": u.name, "role": u.role, "created_at": u.created_at, "disabled": u.disabled}


def list_users(engine: Engine) -> list[dict]:
    with session_scope(engine) as s:
        return [{"id": u.id, "email": u.email, "name": u.name, "role": u.role, "created_at": u.created_at, "disabled": u.disabled,
                 "login": "password" if u.password_hash else "api-key"} for u in s.scalars(select(User).order_by(User.id))]


def set_user_role(engine: Engine, email: str, role: str) -> dict:
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}")
    with session_scope(engine) as s:
        u = s.scalar(select(User).where(User.email == email.strip().lower()))
        if u is None:
            raise ValueError(f"no such user: {email}")
        u.role = role
        return {"id": u.id, "email": u.email, "role": u.role}


def disable_user(engine: Engine, email: str, disabled: bool = True) -> None:
    with session_scope(engine) as s:
        u = s.scalar(select(User).where(User.email == email.strip().lower()))
        if u is None:
            raise ValueError(f"no such user: {email}")
        u.disabled = disabled


def login(engine: Engine, email: str, password: str) -> Identity:
    with session_scope(engine) as s:
        u = s.scalar(select(User).where(User.email == email.strip().lower()))
        if u is None or u.disabled or not verify_password(password, u.password_hash):
            raise AuthError("invalid email or password")
        return _identity(u, "session")


# ---- API keys ----------------------------------------------------------------
def _key_hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def create_api_key(engine: Engine, email: str, name: str) -> tuple[str, dict]:
    """Returns (secret, key_row). The secret is shown exactly once."""
    secret = KEY_PREFIX + secrets.token_urlsafe(32)
    with session_scope(engine) as s:
        u = s.scalar(select(User).where(User.email == email.strip().lower()))
        if u is None:
            raise ValueError(f"no such user: {email}")
        k = ApiKey(user_id=u.id, name=name, prefix=secret[:12], key_hash=_key_hash(secret), created_at=utcnow())
        s.add(k); s.flush()
        return secret, {"id": k.id, "name": k.name, "prefix": k.prefix, "user": u.email, "created_at": k.created_at}


def list_api_keys(engine: Engine) -> list[dict]:
    with session_scope(engine) as s:
        rows = s.execute(select(ApiKey, User.email).join(User, User.id == ApiKey.user_id).order_by(ApiKey.id)).all()
        return [{"id": k.id, "name": k.name, "prefix": k.prefix, "user": email, "created_at": k.created_at,
                 "last_used_at": k.last_used_at, "revoked_at": k.revoked_at} for k, email in rows]


def revoke_api_key(engine: Engine, key_id: int) -> None:
    with session_scope(engine) as s:
        k = s.get(ApiKey, key_id)
        if k is None:
            raise ValueError(f"no such key: {key_id}")
        k.revoked_at = k.revoked_at or utcnow()


def authenticate_api_key(engine: Engine, secret: str) -> Identity:
    if not secret.startswith(KEY_PREFIX):
        raise AuthError("invalid API key")
    with session_scope(engine) as s:
        k = s.scalar(select(ApiKey).where(ApiKey.key_hash == _key_hash(secret)))
        if k is None or k.revoked_at:
            raise AuthError("invalid or revoked API key")
        u = s.get(User, k.user_id)
        if u is None or u.disabled:
            raise AuthError("key owner is disabled")
        k.last_used_at = utcnow()
        return _identity(u, "api-key")


# ---- sessions ----------------------------------------------------------------
class SessionCodec:
    """Signed, expiring session cookies. Carries only the user id; the role is re-read on each request."""
    def __init__(self, secret: str, max_age_hours: int = 12):
        if not secret:
            raise ValueError("auth.session_secret is empty — run `attest init` or set it in attest.toml")
        self._s = URLSafeTimedSerializer(secret, salt="attest.session")
        self.max_age = max_age_hours * 3600

    def issue(self, identity: Identity) -> str:
        return self._s.dumps({"uid": identity.user_id})

    def sign(self, payload: dict) -> str:
        """A short-lived signed blob (OIDC state/nonce/verifier travel in a cookie)."""
        return self._s.dumps(payload)

    def unsign(self, token: str, max_age: int = 600) -> dict:
        try:
            return self._s.loads(token, max_age=max_age)
        except (SignatureExpired, BadSignature) as e:
            raise AuthError("invalid or expired token") from e

    def resolve(self, engine: Engine, token: str) -> Identity:
        try:
            data = self._s.loads(token, max_age=self.max_age)
        except SignatureExpired as e:
            raise AuthError("session expired") from e
        except BadSignature as e:
            raise AuthError("invalid session") from e
        with session_scope(engine) as s:
            u = s.get(User, int(data.get("uid", 0)))
            if u is None or u.disabled:
                raise AuthError("session user is disabled")
            return _identity(u, "session")


def identity_for_email(engine: Engine, email: str, via: str = "oidc") -> Identity:
    with session_scope(engine) as s:
        u = s.scalar(select(User).where(User.email == email.strip().lower()))
        if u is None or u.disabled:
            raise AuthError("user is unknown or disabled")
        return _identity(u, via)
