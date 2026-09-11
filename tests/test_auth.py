import pytest

from attest.auth import (ROLE_GRANTS, AuthError, SessionCodec, authenticate_api_key, create_api_key, create_user, disable_user,
                         hash_password, list_api_keys, list_users, login, revoke_api_key, set_user_role, verify_password)
from attest.db import get_engine, init_db


@pytest.fixture
def engine(tmp_path):
    e = get_engine(f"sqlite:///{tmp_path/'t.db'}"); init_db(e); return e


def test_password_hash_roundtrip():
    h = hash_password("correct horse")
    assert h.startswith("pbkdf2_sha256$") and verify_password("correct horse", h) and not verify_password("wrong", h)
    assert not verify_password("x", None) and not verify_password("x", "garbage")


def test_user_lifecycle_and_login(engine):
    u = create_user(engine, "Sai@Example.com", "engineer", name="Sai", password="pw")
    assert u["email"] == "sai@example.com"
    with pytest.raises(ValueError):
        create_user(engine, "sai@example.com", "engineer")
    with pytest.raises(ValueError):
        create_user(engine, "x@example.com", "king")
    ident = login(engine, "sai@example.com", "pw")
    assert ident.role == "engineer" and ident.via == "session" and ident.can("approve:questionnaire") and not ident.can("manage:users")
    assert ident.scope().user == "sai@example.com"
    with pytest.raises(AuthError):
        login(engine, "sai@example.com", "nope")
    set_user_role(engine, "sai@example.com", "auditor")
    assert login(engine, "sai@example.com", "pw").grants == ROLE_GRANTS["auditor"]
    disable_user(engine, "sai@example.com")
    with pytest.raises(AuthError):
        login(engine, "sai@example.com", "pw")
    assert list_users(engine)[0]["disabled"] is True


def test_api_keys(engine):
    create_user(engine, "ci@example.com", "service")
    secret, row = create_api_key(engine, "ci@example.com", "github actions")
    assert secret.startswith("atst_") and row["prefix"] == secret[:12]
    ident = authenticate_api_key(engine, secret)
    assert ident.via == "api-key" and ident.can("run:collectors") and not ident.can("approve:questionnaire")
    assert list_api_keys(engine)[0]["last_used_at"] is not None
    with pytest.raises(AuthError):
        authenticate_api_key(engine, "atst_not-a-real-key")
    with pytest.raises(AuthError):
        authenticate_api_key(engine, "sk-wrong-prefix")
    revoke_api_key(engine, row["id"])
    with pytest.raises(AuthError):
        authenticate_api_key(engine, secret)


def test_require_raises_403(engine):
    create_user(engine, "aud@example.com", "auditor", password="pw")
    ident = login(engine, "aud@example.com", "pw")
    with pytest.raises(AuthError) as ei:
        ident.require("approve:questionnaire")
    assert ei.value.status == 403


def test_session_cookie(engine):
    create_user(engine, "p@example.com", "admin", password="pw")
    ident = login(engine, "p@example.com", "pw")
    codec = SessionCodec("secret-1", max_age_hours=1)
    token = codec.issue(ident)
    assert codec.resolve(engine, token).email == "p@example.com"
    with pytest.raises(AuthError):
        SessionCodec("secret-2").resolve(engine, token)
    with pytest.raises(AuthError):
        codec.resolve(engine, token + "x")
    with pytest.raises(ValueError):
        SessionCodec("")
