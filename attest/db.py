"""Relational storage for Attest.

SQLite by default (a single file next to the config), Postgres via a URL.
Evidence and audit rows keep the PoC's hash-chain semantics: each row's
sha256 covers its content plus the previous row's digest, and there is no
update path for either table.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from sqlalchemy import (JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint,
                        create_engine, event)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

SCHEMA_VERSION = 1
DEFAULT_URL = "sqlite:///attest.db"

ROLES = ("admin", "engineer", "auditor", "service")
CLASSIFICATIONS = ("publishable", "internal", "restricted")


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Base(DeclarativeBase):
    pass


class Evidence(Base):
    """One collected fact. Append-only; sha256 chains to the previous row."""
    __tablename__ = "evidence"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(32), unique=True, index=True)        # EV-0001…
    source: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(128), index=True)
    control_ids: Mapped[list] = mapped_column(JSON, default=list)
    classification: Mapped[str] = mapped_column(String(16), index=True)
    collected_at: Mapped[str] = mapped_column(String(32), index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    prev_sha256: Mapped[str] = mapped_column(String(64))
    run_id: Mapped[int | None] = mapped_column(ForeignKey("collector_runs.id"), nullable=True)


class Audit(Base):
    """Who did what, with which model version, approved by whom. Append-only, chained."""
    __tablename__ = "audit"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[str] = mapped_column(String(32), index=True)
    actor: Mapped[str] = mapped_column(String(128), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    subject: Mapped[str] = mapped_column(String(256))
    detail: Mapped[str] = mapped_column(Text, default="")
    rule: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    approver: Mapped[str | None] = mapped_column(String(128), nullable=True)
    sha256: Mapped[str] = mapped_column(String(64))
    prev_sha256: Mapped[str] = mapped_column(String(64))


class ControlSnapshot(Base):
    """The state of one control at one evaluation — the observation-window history."""
    __tablename__ = "control_snapshots"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    evaluated_at: Mapped[str] = mapped_column(String(32), index=True)
    control_id: Mapped[str] = mapped_column(String(32), index=True)
    state: Mapped[str] = mapped_column(String(16))                      # PASS | DEGRADED | FAIL
    reason: Mapped[str] = mapped_column(Text, default="")
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    trigger: Mapped[str] = mapped_column(String(32), default="manual")  # manual | schedule | collector | api


class CollectorRun(Base):
    """One execution of one source's collector."""
    __tablename__ = "collector_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_id: Mapped[str] = mapped_column(String(64), index=True)
    trigger: Mapped[str] = mapped_column(String(32), default="manual")  # manual | schedule | api | import
    started_at: Mapped[str] = mapped_column(String(32), index=True)
    finished_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running")  # running | ok | error
    records: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_by: Mapped[str | None] = mapped_column(String(128), nullable=True)


class Draft(Base):
    """A questionnaire draft and, once a human decides, the signed decision."""
    __tablename__ = "drafts"
    question_id: Mapped[str] = mapped_column(String(32), primary_key=True)   # Q-4475…
    question: Mapped[str] = mapped_column(Text)
    control_ids: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16))                      # READY | DECLINED | BLOCKED
    answer: Mapped[str] = mapped_column(Text, default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    citations: Mapped[list] = mapped_column(JSON, default=list)          # [{id, source, collected_at}]
    mode: Mapped[str] = mapped_column(String(32), default="deterministic")
    model_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), index=True)
    created_by: Mapped[str] = mapped_column(String(128))
    decision: Mapped[str | None] = mapped_column(String(16), nullable=True)   # approve | reject | assign
    approver: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decided_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    signature: Mapped[str | None] = mapped_column(String(64), nullable=True)


class RiskAcceptance(Base):
    """A FAIL that a named owner has accepted until a date. Expired acceptances fail the gate."""
    __tablename__ = "risk_acceptances"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    control_id: Mapped[str] = mapped_column(String(32), index=True)
    owner: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(Text)
    expires: Mapped[str] = mapped_column(String(10))                     # YYYY-MM-DD
    created_at: Mapped[str] = mapped_column(String(32))
    created_by: Mapped[str] = mapped_column(String(128))
    revoked_at: Mapped[str | None] = mapped_column(String(32), nullable=True)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(256), default="")
    role: Mapped[str] = mapped_column(String(16), default="engineer")    # one of ROLES
    password_hash: Mapped[str | None] = mapped_column(String(256), nullable=True)  # local login; null for OIDC/service
    created_at: Mapped[str] = mapped_column(String(32))
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)


class ApiKey(Base):
    """Bearer keys. Only the sha256 of the secret is stored; the prefix is for display."""
    __tablename__ = "api_keys"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    prefix: Mapped[str] = mapped_column(String(12), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[str] = mapped_column(String(32))
    last_used_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    revoked_at: Mapped[str | None] = mapped_column(String(32), nullable=True)


class Setting(Base):
    """Installation-level values: schema_version, approval signing key, install id."""
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    __table_args__ = (UniqueConstraint("key"),)


# ---------------------------------------------------------------------------
def get_engine(url: str = DEFAULT_URL) -> Engine:
    kwargs = {"future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _pragmas(dbapi_conn, _record):  # WAL for concurrent readers; FKs on
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()
    return engine


def init_db(engine: Engine) -> None:
    """Create tables if missing and stamp the schema version."""
    Base.metadata.create_all(engine)
    with session_scope(engine) as s:
        row = s.get(Setting, "schema_version")
        if row is None:
            s.add(Setting(key="schema_version", value={"version": SCHEMA_VERSION}))


# -- migrations ---------------------------------------------------------------
MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
# Databases created by init_db() before Alembic existed carry only settings.schema_version;
# this maps that number to the Alembic revision that produces the identical schema.
_SCHEMA_REVISIONS = {1: "0001"}


def _alembic_config(url: str):
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))  # configparser interpolation
    return cfg


def current_revision(url: str) -> str | None:
    """The Alembic revision the database at ``url`` is stamped with, or None if it never was."""
    from alembic.runtime.migration import MigrationContext

    engine = get_engine(url)
    try:
        with engine.connect() as conn:
            return MigrationContext.configure(conn).get_current_revision()
    finally:
        engine.dispose()


def _legacy_revision(url: str) -> str | None:
    """For a database built by init_db() (tables, no alembic_version): the revision to stamp."""
    from sqlalchemy import inspect

    engine = get_engine(url)
    try:
        tables = set(inspect(engine).get_table_names())
        if "alembic_version" in tables or "settings" not in tables:
            return None
        with session_scope(engine) as s:
            stamped = get_setting(s, "schema_version") or {}
        return _SCHEMA_REVISIONS.get(stamped.get("version"))
    finally:
        engine.dispose()


def upgrade(url: str) -> None:
    """Bring the database at ``url`` to the newest schema (``alembic upgrade head``).

    Idempotent: a database already at head is left untouched. A database created by
    init_db() before migrations existed is stamped with the matching revision first.
    """
    from alembic import command

    cfg = _alembic_config(url)
    if current_revision(url) is None:
        legacy = _legacy_revision(url)
        if legacy is not None:
            command.stamp(cfg, legacy)
    command.upgrade(cfg, "head")


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@contextmanager
def session_scope(engine: Engine) -> Iterator[Session]:
    factory = make_session_factory(engine)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_setting(session: Session, key: str, default=None):
    row = session.get(Setting, key)
    return row.value if row is not None else default


def set_setting(session: Session, key: str, value: dict) -> None:
    row = session.get(Setting, key)
    if row is None:
        session.add(Setting(key=key, value=value))
    else:
        row.value = value


def to_dict(row: Base) -> dict:
    return {c.name: getattr(row, c.name) for c in row.__table__.columns}
