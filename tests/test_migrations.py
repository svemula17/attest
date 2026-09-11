"""Alembic migrations produce exactly the schema Base.metadata describes."""
from __future__ import annotations

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect, text

from attest.db import SCHEMA_VERSION, Base, current_revision, get_engine, get_setting, init_db, session_scope, upgrade
from attest.store_sql import SqlEvidenceStore

HEAD = "0001"


def _url(tmp_path, name):
    return f"sqlite:///{tmp_path / name}"


def _schema(engine, table):
    insp = inspect(engine)
    columns = [
        (c["name"], repr(c["type"]), c["nullable"], c.get("default"), bool(c.get("primary_key")))
        for c in insp.get_columns(table)
    ]
    indexes = sorted((i["name"], tuple(i["column_names"]), bool(i["unique"])) for i in insp.get_indexes(table))
    uniques = sorted(tuple(u["column_names"]) for u in insp.get_unique_constraints(table))
    foreign_keys = sorted(
        (tuple(f["constrained_columns"]), f["referred_table"], tuple(f["referred_columns"]))
        for f in insp.get_foreign_keys(table)
    )
    primary_key = tuple(insp.get_pk_constraint(table)["constrained_columns"])
    return {"columns": columns, "indexes": indexes, "uniques": uniques, "fks": foreign_keys, "pk": primary_key}


def test_upgrade_creates_every_table_with_the_metadata_columns(tmp_path):
    migrated_url = _url(tmp_path, "migrated.db")
    assert current_revision(migrated_url) is None
    upgrade(migrated_url)
    assert current_revision(migrated_url) == HEAD

    reference = get_engine(_url(tmp_path, "reference.db"))
    init_db(reference)
    migrated = get_engine(migrated_url)
    try:
        expected = set(Base.metadata.tables)
        assert set(inspect(migrated).get_table_names()) == expected | {"alembic_version"}
        for table in sorted(expected):
            assert _schema(migrated, table) == _schema(reference, table), table
    finally:
        reference.dispose()
        migrated.dispose()


def test_migrated_schema_has_no_drift_from_metadata(tmp_path):
    url = _url(tmp_path, "m.db")
    upgrade(url)
    engine = get_engine(url)
    try:
        with engine.connect() as conn:
            ctx = MigrationContext.configure(conn, opts={"compare_type": True})
            assert compare_metadata(ctx, Base.metadata) == []
    finally:
        engine.dispose()


def test_second_upgrade_is_a_noop(tmp_path):
    url = _url(tmp_path, "twice.db")
    upgrade(url)
    engine = get_engine(url)
    try:
        SqlEvidenceStore(engine).append("s", "k", ["CTL-X"], "internal", {"n": 1})
        before = {t: _schema(engine, t) for t in Base.metadata.tables}
        upgrade(url)
        assert current_revision(url) == HEAD
        assert {t: _schema(engine, t) for t in Base.metadata.tables} == before
        store = SqlEvidenceStore(engine)
        assert store.count() == 1 and store.verify_chain() is True  # data survived
    finally:
        engine.dispose()


def test_upgrade_stamps_schema_version_setting(tmp_path):
    url = _url(tmp_path, "s.db")
    upgrade(url)
    engine = get_engine(url)
    try:
        with session_scope(engine) as s:
            assert get_setting(s, "schema_version") == {"version": SCHEMA_VERSION}
    finally:
        engine.dispose()


def test_upgrade_adopts_a_database_built_by_init_db(tmp_path):
    url = _url(tmp_path, "legacy.db")
    engine = get_engine(url)
    init_db(engine)
    SqlEvidenceStore(engine).append("s", "k", ["CTL-X"], "internal", {"n": 1})
    engine.dispose()
    assert current_revision(url) is None

    upgrade(url)  # would fail with "table already exists" without the stamp
    assert current_revision(url) == HEAD
    engine = get_engine(url)
    try:
        assert SqlEvidenceStore(engine).count() == 1
    finally:
        engine.dispose()


def test_upgraded_database_serves_the_sql_stores(tmp_path):
    url = _url(tmp_path, "live.db")
    upgrade(url)
    engine = get_engine(url)
    try:
        store = SqlEvidenceStore(engine)
        a = store.append("aws-config", "kms.key.rotation", ["CTL-CRYPTO-01"], "publishable", {"status": "ok"})
        assert a.id == "EV-0001" and store.verify_chain() is True
        with engine.connect() as conn:
            assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == HEAD
    finally:
        engine.dispose()


def test_migration_directory_layout():
    from attest.db import MIGRATIONS_DIR

    assert (MIGRATIONS_DIR / "env.py").is_file()
    assert (MIGRATIONS_DIR / "script.py.mako").is_file()
    assert (MIGRATIONS_DIR / "alembic.ini").is_file()
    assert (MIGRATIONS_DIR / "versions" / "0001_initial.py").is_file()


@pytest.mark.parametrize("url", ["sqlite:///:memory:"])
def test_current_revision_on_unmigrated_database_is_none(url):
    assert current_revision(url) is None
