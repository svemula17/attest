"""SQL-backed stores: parity with the JSONL stores, hash chains, and the relational-only tables."""
from __future__ import annotations

import json
import threading
from dataclasses import asdict
from datetime import datetime, timezone

import pytest
from sqlalchemy import text

from attest.audit import AuditEntry, AuditLog
from attest.controls import ControlResult
from attest.db import get_engine, init_db
from attest.evidence import EvidenceRecord, EvidenceStore, compute_sha256
from attest.seed import SEED, seed_into
from attest.store_sql import (AcceptanceStore, DraftStore, RunStore, SnapshotStore, SqlAuditLog, SqlEvidenceStore,
                              compute_audit_sha256)
from attest.util import canonical_json

T0 = "2026-09-09T10:00:00Z"
NOW = datetime(2026, 9, 11, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def engine(tmp_path):
    engine = get_engine(f"sqlite:///{tmp_path / 'attest.db'}")
    init_db(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def freeze_now(monkeypatch):
    """Pin now_iso() in both stores so appends without collected_at hash identically."""
    monkeypatch.setattr("attest.evidence.now_iso", lambda: "2026-09-11T12:00:00Z")
    monkeypatch.setattr("attest.store_sql.now_iso", lambda: "2026-09-11T12:00:00Z")
    monkeypatch.setattr("attest.audit.now_iso", lambda: "2026-09-11T12:00:00Z")


def _seed3(store):
    a = store.append("aws-config", "kms.key.rotation", ["CTL-CRYPTO-01"], "publishable", {"status": "ok"}, collected_at=T0)
    b = store.append("cloudtrail", "log.retention", ["CTL-LOG-01", "CTL-CRYPTO-01"], "internal", {"status": "ok"}, collected_at=T0)
    c = store.append("okta", "mfa.enforced", ["CTL-ACCESS-01"], "restricted", {"status": "ok"}, collected_at=T0)
    return a, b, c


def _tamper(engine, sql, params=None):
    with engine.begin() as conn:
        conn.execute(text(sql), params or {})


# -- evidence: parity with the JSONL store ---------------------------------------

def test_seed_rows_hash_identically_in_jsonl_and_sql(tmp_path, engine, freeze_now):
    jsonl_store, jsonl_audit = EvidenceStore(tmp_path / "evidence.jsonl"), AuditLog(tmp_path / "audit.jsonl")
    sql_store, sql_audit = SqlEvidenceStore(engine), SqlAuditLog(engine)
    seed_into(jsonl_store, jsonl_audit, now=NOW)
    seed_into(sql_store, sql_audit, now=NOW)

    jsonl_records, sql_records = jsonl_store.all(), sql_store.all()
    assert len(sql_records) == len(SEED) + 3  # SEED + roster + idp users + the join's output
    assert [r.sha256 for r in sql_records] == [r.sha256 for r in jsonl_records]
    assert sql_records == jsonl_records  # ids, prev links, payloads: the whole dataclass
    assert sql_store.verify_chain() is True and jsonl_store.verify_chain() is True
    assert sql_store.count() == len(jsonl_records)
    assert sql_audit.all() == jsonl_audit.all()


def test_append_returns_evidence_record_with_contract_digest(engine):
    store = SqlEvidenceStore(engine)
    a, b, c = _seed3(store)
    assert isinstance(a, EvidenceRecord)
    assert [a.id, b.id, c.id] == ["EV-0001", "EV-0002", "EV-0003"]
    assert a.prev_sha256 is None and b.prev_sha256 == a.sha256 and c.prev_sha256 == b.sha256
    for rec in (a, b, c):
        assert rec.sha256 == compute_sha256(asdict(rec))
    assert store.all() == [a, b, c]
    assert store.get("EV-0002") == b
    assert store.get("EV-9999") is None


def test_ids_grow_past_four_digits(engine):
    store = SqlEvidenceStore(engine)
    _tamper(engine, "INSERT INTO evidence (seq, id, source, kind, control_ids, classification, collected_at, payload, sha256, prev_sha256) "
                    "VALUES (9999, 'EV-9999', 's', 'k', '[]', 'internal', :t, '{}', 'x', '')", {"t": T0})
    rec = store.append("s", "k", [], "internal", {}, collected_at=T0)
    assert rec.id == "EV-10000"


def test_collected_at_defaults_to_now_and_run_id_is_stored(engine):
    store = SqlEvidenceStore(engine)
    run_id = RunStore(engine).start("github")
    rec = store.append("github", "pr.review-required", ["CTL-CHANGE-01"], "publishable", {}, run_id=run_id)
    assert rec.collected_at.endswith("Z")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT run_id FROM evidence WHERE id='EV-0001'")).scalar() == run_id
    assert store.verify_chain() is True  # run_id is outside the digest


def test_invalid_classification_rejected_and_nothing_written(engine):
    store = SqlEvidenceStore(engine)
    with pytest.raises(ValueError):
        store.append("okta", "mfa.enforced", ["CTL-ACCESS-01"], "secret", {})
    with pytest.raises(TypeError):
        store.append("okta", "mfa.enforced", ["CTL-ACCESS-01"], "internal", {"bad": object()})
    assert store.count() == 0


def test_run_id_must_reference_a_run(engine):
    from sqlalchemy.exc import IntegrityError
    with pytest.raises(IntegrityError):
        SqlEvidenceStore(engine).append("s", "k", [], "internal", {}, run_id=424242)


# -- evidence: chain integrity ---------------------------------------------------

def test_empty_store_chain_verifies(engine):
    assert SqlEvidenceStore(engine).verify_chain() is True


def test_tampered_payload_breaks_chain(engine):
    store = SqlEvidenceStore(engine)
    _seed3(store)
    assert store.verify_chain() is True
    _tamper(engine, "UPDATE evidence SET payload = :p WHERE id = 'EV-0002'", {"p": json.dumps({"status": "bad"})})
    assert store.verify_chain() is False


def test_removed_middle_row_breaks_chain(engine):
    store = SqlEvidenceStore(engine)
    _seed3(store)
    _tamper(engine, "DELETE FROM evidence WHERE id = 'EV-0002'")
    assert store.verify_chain() is False


def test_relinked_prev_breaks_chain(engine):
    store = SqlEvidenceStore(engine)
    _seed3(store)
    _tamper(engine, "UPDATE evidence SET prev_sha256 = '' WHERE id = 'EV-0003'")
    assert store.verify_chain() is False


def test_concurrent_appenders_keep_one_unbroken_chain(engine):
    store, audit = SqlEvidenceStore(engine), SqlAuditLog(engine)
    errors: list[str] = []

    def worker(n: int):
        try:
            for i in range(10):
                store.append("src", f"kind.{n}", ["CTL-X"], "internal", {"i": i}, collected_at=T0)
                audit.record(f"thread-{n}", "concurrent.append", "s")
        except Exception as exc:  # pragma: no cover - surfaced through the assertion below
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert store.count() == 40
    assert [r.id for r in store.all()] == [f"EV-{i:04d}" for i in range(1, 41)]
    assert store.verify_chain() is True
    assert len(audit.all()) == 40 and audit.verify_chain() is True


# -- evidence: query -------------------------------------------------------------

def test_query_by_control_id_and_kind(engine):
    store = SqlEvidenceStore(engine)
    a, b, c = _seed3(store)
    assert store.query(control_id="CTL-CRYPTO-01") == [a, b]
    assert store.query(control_id="CTL-ACCESS-01") == [c]
    assert store.query(control_id="CTL-NOPE") == []
    assert store.query(kind="log.retention") == [b]
    assert store.query(kind="log") == []  # exact match, not prefix


def test_query_max_classification_is_inclusive_and_ordered(engine):
    store = SqlEvidenceStore(engine)
    a, b, c = _seed3(store)
    assert store.query(max_classification="publishable") == [a]
    assert store.query(max_classification="internal") == [a, b]
    assert store.query(max_classification="restricted") == [a, b, c]
    assert store.query() == [a, b, c]
    assert store.query(control_id="CTL-CRYPTO-01", max_classification="publishable") == [a]
    assert store.query(control_id="CTL-CRYPTO-01", kind="log.retention", max_classification="publishable") == []
    with pytest.raises(ValueError):
        store.query(max_classification="public")


def test_query_unknown_label_in_table_fails_closed(engine):
    store = SqlEvidenceStore(engine)
    a, _, _ = _seed3(store)
    _tamper(engine, "UPDATE evidence SET classification = 'secret' WHERE id = 'EV-0002'")
    assert store.query(max_classification="internal") == [a]
    assert len(store.query()) == 3


# -- evidence: JSONL import / export ----------------------------------------------

def test_import_jsonl_preserves_digests(tmp_path, engine, freeze_now):
    jsonl = EvidenceStore(tmp_path / "evidence.jsonl")
    seed_into(jsonl, AuditLog(tmp_path / "audit.jsonl"), now=NOW)
    store = SqlEvidenceStore(engine)
    assert store.import_jsonl(jsonl.path) == len(jsonl.all())
    assert store.all() == jsonl.all()
    assert store.verify_chain() is True


def test_export_jsonl_roundtrips_byte_identically(tmp_path, engine, freeze_now):
    original = EvidenceStore(tmp_path / "evidence.jsonl")
    seed_into(original, AuditLog(tmp_path / "audit.jsonl"), now=NOW)
    store = SqlEvidenceStore(engine)
    store.import_jsonl(original.path)

    out = tmp_path / "export" / "evidence.jsonl"
    assert store.export_jsonl(out) == store.count()
    assert out.read_bytes() == original.path.read_bytes()
    reopened = EvidenceStore(out)
    assert reopened.verify_chain() is True
    assert reopened.all() == store.all()


def test_import_jsonl_missing_file(engine, tmp_path):
    with pytest.raises(FileNotFoundError):
        SqlEvidenceStore(engine).import_jsonl(tmp_path / "nope.jsonl")


def test_evidence_store_has_no_mutating_methods():
    forbidden = ("update", "delete", "remove", "pop", "clear", "truncate", "rewrite", "replace")
    public = [n for n in dir(SqlEvidenceStore) if not n.startswith("_") and callable(getattr(SqlEvidenceStore, n))]
    assert public == sorted(["all", "append", "count", "export_jsonl", "get", "import_jsonl", "query", "verify_chain"])
    for name in public:
        assert not any(word in name.lower() for word in forbidden)


# -- audit ------------------------------------------------------------------------

def test_audit_record_all_and_chain(engine):
    log = SqlAuditLog(engine)
    e1 = log.record("answer-agent", "draft", "Q-1", model_version="answer-agent v0.4.2", detail="READY")
    e2 = log.record("alice", "approve", "Q-1", approver="bob", rule="four-eyes", detail="ok")
    e3 = log.record("system", "boot", "attest")
    assert isinstance(e1, AuditEntry)
    assert log.all() == [e1, e2, e3]
    assert e3.model_version is None and e3.approver is None and e3.rule is None and e3.detail == ""
    assert log.verify_chain() is True
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT ts, actor, action, subject, detail, rule, model_version, approver, sha256, prev_sha256 "
                                 "FROM audit ORDER BY seq")).mappings().all()
    assert rows[0]["prev_sha256"] == "" and rows[1]["prev_sha256"] == rows[0]["sha256"]
    fields = dict(rows[1])
    fields["prev_sha256"] = rows[0]["sha256"]
    assert rows[1]["sha256"] == compute_audit_sha256(fields)


def test_audit_tamper_detected(engine):
    log = SqlAuditLog(engine)
    log.record("a", "x", "s1")
    log.record("b", "y", "s2")
    _tamper(engine, "UPDATE audit SET detail = 'edited' WHERE seq = 1")
    assert log.verify_chain() is False


def test_audit_query_prefix_and_limit_newest_first(engine):
    log = SqlAuditLog(engine)
    log.record("a", "evidence.seeded", "s")
    log.record("b", "answer.draft", "Q-1")
    log.record("c", "answer.approve", "Q-1")
    log.record("d", "gate.run", "main")
    assert [e.action for e in log.query()] == ["gate.run", "answer.approve", "answer.draft", "evidence.seeded"]
    assert [e.action for e in log.query(action_prefix="answer.")] == ["answer.approve", "answer.draft"]
    assert [e.action for e in log.query(action_prefix="answer.", limit=1)] == ["answer.approve"]
    assert log.query(action_prefix="answer_") == []  # '_' is escaped, not a LIKE wildcard
    assert len(log.query(limit=2)) == 2


def test_audit_log_has_no_mutating_methods():
    public = [n for n in dir(SqlAuditLog) if not n.startswith("_") and callable(getattr(SqlAuditLog, n))]
    assert public == sorted(["all", "query", "record", "verify_chain"])


# -- snapshots --------------------------------------------------------------------

def _results(state_a="PASS", state_b="FAIL"):
    return [
        ControlResult("CTL-A", state_a, ["EV-0001"], f"A is {state_a}"),
        ControlResult("CTL-B", state_b, [], f"B is {state_b}"),
    ]


def test_snapshots_record_latest_history_evaluations(engine):
    snaps = SnapshotStore(engine)
    t1 = snaps.record(_results("PASS", "FAIL"), trigger="collector", evaluated_at="2026-09-10T10:00:00Z")
    t2 = snaps.record(_results("DEGRADED", "FAIL"), evaluated_at="2026-09-11T10:00:00Z")
    t3 = snaps.record([ControlResult("CTL-A", "PASS", ["EV-0002"], "back")], evaluated_at="2026-09-11T11:00:00Z")
    assert (t1, t2, t3) == ("2026-09-10T10:00:00Z", "2026-09-11T10:00:00Z", "2026-09-11T11:00:00Z")

    latest = snaps.latest()
    assert set(latest) == {"CTL-A", "CTL-B"}
    assert latest["CTL-A"]["state"] == "PASS" and latest["CTL-A"]["evaluated_at"] == t3
    assert latest["CTL-A"]["evidence_ids"] == ["EV-0002"] and latest["CTL-A"]["trigger"] == "manual"
    assert latest["CTL-B"]["evaluated_at"] == t2 and latest["CTL-B"]["reason"] == "B is FAIL"

    history = snaps.history("CTL-A")
    assert [h["evaluated_at"] for h in history] == [t3, t2, t1]
    assert [h["state"] for h in history] == ["PASS", "DEGRADED", "PASS"]
    assert history[2]["trigger"] == "collector"
    assert [h["evaluated_at"] for h in snaps.history("CTL-A", since=t2)] == [t3, t2]
    assert [h["evaluated_at"] for h in snaps.history("CTL-A", limit=1)] == [t3]
    assert snaps.history("CTL-ZZZ") == []

    assert snaps.evaluations() == [t3, t2, t1]
    assert snaps.evaluations(limit=2) == [t3, t2]


def test_snapshot_record_defaults_to_now(engine):
    snaps = SnapshotStore(engine)
    stamp = snaps.record(_results())
    assert stamp.endswith("Z") and snaps.evaluations() == [stamp]
    assert snaps.latest()["CTL-B"]["state"] == "FAIL"


# -- collector runs ---------------------------------------------------------------

def test_runs_start_finish_list_latest(engine):
    runs = RunStore(engine)
    r1 = runs.start("github", trigger="schedule")
    r2 = runs.start("hris", started_by="alice")
    r3 = runs.start("github", trigger="api", started_by="ci")
    assert (r1, r2, r3) == (1, 2, 3)

    listed = runs.list()
    assert [r["id"] for r in listed] == [3, 2, 1]
    assert listed[0]["status"] == "running" and listed[0]["finished_at"] is None and listed[0]["records"] == 0
    assert listed[1]["started_by"] == "alice" and listed[1]["trigger"] == "manual"
    assert [r["id"] for r in runs.list(source_id="github")] == [3, 1]
    assert [r["id"] for r in runs.list(limit=1)] == [3]

    done = runs.finish(r1, "ok", records=12)
    assert done["status"] == "ok" and done["records"] == 12 and done["finished_at"].endswith("Z") and done["error"] is None
    failed = runs.finish(r3, "error", error="401 from api.github.com")
    assert failed["status"] == "error" and failed["error"] == "401 from api.github.com"
    with pytest.raises(KeyError):
        runs.finish(999, "ok")

    latest = runs.latest_by_source()
    assert set(latest) == {"github", "hris"}
    assert latest["github"]["id"] == 3 and latest["github"]["status"] == "error"
    assert latest["hris"]["id"] == 2 and latest["hris"]["status"] == "running"


# -- drafts -----------------------------------------------------------------------

def _draft(qid=None, **over):
    d = {
        "question": "Is customer data encrypted at rest?",
        "control_ids": ["CTL-CRYPTO-01"],
        "status": "READY",
        "answer": "Yes.",
        "reason": "",
        "citations": [{"id": "EV-0004", "source": "aws-config", "collected_at": T0}],
        "mode": "deterministic",
        "model_version": None,
        "created_by": "answer-agent",
    }
    if qid:
        d["question_id"] = qid
    d.update(over)
    return d


def test_next_question_id_starts_after_demo_queue(engine):
    drafts = DraftStore(engine)
    assert drafts.next_question_id() == "Q-4475"
    created = drafts.create(_draft())
    assert created["question_id"] == "Q-4475"
    assert drafts.next_question_id() == "Q-4476"
    drafts.create(_draft("Q-9000"))
    drafts.create(_draft("Q-legacy"))  # non-numeric suffixes are ignored
    assert drafts.next_question_id() == "Q-9001"


def test_draft_create_get_list_and_validation(engine):
    drafts = DraftStore(engine)
    a = drafts.create(_draft("Q-4475", created_at="2026-09-11T10:00:00Z"))
    b = drafts.create(_draft("Q-4476", created_at="2026-09-11T11:00:00Z", status="DECLINED", answer=""))
    assert a["created_at"] == "2026-09-11T10:00:00Z" and a["decision"] is None and a["signature"] is None
    assert drafts.get("Q-4475") == a
    assert drafts.get("Q-0000") is None
    assert [d["question_id"] for d in drafts.list()] == ["Q-4476", "Q-4475"]
    assert [d["question_id"] for d in drafts.list(limit=1)] == ["Q-4476"]
    c = drafts.create(_draft("Q-4477"))
    assert c["created_at"].endswith("Z")
    assert b["status"] == "DECLINED"
    with pytest.raises(ValueError, match="already exists"):
        drafts.create(_draft("Q-4475"))
    with pytest.raises(ValueError, match="unknown draft keys: gated"):
        drafts.create(_draft("Q-4478", gated=True))
    with pytest.raises(ValueError, match="missing required keys: question"):
        drafts.create({"status": "READY", "created_by": "x"})
    assert drafts.count_pending() == 3


def test_draft_decide_is_signed_and_final(engine):
    drafts = DraftStore(engine)
    drafts.create(_draft("Q-4475"))
    drafts.create(_draft("Q-4476"))
    decided = drafts.decide("Q-4475", "approve", "alice", "ab" * 32, "2026-09-11T12:00:00Z")
    assert decided["decision"] == "approve" and decided["approver"] == "alice"
    assert decided["signature"] == "ab" * 32 and decided["decided_at"] == "2026-09-11T12:00:00Z"
    assert drafts.get("Q-4475") == decided
    assert drafts.count_pending() == 1
    with pytest.raises(ValueError, match="already decided"):
        drafts.decide("Q-4475", "reject", "mallory", "00" * 32, "2026-09-11T13:00:00Z")
    with pytest.raises(KeyError):
        drafts.decide("Q-0000", "approve", "alice", "x", "2026-09-11T12:00:00Z")
    assert drafts.get("Q-4475")["approver"] == "alice"


# -- risk acceptances -------------------------------------------------------------

def test_acceptances_active_expired_revoked(engine):
    acc = AcceptanceStore(engine)
    live = acc.add("CTL-VENDOR-01", "s.vemula", "BAA execution in progress", "2026-10-31", "admin")
    expired = acc.add("CTL-NET-01", "ops", "WAF migration", "2026-09-01", "admin")
    doomed = acc.add("CTL-LOG-01", "ops", "temporary", "2026-12-31", "admin")
    assert live["id"] == 1 and live["created_at"].endswith("Z") and live["revoked_at"] is None
    assert [a["id"] for a in acc.all()] == [1, 2, 3]

    assert [a["id"] for a in acc.active("2026-09-11")] == [1, 3]
    assert [a["id"] for a in acc.active("2026-09-01")] == [1, 2, 3]   # expiry day still counts
    assert [a["id"] for a in acc.active("2026-11-01")] == [3]

    revoked = acc.revoke(doomed["id"], "2026-09-11T09:00:00Z")
    assert revoked["revoked_at"] == "2026-09-11T09:00:00Z"
    assert [a["id"] for a in acc.active("2026-09-11")] == [1]
    assert acc.revoke(doomed["id"], "2026-09-12T09:00:00Z")["revoked_at"] == "2026-09-11T09:00:00Z"  # first wins
    with pytest.raises(KeyError):
        acc.revoke(999, "2026-09-11T09:00:00Z")
    assert expired["expires"] == "2026-09-01"


def test_acceptance_dates_are_validated(engine):
    acc = AcceptanceStore(engine)
    with pytest.raises(ValueError):
        acc.add("CTL-X", "o", "r", "31/10/2026", "admin")
    with pytest.raises(ValueError):
        acc.active("2026-9-11")
    assert acc.all() == []
