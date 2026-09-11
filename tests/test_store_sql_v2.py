"""Schema v2 stores: questionnaires, the drafts link to them, notifications, package exports."""
from __future__ import annotations

import threading

import pytest
from sqlalchemy.exc import IntegrityError

from attest.db import get_engine, upgrade
from attest.store_sql import DraftStore, NotificationStore, PackageStore, QuestionnaireStore

T0 = "2026-09-09T10:00:00Z"


@pytest.fixture
def engine(tmp_path):
    url = f"sqlite:///{tmp_path / 'attest.db'}"
    upgrade(url)
    engine = get_engine(url)
    yield engine
    engine.dispose()


def _draft(qid=None, **over):
    d = {"question": "Encrypted at rest?", "control_ids": ["CTL-CRYPTO-01"], "status": "READY", "answer": "Yes.",
         "reason": "", "citations": [{"id": "EV-0004", "source": "aws-config", "collected_at": T0}],
         "mode": "deterministic", "model_version": None, "created_by": "answer-agent"}
    if qid:
        d["question_id"] = qid
    d.update(over)
    return d


# -- questionnaires -----------------------------------------------------------------

def test_questionnaire_ids_create_get_list(engine):
    qs = QuestionnaireStore(engine)
    assert qs.next_id() == "QN-0001"
    a = qs.create("Acme vendor review", "acme.xlsx", "s.vemula@attest.internal", 12)
    assert a["id"] == "QN-0001" and a["status"] == "open" and a["row_count"] == 12
    assert a["name"] == "Acme vendor review" and a["source_file"] == "acme.xlsx" and a["created_at"].endswith("Z")
    b = qs.create("  Northwind  ", "", "s.vemula@attest.internal", 3)
    assert b["id"] == "QN-0002" and b["name"] == "Northwind" and b["source_file"] == ""
    assert qs.next_id() == "QN-0003"
    assert qs.get("QN-0001") == a
    assert qs.get("QN-9999") is None
    listed = qs.list()
    assert [q["id"] for q in listed] == ["QN-0002", "QN-0001"]  # newest first; same-second ties by id
    assert [q["id"] for q in qs.list(limit=1)] == ["QN-0002"]


def test_questionnaire_status_and_validation(engine):
    qs = QuestionnaireStore(engine)
    a = qs.create("Acme", "acme.csv", "admin", 1)
    done = qs.set_status(a["id"], "exported")
    assert done["status"] == "exported" and qs.get(a["id"])["status"] == "exported"
    with pytest.raises(ValueError, match="status must be one of"):
        qs.set_status(a["id"], "closed")
    with pytest.raises(KeyError):
        qs.set_status("QN-4242", "exported")
    with pytest.raises(ValueError, match="name"):
        qs.create("   ", "x.csv", "admin", 0)
    assert qs.next_id() == "QN-0002"


def test_questionnaire_ids_are_unique_under_concurrent_creates(engine):
    qs = QuestionnaireStore(engine)
    errors: list[str] = []

    def worker(n):
        try:
            for i in range(5):
                qs.create(f"qn-{n}-{i}", "f.csv", "t", 1)
        except Exception as exc:  # pragma: no cover
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    ids = [q["id"] for q in qs.list()]
    assert len(ids) == 20 and len(set(ids)) == 20 and qs.next_id() == "QN-0021"


# -- drafts <-> questionnaires ----------------------------------------------------------

def test_drafts_link_to_a_questionnaire_and_list_in_import_order(engine):
    qs, drafts = QuestionnaireStore(engine), DraftStore(engine)
    qn = qs.create("Acme", "acme.csv", "admin", 3)
    other = qs.create("Other", "o.csv", "admin", 1)
    a = drafts.create(_draft("Q-4475", created_at="2026-09-11T10:00:00Z"), questionnaire_id=qn["id"])
    b = drafts.create(_draft("Q-4476", created_at="2026-09-11T10:00:00Z", questionnaire_id=qn["id"]))  # as a key works too
    c = drafts.create(_draft("Q-4477", created_at="2026-09-11T09:00:00Z"), questionnaire_id=qn["id"])
    loose = drafts.create(_draft("Q-4478"))
    drafts.create(_draft("Q-4479"), questionnaire_id=other["id"])
    assert a["questionnaire_id"] == qn["id"] and b["questionnaire_id"] == qn["id"] and loose["questionnaire_id"] is None
    assert a["ref"] is None
    assert [d["question_id"] for d in drafts.list_for_questionnaire(qn["id"])] == ["Q-4477", "Q-4475", "Q-4476"]
    assert [d["question_id"] for d in drafts.list_for_questionnaire(other["id"])] == ["Q-4479"]
    assert drafts.list_for_questionnaire("QN-9999") == []
    assert len(drafts.list()) == 5 and drafts.count_pending() == 5
    assert c["questionnaire_id"] == qn["id"]


def test_draft_questionnaire_id_must_reference_a_questionnaire(engine):
    with pytest.raises(IntegrityError):
        DraftStore(engine).create(_draft("Q-4475"), questionnaire_id="QN-0042")
    assert DraftStore(engine).get("Q-4475") is None


def test_draft_ref_is_set_after_drafting_and_survives_the_decision(engine):
    drafts = DraftStore(engine)
    drafts.create(_draft("Q-4475"))
    row = drafts.set_ref("Q-4475", "3.2.1")
    assert row["ref"] == "3.2.1" and drafts.get("Q-4475")["ref"] == "3.2.1"
    decided = drafts.decide("Q-4475", "approve", "alice", "ab" * 32, "2026-09-11T12:00:00Z")
    assert decided["ref"] == "3.2.1" and decided["decision"] == "approve"
    assert drafts.set_ref("Q-4475", None)["ref"] is None
    with pytest.raises(KeyError):
        drafts.set_ref("Q-0000", "x")


# -- notifications --------------------------------------------------------------------

def test_notification_record_is_idempotent_on_dedupe_key(engine):
    ns = NotificationStore(engine)
    assert ns.already_sent("CTL-VENDOR-01:FAIL:2026-09-11") is False
    first = ns.record("CTL-VENDOR-01", "FAIL", "CTL-VENDOR-01:FAIL:2026-09-11", "jira", "sent",
                      detail="SEC-118 created", external_id="SEC-118", owner="vendors@example.com", due="2026-09-25")
    assert first["id"] == 1 and first["external_id"] == "SEC-118" and first["due"] == "2026-09-25"
    assert first["sent_at"].endswith("Z") and first["status"] == "sent"
    assert ns.already_sent("CTL-VENDOR-01:FAIL:2026-09-11") is True
    again = ns.record("CTL-VENDOR-01", "FAIL", "CTL-VENDOR-01:FAIL:2026-09-11", "slack", "error", detail="would be a duplicate")
    assert again == first  # the first delivery is the record; nothing was inserted
    assert len(ns.recent()) == 1


def test_notification_recent_is_newest_first_and_limited(engine):
    ns = NotificationStore(engine)
    for i in range(4):
        ns.record("CTL-X", "DEGRADED", f"k-{i}", "slack", "sent" if i % 2 == 0 else "skipped", detail=str(i))
    assert [n["dedupe_key"] for n in ns.recent()] == ["k-3", "k-2", "k-1", "k-0"]
    assert [n["dedupe_key"] for n in ns.recent(limit=2)] == ["k-3", "k-2"]
    assert [n["status"] for n in ns.recent(limit=None)] == ["skipped", "sent", "skipped", "sent"]
    finding = ns.record("CTL-ACCESS-02", "finding", "join:leaver@example.com", "email", "sent", owner="hr@example.com")
    assert finding["kind"] == "finding" and finding["target"] == "email" and finding["external_id"] is None
    assert ns.recent()[0]["dedupe_key"] == "join:leaver@example.com"


def test_notification_validation(engine):
    ns = NotificationStore(engine)
    with pytest.raises(ValueError, match="kind"):
        ns.record("CTL-X", "PASS", "k", "slack", "sent")
    with pytest.raises(ValueError, match="target"):
        ns.record("CTL-X", "FAIL", "k", "pager", "sent")
    with pytest.raises(ValueError, match="status"):
        ns.record("CTL-X", "FAIL", "k", "slack", "queued")
    with pytest.raises(ValueError, match="dedupe_key"):
        ns.record("CTL-X", "FAIL", "", "slack", "sent")
    with pytest.raises(ValueError, match="due"):
        ns.record("CTL-X", "FAIL", "k", "slack", "sent", due="25/09/2026")
    assert ns.recent() == []


def test_notification_concurrent_same_key_yields_one_row(engine):
    ns = NotificationStore(engine)
    results: list[dict] = []
    lock = threading.Lock()

    def worker(n):
        row = ns.record("CTL-LOG-01", "FAIL", "same-key", "slack", "sent", detail=f"writer {n}")
        with lock:
            results.append(row)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 8 and len({r["id"] for r in results}) == 1
    assert len(ns.recent()) == 1


# -- package exports ------------------------------------------------------------------

def test_package_record_and_list(engine):
    ps = PackageStore(engine)
    manifest = {"format": "attest-package/1", "files": {"controls.json": "ab" * 32}, "signature": "cd" * 32}
    a = ps.record("j.okafor@auditfirm.example", "soc2", "2026-07-01", "/exports/soc2.zip", "11" * 32, manifest)
    b = ps.record("admin", None, None, "/exports/all.zip", "22" * 32, {"format": "attest-package/1"})
    assert a["id"] == 1 and a["framework"] == "soc2" and a["since"] == "2026-07-01" and a["manifest"] == manifest
    assert a["created_at"].endswith("Z") and a["path"] == "/exports/soc2.zip" and a["sha256"] == "11" * 32
    assert b["framework"] is None and b["since"] is None
    assert [p["id"] for p in ps.list()] == [2, 1]
    assert [p["id"] for p in ps.list(limit=1)] == [2]
    with pytest.raises(ValueError, match="sha256"):
        ps.record("admin", None, None, "/x.zip", "short", {})
    with pytest.raises(TypeError):
        ps.record("admin", None, None, "/x.zip", "33" * 32, {"bad": object()})
    assert len(ps.list()) == 2
