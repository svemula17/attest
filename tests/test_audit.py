import dataclasses
import json
import re

from attest.audit import AuditEntry, AuditLog
from attest.util import parse_iso

ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _log(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


def test_creates_file_if_missing(tmp_path):
    path = tmp_path / "nested" / "audit.jsonl"
    log = AuditLog(path)
    assert path.exists()
    assert log.all() == []


def test_record_all_roundtrip(tmp_path):
    log = _log(tmp_path)
    e1 = log.record("answer-agent", "draft", "Q-1", model_version="answer-agent v0.4.2", detail="READY")
    e2 = log.record("alice", "approve", "Q-1", approver="bob", rule="four-eyes", detail="ok")
    assert isinstance(e1, AuditEntry)
    assert log.all() == [e1, e2]
    assert e1.actor == "answer-agent" and e1.action == "draft" and e1.subject == "Q-1"
    assert e1.model_version == "answer-agent v0.4.2" and e1.detail == "READY"
    assert e2.approver == "bob" and e2.rule == "four-eyes"


def test_defaults_are_none_and_empty_detail(tmp_path):
    e = _log(tmp_path).record("system", "boot", "attest")
    assert e.model_version is None and e.approver is None and e.rule is None
    assert e.detail == ""


def test_ts_is_iso_utc(tmp_path):
    e = _log(tmp_path).record("system", "boot", "attest")
    assert ISO_RE.match(e.ts)
    assert parse_iso(e.ts).utcoffset().total_seconds() == 0


def test_reopened_log_reads_entries_from_disk(tmp_path):
    path = tmp_path / "audit.jsonl"
    first = AuditLog(path)
    e1 = first.record("a", "x", "s1")
    e2 = first.record("b", "y", "s2", rule="r")
    reopened = AuditLog(path)
    assert reopened.all() == [e1, e2]
    e3 = reopened.record("c", "z", "s3")
    assert reopened.all() == [e1, e2, e3]
    assert AuditLog(path).all() == [e1, e2, e3]


def test_on_disk_format_is_jsonl(tmp_path):
    log = _log(tmp_path)
    e1 = log.record("a", "x", "s1")
    log.record("b", "y", "s2")
    lines = log.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == dataclasses.asdict(e1)


def test_entries_are_frozen(tmp_path):
    import pytest

    e = _log(tmp_path).record("a", "x", "s1")
    with pytest.raises(dataclasses.FrozenInstanceError):
        e.actor = "mallory"


def test_log_has_no_mutating_methods():
    public = [name for name in dir(AuditLog) if not name.startswith("_")]
    assert public == sorted(["all", "record"])
