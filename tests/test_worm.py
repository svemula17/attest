"""WORM audit export: the JSONL + proof pair, and the S3 Object Lock upload (with a fake client)."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import text

from attest.audit import AuditLog
from attest.config import default_config_toml, parse_config
from attest.db import get_engine, upgrade
from attest.service import Service
from attest.store_sql import SqlAuditLog
from attest.worm import PROOF_FORMAT, export_audit, parse_bucket_uri, proof_path, upload_worm


@pytest.fixture
def engine(tmp_path):
    url = f"sqlite:///{tmp_path / 'attest.db'}"
    upgrade(url)
    engine = get_engine(url)
    yield engine
    engine.dispose()


@pytest.fixture
def sandbox(tmp_path):
    cfg_path = tmp_path / "attest.toml"
    cfg_path.write_text(default_config_toml(mode="sandbox", storage_url=f"sqlite:///{tmp_path / 'attest.db'}"))
    cfg = parse_config(cfg_path.read_text(), path=cfg_path)
    upgrade(cfg.storage.url)
    engine = get_engine(cfg.storage.url)
    svc = Service(cfg, engine)
    svc.reseed()
    yield svc
    engine.dispose()


class FakeS3:
    """Records put_object calls the way boto3's client would receive them."""

    def __init__(self, fail_on: str | None = None):
        self.calls: list[dict] = []
        self.fail_on = fail_on

    def put_object(self, **kwargs):
        if self.fail_on and kwargs["Key"].endswith(self.fail_on):
            raise RuntimeError("AccessDenied")
        self.calls.append(kwargs)
        return {"ETag": '"x"', "ChecksumSHA256": "y"}


def _stored_digests(engine) -> list[str]:
    with engine.connect() as conn:
        return [r[0] for r in conn.execute(text("SELECT sha256 FROM audit ORDER BY seq"))]


# -- export ------------------------------------------------------------------------------

def test_export_writes_every_entry_and_a_proof_bound_to_the_chain(engine, tmp_path):
    log = SqlAuditLog(engine)
    e1 = log.record("answer-agent", "draft", "Q-1", model_version="answer-agent v0.4.2", detail="READY")
    e2 = log.record("alice", "approve", "Q-1", approver="alice", rule="four-eyes")
    e3 = log.record("system", "boot", "attest")
    out = tmp_path / "exports" / "audit.jsonl"
    proof = export_audit(log, out)

    lines = out.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line) for line in lines] == [asdict(e1), asdict(e2), asdict(e3)]
    assert proof["path"] == str(out) and proof["proof_path"] == str(out) + ".proof.json" and proof_path(out).is_file()
    on_disk = json.loads(proof_path(out).read_text())
    assert on_disk == {k: v for k, v in proof.items() if k not in ("path", "proof_path")}
    assert on_disk["format"] == PROOF_FORMAT and on_disk["file"] == "audit.jsonl" and on_disk["since"] is None
    assert on_disk["count"] == on_disk["total"] == 3
    assert on_disk["first_ts"] == e1.ts and on_disk["last_ts"] == e3.ts
    assert on_disk["last_sha256"] == _stored_digests(engine)[-1]  # recomputed digest == the table's chain
    assert on_disk["chain_verified"] is True
    assert on_disk["sha256_of_file"] == hashlib.sha256(out.read_bytes()).hexdigest()
    assert on_disk["exported_at"].endswith("Z")


def test_export_since_keeps_the_digest_of_the_last_exported_entry(engine, tmp_path, monkeypatch):
    log = SqlAuditLog(engine)
    stamps = iter(["2026-09-01T00:00:00Z", "2026-09-05T00:00:00Z", "2026-09-10T00:00:00Z"])
    monkeypatch.setattr("attest.store_sql.now_iso", lambda: next(stamps))
    log.record("a", "one", "s")
    log.record("b", "two", "s")
    log.record("c", "three", "s")
    out = tmp_path / "since.jsonl"
    proof = export_audit(log, out, since="2026-09-05")
    entries = [json.loads(line) for line in out.read_text().splitlines()]
    assert [e["action"] for e in entries] == ["two", "three"]
    assert proof["count"] == 2 and proof["total"] == 3 and proof["since"] == "2026-09-05"
    assert proof["first_ts"] == "2026-09-05T00:00:00Z" and proof["last_ts"] == "2026-09-10T00:00:00Z"
    assert proof["last_sha256"] == _stored_digests(engine)[-1]
    nothing = export_audit(log, tmp_path / "none.jsonl", since="2027-01-01")
    assert nothing["count"] == 0 and nothing["first_ts"] is None and nothing["last_sha256"] is None
    assert (tmp_path / "none.jsonl").read_bytes() == b""
    with pytest.raises(ValueError, match="since"):
        export_audit(log, tmp_path / "bad.jsonl", since="last week")


def test_export_reports_a_tampered_chain(engine, tmp_path):
    log = SqlAuditLog(engine)
    log.record("a", "x", "s1")
    log.record("b", "y", "s2")
    with engine.begin() as conn:
        conn.execute(text("UPDATE audit SET detail = 'edited' WHERE seq = 1"))
    proof = export_audit(log, tmp_path / "audit.jsonl")
    assert proof["chain_verified"] is False and proof["count"] == 2
    assert proof["last_sha256"] != _stored_digests(engine)[-1]  # the recomputed chain diverges from the stored one


def test_export_from_the_jsonl_log_has_no_chain_verdict(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("a", "x", "s")
    proof = export_audit(log, tmp_path / "out" / "audit.jsonl")
    assert proof["count"] == 1 and proof["chain_verified"] is None and len(proof["last_sha256"]) == 64


# -- upload ------------------------------------------------------------------------------

def test_upload_locks_both_files_in_compliance_mode(engine, tmp_path):
    log = SqlAuditLog(engine)
    log.record("a", "x", "s")
    out = tmp_path / "audit-2026-09-11.jsonl"
    export_audit(log, out)
    fake = FakeS3()
    before = datetime.now(timezone.utc)
    res = upload_worm(out, "s3://compliance-worm/attest/prod/", 365, client=fake)
    after = datetime.now(timezone.utc)

    assert res["bucket"] == "compliance-worm" and res["mode"] == "COMPLIANCE" and res["retain_days"] == 365
    assert res["keys"] == ["attest/prod/audit-2026-09-11.jsonl", "attest/prod/audit-2026-09-11.jsonl.proof.json"]
    assert [c["Key"] for c in fake.calls] == res["keys"]
    for call, path in zip(fake.calls, (out, proof_path(out))):
        assert call["Bucket"] == "compliance-worm"
        assert call["Body"] == path.read_bytes()
        assert call["ObjectLockMode"] == "COMPLIANCE"
        assert call["ChecksumAlgorithm"] == "SHA256"
        until = call["ObjectLockRetainUntilDate"]
        assert until.tzinfo is not None
        assert before + timedelta(days=365) <= until <= after + timedelta(days=365)
        assert set(call) == {"Bucket", "Key", "Body", "ObjectLockMode", "ObjectLockRetainUntilDate", "ChecksumAlgorithm"}
    assert res["retain_until"] == fake.calls[0]["ObjectLockRetainUntilDate"].strftime("%Y-%m-%dT%H:%M:%SZ")


def test_upload_without_a_prefix_and_input_validation(engine, tmp_path):
    log = SqlAuditLog(engine)
    log.record("a", "x", "s")
    out = tmp_path / "audit.jsonl"
    export_audit(log, out)
    fake = FakeS3()
    assert upload_worm(out, "s3://bucket-only", 30, client=fake)["keys"] == ["audit.jsonl", "audit.jsonl.proof.json"]
    assert parse_bucket_uri("s3://b/p/q/") == ("b", "p/q") and parse_bucket_uri("s3://b") == ("b", "")
    for bad in ("compliance-worm/attest", "s3:///prefix", "https://bucket.s3.amazonaws.com", ""):
        with pytest.raises(ValueError):
            upload_worm(out, bad, 30, client=fake)
    with pytest.raises(ValueError, match="retain_days"):
        upload_worm(out, "s3://b/p", 0, client=fake)
    with pytest.raises(FileNotFoundError):
        upload_worm(tmp_path / "missing.jsonl", "s3://b/p", 30, client=fake)
    proof_path(out).unlink()
    with pytest.raises(FileNotFoundError, match="proof"):
        upload_worm(out, "s3://b/p", 30, client=fake)
    assert len(fake.calls) == 2  # only the one good upload went through


def test_upload_uses_boto3_when_no_client_is_given(engine, tmp_path, monkeypatch):
    import boto3
    log = SqlAuditLog(engine)
    log.record("a", "x", "s")
    out = tmp_path / "audit.jsonl"
    export_audit(log, out)
    fake = FakeS3()
    seen = []
    monkeypatch.setattr(boto3, "client", lambda name, **kw: (seen.append(name), fake)[1])
    res = upload_worm(out, "s3://b/p", 7)
    assert seen == ["s3"] and len(fake.calls) == 2 and res["keys"][0] == "p/audit.jsonl"


# -- CLI ----------------------------------------------------------------------------------

def _cli(*argv: str) -> int:
    from attest.cli_product import register
    p = argparse.ArgumentParser()
    p.add_argument("--config")
    p.add_argument("--data", type=Path, default=Path("data"))
    sub = p.add_subparsers(dest="cmd", required=True)
    register(sub)
    args = p.parse_args(list(argv))
    return args.fn(args)


def test_cli_audit_export_writes_proof_and_uploads_when_asked(sandbox, tmp_path, capsys, monkeypatch):
    import boto3
    cfg = str(sandbox.cfg.path)
    out = tmp_path / "audit.jsonl"
    total = len(sandbox.audit.all())
    assert _cli("--config", cfg, "audit-export", "--out", str(out)) == 0
    text = capsys.readouterr().out
    assert f"wrote {out} ({total} of {total} entries)" in text and "audit chain intact" in text and "proof" in text
    assert proof_path(out).is_file() and len(out.read_text().splitlines()) == total
    latest = sandbox.audit.query(limit=1)[0]
    assert latest.action == "audit.exported" and latest.subject == "audit.jsonl" and "s3://" not in latest.detail

    fake = FakeS3()
    monkeypatch.setattr(boto3, "client", lambda name, **kw: fake)
    assert _cli("--config", cfg, "audit-export", "--out", str(out), "--s3", "s3://compliance-worm/attest", "--retain-days", "90") == 0
    text = capsys.readouterr().out
    assert "uploaded s3://compliance-worm/attest/audit.jsonl and its proof · Object Lock COMPLIANCE until" in text and "(90 days)" in text
    assert [c["Key"] for c in fake.calls] == ["attest/audit.jsonl", "attest/audit.jsonl.proof.json"]
    assert all(c["ObjectLockMode"] == "COMPLIANCE" for c in fake.calls)
    assert "s3://compliance-worm/attest/audit.jsonl locked until" in sandbox.audit.query(limit=1)[0].detail

    failing = FakeS3(fail_on="audit.jsonl")
    monkeypatch.setattr(boto3, "client", lambda name, **kw: failing)
    assert _cli("--config", cfg, "audit-export", "--out", str(out), "--s3", "s3://compliance-worm/attest") == 1
    assert "upload to s3://compliance-worm/attest failed: AccessDenied" in capsys.readouterr().out
    assert _cli("--config", cfg, "audit-export", "--out", str(out), "--since", "soon") == 2
    assert "since must be" in capsys.readouterr().out


def test_cli_audit_export_reads_the_bucket_from_config(sandbox, tmp_path, capsys, monkeypatch):
    import boto3
    cfg_path = sandbox.cfg.path
    cfg_path.write_text(cfg_path.read_text().replace('# audit_worm_bucket = "s3://compliance-worm/attest"',
                                                     'audit_worm_bucket = "s3://from-config/audit"\naudit_worm_retain_days = 400'))
    fake = FakeS3()
    monkeypatch.setattr(boto3, "client", lambda name, **kw: fake)
    out = tmp_path / "a.jsonl"
    assert _cli("--config", str(cfg_path), "audit-export", "--out", str(out)) == 0
    assert "(400 days)" in capsys.readouterr().out
    assert fake.calls[0]["Bucket"] == "from-config" and fake.calls[0]["Key"] == "audit/a.jsonl"
