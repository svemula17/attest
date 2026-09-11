"""Auditor evidence packages: contents, digests, signature, tampering, scope filters, and the CLI."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from attest.auth import SYSTEM
from attest.config import default_config_toml, parse_config
from attest.controls import FRAMEWORKS
from attest.db import get_engine, upgrade
from attest.packages import (FORMAT, MANIFEST, build_package, manifest_signing_bytes, package_signer, validate_since,
                             verify_package)
from attest.service import Service
from attest.store_sql import PackageStore

FILES = {"manifest.json", "controls.json", "controls.csv", "posture.json", "evidence.jsonl", "chain.json", "audit.jsonl",
         "acceptances.json", "README.txt"}


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


def _read(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as zf:
        return {name: zf.read(name) for name in zf.namelist()}


def _rewrite(path: Path, replace: dict[str, bytes | None], add: dict[str, bytes] | None = None) -> None:
    """Rewrite the zip with some members replaced (None = dropped) and some added: the tampering primitive."""
    files = _read(path)
    for name, data in replace.items():
        if data is None:
            files.pop(name)
        else:
            files[name] = data
    files.update(add or {})
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)


def _days_ago(n: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=n)).strftime("%Y-%m-%d")


# -- build -----------------------------------------------------------------------------

def test_package_contents_and_manifest(sandbox, tmp_path):
    out = tmp_path / "exports" / "all.zip"
    manifest = build_package(sandbox, out, created_by="j.okafor@auditfirm.example")
    files = _read(out)
    assert set(files) == FILES
    assert json.loads(files[MANIFEST]) == manifest
    assert manifest["format"] == FORMAT and manifest["generated_by"] == "j.okafor@auditfirm.example"
    assert manifest["framework"] is None and manifest["since"] is None and manifest["include_restricted"] is False
    assert set(manifest["files"]) == FILES - {MANIFEST}
    for name, digest in manifest["files"].items():
        assert hashlib.sha256(files[name]).hexdigest() == digest, name
    assert len(manifest["signature"]) == 64 and manifest["chain_verified"] is True

    controls = json.loads(files["controls.json"])
    assert {c["id"] for c in controls} == set(sandbox.catalog)
    vendor = next(c for c in controls if c["id"] == "CTL-VENDOR-01")
    assert vendor["state"] == "FAIL" and vendor["citations"] == {"soc2": ["CC9.2"], "iso27001": ["A.5.19"], "hipaa": ["164.314(a)"]}
    assert vendor["hipaa_spec"] == "required" and "baa.executed" in vendor["required_kinds"]
    counts = manifest["counts"]
    assert counts["controls"] == len(controls) and counts["states"]["FAIL"] == 1
    assert counts["states"]["PASS"] + counts["states"]["DEGRADED"] + counts["states"]["FAIL"] == counts["controls"]

    csv_lines = files["controls.csv"].decode().splitlines()
    assert csv_lines[0] == "id,name,state,reason,evidence_ids,soc2,iso27001,hipaa,hipaa_spec"
    assert len(csv_lines) == len(controls) + 1
    assert any(line.startswith("CTL-VENDOR-01,Subprocessor agreements,FAIL,") and ",CC9.2,A.5.19,164.314(a),required" in line for line in csv_lines)

    posture = json.loads(files["posture.json"])
    assert set(posture) == set(FRAMEWORKS) and counts["posture_rows"] == sum(len(v) for v in posture.values())
    assert posture["hipaa"] == sandbox.controls.posture("hipaa")

    evidence = [json.loads(line) for line in files["evidence.jsonl"].decode().splitlines()]
    records = sandbox.store.all()
    assert counts["evidence"] == len(evidence) == sum(1 for r in records if r.classification != "restricted")
    assert counts["evidence_total"] == len(records) and all(e["classification"] != "restricted" for e in evidence)
    assert [e["id"] for e in evidence] == [r.id for r in records if r.classification != "restricted"]  # ledger order
    assert set(evidence[0]) == {"id", "source", "kind", "control_ids", "classification", "collected_at", "payload", "sha256", "prev_sha256"}

    chain = json.loads(files["chain.json"])
    assert chain == dict(count=len(records), first_id=records[0].id, last_id=records[-1].id, last_sha256=records[-1].sha256,
                         exported=len(evidence), verified=True)

    audit = [json.loads(line) for line in files["audit.jsonl"].decode().splitlines()]
    assert audit and counts["audit"] == len(audit)
    assert not any(a["action"].startswith("guardrail.") for a in audit)
    assert [a["ts"] for a in audit] == sorted(a["ts"] for a in audit)  # oldest first
    assert set(audit[0]) == {"ts", "actor", "model_version", "action", "subject", "approver", "rule", "detail"}

    assert json.loads(files["acceptances.json"]) == sandbox.acceptances.all() == []
    readme = files["README.txt"].decode()
    assert "attest package-verify" in readme and "HMAC-SHA256" in readme and "j.okafor@auditfirm.example" in readme
    assert PackageStore(sandbox.engine).list() == []  # build_package records nothing; Service.build_package does


def test_acceptances_and_audit_scope_are_included(sandbox, tmp_path):
    sandbox.acceptances.add("CTL-VENDOR-01", "s.vemula", "BAA execution in progress", "2026-12-31", "admin")
    out = tmp_path / "p.zip"
    manifest = build_package(sandbox, out)
    files = _read(out)
    acc = json.loads(files["acceptances.json"])
    assert len(acc) == 1 and acc[0]["control_id"] == "CTL-VENDOR-01" and manifest["counts"]["acceptances"] == 1


# -- verify ------------------------------------------------------------------------------

def test_verify_accepts_an_untouched_package_and_rejects_a_foreign_key(sandbox, tmp_path):
    out = tmp_path / "p.zip"
    manifest = build_package(sandbox, out)
    assert verify_package(out, sandbox.sign_bytes) == (True, [])
    assert sandbox.sign_bytes(manifest_signing_bytes(manifest)) == manifest["signature"]
    ok, problems = verify_package(out, lambda data: "00" * 32)
    assert ok is False and problems == ["manifest.json: signature does not verify with this installation's key"]


@pytest.mark.parametrize("name", ["controls.csv", "evidence.jsonl", "audit.jsonl", "README.txt"])
def test_tampering_a_file_inside_the_zip_fails_verification(sandbox, tmp_path, name):
    out = tmp_path / "p.zip"
    build_package(sandbox, out)
    original = _read(out)[name]
    _rewrite(out, {name: original + b"\n# edited after signing\n"})
    ok, problems = verify_package(out, sandbox.sign_bytes)
    assert ok is False
    assert len(problems) == 1 and problems[0].startswith(f"{name}: sha256 ") and "does not match the manifest" in problems[0]


def test_editing_the_manifest_breaks_the_signature_and_removing_or_adding_files_is_reported(sandbox, tmp_path):
    out = tmp_path / "p.zip"
    manifest = build_package(sandbox, out)
    edited = dict(manifest, generated_by="mallory")  # re-attributed, signature untouched
    _rewrite(out, {MANIFEST: json.dumps(edited).encode()})
    ok, problems = verify_package(out, sandbox.sign_bytes)
    assert ok is False and problems == ["manifest.json: signature does not verify with this installation's key"]

    build_package(sandbox, out)
    _rewrite(out, {"acceptances.json": None}, add={"notes.txt": b"added later"})
    ok, problems = verify_package(out, sandbox.sign_bytes)
    assert ok is False
    assert "acceptances.json: listed in the manifest but missing from the package" in problems
    assert "notes.txt: present in the package but not listed in the manifest" in problems

    # a file whose digest was 'fixed' in the manifest still fails: the signature covers the digests
    build_package(sandbox, out)
    files = _read(out)
    forged = json.loads(files[MANIFEST])
    forged["files"]["controls.csv"] = hashlib.sha256(b"forged").hexdigest()
    _rewrite(out, {"controls.csv": b"forged", MANIFEST: json.dumps(forged).encode()})
    ok, problems = verify_package(out, sandbox.sign_bytes)
    assert ok is False and problems == ["manifest.json: signature does not verify with this installation's key"]


def test_verify_rejects_non_packages(tmp_path):
    missing = tmp_path / "nope.zip"
    assert verify_package(missing, lambda b: "x")[0] is False
    not_zip = tmp_path / "text.zip"
    not_zip.write_text("hello")
    assert verify_package(not_zip, lambda b: "x") == (False, ["text.zip: not a zip file"])
    empty = tmp_path / "empty.zip"
    with zipfile.ZipFile(empty, "w") as zf:
        zf.writestr("README.txt", "no manifest")
    assert verify_package(empty, lambda b: "x") == (False, ["manifest.json: missing from the package"])
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr(MANIFEST, "{not json")
    assert verify_package(bad, lambda b: "x") == (False, ["manifest.json: not valid JSON"])
    wrong = tmp_path / "wrong.zip"
    with zipfile.ZipFile(wrong, "w") as zf:
        zf.writestr(MANIFEST, json.dumps({"format": "other/9", "files": {}, "signature": ""}))
    ok, problems = verify_package(wrong, lambda b: "x")
    assert ok is False and any("format is 'other/9'" in p for p in problems) and any("no 'files'" in p for p in problems)
    assert any("no signature" in p for p in problems)


# -- filters -----------------------------------------------------------------------------

def test_since_filters_evidence_and_audit(sandbox, tmp_path):
    since = _days_ago(20)  # the seeded access review is 41 days old; everything else is younger
    out = tmp_path / "recent.zip"
    manifest = build_package(sandbox, out, since=since)
    files = _read(out)
    evidence = [json.loads(line) for line in files["evidence.jsonl"].decode().splitlines()]
    all_records = [r for r in sandbox.store.all() if r.classification != "restricted"]
    old = [r for r in all_records if r.collected_at < since]
    assert len(old) == 1 and old[0].kind == "access-review.quarterly"
    assert [e["id"] for e in evidence] == [r.id for r in all_records if r.collected_at >= since]
    assert manifest["since"] == since and manifest["counts"]["evidence"] == len(all_records) - 1
    assert json.loads(files["chain.json"])["count"] == len(sandbox.store.all())  # the ledger, not the subset
    audit = [json.loads(line) for line in files["audit.jsonl"].decode().splitlines()]
    assert audit and all(a["ts"] >= since for a in audit)

    future = _days_ago(-1)
    manifest = build_package(sandbox, tmp_path / "none.zip", since=future)
    assert manifest["counts"]["evidence"] == 0 and manifest["counts"]["audit"] == 0
    assert verify_package(tmp_path / "none.zip", sandbox.sign_bytes) == (True, [])

    with pytest.raises(ValueError, match="since"):
        build_package(sandbox, tmp_path / "bad.zip", since="20/07/2026")
    with pytest.raises(ValueError, match="calendar"):
        validate_since("2026-02-30")
    assert validate_since(None) is None and validate_since("2026-07-01") == "2026-07-01"
    assert validate_since("2026-07-01T12:00:00Z") == "2026-07-01T12:00:00Z"


def test_framework_filter_scopes_controls_posture_and_evidence(sandbox, tmp_path):
    out = tmp_path / "hipaa.zip"
    manifest = build_package(sandbox, out, framework="hipaa")
    files = _read(out)
    controls = json.loads(files["controls.json"])
    expected = {c.id for c in sandbox.catalog.values() if c.mappings.get("hipaa")}
    assert {c["id"] for c in controls} == expected and "CTL-NET-01" not in expected and "CTL-CRYPTO-01" in expected
    assert all(c["citations"]["hipaa"] for c in controls)
    assert set(json.loads(files["posture.json"])) == {"hipaa"}
    evidence = [json.loads(line) for line in files["evidence.jsonl"].decode().splitlines()]
    assert evidence and all(set(e["control_ids"]) & expected for e in evidence)
    assert not any(e["kind"] == "waf.enabled" for e in evidence)  # CTL-NET-01 only: not HIPAA-mapped
    assert manifest["framework"] == "hipaa" and manifest["counts"]["controls"] == len(expected)
    assert verify_package(out, sandbox.sign_bytes) == (True, [])
    with pytest.raises(ValueError, match="unknown framework"):
        build_package(sandbox, tmp_path / "x.zip", framework="pci")


def test_restricted_evidence_is_excluded_unless_asked_for(sandbox, tmp_path):
    restricted = [r for r in sandbox.store.all() if r.classification == "restricted"]
    assert len(restricted) == 1 and restricted[0].kind == "finding.open"
    default = build_package(sandbox, tmp_path / "default.zip")
    ids = {json.loads(line)["id"] for line in _read(tmp_path / "default.zip")["evidence.jsonl"].decode().splitlines()}
    assert restricted[0].id not in ids and default["include_restricted"] is False
    full = build_package(sandbox, tmp_path / "full.zip", include_restricted=True)
    ids = {json.loads(line)["id"] for line in _read(tmp_path / "full.zip")["evidence.jsonl"].decode().splitlines()}
    assert restricted[0].id in ids and full["include_restricted"] is True
    assert full["counts"]["evidence"] == default["counts"]["evidence"] + 1 == len(sandbox.store.all())
    assert "restricted evidence included" in _read(tmp_path / "full.zip")["README.txt"].decode()


# -- signer resolution -----------------------------------------------------------------------

def test_signer_falls_back_from_sign_bytes_to_the_key_to_an_explicit_signer(sandbox, tmp_path):
    class KeyOnly:
        key = sandbox.key
    class Nothing:
        pass
    data = b"manifest bytes"
    assert package_signer(KeyOnly())(data) == sandbox.sign_bytes(data)
    assert package_signer(sandbox)(data) == sandbox.sign_bytes(data)
    assert package_signer(Nothing(), signer=lambda b: "explicit")(data) == "explicit"
    with pytest.raises(TypeError, match="sign_bytes"):
        package_signer(Nothing())
    manifest = build_package(sandbox, tmp_path / "s.zip", signer=lambda b: "ff" * 32)
    assert manifest["signature"] == "ff" * 32
    assert verify_package(tmp_path / "s.zip", lambda b: "ff" * 32) == (True, [])
    assert verify_package(tmp_path / "s.zip", sandbox.sign_bytes)[0] is False


# -- through the service and the CLI --------------------------------------------------------

def test_service_build_package_records_the_export_and_audits_it(sandbox, tmp_path):
    out = tmp_path / "soc2.zip"
    res = sandbox.build_package(SYSTEM, out, framework="soc2", since=_days_ago(30))
    assert res["path"] == str(out) and res["sha256"] == hashlib.sha256(out.read_bytes()).hexdigest()
    rows = PackageStore(sandbox.engine).list()
    assert len(rows) == 1 and rows[0]["sha256"] == res["sha256"] and rows[0]["framework"] == "soc2"
    assert rows[0]["manifest"] == res["manifest"] and rows[0]["created_by"] == SYSTEM.email
    assert any(e.action == "package.built" and e.subject == "soc2.zip" for e in sandbox.audit.query(limit=5))
    assert verify_package(out, sandbox.sign_bytes) == (True, [])


def _cli(*argv: str) -> int:
    from attest.cli_product import register
    p = argparse.ArgumentParser()
    p.add_argument("--config")
    p.add_argument("--data", type=Path, default=Path("data"))
    sub = p.add_subparsers(dest="cmd", required=True)
    register(sub)
    args = p.parse_args(list(argv))
    return args.fn(args)


def test_cli_package_and_package_verify(sandbox, tmp_path, capsys):
    cfg = str(sandbox.cfg.path)
    out = tmp_path / "cli.zip"
    assert _cli("--config", cfg, "package", "--framework", "iso27001", "--since", _days_ago(30), "--out", str(out)) == 0
    text = capsys.readouterr().out
    assert f"wrote {out}" in text and "ISO/IEC 27001:2022" in text and "evidence chain intact" in text and "package-verify" in text
    assert PackageStore(sandbox.engine).list()[0]["framework"] == "iso27001"

    assert _cli("--config", cfg, "package-verify", str(out)) == 0
    text = capsys.readouterr().out
    assert "cli.zip: OK" in text and "scope: iso27001" in text

    _rewrite(out, {"posture.json": b"{}"})
    assert _cli("--config", cfg, "package-verify", str(out)) == 4
    text = capsys.readouterr().out
    assert "cli.zip: FAILED (1 problem)" in text and "posture.json: sha256" in text

    assert _cli("--config", cfg, "package", "--since", "yesterday", "--out", str(tmp_path / "x.zip")) == 2
    assert "since must be" in capsys.readouterr().out and not (tmp_path / "x.zip").exists()

    assert _cli("--config", cfg, "package", "--include-restricted", "--out", str(tmp_path / "r.zip")) == 0
    assert "restricted evidence included" in capsys.readouterr().out


def test_cli_package_reports_a_broken_chain(sandbox, tmp_path, capsys):
    sandbox.tamper()
    out = tmp_path / "broken.zip"
    assert _cli("--config", str(sandbox.cfg.path), "package", "--out", str(out)) == 4
    assert "evidence chain BROKEN" in capsys.readouterr().out
    assert json.loads(_read(out)["chain.json"])["verified"] is False
    assert verify_package(out, sandbox.sign_bytes) == (True, [])  # the package is honest about it, and intact
