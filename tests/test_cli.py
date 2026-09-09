"""End-to-end: seed → evaluate → answer → read-doc → verify, through the CLI."""
from pathlib import Path

import pytest

from attest.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture
def data(tmp_path):
    assert main(["--data", str(tmp_path), "seed"]) == 0
    return tmp_path


def test_seed_then_evaluate_prints_three_frameworks(data, capsys):
    assert main(["--data", str(data), "evaluate"]) == 0
    out = capsys.readouterr().out
    for name in ("SOC 2 Type II", "ISO/IEC 27001:2022", "HIPAA Security Rule"):
        assert name in out
    assert "FAIL" in out and "DEGRADED" in out and "PASS" in out


def test_single_gap_fails_three_frameworks(data, capsys):
    assert main(["--data", str(data), "evaluate", "--json"]) == 0
    import json
    posture = json.loads(capsys.readouterr().out)["posture"]
    failing = {fw: {r["framework_id"] for r in rows if r["state"] == "FAIL"} for fw, rows in posture.items()}
    assert "CC9.2" in failing["soc2"]
    assert "A.5.19" in failing["iso27001"]
    assert "164.314(a)" in failing["hipaa"]


def test_answer_ready_cites_only_publishable(data, capsys):
    rc = main(["--data", str(data), "answer", "Q-4471", "Is PHI encrypted at rest and in transit?",
               "--controls", "CTL-CRYPTO-01", "CTL-CRYPTO-02"])
    out = capsys.readouterr().out
    assert rc == 0 and "READY" in out
    assert "cites:" in out
    # the restricted open finding is in the store but must never be cited
    assert "finding" not in out.lower()


def test_answer_declines_when_no_evidence(data, capsys):
    rc = main(["--data", str(data), "answer", "Q-4474", "Any reportable breach in 24 months?",
               "--controls", "CTL-NONEXISTENT"])
    out = capsys.readouterr().out
    assert rc == 2 and "DECLINED" in out


def test_read_doc_quarantines_injection(data, capsys):
    rc = main(["--data", str(data), "read-doc", str(EXAMPLES / "vendor-soc2-excerpt.txt")])
    out = capsys.readouterr().out
    assert rc == 0 and "QUARANTINED" in out and "ignore-prior-instructions" in out


def test_read_doc_clean(data, capsys):
    rc = main(["--data", str(data), "read-doc", str(EXAMPLES / "vendor-clean-excerpt.txt")])
    assert rc == 0 and "clean" in capsys.readouterr().out


def test_read_doc_refuses_write_tools(data, capsys):
    rc = main(["--data", str(data), "read-doc", str(EXAMPLES / "vendor-soc2-excerpt.txt"),
               "--tools", "read:documents", "write:evidence"])
    assert rc == 3 and "untrusted-doc-isolation" in capsys.readouterr().out


def test_verify_chain_and_tamper(data, capsys):
    assert main(["--data", str(data), "verify"]) == 0
    f = data / "evidence.jsonl"
    lines = f.read_text().splitlines()
    lines[3] = lines[3].replace('"pass"', '"fail"', 1)
    f.write_text("\n".join(lines) + "\n")
    assert main(["--data", str(data), "verify"]) == 4


def test_audit_has_entries_for_every_agent_action(data, capsys):
    main(["--data", str(data), "answer", "Q-1", "q", "--controls", "CTL-LOG-01"])
    main(["--data", str(data), "read-doc", str(EXAMPLES / "vendor-soc2-excerpt.txt")])
    capsys.readouterr()
    assert main(["--data", str(data), "audit"]) == 0
    out = capsys.readouterr().out
    assert "draft.ready" in out
    assert "Q-1" in out


def test_export_json(data, tmp_path, capsys):
    out_file = tmp_path / "export.json"
    assert main(["--data", str(data), "export", "--out", str(out_file)]) == 0
    import json
    doc = json.loads(out_file.read_text())
    assert doc["chain_intact"] is True
    assert set(doc["posture"]) == {"soc2", "iso27001", "hipaa"}
    assert doc["summary"]["total"] >= 10
