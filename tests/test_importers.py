"""File imports: CSV/JSON → evidence, validated whole, all-or-nothing."""
import argparse
import json
from pathlib import Path

import pytest

from attest.audit import AuditLog
from attest.cli_collect import register
from attest.collectors.joiner_leaver import run_join
from attest.evidence import EvidenceStore
from attest.importers import ImportProblem, ImportResult, import_file, infer_csv_mapping
from attest.util import parse_iso

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "imports"

EVIDENCE_HEADER = "source,kind,control_ids,classification,collected_at,summary,result"


@pytest.fixture
def store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.jsonl")


def write(tmp_path, name, text, encoding="utf-8"):
    p = tmp_path / name
    p.write_text(text, encoding=encoding)
    return p


# -- mapping: evidence (CSV) -----------------------------------------------------

def test_evidence_csv_one_record_per_row(store, tmp_path):
    p = write(tmp_path, "rows.csv", EVIDENCE_HEADER + ",payload_json\n"
              'aws-config,kms.key.rotation,CTL-CRYPTO-01;CTL-CRYPTO-02,publishable,2026-09-10T08:00:00Z,Rotation on,pass,"{""keys"": 12, ""summary"": ""overridden""}"\n'
              "snyk,vuln.findings-sla,CTL-VULN-01,internal,,3 highs open,fail,\n")
    result = import_file(store, p)
    assert result == ImportResult(records=2, kinds=["kms.key.rotation", "vuln.findings-sla"], warnings=[])
    a, b = store.all()
    assert a.source == "aws-config" and a.control_ids == ["CTL-CRYPTO-01", "CTL-CRYPTO-02"]
    assert a.collected_at == "2026-09-10T08:00:00Z" and a.classification == "publishable"
    assert a.payload == {"keys": 12, "summary": "Rotation on", "result": "pass"}  # the columns win over payload_json
    assert b.classification == "internal" and b.control_ids == ["CTL-VULN-01"]
    assert b.payload == {"summary": "3 highs open", "result": "fail"}
    parse_iso(b.collected_at)  # defaulted to now
    assert store.verify_chain()


def test_evidence_csv_example_file(store):
    result = import_file(store, EXAMPLES / "evidence.csv")
    assert result.records == 6 and result.warnings == []
    records = store.all()
    assert {r.source for r in records} == {"aws-config", "cloudtrail", "mdm", "training", "vendor-registry"}
    baa = [r for r in records if r.kind == "baa.executed"][0]
    assert baa.payload["result"] == "fail" and baa.payload["missing"] == ["Acme Analytics", "Northwind Mail"]
    assert baa.classification == "internal"


# -- mapping: hris.roster / idp.users (CSV) -------------------------------------

def test_hris_roster_example_becomes_one_record(store):
    result = import_file(store, EXAMPLES / "hris-roster.csv")
    assert result == ImportResult(records=1, kinds=["hris.roster"], warnings=[])
    (rec,) = store.all()
    assert rec.source == "hris" and rec.control_ids == ["CTL-ACCESS-02"] and rec.classification == "internal"
    assert rec.payload["summary"] == "HRIS roster: 6 employees, 2 terminated" and rec.payload["result"] == "pass"
    employees = {e["id"]: e for e in rec.payload["employees"]}
    assert employees["E-1001"]["terminated"] is None
    assert employees["E-1004"] == {"id": "E-1004", "name": "Tomás Ferreira", "email": "tomas.ferreira@example.com",
                                   "hired": "2020-11-16", "terminated": "2026-07-31"}


def test_idp_users_example_becomes_one_record(store):
    result = import_file(store, EXAMPLES / "idp-users.csv")
    assert result == ImportResult(records=1, kinds=["idp.users"], warnings=[])
    (rec,) = store.all()
    assert rec.source == "okta" and rec.control_ids == ["CTL-ACCESS-02"] and rec.classification == "internal"
    assert rec.payload["summary"] == "IdP users: 5 active, 1 deprovisioned"
    users = {u["email"]: u for u in rec.payload["users"]}
    assert users["tomas.ferreira@example.com"] == {"email": "tomas.ferreira@example.com", "status": "deprovisioned",
                                                    "deprovisioned_at": "2026-07-31T17:12:00Z"}
    assert users["kenji.watanabe@example.com"]["status"] == "active"
    assert users["kenji.watanabe@example.com"]["deprovisioned_at"] is None


def test_example_files_join_into_a_finding(store):
    import_file(store, EXAMPLES / "hris-roster.csv")
    import_file(store, EXAMPLES / "idp-users.csv")
    rec = run_join(store)
    assert rec.payload["result"] == "fail" and rec.payload["checked"] == 2
    assert [o["email"] for o in rec.payload["orphans"]] == ["kenji.watanabe@example.com"]
    assert "Kenji Watanabe" in rec.payload["summary"]


def test_hris_validation_reports_physical_row_numbers(store, tmp_path):
    p = write(tmp_path, "roster.csv",
              "# a comment on line 1\n"
              "employee_id,name,email,hired,terminated\n"
              "E-1,Ada,ada@x,2020-01-01,\n"
              "E-2,Bob,,2020-13-01,\n"
              "E-3,Cy,cy@x,2020-01-01,soon\n")
    with pytest.raises(ImportProblem) as exc:
        import_file(store, p)
    assert [x.split(":")[0] for x in exc.value.problems] == ["row 4", "row 4", "row 5"]
    assert "email is blank" in exc.value.problems[0]
    assert "hired '2020-13-01'" in exc.value.problems[1]
    assert "terminated 'soon'" in exc.value.problems[2]
    assert store.all() == [] and (tmp_path / "evidence.jsonl").read_text() == ""


def test_idp_validation_and_warnings(store, tmp_path):
    bad = write(tmp_path, "bad.csv", "email,status,deprovisioned_at\nada@x,disabled,\nbob@x,deprovisioned,last week\n")
    with pytest.raises(ImportProblem) as exc:
        import_file(store, bad)
    assert exc.value.problems == [
        "row 2: status 'disabled' must be active or deprovisioned",
        "row 3: deprovisioned_at 'last week' must be UTC ISO-8601 like 2026-08-15T09:40:00Z or blank",
    ]
    assert store.all() == []
    ok = write(tmp_path, "ok.csv", "email,status,deprovisioned_at\nada@x,deprovisioned,\nADA@x,active,\n")
    result = import_file(store, ok)
    assert result.records == 1
    assert result.warnings == ["row 2: ada@x is deprovisioned without a deprovisioned_at; the join cannot check its SLA",
                               "row 3: duplicate email ADA@x (also row 2)"]


def test_fixed_source_mappings_ignore_the_source_argument(store):
    result = import_file(store, EXAMPLES / "hris-roster.csv", source="workday")
    assert store.all()[0].source == "hris"
    assert result.warnings == ["file: source 'workday' ignored; hris.roster records always have source 'hris'"]


# -- mapping: evidence.json ------------------------------------------------------

def test_evidence_json_example(store):
    result = import_file(store, EXAMPLES / "evidence.json")
    assert result.records == 4 and result.warnings == []
    assert result.kinds == ["iam.least-privilege", "sso.enforced", "vuln.findings-sla", "backup.restore-test"]
    first, second = store.all()[:2]
    assert first.collected_at == "2026-09-10T08:00:00Z" and first.payload["principals_checked"] == 148
    parse_iso(second.collected_at)  # no collected_at in the file: defaulted to now
    assert second.control_ids == ["CTL-ACCESS-01"]


def test_json_unknown_keys_warn_but_missing_keys_are_problems(store, tmp_path):
    good = write(tmp_path, "good.json", json.dumps([
        {"source": "okta", "kind": "sso.enforced", "control_ids": ["CTL-ACCESS-01"], "classification": "publishable",
         "payload": {"summary": "ok", "result": "pass"}, "note": "extra"},
    ]))
    result = import_file(store, good)
    assert result.records == 1 and result.warnings == ["row 1: ignoring unknown key 'note'"]

    bad = write(tmp_path, "bad.json", json.dumps([
        {"source": "okta", "control_ids": [], "classification": "publishable", "payload": {"summary": "x", "result": "pass"}},
        {"source": "okta", "kind": "k", "control_ids": "CTL-1", "classification": "public",
         "payload": {"summary": "", "result": "maybe"}, "collected_at": "nope"},
        "not an object",
    ]))
    with pytest.raises(ImportProblem) as exc:
        import_file(store, bad)
    problems = exc.value.problems
    assert problems[0] == "row 1: missing required key(s): kind"
    assert [x.split(":")[0] for x in problems[1:]] == ["row 2"] * 5 + ["row 3"]
    assert any("control_ids must be a list" in x for x in problems)
    assert any("classification 'public'" in x for x in problems)
    assert any("payload.summary" in x for x in problems) and any("payload.result 'maybe'" in x for x in problems)
    assert any("collected_at 'nope'" in x for x in problems)
    assert len(store.all()) == 1  # only the good file landed


def test_json_shapes(store, tmp_path):
    enveloped = write(tmp_path, "env.json", json.dumps({"comment": "notes live here", "records": [
        {"source": "okta", "kind": "sso.enforced", "control_ids": [], "classification": "publishable",
         "payload": {"summary": "ok", "result": "pass"}}]}))
    assert import_file(store, enveloped).warnings == []
    for name, text, problem in [
        ("obj.json", '{"kind": "x"}', "file: expected a JSON array of records, or an object with a 'records' array"),
        ("empty.json", "[]", "file: no records"),
        ("broken.json", "[{", "file: not valid JSON"),
    ]:
        with pytest.raises(ImportProblem) as exc:
            import_file(store, write(tmp_path, name, text))
        assert exc.value.problems[0].startswith(problem)
    assert len(store.all()) == 1


# -- inference, sources, all-or-nothing -----------------------------------------

def test_mapping_is_inferred_from_extension_and_header(store, tmp_path):
    assert infer_csv_mapping(["employee_id", "name", "email", "hired", "terminated"]) == "hris.roster"
    assert infer_csv_mapping(["email", "status", "deprovisioned_at"]) == "idp.users"
    assert infer_csv_mapping(["email", "status", "deprovisioned_at", "extra"]) == "evidence"
    assert import_file(store, EXAMPLES / "evidence.json").records == 4
    assert import_file(store, EXAMPLES / "idp-users.csv").kinds == ["idp.users"]
    txt = write(tmp_path, "rows.txt", EVIDENCE_HEADER + "\nokta,sso.enforced,CTL-ACCESS-01,publishable,,SSO on,pass\n")
    with pytest.raises(ImportProblem) as exc:
        import_file(store, txt)
    assert exc.value.problems[0].startswith("file: cannot infer a mapping from extension '.txt'")
    assert import_file(store, txt, mapping="evidence").records == 1  # an explicit mapping beats the extension
    assert import_file(store, EXAMPLES / "evidence.json", mapping="evidence.json").records == 4


def test_unknown_mapping_and_missing_file(store, tmp_path):
    with pytest.raises(ValueError, match="unknown mapping 'xml'") as exc:
        import_file(store, EXAMPLES / "evidence.json", mapping="xml")
    assert not isinstance(exc.value, ImportProblem)
    with pytest.raises(FileNotFoundError):
        import_file(store, tmp_path / "nope.csv")


def test_validation_reports_rows_and_writes_nothing(store, tmp_path):
    p = write(tmp_path, "rows.csv", EVIDENCE_HEADER + "\n"
              "aws-config,kms.key.rotation,CTL-CRYPTO-01,publishable,,Fine,pass\n"
              "aws-config,,CTL-CRYPTO-01,secret,,Missing kind,pass\n"
              "okta,sso.enforced,CTL-ACCESS-01,publishable,yesterday,Bad timestamp,maybe\n")
    with pytest.raises(ImportProblem) as exc:
        import_file(store, p)
    problems = exc.value.problems
    assert [x.split(":")[0] for x in problems] == ["row 3", "row 3", "row 4", "row 4"]
    assert "kind is blank" in problems[0] and "classification 'secret'" in problems[1]
    assert "collected_at 'yesterday'" in problems[2] and "result 'maybe'" in problems[3]
    assert "row 3" in str(exc.value) and "nothing was written" in str(exc.value)
    assert store.all() == [] and (tmp_path / "evidence.jsonl").read_text() == ""  # row 2 was fine; still nothing landed


def test_header_problems_are_file_level(store, tmp_path):
    with pytest.raises(ImportProblem) as exc:
        import_file(store, write(tmp_path, "short.csv", "source,kind\nokta,sso.enforced\n"))
    assert exc.value.problems == ["file: header is missing column(s): control_ids, classification, summary, result (found: source, kind)"]
    with pytest.raises(ImportProblem) as exc:
        import_file(store, write(tmp_path, "empty.csv", "# only a comment\n"))
    assert exc.value.problems == ["file: empty (no header row)"]
    with pytest.raises(ImportProblem) as exc:
        import_file(store, write(tmp_path, "norows.csv", EVIDENCE_HEADER + "\n"))
    assert exc.value.problems == ["file: no data rows"]


def test_unknown_source_is_a_warning_not_an_error(store, tmp_path):
    p = write(tmp_path, "rows.csv", EVIDENCE_HEADER + "\n"
              "homegrown,scan.weekly,CTL-VULN-01,publishable,,Scan ran,pass\n"
              "homegrown,scan.monthly,CTL-VULN-01,publishable,,Scan ran,pass\n")
    result = import_file(store, p)
    assert result.records == 2
    assert result.warnings == ["row 2: source 'homegrown' is not in the source catalog (attest sources); kept as-is"]
    assert store.all()[0].source == "homegrown"


def test_source_argument_fills_blank_sources(store, tmp_path):
    p = write(tmp_path, "rows.csv", EVIDENCE_HEADER + "\n,ci.policy-gate,CTL-CHANGE-01,publishable,,Gate on,pass\n")
    with pytest.raises(ImportProblem) as exc:
        import_file(store, p)
    assert exc.value.problems == ["row 2: source is blank and no default source was given"]
    assert import_file(store, p, source="ci-cd").records == 1 and store.all()[0].source == "ci-cd"
    j = write(tmp_path, "rows.json", json.dumps([{"kind": "ci.policy-gate", "control_ids": [], "classification": "publishable",
                                                  "payload": {"summary": "Gate on", "result": "pass"}}]))
    assert import_file(store, j, source="ci-cd").records == 1 and store.all()[-1].source == "ci-cd"
    with pytest.raises(ImportProblem, match="missing required key\\(s\\): source"):
        import_file(store, j)


def test_comments_blank_lines_and_bom_are_tolerated(store, tmp_path):
    p = write(tmp_path, "rows.csv",
              "# generated by the vendor tool\n\n" + EVIDENCE_HEADER + "\n\n"
              "okta,sso.enforced,CTL-ACCESS-01,publishable,,SSO on,pass\n"
              "# trailing note,,,,,,\n", encoding="utf-8-sig")
    assert import_file(store, p) == ImportResult(records=1, kinds=["sso.enforced"], warnings=[])


def test_run_id_is_forwarded_only_when_the_store_accepts_it(store):
    class RunAwareStore:
        def __init__(self):
            self.run_ids = []

        def append(self, source, kind, control_ids, classification, payload, collected_at=None, run_id=None):
            self.run_ids.append(run_id)

        def query(self, **kw):
            return []

        def all(self):
            return []

    aware = RunAwareStore()
    assert import_file(aware, EXAMPLES / "evidence.json", run_id=7).records == 4
    assert aware.run_ids == [7, 7, 7, 7]
    assert import_file(store, EXAMPLES / "evidence.json", run_id=7).records == 4  # the JSONL store has no run_id; still fine


# -- through the CLI ------------------------------------------------------------

def _parser():
    p = argparse.ArgumentParser(prog="attest")
    p.add_argument("--data", type=Path, default=Path("data"))
    p.add_argument("--config")
    sub = p.add_subparsers(dest="cmd", required=True)
    register(sub)
    return p


def cli(argv):
    args = _parser().parse_args(argv)
    return args.fn(args)


def test_cli_import_prints_records_kinds_and_audits(tmp_path, capsys):
    rc = cli(["--data", str(tmp_path), "import", str(EXAMPLES / "evidence.csv")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "imported 6 records from" in out and "kinds: kms.key.rotation, storage.encrypted" in out
    assert "warning" not in out
    assert len(EvidenceStore(tmp_path / "evidence.jsonl").all()) == 6
    entry = AuditLog(tmp_path / "audit.jsonl").all()[-1]
    assert entry.action == "import.ok" and entry.subject == "evidence.csv" and entry.actor == "importer"


def test_cli_import_exit_3_lists_every_problem(tmp_path, capsys):
    p = tmp_path / "rows.csv"
    p.write_text(EVIDENCE_HEADER + "\nokta,,CTL-ACCESS-01,publishable,,x,pass\nokta,sso.enforced,CTL-ACCESS-01,top-secret,,x,pass\n")
    rc = cli(["--data", str(tmp_path), "import", str(p)])
    out = capsys.readouterr().out
    assert rc == 3
    assert "2 problem(s); nothing was written" in out and "row 2: kind is blank" in out and "row 3: classification" in out
    assert EvidenceStore(tmp_path / "evidence.jsonl").all() == []
    assert AuditLog(tmp_path / "audit.jsonl").all()[-1].action == "import.rejected"


def test_cli_import_mapping_source_and_warnings(tmp_path, capsys):
    p = tmp_path / "rows.txt"
    p.write_text(EVIDENCE_HEADER + "\n,ci.policy-gate,CTL-CHANGE-01,publishable,,Gate on,pass\nhomegrown,scan.weekly,,publishable,,Ran,pass\n")
    rc = cli(["--data", str(tmp_path), "import", str(p), "--mapping", "evidence", "--source", "ci-cd"])
    out = capsys.readouterr().out
    assert rc == 0 and "imported 2 records" in out
    assert "warning: row 3: source 'homegrown' is not in the source catalog" in out
    assert [r.source for r in EvidenceStore(tmp_path / "evidence.jsonl").all()] == ["ci-cd", "homegrown"]


def test_cli_import_missing_file_exit_1(tmp_path, capsys):
    assert cli(["--data", str(tmp_path), "import", str(tmp_path / "nope.csv")]) == 1
    assert "not found" in capsys.readouterr().out


def test_cli_import_rejects_unknown_mapping_at_parse_time():
    with pytest.raises(SystemExit):
        _parser().parse_args(["import", "x.csv", "--mapping", "xml"])
