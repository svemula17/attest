"""The collector registry: one place that runs each configured source type, with run bookkeeping."""
import argparse
import shutil
from pathlib import Path

import pytest

from attest import cli_collect
from attest.audit import AuditLog
from attest.collectors import github as gh
from attest.collectors.registry import COLLECTORS, run_all, run_source
from attest.config import SourceConfig, parse_config
from attest.evidence import EvidenceStore

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "imports"

CONFIG = """
[sources.hris]
type = "csv"
[sources.hris.params]
path = "imports/hris-roster.csv"
mapping = "hris.roster"

[sources.idp]
type = "csv"
[sources.idp.params]
path = "imports/idp-users.csv"

[sources.leavers]
type = "hris-idp-join"
schedule = "0 6 * * *"

[sources.evidence]
type = "json"
[sources.evidence.params]
path = "imports/evidence.json"

[sources.rows]
type = "csv"
[sources.rows.params]
path = "imports/evidence.csv"

[sources.github]
type = "github"
[sources.github.params]
repos = ["acme/widgets", "acme/api"]
token_env = "GITHUB_TOKEN"

[sources.broken]
type = "csv"
[sources.broken.params]
path = "imports/missing.csv"

[sources.paused]
type = "json"
enabled = false
[sources.paused.params]
path = "imports/evidence.json"
"""

ENABLED = ["hris", "idp", "leavers", "evidence", "rows", "github", "broken"]

PROTECTED = {"required_pull_request_reviews": {"required_approving_review_count": 1},
             "required_status_checks": {"contexts": ["ci/test"]}}


class FakeRuns:
    """Duck-typed run store: start()/finish()/last(), recording every call."""

    def __init__(self):
        self.calls = []
        self._next = 1
        self.status = {}

    def start(self, source_id, trigger, started_by):
        run_id = self._next
        self._next += 1
        self.calls.append(("start", run_id, source_id, trigger, started_by))
        return run_id

    def finish(self, run_id, status, records, error=None):
        self.calls.append(("finish", run_id, status, records, error))
        self.status[self.calls[-1][1]] = status

    def last(self, source_id):
        for call in reversed(self.calls):
            if call[0] == "start" and call[2] == source_id:
                return {"status": self.status.get(call[1], "running")}
        return None


@pytest.fixture
def env(tmp_path):
    shutil.copytree(EXAMPLES, tmp_path / "imports")
    config = parse_config(CONFIG, path=tmp_path / "attest.toml")
    store = EvidenceStore(tmp_path / "data" / "evidence.jsonl")
    audit = AuditLog(tmp_path / "data" / "audit.jsonl")
    return config, store, audit


@pytest.fixture
def github(monkeypatch):
    calls = []

    def fetch(url, token):
        calls.append((url, token))
        if url.endswith("/protection"):
            return 200, PROTECTED
        return 200, {"default_branch": "main"}

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setattr(gh, "_default_fetch", fetch)

    def fake_collect(ctx, transport=None):  # the org-wide collector, driven by the same fake fetch
        from attest.collectors.registry import CollectResult
        repos = ctx.source.params.get("repos")
        if not repos and not ctx.source.params.get("org"):
            raise ValueError("params.org or params.repos (a list of 'owner/name') is required")
        n = 0
        for repo in repos or []:
            n += len(gh.collect_branch_protection(ctx.store, repo, token="t0k", fetch=fetch))
        return CollectResult(records=n, summary=f"github: {n} records")

    monkeypatch.setattr(gh, "collect", fake_collect)
    return calls


def test_registry_covers_the_configurable_types():
    assert {"csv", "json", "github", "hris-idp-join", "aws", "okta", "bamboohr", "http-json"} <= set(COLLECTORS)


def test_run_source_csv_ok_records_the_run_and_audits(env):
    config, store, audit = env
    runs = FakeRuns()
    out = run_source(config, "hris", store, audit, runs=runs, trigger="manual", started_by="s.vemula")
    assert out == {"source_id": "hris", "type": "csv", "status": "ok", "records": 1,
                   "summary": "1 record from hris-roster.csv (hris.roster)", "run_id": 1, "error": None}
    assert runs.calls == [("start", 1, "hris", "manual", "s.vemula"), ("finish", 1, "ok", 1, None)]
    entry = audit.all()[-1]
    assert (entry.actor, entry.action, entry.subject, entry.detail) == ("collector:csv", "collect.ok", "hris", out["summary"])
    assert [r.kind for r in store.all()] == ["hris.roster"]


def test_csv_mapping_is_inferred_and_json_defaults_to_evidence_json(env):
    config, store, audit = env
    assert run_source(config, "idp", store, audit)["records"] == 1
    out = run_source(config, "evidence", store, audit)
    assert out["type"] == "json" and out["records"] == 4 and out["run_id"] is None
    assert out["summary"].startswith("4 records from evidence.json (iam.least-privilege, ")
    assert [r.kind for r in store.all()][:2] == ["idp.users", "iam.least-privilege"]


def test_join_finding_is_still_a_successful_run(env):
    config, store, audit = env
    run_source(config, "hris", store, audit)
    run_source(config, "idp", store, audit)
    out = run_source(config, "leavers", store, audit, runs=FakeRuns())
    assert out["status"] == "ok" and out["records"] == 1 and out["type"] == "hris-idp-join"
    assert "Kenji Watanabe" in out["summary"] and "leaver still active" in out["summary"]
    rec = store.query(kind="access.leaver-deprovisioned")[-1]
    assert rec.payload["result"] == "fail" and rec.payload["summary"] == out["summary"]
    assert audit.all()[-1].action == "collect.ok" and audit.all()[-1].actor == "collector:hris-idp-join"


def test_join_without_inputs_is_an_error_run(env):
    config, store, audit = env
    runs = FakeRuns()
    with pytest.raises(ValueError, match="no hris.roster record"):
        run_source(config, "leavers", store, audit, runs=runs)
    assert runs.calls[-1] == ("finish", 1, "error", 0, "no hris.roster record in the store")
    assert audit.all()[-1].action == "collect.error"


def test_github_type_runs_the_org_wide_collector(env, monkeypatch):
    """type = "github" dispatches to attest.collectors.github.collect(ctx)."""
    import attest.collectors.github as gh
    from attest.collectors.registry import CollectResult
    seen = {}
    def fake_collect(ctx, transport=None):
        seen["source"] = ctx.source.id; seen["params"] = ctx.source.params
        return CollectResult(records=0, summary="stubbed")
    monkeypatch.setattr(gh, "collect", fake_collect)
    config, store, audit = env[:3]
    runs = FakeRuns()
    result = run_source(config, "github", store, audit, runs=runs)
    assert result["status"] == "ok" and seen["source"] == "github" and seen["params"]["token_env"] == "GITHUB_TOKEN"


def test_github_without_the_named_env_var_is_an_error_run(env, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False); monkeypatch.delenv("GH_TOKEN", raising=False)
    config, store, audit = env[:3]
    runs = FakeRuns()
    with pytest.raises(PermissionError):
        run_source(config, "github", store, audit, runs=runs)
    assert any(c[0] == "finish" and c[2] == "error" for c in runs.calls)



def test_github_needs_repos(env):
    config, store, audit = env
    config.sources["github"].params["repos"] = []
    with pytest.raises(ValueError, match="params.org or params.repos"):
        run_source(config, "github", store, audit)


def test_error_path_finishes_the_run_audits_and_reraises(env):
    config, store, audit = env
    runs = FakeRuns()
    with pytest.raises(FileNotFoundError) as exc:
        run_source(config, "broken", store, audit, runs=runs)
    message = str(exc.value)
    assert "missing.csv" in message
    assert runs.calls == [("start", 1, "broken", "manual", None), ("finish", 1, "error", 0, message)]
    entry = audit.all()[-1]
    assert (entry.actor, entry.action, entry.subject, entry.detail) == ("collector:csv", "collect.error", "broken", message)
    assert store.all() == []


def test_refusals_happen_before_any_run_starts(env):
    config, store, audit = env
    runs = FakeRuns()
    with pytest.raises(ValueError, match="unknown source 'nope'") as exc:
        run_source(config, "nope", store, audit, runs=runs)
    assert "hris" in str(exc.value) and "leavers" in str(exc.value)
    with pytest.raises(ValueError, match="source 'paused' is disabled"):
        run_source(config, "paused", store, audit, runs=runs)
    config.sources["cloud"] = SourceConfig(id="cloud", type="carrier-pigeon")
    with pytest.raises(ValueError, match="unknown type 'carrier-pigeon'"):
        run_source(config, "cloud", store, audit, runs=runs)
    assert runs.calls == [] and audit.all() == []


def test_run_all_continues_past_failures(env, github):
    config, store, audit = env
    runs = FakeRuns()
    results = run_all(config, store, audit, runs=runs)
    assert [r["source_id"] for r in results] == ENABLED  # config order; disabled 'paused' skipped
    assert [r["status"] for r in results] == ["ok"] * 6 + ["error"]
    assert "missing.csv" in results[-1]["error"] and results[-1]["records"] == 0
    assert [r["run_id"] for r in results] == list(range(1, 8))
    assert sum(r["records"] for r in results) == 1 + 1 + 1 + 4 + 6 + 4
    starts = [c for c in runs.calls if c[0] == "start"]
    finishes = [c for c in runs.calls if c[0] == "finish"]
    assert len(starts) == len(finishes) == 7 and all(c[3] == "schedule" for c in starts)
    assert finishes[-1][2] == "error"
    assert [e.action for e in audit.all()] == ["collect.ok"] * 6 + ["collect.error"]


def test_run_all_can_include_disabled_and_reports_unknown_types(env, github):
    config, store, audit = env
    config.sources["cloud"] = SourceConfig(id="cloud", type="carrier-pigeon")
    results = {r["source_id"]: r for r in run_all(config, store, audit, only_enabled=False, trigger="manual")}
    assert results["paused"]["status"] == "ok" and results["paused"]["records"] == 4
    assert results["cloud"]["status"] == "error" and "unknown type 'carrier-pigeon'" in results["cloud"]["error"]
    assert results["hris"]["status"] == "ok"


# -- through the CLI ------------------------------------------------------------

def _parser():
    p = argparse.ArgumentParser(prog="attest")
    p.add_argument("--data", type=Path, default=Path("data"))
    p.add_argument("--config")
    sub = p.add_subparsers(dest="cmd", required=True)
    cli_collect.register(sub)
    return p


@pytest.fixture
def cli(tmp_path):
    shutil.copytree(EXAMPLES, tmp_path / "imports")
    (tmp_path / "attest.toml").write_text(CONFIG)

    def run(*argv):
        args = _parser().parse_args(["--data", str(tmp_path / "data"), "--config", str(tmp_path / "attest.toml"), *argv])
        return args.fn(args)

    run.data = tmp_path / "data"
    return run


def test_cli_collect_one_source(cli, capsys):
    assert cli("collect", "hris") == 0
    out = capsys.readouterr().out
    assert "hris" in out and "ok" in out and "1 record" in out and "hris-roster.csv" in out
    assert [r.kind for r in EvidenceStore(cli.data / "evidence.jsonl").all()] == ["hris.roster"]
    assert AuditLog(cli.data / "audit.jsonl").all()[-1].action == "collect.ok"


def test_cli_collect_all_exits_1_when_any_source_fails(cli, github, capsys):
    assert cli("collect", "--all") == 1
    out = capsys.readouterr().out
    assert "broken" in out and "error" in out and "missing.csv" in out
    assert "6 ok · 1 error · 17 records appended" in out
    assert len(EvidenceStore(cli.data / "evidence.jsonl").all()) == 17


def test_cli_collect_usage_and_failure_exit_codes(cli, capsys):
    assert cli("collect") == 2 and "give a source id or --all" in capsys.readouterr().out
    assert cli("collect", "nope") == 2 and "unknown source 'nope'" in capsys.readouterr().out
    assert cli("collect", "paused") == 2 and "disabled" in capsys.readouterr().out
    assert cli("collect", "broken") == 1 and "missing.csv" in capsys.readouterr().out
    assert AuditLog(cli.data / "audit.jsonl").all()[-1].action == "collect.error"


def test_cli_collect_without_config_exits_2(tmp_path, capsys):
    args = _parser().parse_args(["--data", str(tmp_path), "--config", str(tmp_path / "missing.toml"), "collect", "hris"])
    assert args.fn(args) == 2 and "config not found" in capsys.readouterr().out


def test_cli_sources_list_table(cli, capsys):
    assert cli("sources", "list") == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == ["ID", "TYPE", "SCHEDULE", "ENABLED", "LAST"]
    rows = {ln.split()[0]: ln for ln in lines[2:]}
    assert set(rows) == set(ENABLED) | {"paused"}
    assert rows["leavers"].split() == ["leavers", "hris-idp-join", "0", "6", "*", "*", "*", "yes", "—"]
    assert rows["paused"].split() == ["paused", "json", "—", "no", "—"]


def test_cli_sources_list_shows_last_run_status_when_a_runs_store_exists(cli, monkeypatch, capsys):
    runs = FakeRuns()
    monkeypatch.setattr(cli_collect, "open_runs", lambda args: runs)
    cli("collect", "hris")
    cli("collect", "broken")
    capsys.readouterr()
    assert cli("sources", "list") == 0
    rows = {ln.split()[0]: ln.split()[-1] for ln in capsys.readouterr().out.splitlines()[2:]}
    assert rows["hris"] == "ok" and rows["broken"] == "error" and rows["idp"] == "—"
    assert [c[0] for c in runs.calls] == ["start", "finish", "start", "finish"]


def test_register_reuses_an_existing_sources_parser():
    p = argparse.ArgumentParser(prog="attest")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("sources").set_defaults(fn="catalog")
    cli_collect.register(sub)
    assert p.parse_args(["sources"]).fn == "catalog"
    assert p.parse_args(["sources", "list"]).fn is cli_collect.cmd_sources_list
    assert p.parse_args(["collect", "--all"]).fn is cli_collect.cmd_collect
