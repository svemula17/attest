"""Generic JSON-API collector over httpx.MockTransport (no network)."""
import httpx
import pytest

from attest.audit import AuditLog
from attest.collectors import http_json
from attest.collectors.http_json import collect, describe, evaluate, render, resolve
from attest.collectors.registry import CollectContext
from attest.config import Config, SourceConfig
from attest.controls import ControlEngine, default_catalog
from attest.evidence import EvidenceStore

URL = "https://api.example.com/v1/summary"
BODY = {"data": {"open_critical": 0, "open_high": 3, "sla_breaches": 0, "status": "ok", "tags": ["scanned", "prod"],
                 "results": [{"name": "web", "uptime": 99.97}, {"name": "api", "uptime": 99.5}]},
        "meta": {"generated": "2026-09-11"}}


def make_ctx(tmp_path, params, source_id="snyk"):
    store = EvidenceStore(tmp_path / "data" / "evidence.jsonl")
    audit = AuditLog(tmp_path / "data" / "audit.jsonl")
    return CollectContext(store=store, audit=audit, source=SourceConfig(id=source_id, type="http-json", params=params), config=Config())


class FakeAPI:
    def __init__(self, body=BODY, status=200, text=None):
        self.body, self.status, self.text = body, status, text
        self.calls: list[httpx.Request] = []

    def transport(self):
        return httpx.MockTransport(self)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if self.text is not None:
            return httpx.Response(self.status, text=self.text, request=request)
        return httpx.Response(self.status, json=self.body, request=request)


def base_params(**over):
    p = {"url": URL, "token_env": "SNYK_TOKEN", "kind": "vuln.findings-sla",
         "summary": "{data.open_critical} critical, {data.open_high} high open; {data.sla_breaches} SLA breaches",
         "checks": [{"path": "data.open_critical", "op": "==", "value": 0}, {"path": "data.sla_breaches", "op": "<=", "value": 0}]}
    p.update(over)
    return p


@pytest.fixture(autouse=True)
def token(monkeypatch):
    monkeypatch.setenv("SNYK_TOKEN", "s3cret")


# ── resolver and template ────────────────────────────────────────────────

def test_resolve_walks_dicts_and_list_indexes():
    assert resolve(BODY, "data.open_high") == 3
    assert resolve(BODY, "data.results.1.name") == "api"
    assert resolve(BODY, "data.results.-1.uptime") == 99.5
    assert resolve(BODY, "meta") == {"generated": "2026-09-11"}
    for path in ("data.nope", "data.results.7.name", "data.open_high.deeper", "results"):
        with pytest.raises(ValueError, match=f"path '{path}' is not in the response"):
            resolve(BODY, path)


def test_render_uses_dotted_paths_with_format_specs():
    assert render("{data.open_critical} critical, {data.results.0.uptime:.1f}% up, {data.status!r}", BODY) == "0 critical, 100.0% up, 'ok'"
    assert render("no placeholders {{literal}}", BODY) == "no placeholders {literal}"
    with pytest.raises(ValueError, match="path 'data.missing' is not in the response"):
        render("{data.missing} things", BODY)
    with pytest.raises(ValueError, match="must name a path"):
        render("{} things", BODY)


@pytest.mark.parametrize("path,op,value,ok", [
    ("data.open_critical", "==", 0, True), ("data.status", "==", "ok", True), ("data.status", "==", "bad", False),
    ("data.open_high", "!=", 3, False), ("data.open_high", "!=", 4, True),
    ("data.open_high", "<", 4, True), ("data.open_high", "<", 3, False),
    ("data.open_high", "<=", 3, True), ("data.open_high", "<=", 2, False),
    ("data.results.0.uptime", ">", 99.9, True), ("data.results.1.uptime", ">", 99.9, False),
    ("data.open_high", ">=", 3, True), ("data.open_high", ">=", 4, False),
    ("meta.generated", ">=", "2026-09-01", True), ("meta.generated", ">=", "2026-10-01", False),
    ("data.status", "in", ["ok", "degraded"], True), ("data.status", "in", ["down"], False), ("data.status", "in", "looks ok", True),
    ("data.tags", "contains", "prod", True), ("data.tags", "contains", "staging", False), ("data.status", "contains", "o", True),
    ("data.status", "exists", True, True), ("data.nope", "exists", True, False), ("data.nope", "exists", False, True),
])
def test_every_operator(path, op, value, ok):
    [r] = evaluate(BODY, [{"path": path, "op": op, "value": value}])
    assert r["ok"] is ok and r == {"path": path, "op": op, "value": value, "actual": r["actual"], "ok": ok}
    if op == "exists":
        assert (r["actual"] is None) == path.endswith("nope")  # a missing path has no actual value
    else:
        assert r["actual"] == resolve(BODY, path)


def test_numeric_string_compares_as_number_and_unorderable_is_an_error():
    body = {"pct": "99.95", "flag": True}
    assert evaluate(body, [{"path": "pct", "op": ">=", "value": 99.9}])[0]["ok"] is True
    with pytest.raises(ValueError, match="cannot order"):
        evaluate(body, [{"path": "flag", "op": ">", "value": 0}])
    with pytest.raises(ValueError, match="path 'nope' is not in the response"):
        evaluate(body, [{"path": "nope", "op": "==", "value": 1}])


# ── the collector ────────────────────────────────────────────────────────

def test_one_record_with_bearer_token_rendered_summary_and_checks(tmp_path):
    fake = FakeAPI()
    ctx = make_ctx(tmp_path, base_params())
    out = collect(ctx, transport=fake.transport())
    assert out.records == 1 and out.summary == "0 critical, 3 high open; 0 SLA breaches"
    [rec] = ctx.store.all()
    assert rec.kind == "vuln.findings-sla" and rec.source == "snyk" and rec.classification == "publishable"
    assert rec.control_ids == ["CTL-VULN-01"]
    assert rec.payload["result"] == "pass" and rec.payload["summary"] == out.summary
    assert rec.payload["checks"] == [
        {"path": "data.open_critical", "op": "==", "value": 0, "actual": 0, "ok": True},
        {"path": "data.sla_breaches", "op": "<=", "value": 0, "actual": 0, "ok": True},
    ]
    assert rec.payload["url"] == URL and rec.payload["status"] == 200 and rec.payload["method"] == "GET"
    assert rec.payload["collected_by"] == "snyk"
    [req] = fake.calls
    assert req.method == "GET" and str(req.url) == URL
    assert req.headers["Authorization"] == "Bearer s3cret" and req.headers["Accept"] == "application/json"
    assert ctx.store.verify_chain()


def test_failed_check_is_a_failing_record_not_an_error(tmp_path):
    body = {"data": {"open_critical": 2, "open_high": 3, "sla_breaches": 1}}
    ctx = make_ctx(tmp_path, base_params())
    out = collect(ctx, transport=FakeAPI(body).transport())
    assert out.summary == "2 critical, 3 high open; 1 SLA breaches"
    [rec] = ctx.store.all()
    assert rec.payload["result"] == "fail"
    assert [c["ok"] for c in rec.payload["checks"]] == [False, False]
    assert rec.payload["checks"][0]["actual"] == 2


def test_root_custom_header_method_classification_and_control_ids(tmp_path, monkeypatch):
    monkeypatch.setenv("UPTIME_KEY", "abc")
    fake = FakeAPI({"response": {"monitor": {"name": "web", "uptime_30d": 99.98}}})
    params = {"url": "https://uptime.example.com/api/status", "method": "post", "header_name": "X-Api-Key", "header_env": "UPTIME_KEY",
              "kind": "uptime.availability", "root": "response.monitor", "classification": "internal", "control_ids": ["CTL-AVAIL-01"],
              "summary": "{name}: {uptime_30d}% over 30 days", "checks": [{"path": "uptime_30d", "op": ">=", "value": 99.9}], "timeout": 5}
    ctx = make_ctx(tmp_path, params, source_id="uptime")
    out = collect(ctx, transport=fake.transport())
    assert out.summary == "web: 99.98% over 30 days"
    [rec] = ctx.store.all()
    assert rec.source == "uptime" and rec.classification == "internal" and rec.control_ids == ["CTL-AVAIL-01"]
    assert rec.payload["result"] == "pass" and rec.payload["root"] == "response.monitor" and rec.payload["method"] == "POST"
    [req] = fake.calls
    assert req.method == "POST" and req.headers["X-Api-Key"] == "abc" and "Authorization" not in req.headers
    assert {r.control_id: r.state for r in ControlEngine(default_catalog(), ctx.store).evaluate()}["CTL-AVAIL-01"] == "PASS"


def test_missing_root_or_summary_path_is_an_error_naming_it(tmp_path):
    ctx = make_ctx(tmp_path, base_params(root="data.nested"))
    with pytest.raises(ValueError, match="path 'data.nested' is not in the response"):
        collect(ctx, transport=FakeAPI().transport())
    ctx = make_ctx(tmp_path, base_params(summary="{data.open_critical} critical of {data.total}"))
    with pytest.raises(ValueError, match="path 'data.total' is not in the response"):
        collect(ctx, transport=FakeAPI().transport())
    ctx = make_ctx(tmp_path, base_params(checks=[{"path": "data.typo", "op": "==", "value": 0}]))
    with pytest.raises(ValueError, match="path 'data.typo' is not in the response"):
        collect(ctx, transport=FakeAPI().transport())
    assert ctx.store.all() == []


def test_checks_are_required_and_validated_before_any_request(tmp_path):
    fake = FakeAPI()
    for checks, msg in [(None, "params.checks is required"), ([], "params.checks is required"),
                        ([{"op": "==", "value": 1}], r"checks\[0\] needs a dotted 'path'"),
                        ([{"path": "a", "op": "~", "value": 1}], "op must be one of"),
                        ([{"path": "a", "op": "=="}], "needs a 'value'")]:
        with pytest.raises(ValueError, match=msg):
            collect(make_ctx(tmp_path, base_params(checks=checks)), transport=fake.transport())
    assert fake.calls == []


def test_unknown_kind_source_url_and_summary_are_rejected_before_any_request(tmp_path):
    fake = FakeAPI()
    with pytest.raises(ValueError, match="params.kind 'vuln.nope' is not an evidence kind"):
        collect(make_ctx(tmp_path, base_params(kind="vuln.nope")), transport=fake.transport())
    with pytest.raises(ValueError, match="params.source 'nope' is not a source"):
        collect(make_ctx(tmp_path, base_params(source="nope")), transport=fake.transport())
    with pytest.raises(ValueError, match="needs params.url"):
        collect(make_ctx(tmp_path, base_params(url="")), transport=fake.transport())
    with pytest.raises(ValueError, match="params.summary"):
        collect(make_ctx(tmp_path, base_params(summary="")), transport=fake.transport())
    with pytest.raises(ValueError, match="header_env needs params.header_name"):
        collect(make_ctx(tmp_path, base_params(header_env="X")), transport=fake.transport())
    assert fake.calls == []


def test_secrets_come_from_the_environment_only(tmp_path, monkeypatch):
    fake = FakeAPI()
    monkeypatch.delenv("SNYK_TOKEN")
    with pytest.raises(PermissionError, match="SNYK_TOKEN"):
        collect(make_ctx(tmp_path, base_params()), transport=fake.transport())
    with pytest.raises(PermissionError, match="header_env"):
        collect(make_ctx(tmp_path, base_params(token_env=None, header_name="X-Api-Key")), transport=fake.transport())
    assert fake.calls == []
    # no auth at all is allowed (a public endpoint)
    collect(make_ctx(tmp_path, base_params(token_env=None)), transport=fake.transport())
    assert "Authorization" not in fake.calls[0].headers


@pytest.mark.parametrize("status,exc", [(401, PermissionError), (403, PermissionError), (500, RuntimeError), (302, RuntimeError)])
def test_non_2xx_statuses(tmp_path, status, exc):
    ctx = make_ctx(tmp_path, base_params())
    with pytest.raises(exc, match=str(status)):
        collect(ctx, transport=FakeAPI(status=status).transport())
    assert ctx.store.all() == []


def test_non_json_body_is_a_runtime_error(tmp_path):
    with pytest.raises(RuntimeError, match="did not return JSON"):
        collect(make_ctx(tmp_path, base_params()), transport=FakeAPI(text="<html>").transport())


def test_describe_and_type():
    assert http_json.TYPE == "http-json"
    d = describe()
    assert {"url", "kind", "summary", "checks", "token_env", "header_name", "header_env", "root", "timeout", "control_ids", "classification"} <= set(d["params"])
    assert d["secrets"] == ["token_env", "header_env"]
    for op in http_json.OPS:
        assert op in d["params"]["checks"]
