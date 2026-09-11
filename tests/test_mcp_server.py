"""attest.mcp_server: read-only MCP over stdio.

Most tests drive handle() in-process; one runs the real server as a subprocess
and checks that stdout carries nothing but JSON-RPC lines.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from attest.audit import AuditLog
from attest.mcp_server import DEFAULT_PROTOCOL_VERSION, TOOLS, Context, handle
from attest.seed import seed

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL_NAMES = ["evidence_query", "evidence_get", "controls_posture"]
RECORD_KEYS = {"id", "source", "kind", "control_ids", "collected_at", "summary", "result", "sha256"}
ROW_KEYS = {"framework_id", "control_id", "name", "state", "evidence_ids", "spec"}


@pytest.fixture
def ctx(tmp_path):
    seed(tmp_path)
    return Context(tmp_path)


def rpc(ctx, method, params=None, id=1):
    request = {"jsonrpc": "2.0", "id": id, "method": method}
    if params is not None:
        request["params"] = params
    return handle(request, ctx)


def call(ctx, tool, arguments=None):
    """tools/call helper -> (is_error, parsed result or error text)."""
    response = rpc(ctx, "tools/call", {"name": tool, "arguments": arguments or {}})
    assert "result" in response, response
    result = response["result"]
    assert set(result) == {"content", "isError"}
    assert [c["type"] for c in result["content"]] == ["text"]
    text = result["content"][0]["text"]
    return result["isError"], (text if result["isError"] else json.loads(text))


def ids_by_classification(ctx) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for r in ctx.store.all():
        out.setdefault(r.classification, set()).add(r.id)
    return out


# -- handshake -------------------------------------------------------------------

@pytest.mark.parametrize("version", ["2025-06-18", "2025-11-25"])
def test_initialize_echoes_supported_protocol_version(ctx, version):
    response = rpc(ctx, "initialize", {"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}})
    assert response["jsonrpc"] == "2.0" and response["id"] == 1
    result = response["result"]
    assert result["protocolVersion"] == version
    assert result["capabilities"] == {"tools": {"listChanged": False}}
    assert result["serverInfo"] == {"name": "attest-evidence", "version": "0.1.0"}
    assert ctx.protocol_version == version


@pytest.mark.parametrize("params", [{"protocolVersion": "2024-11-05"}, {"protocolVersion": 7}, {}])
def test_initialize_falls_back_to_default_version(ctx, params):
    assert rpc(ctx, "initialize", params)["result"]["protocolVersion"] == DEFAULT_PROTOCOL_VERSION == "2025-06-18"


def test_initialized_notification_gets_no_response(ctx):
    assert ctx.initialized is False
    assert handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, ctx) is None
    assert ctx.initialized is True
    assert handle({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}, ctx) is None


def test_ping(ctx):
    assert rpc(ctx, "ping", id="p-1") == {"jsonrpc": "2.0", "id": "p-1", "result": {}}


# -- tools/list ------------------------------------------------------------------

def test_tools_list_returns_exactly_the_three_pinned_tools(ctx):
    result = rpc(ctx, "tools/list")["result"]
    assert set(result) == {"tools"}  # no nextCursor: nothing to page
    tools = result["tools"]
    assert [t["name"] for t in tools] == TOOL_NAMES
    for tool in tools:
        assert isinstance(tool["description"], str) and tool["description"]
        schema = tool["inputSchema"]
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert isinstance(schema["properties"], dict) and schema["properties"]
        assert tool["annotations"]["readOnlyHint"] is True
        assert tool["annotations"]["destructiveHint"] is False
    assert set(tools[0]["inputSchema"]["properties"]) == {"control_id", "kind", "limit"}
    assert tools[1]["inputSchema"]["required"] == ["id"]
    assert tools[2]["inputSchema"]["properties"]["framework"]["enum"] == ["soc2", "iso27001", "hipaa"]


def test_tool_definitions_are_pinned(ctx):
    assert isinstance(TOOLS, tuple) and len(TOOLS) == 3
    first = rpc(ctx, "tools/list")["result"]["tools"]
    first[0]["name"] = "evidence_delete"          # mutate the copy we were handed
    first[1]["inputSchema"]["additionalProperties"] = True
    again = rpc(ctx, "tools/list", {"cursor": "ignored"})["result"]["tools"]
    assert [t["name"] for t in again] == TOOL_NAMES
    assert again[1]["inputSchema"]["additionalProperties"] is False
    assert [t["name"] for t in TOOLS] == TOOL_NAMES


# -- evidence_query --------------------------------------------------------------

def test_evidence_query_returns_only_publishable_records(ctx):
    by_class = ids_by_classification(ctx)
    assert by_class["internal"] and by_class["restricted"]  # the seed has both

    is_error, result = call(ctx, "evidence_query", {"limit": 100})
    assert is_error is False
    returned = {r["id"] for r in result["records"]}
    assert returned == by_class["publishable"]
    assert not returned & by_class["internal"]
    assert not returned & by_class["restricted"]
    assert result["count"] == len(by_class["publishable"]) and result["truncated"] is False
    for record in result["records"]:
        assert set(record) == RECORD_KEYS          # no payload, no classification
        assert isinstance(record["summary"], str) and record["summary"]
        assert record["result"] in {"pass", "fail"}
        assert record["sha256"] == ctx.store.get(record["id"]).sha256


def test_evidence_query_filters(ctx):
    restricted = ids_by_classification(ctx)["restricted"]
    is_error, result = call(ctx, "evidence_query", {"control_id": "CTL-CRYPTO-01"})
    assert is_error is False
    kinds = sorted(r["kind"] for r in result["records"])
    assert kinds == ["kms.key.rotation", "storage.encrypted"]      # restricted finding.open excluded
    assert not {r["id"] for r in result["records"]} & restricted

    _, by_kind = call(ctx, "evidence_query", {"kind": "tls.policy"})
    assert [r["kind"] for r in by_kind["records"]] == ["tls.policy"]
    _, hidden = call(ctx, "evidence_query", {"kind": "finding.open"})  # exists, but restricted
    assert hidden == {"records": [], "count": 0, "truncated": False}


def test_evidence_query_limit(ctx):
    publishable = len(ids_by_classification(ctx)["publishable"])
    _, page = call(ctx, "evidence_query", {"limit": 2})
    assert page["count"] == 2 and len(page["records"]) == 2 and page["truncated"] is True
    _, clamped = call(ctx, "evidence_query", {"limit": 5000})     # capped at 100, seed has fewer
    assert clamped["count"] == publishable and clamped["truncated"] is False
    is_error, text = call(ctx, "evidence_query", {"limit": 0})
    assert is_error is True and "limit" in text


# -- evidence_get ----------------------------------------------------------------

def test_evidence_get_publishable_record(ctx):
    record = ctx.store.get("EV-0001")
    assert record.classification == "publishable"
    is_error, result = call(ctx, "evidence_get", {"id": "EV-0001"})
    assert is_error is False
    assert set(result) == RECORD_KEYS
    assert result["id"] == "EV-0001" and result["sha256"] == record.sha256
    assert result["summary"] == record.payload["summary"]


def test_evidence_get_restricted_internal_and_missing_are_indistinguishable(ctx):
    by_class = ids_by_classification(ctx)
    restricted = sorted(by_class["restricted"])[0]
    internal = sorted(by_class["internal"])[0]
    missing = "EV-9999"
    assert ctx.store.get(missing) is None

    responses = {}
    for rid in (restricted, internal, missing):
        response = rpc(ctx, "tools/call", {"name": "evidence_get", "arguments": {"id": rid}})
        assert "error" not in response                       # a tool result, not a protocol error
        result = response["result"]
        assert result["isError"] is True
        assert result["content"] == [{"type": "text", "text": f"{rid} is not publishable"}]
        responses[rid] = json.dumps(result, sort_keys=True).replace(rid, "<ID>")
    assert len(set(responses.values())) == 1                 # byte-identical modulo the id echoed back


# -- controls_posture ------------------------------------------------------------

@pytest.mark.parametrize("framework", ["soc2", "iso27001", "hipaa"])
def test_controls_posture_rows(ctx, framework):
    publishable = ids_by_classification(ctx)["publishable"]
    is_error, result = call(ctx, "controls_posture", {"framework": framework})
    assert is_error is False
    assert result["framework"] == framework and result["framework_name"]
    rows = result["rows"]
    assert rows and all(set(r) == ROW_KEYS for r in rows)
    assert {r["state"] for r in rows} <= {"PASS", "DEGRADED", "FAIL"}
    assert result["counts"]["total"] == len(rows)
    assert result["counts"]["pass"] + result["counts"]["degraded"] + result["counts"]["fail"] == len(rows)
    for row in rows:
        assert set(row["evidence_ids"]) <= publishable         # never cite what cannot be fetched
    expected = {r["control_id"]: r["state"] for r in ctx.engine.posture(framework)}
    assert {r["control_id"]: r["state"] for r in rows} == expected


def test_controls_posture_reflects_the_seeded_gap(ctx):
    _, hipaa = call(ctx, "controls_posture", {"framework": "hipaa"})
    states = {r["control_id"]: r["state"] for r in hipaa["rows"]}
    assert states["CTL-VENDOR-01"] == "FAIL"                  # missing BAAs
    assert states["CTL-PRIV-01"] == "DEGRADED"                # quarterly review past SLA
    assert states["CTL-CRYPTO-01"] == "PASS"                  # restricted finding is not a required kind
    is_error, text = call(ctx, "controls_posture", {"framework": "pci"})
    assert is_error is True and "framework" in text


# -- error paths -----------------------------------------------------------------

def test_unknown_tool_is_an_error_result(ctx):
    response = rpc(ctx, "tools/call", {"name": "evidence_append", "arguments": {}})
    assert "error" not in response
    assert response["result"]["isError"] is True
    assert "Unknown tool" in response["result"]["content"][0]["text"]


def test_bad_arguments_are_error_results(ctx):
    cases = [
        ("evidence_query", {"payload": True}),                # additionalProperties: false
        ("evidence_query", {"limit": "ten"}),                 # wrong type
        ("evidence_get", {}),                                 # missing required
        ("evidence_get", {"id": 1}),                          # wrong type
        ("controls_posture", {"framework": "nist"}),          # not in enum
    ]
    for tool, arguments in cases:
        is_error, text = call(ctx, tool, arguments)
        assert is_error is True, (tool, arguments, text)


def test_unknown_method_is_32601(ctx):
    response = rpc(ctx, "resources/list", id=9)
    assert response == {"jsonrpc": "2.0", "id": 9, "error": {"code": -32601, "message": "Method not found: resources/list"}}
    assert rpc(ctx, "tools/delete")["error"]["code"] == -32601


def test_malformed_requests(ctx):
    assert handle("not an object", ctx)["error"]["code"] == -32600
    assert handle({"jsonrpc": "2.0", "id": 1}, ctx)["error"]["code"] == -32600          # no method
    assert handle({"jsonrpc": "1.0", "id": 1, "method": "ping"}, ctx)["error"]["code"] == -32600
    assert rpc(ctx, "tools/call", {"name": ""})["error"]["code"] == -32602               # bad params
    assert rpc(ctx, "tools/call", {"name": "evidence_get", "arguments": []})["error"]["code"] == -32602
    assert handle({"jsonrpc": "2.0", "id": 2, "method": "ping", "params": "x"}, ctx)["error"]["code"] == -32602


# -- audit -----------------------------------------------------------------------

def test_every_tool_call_is_audited(ctx):
    before = len(ctx.audit.all())
    rpc(ctx, "tools/list")
    rpc(ctx, "ping")
    assert len(ctx.audit.all()) == before                     # reads of the tool surface are not tool calls
    call(ctx, "evidence_query", {"limit": 1})
    call(ctx, "evidence_get", {"id": "EV-9999"})
    call(ctx, "nope")
    entries = ctx.audit.all()[before:]
    assert [e.subject for e in entries] == ["evidence_query", "evidence_get", "nope"]
    for entry in entries:
        assert entry.actor == "mcp-client" and entry.action == "mcp.tools/call"
        assert entry.rule is None and entry.approver is None
    assert entries[0].detail.startswith("ok;")
    assert entries[1].detail.startswith("error: EV-9999 is not publishable")
    assert entries[2].detail.startswith("error: Unknown tool")


# -- the real thing over stdio ---------------------------------------------------

def test_stdio_subprocess_round_trip(tmp_path):
    data = tmp_path / "data"
    store, audit = seed(data)
    publishable = {r.id for r in store.all() if r.classification == "publishable"}
    audited_before = len(audit.all())

    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "pytest", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "evidence_query", "arguments": {"limit": 100}}},
    ]
    stdin = "".join(json.dumps(m) + "\n" for m in messages) + "{this is not json\n"

    proc = subprocess.run(
        [sys.executable, "-m", "attest.mcp_server", "--data", str(data)],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr

    lines = proc.stdout.splitlines()
    assert lines and all(line.strip() for line in lines)
    responses = [json.loads(line) for line in lines]           # every stdout line is JSON ...
    assert all(r["jsonrpc"] == "2.0" for r in responses)       # ... and every one is JSON-RPC
    assert [r["id"] for r in responses] == [1, 2, 3, None]     # notification got no reply; parse error has id null

    init, listing, query, parse_error = responses
    assert init["result"]["protocolVersion"] == "2025-11-25"
    assert init["result"]["serverInfo"]["name"] == "attest-evidence"
    assert [t["name"] for t in listing["result"]["tools"]] == TOOL_NAMES
    assert query["result"]["isError"] is False
    payload = json.loads(query["result"]["content"][0]["text"])
    assert {r["id"] for r in payload["records"]} == publishable
    assert parse_error["error"]["code"] == -32700

    # The call was audited by the subprocess, on disk, with the fixed actor (fresh handle: the seed's is cached).
    entries = AuditLog(data / "audit.jsonl").all()
    assert len(entries) == audited_before + 1
    assert entries[-1].actor == "mcp-client" and entries[-1].action == "mcp.tools/call" and entries[-1].subject == "evidence_query"


def test_mcp_from_config_requires_a_key_with_read_evidence(tmp_path, monkeypatch):
    """The real-tool path: SQL store from attest.toml, identity from an API key."""
    from attest.auth import AuthError, create_api_key, create_user
    from attest.config import default_config_toml
    from attest.db import get_engine, upgrade
    from attest.mcp_server import Context, handle
    from attest.seed import seed_into
    from attest.store_sql import SqlAuditLog, SqlEvidenceStore

    cfg_path = tmp_path / "attest.toml"
    cfg_path.write_text(default_config_toml(mode="production", storage_url=f"sqlite:///{tmp_path/'m.db'}"))
    url = f"sqlite:///{tmp_path/'m.db'}"
    upgrade(url); engine = get_engine(url)
    seed_into(SqlEvidenceStore(engine), SqlAuditLog(engine))
    create_user(engine, "ci@example.com", "service")
    secret, _ = create_api_key(engine, "ci@example.com", "mcp")
    with pytest.raises(AuthError):
        Context.from_config(str(cfg_path), None)
    with pytest.raises(AuthError):
        Context.from_config(str(cfg_path), "atst_nope")
    ctx = Context.from_config(str(cfg_path), secret)
    assert ctx.actor == "mcp:ci@example.com"
    res = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                  "params": {"name": "evidence_query", "arguments": {"limit": 5}}}, ctx)
    assert res["result"]["isError"] is False
    assert ctx.audit.query(action_prefix="mcp.")[0].actor == "mcp:ci@example.com"
