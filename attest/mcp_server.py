"""Read-only MCP server over stdio for the attest evidence store.

This is the concrete artifact behind the claim "read-only MCP scoped to named
collections, pinned tool definitions, no dynamic tool loading":

* **Read-only.** Exactly three tools, every one of them a query.  Nothing in
  this module can append, approve, decide, or write anything except its own
  audit entries; the tool annotations advertise ``readOnlyHint: true``.
* **Scoped.** Only records classified ``publishable`` ever leave the process.
  The store is queried with ``max_classification="publishable"`` and the
  result is re-checked by :func:`attest.guardrails.egress_classification_gate`
  before serialisation.  Raw payloads are never returned; only ``summary`` and
  ``result`` are surfaced.
* **Pinned.** :data:`TOOLS` is a module-level tuple.  ``tools/list`` returns a
  copy of it, ``listChanged`` is ``false``, and there is no registration API.
* **Audited.** Every ``tools/call`` (including unknown tool names) is written
  to the append-only :class:`attest.audit.AuditLog`.

Transport: newline-delimited JSON-RPC 2.0 on stdin/stdout.  Stdout carries
JSON-RPC responses only; all logging goes to stderr.  Stdlib only.
"""
from __future__ import annotations

import argparse
import os
import copy
import json
import sys
from pathlib import Path
from typing import Any, Callable, TextIO

from attest import __version__
from attest.audit import AuditLog
from attest.controls import FRAMEWORKS, ControlEngine, default_catalog
from attest.evidence import EvidenceStore
from attest.guardrails import GuardrailViolation, egress_classification_gate
from attest.util import canonical_json

__all__ = ["TOOLS", "Context", "handle", "serve", "main"]

SERVER_NAME = "attest-evidence"
SERVER_VERSION = __version__  # "0.1.0"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-11-25")
DEFAULT_PROTOCOL_VERSION = "2025-06-18"

EGRESS_CEILING = "publishable"   # the only classification that may leave the process
DEFAULT_LIMIT = 20
MAX_LIMIT = 100

AUDIT_ACTOR = "mcp-client"
AUDIT_ACTION = "mcp.tools/call"

# JSON-RPC 2.0 error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

INSTRUCTIONS = (
    "attest-evidence is a read-only view of a compliance evidence store. "
    "Only evidence classified 'publishable' is visible; internal and restricted "
    "records are never returned and cannot be probed for. Nothing here can "
    "create, modify, approve or delete anything. Cite evidence by id (EV-xxxx) "
    "and sha256."
)

_READ_ONLY_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}

# --------------------------------------------------------------------------- #
# Pinned tool definitions.  This tuple is the whole tool surface: there is no
# registration function and tools/list never returns anything else.
# --------------------------------------------------------------------------- #
TOOLS: tuple[dict, ...] = (
    {
        "name": "evidence_query",
        "description": (
            "List publishable evidence records from the append-only, hash-chained "
            "evidence store. Optional exact-match filters: control_id (internal "
            "control id such as CTL-CRYPTO-01) and kind (evidence kind such as "
            "kms.key.rotation). Each record has id, source, kind, control_ids, "
            "collected_at, summary, result and sha256; raw payloads are never "
            "returned. Records classified internal or restricted are never "
            "returned and never counted."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "control_id": {
                    "type": "string",
                    "description": "Exact internal control id, e.g. CTL-CRYPTO-01.",
                },
                "kind": {
                    "type": "string",
                    "description": "Exact evidence kind, e.g. kms.key.rotation.",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "default": DEFAULT_LIMIT,
                    "description": f"Maximum records to return (default {DEFAULT_LIMIT}; capped at {MAX_LIMIT}).",
                },
            },
            "additionalProperties": False,
        },
        "annotations": {"title": "Query publishable evidence", **_READ_ONLY_ANNOTATIONS},
    },
    {
        "name": "evidence_get",
        "description": (
            "Fetch one publishable evidence record by id (e.g. EV-0001), with the "
            "same fields as evidence_query. An id that is missing and an id that "
            "exists but is not publishable produce the identical error, so this "
            "tool cannot be used to probe for restricted records."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Evidence record id, e.g. EV-0001."},
            },
            "required": ["id"],
            "additionalProperties": False,
        },
        "annotations": {"title": "Get one publishable evidence record", **_READ_ONLY_ANNOTATIONS},
    },
    {
        "name": "controls_posture",
        "description": (
            "Evaluate the control catalog against the evidence store and return "
            "the posture rows for one framework. Each row has framework_id (the "
            "framework's own clause id), control_id, name, state (PASS, DEGRADED "
            "or FAIL), evidence_ids (publishable records only) and spec (HIPAA "
            "'required' / 'addressable', or null). States are computed from all "
            "evidence; only citable (publishable) evidence ids are listed."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "enum": list(FRAMEWORKS),  # ["soc2", "iso27001", "hipaa"]
                    "description": "Framework to report: soc2, iso27001 or hipaa.",
                },
            },
            "required": ["framework"],
            "additionalProperties": False,
        },
        "annotations": {"title": "Control posture by framework", **_READ_ONLY_ANNOTATIONS},
    },
)


# --------------------------------------------------------------------------- #
# Server context
# --------------------------------------------------------------------------- #
class Context:
    """Open handles for one server process (store, audit log, control engine)."""

    def __init__(self, data_dir: Path | None = None, store=None, audit=None, actor: str | None = None):
        if store is None:  # the PoC layout: JSONL files in a data directory
            self.data_dir = Path(data_dir or "data")
            store = EvidenceStore(self.data_dir / "evidence.jsonl")
            audit = AuditLog(self.data_dir / "audit.jsonl")
        else:
            self.data_dir = None
        self.store = store
        self.audit = audit
        self.actor = actor or AUDIT_ACTOR
        self.engine = ControlEngine(default_catalog(), self.store)
        self.protocol_version = DEFAULT_PROTOCOL_VERSION
        self.initialized = False

    @classmethod
    def from_config(cls, config_path: str | None, api_key: str | None) -> "Context":
        """The real tool: SQL store from attest.toml, identity from an API key with read:evidence."""
        from attest.auth import AuthError, authenticate_api_key
        from attest.config import load_config
        from attest.db import get_engine, upgrade
        from attest.store_sql import SqlAuditLog, SqlEvidenceStore
        cfg = load_config(config_path)
        url = cfg.storage.url
        if url.startswith("sqlite:///") and not url.startswith("sqlite:////"):
            url = "sqlite:///" + str(cfg.resolve(url[len("sqlite:///"):]))
        if not api_key:
            raise AuthError("ATTEST_API_KEY is required to serve MCP from attest.toml (create one with `attest keys create`)")
        upgrade(url)
        engine = get_engine(url)
        identity = authenticate_api_key(engine, api_key)
        identity.require("read:evidence")
        ctx = cls(store=SqlEvidenceStore(engine), audit=SqlAuditLog(engine), actor=f"mcp:{identity.email}")
        ctx.identity = identity
        return ctx


class ToolError(Exception):
    """A tool-level failure. Reported to the client as an ``isError`` result, never as a JSON-RPC error."""


class _InvalidParams(Exception):
    """Malformed ``params`` on a request; becomes JSON-RPC error -32602."""


def _log(message: str) -> None:
    """Operator log. Never stdout: that channel carries JSON-RPC only."""
    print(f"[{SERVER_NAME}] {message}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #
def _public_record(record) -> dict:
    """The only projection of an evidence record that leaves the process."""
    payload = record.payload if isinstance(record.payload, dict) else {}
    return {
        "id": record.id,
        "source": record.source,
        "kind": record.kind,
        "control_ids": list(record.control_ids),
        "collected_at": record.collected_at,
        "summary": payload.get("summary"),
        "result": payload.get("result"),
        "sha256": record.sha256,
    }


def _not_publishable(record_id: str) -> str:
    # One message for "missing" and "exists but restricted": existence is not disclosed.
    return f"{record_id} is not publishable"


def _evidence_query(args: dict, ctx: Context) -> dict:
    limit = args.get("limit", DEFAULT_LIMIT)
    if isinstance(limit, float) and limit.is_integer():
        limit = int(limit)
    if limit < 1:
        raise ToolError("Argument 'limit' must be at least 1")
    limit = min(limit, MAX_LIMIT)

    matches = ctx.store.query(
        control_id=args.get("control_id"),
        kind=args.get("kind"),
        max_classification=EGRESS_CEILING,
    )
    page = matches[:limit]
    egress_classification_gate(page, EGRESS_CEILING)  # belt and braces; raises GuardrailViolation
    return {
        "records": [_public_record(r) for r in page],
        "count": len(page),
        "truncated": len(matches) > limit,
    }


def _evidence_get(args: dict, ctx: Context) -> dict:
    record_id = args["id"]
    record = ctx.store.get(record_id)
    if record is not None:
        try:
            egress_classification_gate([record], EGRESS_CEILING)
        except GuardrailViolation as exc:
            _log(f"evidence_get refused by {exc.rule}")
            record = None
    if record is None:
        raise ToolError(_not_publishable(record_id))
    return _public_record(record)


def _controls_posture(args: dict, ctx: Context) -> dict:
    framework = args["framework"]
    try:
        rows = ctx.engine.posture(framework)
    except ValueError as exc:
        raise ToolError(str(exc)) from None
    citable = {r.id for r in ctx.store.query(max_classification=EGRESS_CEILING)}
    for row in rows:
        row["evidence_ids"] = [i for i in row["evidence_ids"] if i in citable]
    counts = {
        "pass": sum(1 for r in rows if r["state"] == "PASS"),
        "degraded": sum(1 for r in rows if r["state"] == "DEGRADED"),
        "fail": sum(1 for r in rows if r["state"] == "FAIL"),
        "total": len(rows),
    }
    return {
        "framework": framework,
        "framework_name": FRAMEWORKS[framework],
        "rows": rows,
        "counts": counts,
    }


_TOOL_HANDLERS: dict[str, Callable[[dict, Context], dict]] = {
    "evidence_query": _evidence_query,
    "evidence_get": _evidence_get,
    "controls_posture": _controls_posture,
}
_TOOL_SCHEMAS: dict[str, dict] = {tool["name"]: tool["inputSchema"] for tool in TOOLS}
assert set(_TOOL_HANDLERS) == set(_TOOL_SCHEMAS), "every pinned tool needs exactly one handler"


def _validate_arguments(schema: dict, arguments: dict) -> None:
    """Minimal JSON-schema check sufficient for the pinned schemas (types, enum, required, no extras)."""
    properties = schema["properties"]
    extra = sorted(set(arguments) - set(properties))
    if extra:
        raise ToolError(f"Unexpected argument(s): {', '.join(extra)}")
    for key in schema.get("required", ()):
        if key not in arguments:
            raise ToolError(f"Missing required argument: {key}")
    for key, value in arguments.items():
        spec = properties[key]
        expected = spec.get("type")
        if expected == "string" and not isinstance(value, str):
            raise ToolError(f"Argument '{key}' must be a string")
        if expected == "integer":
            integral = isinstance(value, int) and not isinstance(value, bool)
            integral = integral or (isinstance(value, float) and value.is_integer())
            if not integral:
                raise ToolError(f"Argument '{key}' must be an integer")
        if "enum" in spec and value not in spec["enum"]:
            raise ToolError(f"Argument '{key}' must be one of: {', '.join(spec['enum'])}")


# --------------------------------------------------------------------------- #
# JSON-RPC methods
# --------------------------------------------------------------------------- #
def _initialize(params: dict, ctx: Context) -> dict:
    requested = params.get("protocolVersion")
    ctx.protocol_version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
    return {
        "protocolVersion": ctx.protocol_version,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        "instructions": INSTRUCTIONS,
    }


def _ping(params: dict, ctx: Context) -> dict:
    return {}


def _tools_list(params: dict, ctx: Context) -> dict:
    # Copies, so a caller can never mutate the pinned definitions.
    return {"tools": [copy.deepcopy(tool) for tool in TOOLS]}


def _tools_call(params: dict, ctx: Context) -> dict:
    name = params.get("name")
    if not isinstance(name, str) or not name:
        raise _InvalidParams("tools/call requires a non-empty string 'name'")
    arguments = params.get("arguments")
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise _InvalidParams("tools/call 'arguments' must be an object")

    is_error, text = True, "Internal error"
    try:
        tool = _TOOL_HANDLERS.get(name)
        if tool is None:
            raise ToolError(f"Unknown tool: {name}")
        _validate_arguments(_TOOL_SCHEMAS[name], arguments)
        text, is_error = json.dumps(tool(arguments, ctx)), False
    except ToolError as exc:
        text = str(exc)
    except GuardrailViolation as exc:  # the egress gate fired: refuse, log the rule, disclose nothing
        _log(f"{name} refused by guardrail {exc.rule}")
        text = f"{name} refused by guardrail {exc.rule}"
    finally:
        status = "ok" if not is_error else f"error: {text}"
        ctx.audit.record(
            actor=ctx.actor,
            action=AUDIT_ACTION,
            subject=name[:200],
            rule=None,
            detail=f"{status}; arguments={canonical_json(arguments)}"[:1000],
        )
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


_METHODS: dict[str, Callable[[dict, Context], dict]] = {
    "initialize": _initialize,
    "ping": _ping,
    "tools/list": _tools_list,
    "tools/call": _tools_call,
}


def _error(request_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def handle(request: Any, ctx: Context) -> dict | None:
    """Handle one decoded JSON-RPC message. Returns the response dict, or ``None`` for notifications."""
    if not isinstance(request, dict):
        return _error(None, INVALID_REQUEST, "Invalid Request: expected a JSON object")
    is_notification = "id" not in request
    request_id = request.get("id")
    method = request.get("method")
    if request.get("jsonrpc", "2.0") != "2.0" or not isinstance(method, str):
        return None if is_notification else _error(request_id, INVALID_REQUEST, "Invalid Request")
    params = request.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return None if is_notification else _error(request_id, INVALID_PARAMS, "Invalid params: expected an object")

    if is_notification:
        if method == "notifications/initialized":
            ctx.initialized = True
        else:
            _log(f"ignoring notification {method}")
        return None

    handler = _METHODS.get(method)
    if handler is None:
        return _error(request_id, METHOD_NOT_FOUND, f"Method not found: {method}")
    try:
        result = handler(params, ctx)
    except _InvalidParams as exc:
        return _error(request_id, INVALID_PARAMS, f"Invalid params: {exc}")
    except Exception as exc:  # a bug must neither kill the loop nor leak a traceback to the client
        _log(f"internal error in {method}: {exc!r}")
        return _error(request_id, INTERNAL_ERROR, "Internal error")
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


# --------------------------------------------------------------------------- #
# stdio transport
# --------------------------------------------------------------------------- #
def _write(stdout: TextIO, message: dict) -> None:
    stdout.write(json.dumps(message, ensure_ascii=True) + "\n")
    stdout.flush()


def serve(stdin: TextIO, stdout: TextIO, ctx: Context) -> int:
    """Read newline-delimited JSON-RPC from ``stdin`` until EOF; write responses to ``stdout``."""
    while True:
        line = stdin.readline()
        if not line:
            return 0
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            _write(stdout, _error(None, PARSE_ERROR, "Parse error"))
            continue
        if isinstance(request, list):  # JSON-RPC batching was removed from MCP in 2025-06-18
            _write(stdout, _error(None, INVALID_REQUEST, "Invalid Request: batches are not supported"))
            continue
        response = handle(request, ctx)
        if response is not None:
            _write(stdout, response)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="attest-mcp",
        description="Read-only MCP server (stdio) over the attest evidence store.",
    )
    parser.add_argument(
        "--data",
        type=Path,
        default=None,
        help="PoC layout: directory holding evidence.jsonl and audit.jsonl",
    )
    parser.add_argument("--config", help="attest.toml of a real installation; requires $ATTEST_API_KEY (a key with read:evidence)")
    args = parser.parse_args(argv)
    if args.config or (args.data is None and os.environ.get("ATTEST_CONFIG")):
        try:
            ctx = Context.from_config(args.config, os.environ.get("ATTEST_API_KEY"))
        except Exception as e:  # never start with a half-configured identity
            _log(f"refusing to start: {e}")
            return 2
        _log(f"v{SERVER_VERSION} serving {len(TOOLS)} read-only tools as {ctx.actor} over stdio")
    else:
        ctx = Context(args.data or Path("data"))
        _log(f"v{SERVER_VERSION} serving {len(TOOLS)} read-only tools from {ctx.data_dir} over stdio")
    try:
        return serve(sys.stdin, sys.stdout, ctx)
    except (KeyboardInterrupt, BrokenPipeError):
        return 0


if __name__ == "__main__":
    sys.exit(main())
