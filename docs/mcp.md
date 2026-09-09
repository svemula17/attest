# MCP server (read-only)

`attest.mcp_server` exposes the evidence store to AI clients as a **read-only MCP server over stdio**.
It is the concrete artifact behind the claim *"read-only MCP scoped to named collections, pinned tool definitions, no dynamic tool loading."*
Stdlib only: no `mcp` package, no third-party dependencies.

## What it exposes

Exactly three tools, all queries:

| Tool | Arguments | Returns |
|---|---|---|
| `evidence_query` | `control_id?`, `kind?`, `limit?` (default 20, capped at 100) | publishable records: `id, source, kind, control_ids, collected_at, summary, result, sha256` |
| `evidence_get` | `id` | one publishable record, same fields |
| `controls_posture` | `framework`: `soc2` \| `iso27001` \| `hipaa` | posture rows: `framework_id, control_id, name, state, evidence_ids, spec` plus counts |

Every tool schema sets `additionalProperties: false` and carries `readOnlyHint: true`.
The server implements `initialize` (protocol `2025-06-18` or `2025-11-25`), `notifications/initialized`, `ping`, `tools/list` and `tools/call`; anything else is JSON-RPC `-32601`.

## Why it is read-only, and how that is enforced

- **No write path.** The tool set has no append/approve/decide operation. `TOOLS` is a module-level tuple; `tools/list` returns copies, `listChanged` is `false`, and there is no registration API, so the surface an AI client sees is the surface that was reviewed.
- **Scoped to publishable evidence.** Queries run with `max_classification="publishable"` and results are re-checked by `attest.guardrails.egress_classification_gate` before serialisation. Raw payloads never leave the process; only `summary` and `result` are surfaced.
- **No existence oracle.** `evidence_get` returns the identical error (`EV-xxxx is not publishable`) whether an id is missing, internal or restricted. `controls_posture` computes states from all evidence but lists only publishable ids, so nothing non-citable is ever named.
- **Audited.** Every `tools/call`, including unknown tool names and refused lookups, is written to the append-only audit log as `actor=mcp-client action=mcp.tools/call subject=<tool>`.
- **Clean channel.** Stdout carries JSON-RPC responses only; all logging goes to stderr.

## Running it

```sh
cd /absolute/path/attest
python3 -m attest.mcp_server --data /absolute/path/attest/data
```

(`attest-mcp` is available as a console script once `attest-mcp = "attest.mcp_server:main"` is added under `[project.scripts]` and the package is installed.)

## Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "attest-evidence": {
      "command": "python3",
      "args": ["-m", "attest.mcp_server", "--data", "/absolute/path/attest/data"],
      "cwd": "/absolute/path/attest"
    }
  }
}
```

`cwd` may not be supported by every client. If it is not, either set `PYTHONPATH` instead:

```json
"attest-evidence": {
  "command": "python3",
  "args": ["-m", "attest.mcp_server", "--data", "/absolute/path/attest/data"],
  "env": {"PYTHONPATH": "/absolute/path/attest"}
}
```

or wrap the command in a shell:

```json
"attest-evidence": {
  "command": "sh",
  "args": ["-c", "cd /absolute/path/attest && python3 -m attest.mcp_server --data /absolute/path/attest/data"]
}
```

## Claude Code

```sh
claude mcp add attest-evidence -e PYTHONPATH=/absolute/path/attest -- python3 -m attest.mcp_server --data /absolute/path/attest/data
```
