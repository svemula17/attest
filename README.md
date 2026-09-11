# Attest

A self-hosted, continuous compliance control plane with a governed AI agent layer.

Controls are tested continuously against evidence and mapped outward to SOC 2, ISO/IEC 27001:2022 and the HIPAA Security Rule. Evidence is append-only and hash-chained. Agents draft questionnaire answers and read untrusted vendor documents behind guardrails that are enforced in code — every claim cites an evidence record, and a named human signs every decision.

```
Sources ──► Collectors ──► Evidence store ──► Control engine ──► Agent layer ──► Human approval ──► Audit log
 22 systems  scheduled     append-only,       one catalog,       6 guardrails,    HMAC-signed      actor · model
 8 families  or imported   SHA-256 chained    3 frameworks       drafts only      by a named user  version · approver
```

## Run it

```bash
pip install -e ".[dev]"
attest init --sandbox          # attest.toml + attest.db + demo users, seeded with representative evidence
attest serve                   # http://127.0.0.1:8765  (API docs at /docs)
```

Sandbox mode signs the browser in as the demo engineer; switch personas from the top bar to watch the requester-scoped-identity guardrail deny an auditor. For a real installation:

```bash
attest init --admin-email you@example.com      # production mode: prints the admin API key once
attest serve
```

Or with Docker (Postgres included):

```bash
docker compose up               # http://localhost:8765 · admin@example.com / change-me on first boot
```

## Feed it evidence — no integrations required

`attest init` writes `attest.toml` with four sources that read files from `imports/`:

| Source | Type | What it does |
|---|---|---|
| `hris` | csv | `imports/hris-roster.csv` → one `hris.roster` record (employee_id, name, email, hired, terminated) |
| `idp` | csv | `imports/idp-users.csv` → one `idp.users` record (email, status, deprovisioned_at) |
| `leavers` | hris-idp-join | joins the two above; a terminated employee whose IdP account is still active fails **CTL-ACCESS-02** |
| `evidence` | json | `imports/evidence.json` → any evidence records, one per object |

```bash
attest collect hris && attest collect idp && attest collect leavers   # or click "Run now" in the console
attest import my-export.csv --mapping evidence                        # generic CSV: source,kind,control_ids,classification,collected_at,summary,result
```

Every import is validated as a whole before a single record is written, recorded as a collector run, and hash-chained on ingest. Add a `schedule = "0 6 * * *"` (cron, UTC) to any source and the built-in scheduler runs it.

Live collectors so far: **GitHub** (branch protection, `GITHUB_TOKEN`) and the **HRIS × IdP join**. The evidence-source catalog in [`attest/sources.py`](attest/sources.py) names the 22 systems across eight families that a real fleet fills in.

## Identity and roles

| Role | Grants |
|---|---|
| admin | everything, plus users and API keys |
| engineer | read evidence and documents, approve questionnaires, run collectors, manage acceptances, import |
| auditor | read evidence |
| service | read evidence, run collectors, import — for CI and the MCP server |

People sign in with a password (`attest users add`); services use `Authorization: Bearer atst_…` (`attest keys create`). The agent layer inherits the requester's grants, never a service account's — that is the confused-deputy control, and it runs on real identities.

## What the API gives you

`GET /docs` is the full OpenAPI surface. The important ones:

- `GET /api/state` — everything the console renders
- `POST /api/answer` · `POST /api/decide` · `POST /api/read-doc` — the agent layer and the human decision
- `GET /api/evidence` · `GET /api/audit` · `GET /api/controls/{id}/history` — the ledger and control history
- `POST /api/import` · `POST /api/sources/{id}/collect` · `GET /api/runs`
- `GET /api/gate` · `POST /api/acceptances` — the CI gate with expiring risk acceptances

CI gate: `attest gate` exits non-zero on any FAIL without a current acceptance; `--strict` makes DEGRADED fail too. This repository gates itself in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Guardrails (code, not prompts)

| Rule | What it enforces | Threat |
|---|---|---|
| `untrusted-doc-isolation` | untrusted documents are read in a context with zero write-capable tools | LLM01 |
| `citation-required` | every generated claim resolves to an evidence id, or the draft is rejected | grounding |
| `egress-classification-gate` | customer-facing agents query the publishable set only — a retrieval boundary | LLM02 |
| `tool-allowlist` | declared tools, pinned MCP servers, no dynamic loading | LLM06 |
| `max-steps` | a hard step budget the agent cannot raise | LLM06 |
| `requester-scoped-identity` | the agent acts with the requester's grants | confused deputy |

Optional: set `[llm] enabled = true` and install `attest[llm]` to have Claude draft answers — the same guardrails validate its output, and a hallucinated citation is rejected before a reviewer ever sees it.

## Layout

```
attest/
  db.py  store_sql.py  migrations/   relational storage, hash-chained, Alembic migrations
  config.py                          attest.toml
  auth.py  api.py  service.py        identity, HTTP surface, domain layer
  controls.py  sources.py            control catalog · evidence-source catalog
  evidence.py  audit.py              the original JSONL stores (still used by the CLI's data-dir commands and tests)
  agent.py  guardrails.py  llm.py    the governed agent layer
  importers.py  collectors/          CSV/JSON import, GitHub, HRIS×IdP join, the registry
  scheduler.py                       cron-scheduled collector runs
  mcp_server.py                      read-only MCP server over the publishable evidence
dashboard/                           the console (one HTML file) and the sign-in page
deck/                                the presentation and its build script
```

## Honest scope

Real: the storage, control engine, guardrails, agents, audit log, auth, scheduler, importers, GitHub collector and the join — all with tests. Not yet: live AWS/Okta/HRIS collectors (CSV/JSON import stands in), OIDC login (local passwords and API keys for now), notifications, evidence-package export.
