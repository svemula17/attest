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

## Live collectors

Every source is a `[sources.<id>]` block in `attest.toml`; secrets are always named by environment variable, never written in the file (the config loader refuses literal tokens).

| Type | Reads | Feeds |
|---|---|---|
| `aws` | Config rule compliance, IAM account summary + access-key age, Access Analyzer findings, CloudTrail trails, GuardDuty findings, Security Hub failed findings — via a read-only role (`role_arn` optional) | encryption, network, logging, IAM, detection controls |
| `okta` | users + status, MFA factors, sign-on policy | `idp.users` (join input), `idp.mfa-enrollment`, `sso.enforced` |
| `github` | org-wide branch protection, required checks, secret-scanning alerts, sampled merged PRs with approvals | change-management controls |
| `bamboohr` | the employee roster with hire/termination dates | `hris.roster` (join input) |
| `hris-idp-join` | the two records above | `access.leaver-deprovisioned` → **CTL-ACCESS-02** |
| `http-json` | any JSON API, with a summary template and pass/fail checks you declare | any kind in the catalog |
| `csv` / `json` | files under `imports/` | anything |

Sign in with your identity provider: `[auth.oidc]` (Okta, Entra ID, Google — any OpenID Connect issuer; Authorization Code + PKCE, ID tokens verified against JWKS, roles mapped from a claim). Docs: [`docs/collectors-aws-okta.md`](docs/collectors-aws-okta.md), [`docs/collectors-github-hris-http.md`](docs/collectors-github-hris-http.md).

## For the audit

- **Evidence packages** — `attest package --framework hipaa --since 2026-01-01` (or the button on the Frameworks view) writes a zip: control matrix (CSV + JSON), posture, evidence records, hash-chain proof, audit trail, acceptances, and a manifest whose SHA-256s and HMAC signature `attest package-verify` checks. Restricted records stay out unless an engineer asks for them.
- **Questionnaires** — import a customer questionnaire (CSV/XLSX with a `question` column); the agent drafts every row with citations, humans approve in the queue, export CSV/XLSX with answers, approver and signature.
- **Control history** — click any control on the Posture view: pass rate, transitions and a timeline over the observation window (`GET /api/history/summary?days=90`).
- **Notifications** — a new FAIL, DEGRADED or join finding goes to Slack and/or Jira with an owner and a due date (`[notifications]`), deduplicated per control and state, recorded on the ledger.
- **WORM audit export** — `attest audit-export --s3 s3://bucket/prefix --retain-days 365` uploads the audit trail and its chain proof under S3 Object Lock (COMPLIANCE mode).
- **MCP** — `ATTEST_API_KEY=… attest-mcp --config attest.toml` serves the publishable evidence to AI clients as the key's user, every call audited.

## Hardening

Security headers (CSP, frame-ancestors, nosniff, referrer policy, optional HSTS), per-IP login throttling and per-identity API rate limits, an origin check on cookie-authenticated state changes, secrets by environment name only, signed approvals and packages, a hash-chained ledger with no update path, SBOM + `pip-audit` in CI and a tagged release pipeline that publishes wheels, an SBOM and a container image. See [`docs/security.md`](docs/security.md) and [`SECURITY.md`](SECURITY.md).

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
