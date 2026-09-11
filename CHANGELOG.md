# Changelog

All notable changes to Attest. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/). Release tags `v*` build the wheel, SBOM and container image (`.github/workflows/release.yml`).

## [0.3.0] — Unreleased

Live integrations, the audit-facing product surface, and hardening.

### Added
- **Collectors**: `aws` (Config rules, IAM summary and key age, Access Analyzer, CloudTrail, GuardDuty, Security Hub; optional `role_arn`), `okta` (users, MFA factors, sign-on policy), org-wide `github` (branch protection, required checks, secret scanning, sampled merge reviews across an organisation), `bamboohr` (roster with hire/termination dates), and `http-json` (any JSON API mapped to a catalog kind with a summary template and pass/fail checks). A shared collector base: kinds come from the catalog, secrets from named environment variables only.
- **OIDC sign-in** (`[auth.oidc]`): Authorization Code + PKCE against any OpenID Connect issuer, ID tokens verified against JWKS, roles mapped from a claim, domain allow-list, first-login user creation. `GET /api/auth/methods`, `/api/auth/oidc/start`, `/api/auth/oidc/callback`.
- **Evidence packages**: a signed zip for auditors — control matrix, posture, evidence, chain proof, audit trail, acceptances and an HMAC-signed manifest (`POST /api/package`, `GET /api/packages`, `attest package`, `attest package-verify`). Restricted records excluded unless requested.
- **Questionnaires**: import a customer questionnaire (CSV/XLSX), draft every row with citations, approve in the queue, export with answers, approver and signature (`/api/questionnaires…`, `attest questionnaire`).
- **Control history**: `GET /api/history/summary?days=` — pass rate, transitions and a timeline per control over the observation window.
- **Notifications** (`[notifications]`): a new FAIL, a PASS→DEGRADED transition or an HRIS × IdP finding goes to a Slack webhook and/or a Jira Cloud issue with an owner and a due date, deduplicated per control, kind and reason, every attempt recorded (`GET /api/notifications`). `attest.notify.diff_states` / `Notifier`.
- **WORM audit export**: `[security] audit_worm_bucket` / `audit_worm_retain_days`; `attest audit-export --s3` uploads the audit trail and its chain proof under S3 Object Lock (COMPLIANCE mode).
- **Request hardening** (`attest.security`, installed by `create_app`): security headers and a Content-Security-Policy, HSTS opt-in, per-IP login throttling and per-identity API rate limits (token bucket, `429` + `Retry-After`), and an origin check on cookie-authenticated state changes.
- **MCP over a real installation**: `attest-mcp --config attest.toml` with `$ATTEST_API_KEY` serves publishable evidence as that key's user.
- **Release pipeline**: on a `v*` tag — tests, wheel + sdist, CycloneDX SBOM, `pip-audit --strict`, image to `ghcr.io/<repo>:<tag>` and `:latest`, GitHub release with artifacts. `pip-audit` also runs in CI.
- **Docs**: `docs/` (install, configuration, security, operations, API, collectors), `SECURITY.md`, this changelog.
- Schema revision `0002`: `questionnaires`, `notifications`, `package_exports`; `drafts.questionnaire_id` and `drafts.ref`.

### Changed
- `pyproject.toml` extras: `postgres`, `aws`, `xlsx`; `dev` now includes `cyclonedx-bom`, `pip-audit`, `build`, `boto3`, `openpyxl`. `PyJWT[crypto]` is a core dependency (OIDC).
- The config parser rejects literal secrets in `[sources.*.params]`, `[notifications.jira]` and `[auth.oidc]`.
- API version string `0.3.0`.

## [0.2.0] — 2026-09-11

Phase 1 of the real tool: the proof of concept became an installable server.

### Added
- **Relational storage** on SQLAlchemy — SQLite by default, Postgres by URL — with Alembic migrations (`attest upgrade`), keeping the JSONL hash-chain semantics for evidence and audit rows (byte-identical digests) and adding control snapshots, collector runs, drafts with signed decisions, risk acceptances, users, API keys and settings. Concurrent appends are serialised on both backends.
- **`attest.toml`** (`attest init`): server, storage, auth, sources with cron schedules, acceptances, SLA overrides, LLM. `attest config` validates it.
- **Authentication and roles**: local passwords (PBKDF2), signed session cookies, `atst_` API keys stored hashed; roles `admin`, `engineer`, `auditor`, `service` resolve to grants, and the requester-scoped-identity guardrail runs on real identities. `attest users …`, `attest keys …`.
- **FastAPI HTTP surface** (`attest serve`, `/docs`): console state, the agent actions and the human decision, controls and history, evidence and audit, sources, runs, import, acceptances, the CI gate, users and keys, sandbox demo endpoints. The console is served from the same process with a sign-in page.
- **Scheduler**: cron-scheduled collector runs on APScheduler, UTC, coalesced, with misfire grace; jobs visible in `/api/health`.
- **Importers**: CSV (`evidence`, `hris.roster`, `idp.users`) and JSON (`evidence.json`) validated as a whole before anything is written; `attest import`, `POST /api/import`, and file-backed `csv`/`json` sources.
- **Collector registry** with run bookkeeping; the GitHub branch-protection collector and the HRIS × IdP join as configured sources (`attest collect`).
- **Docker**: a single image (`attest init` on first boot, `attest serve`), `docker-compose.yml` with Postgres 16 and a health check.
- **Evidence-source catalog** (`attest sources`): 22 systems across eight families, every control kind owned by exactly one source.
- Sandbox mode: seeded data, demo users and personas, tamper/reseed/terminate demos.

## [0.1.0] — 2026-09-09

The proof of concept: stdlib-only Python, JSONL stores, tests throughout.

### Added
- Append-only, SHA-256 hash-chained evidence store and audit log (`attest/evidence.py`, `attest/audit.py`) with `verify_chain()`.
- Control catalog and engine mapping internal controls to SOC 2, ISO/IEC 27001:2022 and the HIPAA Security Rule, with freshness SLAs and PASS / DEGRADED / FAIL states.
- Six guardrails enforced in code: untrusted-document isolation, citation required, egress classification gate, tool allowlist, step budget, requester-scoped identity — plus injection *detection* for logging.
- A deterministic answer agent and an isolated reader agent; optional Claude drafting behind the same guardrails.
- The console (one HTML file) and a stdlib HTTP server with personas; the CI gate (`attest gate`, `gate.json`); the read-only MCP server over publishable evidence; the HRIS × IdP join; the presentation deck.

[0.3.0]: https://github.com/svemula17/attest/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/svemula17/attest/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/svemula17/attest/releases/tag/v0.1.0
