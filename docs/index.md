# Attest documentation

Attest is a self-hosted, continuous compliance control plane with a governed AI agent layer.

Controls are tested continuously against evidence and mapped outward to SOC 2, ISO/IEC 27001:2022 and the HIPAA Security Rule. Evidence is append-only and hash-chained. Agents draft questionnaire answers and read untrusted vendor documents behind guardrails that are enforced in code: every claim cites an evidence record, and a named human signs every decision.

```
Sources ──► Collectors ──► Evidence store ──► Control engine ──► Agent layer ──► Human approval ──► Audit log
 22 systems  scheduled     append-only,       one catalog,       6 guardrails,    HMAC-signed      actor · model
 8 families  or imported   SHA-256 chained    3 frameworks       drafts only      by a named user  version · approver
```

One process serves everything: the HTTP API and console (`attest serve`), the cron scheduler that runs collectors, the control engine, and the agent layer. State lives in one database (SQLite by default, Postgres by URL) next to one config file, `attest.toml`.

## Where to start

| I want to… | Read |
|---|---|
| Run it — pip, `attest init`, Docker Compose, Postgres, upgrades | [install.md](install.md) |
| Understand every key in `attest.toml` and where secrets go | [configuration.md](configuration.md) |
| Know what it protects against and what it does not | [security.md](security.md) |
| Back it up, migrate it, read its logs, reset the sandbox | [operations.md](operations.md) |
| Call the API from CI or a script | [api.md](api.md) |
| Pull evidence from GitHub, BambooHR or any JSON API | [collectors-github-hris-http.md](collectors-github-hris-http.md) |
| Give an AI client read-only access to publishable evidence | [mcp.md](mcp.md) |
| Report a vulnerability | [../SECURITY.md](../SECURITY.md) |
| See what changed | [../CHANGELOG.md](../CHANGELOG.md) |

## Vocabulary

- **Evidence record** — one collected fact: `source`, `kind` (dotted, e.g. `kms.key.rotation`), `control_ids`, `classification` (`publishable` | `internal` | `restricted`), `collected_at`, `payload` (with `summary` and `result: pass|fail`), and a SHA-256 that chains to the previous record.
- **Control** — names the evidence kinds that must all be present, fresh and passing; cites SOC 2 criteria, ISO Annex A controls and HIPAA specifications. States: `PASS`, `DEGRADED` (present but stale), `FAIL` (missing or a failing record).
- **Source** — a `[sources.<id>]` block in `attest.toml`: a type, optional cron schedule, params. Files under `imports/` are sources too.
- **Guardrail** — a deterministic check in `attest/guardrails.py` that raises before anything harmful can happen. Six of them; see [security.md](security.md).
- **Grant** — what a role may do (`read:evidence`, `approve:questionnaire`, …). The agent layer checks grants, never roles, and always the *requester's* grants.
- **Risk acceptance** — a named owner accepting a FAIL until a date. The CI gate honours it until it expires.
