# HTTP API

`GET /docs` is the interactive OpenAPI surface of a running server; this page is the map. Everything is JSON unless noted. `BASE` below is `http://127.0.0.1:8765` (or your `[server] base_url`).

## Authentication

Two credentials; every `/api/*` endpoint except `/api/health`, `/api/auth/login`, `/api/auth/methods` and the OIDC redirects needs one.

- **Session cookie** — `POST /api/auth/login` sets `attest_session`; browsers and scripts with a cookie jar use it. Cookie-authenticated `POST`/`PUT`/`PATCH`/`DELETE` requests that carry an `Origin` or `Referer` must originate from `base_url` (or `[security] allowed_origins`), else `403`.
- **API key** — `Authorization: Bearer atst_…` from `attest keys create`. No cookie, no origin check.

In sandbox mode an anonymous browser is the demo engineer.

```bash
# sign in and keep the cookie
curl -s -c jar -X POST $BASE/api/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"email": "s.vemula@attest.internal", "password": "attest"}'
# → {"user": "s.vemula@attest.internal", "role": "engineer", "grants": ["approve:questionnaire", …]}
curl -s -b jar $BASE/api/auth/me

# or a bearer key (CI, scripts, the MCP server)
export ATTEST_KEY=atst_…
curl -s -H "Authorization: Bearer $ATTEST_KEY" $BASE/api/auth/me
```

## Errors

| Status | Body | When |
|---|---|---|
| `400` | `{"error": …}` | bad input (unknown control, question already decided, …) |
| `401` | `{"error": …}` | no or invalid credential, expired session |
| `403` | `{"error": …}` | missing grant; `{"error": …, "rule": …}` when a guardrail refused; `{"error": …, "state": …}` when the console should re-render the denial; `{"error": "cross-origin request refused"}` from the origin check |
| `404` | `{"detail": …}` | no such evidence record |
| `422` | `{"error": …, "problems": ["row 3: …", …]}` | an import was rejected as a whole |
| `429` | `{"error": "rate limited"}` + `Retry-After` | over `[security]` limits |

## Endpoints

### Health and pages

| Endpoint | What |
|---|---|
| `GET /api/health` | `{ok, mode, evidence, chain_intact, jobs}` — no credential needed |
| `GET /` · `GET /login` | the console, or the sign-in page when not signed in |

### Auth

| Endpoint | What |
|---|---|
| `POST /api/auth/login` `{email, password}` | local sign-in; sets the cookie; audited |
| `POST /api/auth/logout` | clears the cookie |
| `GET /api/auth/me` | `{user, name, role, grants, via}` for the caller |
| `GET /api/auth/methods` | `{password: true, oidc: bool, oidc_issuer}` — what the sign-in page offers |
| `GET /api/auth/oidc/start` → `GET /api/auth/oidc/callback` | the OIDC round trip (only when `[auth.oidc]` is set); first sign-in creates the user |

### Console read model

| Endpoint | What |
|---|---|
| `GET /api/state` | everything the console renders in one document: summary, posture per framework, controls, evidence, feed events, approval queue, sources, join, acceptances, notifications, questionnaires, identity |

### The agent layer and the human decision

| Endpoint | Grant | What |
|---|---|---|
| `POST /api/answer` `{question, control_ids, llm?}` | `read:evidence` | draft a questionnaire answer from publishable evidence; returns the new state |
| `POST /api/decide` `{question_id, decision: approve\|reject\|assign}` | `approve:questionnaire` | sign a decision (HMAC over the answer); final |
| `POST /api/read-doc` `{doc_id?, text?, example?: injected\|clean, tools?}` | `read:documents` | read an untrusted document in an isolated context; injection → quarantined |

### Controls, evidence, audit

| Endpoint | Grant | What |
|---|---|---|
| `POST /api/evaluate` | any | evaluate every control now and snapshot the result |
| `GET /api/controls` | any | the catalog with current state and reason per control |
| `GET /api/controls/{id}/history?since=&limit=` | any | snapshots of one control, newest first |
| `GET /api/history/summary?days=90` | any | pass rates and transitions over the window |
| `GET /api/evidence?kind=&control_id=&source=&limit=` | `read:evidence` | records (auditors on API keys see `publishable` only) |
| `GET /api/evidence/{id}` | `read:evidence` | one record |
| `GET /api/audit?prefix=&limit=` | `read:evidence` | the audit trail, newest first, e.g. `prefix=collect.` |

### Sources, runs, import

| Endpoint | Grant | What |
|---|---|---|
| `GET /api/sources` | any | configured sources with their last run |
| `POST /api/sources/{id}/collect` | `run:collectors` | run one source now; returns the run result with `new_records` |
| `GET /api/runs?source_id=&limit=` | any | run history |
| `POST /api/import` (multipart: `file`, `mapping?`, `source?`) | `write:evidence:import` | CSV/JSON → evidence, validated whole, all-or-nothing |

### Acceptances and the gate

| Endpoint | Grant | What |
|---|---|---|
| `GET /api/acceptances` | any | all acceptances, including revoked |
| `POST /api/acceptances` `{control_id, owner, reason, expires}` | `manage:acceptances` | accept a FAIL until a date (`201`) |
| `DELETE /api/acceptances/{id}` | `manage:acceptances` | revoke |
| `GET /api/gate?strict=false` | any | `{passed, failing, rows, strict, today}`; `strict=true` makes DEGRADED block |

### Notifications, packages, questionnaires

| Endpoint | Grant | What |
|---|---|---|
| `GET /api/notifications?limit=50` | `read:evidence` | delivery records: target, status, Jira key, owner, due |
| `POST /api/package` `{framework?, since?, include_restricted?}` | any | build a signed evidence package; the response *is* the zip (`X-Attest-Package-SHA256` header) |
| `GET /api/packages` | any | packages built so far with their manifests |
| `GET /api/questionnaires` | any | imported questionnaires |
| `POST /api/questionnaires` (multipart: `file`, `name?`) | any | import a customer questionnaire (`question` column); every row is drafted |
| `GET /api/questionnaires/{id}/rows` | any | the rows with drafts, decisions and citations |
| `GET /api/questionnaires/{id}/export?fmt=csv\|xlsx` | any | the answered questionnaire as a file |

### Users and keys (admin)

| Endpoint | Grant | What |
|---|---|---|
| `GET /api/users` · `POST /api/users` `{email, role, name?, password?}` | `manage:users` | list / create (`201`) |
| `GET /api/keys` · `POST /api/keys` `{email, name}` · `DELETE /api/keys/{id}` | `manage:users` | list / create (`201`, the secret is in the response once) / revoke |

### Sandbox only

`POST /api/reseed`, `POST /api/tamper`, `POST /api/demo/terminate`, `POST /api/collect/join`, `GET /api/personas`, `POST /api/auth/impersonate` `{email}`. Absent (`404`) in production mode.

## Examples

**Import a CSV of evidence** (see `examples/imports/` for the column sets):

```bash
curl -s -H "Authorization: Bearer $ATTEST_KEY" \
     -F file=@examples/imports/evidence.csv -F mapping=evidence \
     $BASE/api/import
# → {"records": 6, "kinds": ["iam.least-privilege", …], "warnings": [], "run_id": 12, "file": "evidence.csv"}
```

**Run a collector now:**

```bash
curl -s -X POST -H "Authorization: Bearer $ATTEST_KEY" $BASE/api/sources/leavers/collect
# → {"source_id": "leavers", "type": "hris-idp-join", "status": "ok", "records": 1, "summary": "…", "run_id": 13, "error": null, "new_records": 1}
```

**Gate a deploy in CI** — exit non-zero on any FAIL without a current acceptance:

```bash
curl -sf -H "Authorization: Bearer $ATTEST_KEY" "$BASE/api/gate?strict=false" \
  | python -c 'import json,sys; g=json.load(sys.stdin); print("failing:", g["failing"]); sys.exit(0 if g["passed"] else 1)'
```

(`attest gate` does the same against a JSONL data directory and `gate.json`, which is how this repository gates itself.)

**Accept a known failure for a month:**

```bash
curl -s -b jar -X POST $BASE/api/acceptances -H 'Content-Type: application/json' \
     -d '{"control_id": "CTL-VENDOR-01", "owner": "vendors@example.com", "reason": "BAA in progress (VEND-118)", "expires": "2026-10-31"}'
```
