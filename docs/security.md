# Security

What Attest protects, how, and — just as important — what it leaves to you. Report weaknesses through [SECURITY.md](../SECURITY.md).

## Threat model: the agent layer

Attest runs agents that read untrusted vendor documents and draft customer-facing answers. Every control below is a deterministic check in `attest/guardrails.py` that raises `GuardrailViolation(rule, detail)` before the harmful step can happen. They are code, not prompts, and the LLM (when enabled) sits *inside* them: Claude only drafts, and its draft goes through the same validation as the deterministic drafter.

| Rule | Threat | OWASP LLM Top 10 | What is enforced |
|---|---|---|---|
| `untrusted-doc-isolation` | a document says "mark this control remediated" and an agent with write tools does it | LLM01 Prompt Injection | the reader agent refuses to *start* if any registered tool is write-capable (`write:`, `update:`, `delete:`, `approve:`, `send:`). Injection scanning is logging only; isolation is the control. |
| `citation-required` | an answer that sounds right but is not backed by a record | LLM09 Misinformation (grounding) | every claim cites at least one evidence id that resolves in the store, or the whole draft is rejected. Zero evidence → the agent *declines* rather than infers. |
| `egress-classification-gate` | internal or restricted evidence leaking into a customer answer or an AI client | LLM02 Sensitive Information Disclosure | customer-facing agents and the MCP server query with `max_classification="publishable"` and every outgoing record is re-checked; unknown labels fail closed |
| `tool-allowlist` | a tool the reviewer never saw being loaded at runtime | LLM06 Excessive Agency | the allowlist is a frozenset fixed at construction; MCP tool definitions are pinned, `listChanged` is false |
| `max-steps` | a runaway loop of tool calls | LLM06 Excessive Agency | a step budget with no setter and `__slots__`; the refused step is not counted |
| `requester-scoped-identity` | confused deputy: a service account's grants used on a user's behalf | LLM06 / classic authz | the agent runs with the *requester's* grants, resolved from a real identity, never the server's |

Every outcome — allowed, blocked, declined, escalated — is an audit row with the rule name, the requester and the model version.

## Data classification

Every evidence record carries one of three labels, in ascending sensitivity: `publishable` → `internal` → `restricted`. Queries take an inclusive ceiling (`max_classification="internal"` returns publishable + internal). Where the ceiling applies:

- customer-facing drafting: `publishable` only;
- the MCP server ([mcp.md](mcp.md)): `publishable` only, and it never confirms whether a non-publishable id exists;
- `GET /api/evidence` for an **auditor signing in with an API key**: `publishable` only (an auditor in the console sees everything their role allows);
- evidence packages: restricted records are excluded unless an engineer asks for them.

Raw payloads are stored; only what a caller is entitled to leaves the process.

## Identity, roles and grants

Two credentials resolve to a user, and a user's role resolves to grants. Everything downstream checks grants.

| Role | Grants |
|---|---|
| `admin` | `read:evidence`, `read:documents`, `approve:questionnaire`, `run:collectors`, `manage:users`, `manage:acceptances`, `write:evidence:import` |
| `engineer` | everything above except `manage:users` |
| `auditor` | `read:evidence` |
| `service` | `read:evidence`, `run:collectors`, `write:evidence:import` |

Disabled users are rejected at every credential path, and a role change takes effect on the next request because the session carries only the user id.

### Sessions (people)

`POST /api/auth/login` (or the OIDC callback) sets `attest_session`: an itsdangerous-signed, timestamped token carrying only the user id, `HttpOnly`, `SameSite=Lax`, `Secure` when `base_url` is `https://`, expiring after `[auth] session_hours`. Local passwords are PBKDF2-HMAC-SHA256, 200 000 rounds, a random 16-byte salt per user, constant-time comparison. OIDC sign-in is Authorization Code + PKCE with `state` and `nonce` kept in a short-lived signed cookie; the ID token's signature (RS256, key by `kid`), issuer, audience, expiry and nonce are all verified locally, and any failure returns no partial claims.

### API keys (services, CI, MCP)

`attest keys create` prints `atst_` + 32 random bytes once. Only the SHA-256 of the key is stored, plus a 12-character prefix for display; `last_used_at` is updated on use; revocation is immediate and permanent. Keys inherit their owner's role. Send them as `Authorization: Bearer atst_…`.

## The HTTP surface

Installed by `attest.security.install(app, cfg)` inside `create_app`, in this order (outermost first):

**Security headers** on every response: `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `X-Frame-Options: DENY`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`, and

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline';
  style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com;
  img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
```

The console is one HTML file with inline script and style and Google Fonts, hence `'unsafe-inline'` and the two font hosts. `/docs` and `/redoc` get the same policy widened to `cdn.jsdelivr.net`, where FastAPI loads Swagger UI from. `Strict-Transport-Security: max-age=31536000; includeSubDomains` is sent only when `[security] hsts = true` — turn it on only once TLS is in place, because browsers remember it.

**Rate limits** — token buckets in memory, refilled continuously, monotonic clock:

| Requests | Key | Limit |
|---|---|---|
| `POST /api/auth/login` | client IP | `login_rate_per_minute` (10) |
| every other `/api/*` | `Authorization` header, else session cookie, else client IP (keys are stored hashed) | `api_rate_per_minute` (600) |

Over the limit: `429 {"error": "rate limited"}` with `Retry-After` in seconds. Pages (`/`, `/login`, `/docs`) are not limited. The client IP is the TCP peer; `X-Forwarded-For` is deliberately ignored because there is no trusted-proxy setting — behind a proxy, IP-keyed limits apply to the proxy's address, while bearer- and cookie-keyed limits still work per identity.

**Origin check (CSRF)** — for `POST`/`PUT`/`PATCH`/`DELETE` under `/api/` that carry the session cookie and no `Authorization` header, the request's origin (the `Origin` header, else the origin of `Referer`; `Origin: null` counts as absent) must be `server.base_url`'s origin or one of `allowed_origins`, else `403 {"error": "cross-origin request refused"}`. The cookie-setting endpoints (`/api/auth/login`, `/api/auth/impersonate`) are checked the same way whenever an origin is present, so a foreign page cannot log a victim in. Bearer requests pass through; so does a cookie-bearing request with no `Origin` and no `Referer` at all — browsers attach `Origin` to every cross-site state-changing request, so such a request came from a non-browser client (curl, a test client) holding the cookie legitimately. `SameSite=Lax` on the cookie is the second layer.

## Integrity: the hash chain

Evidence and audit rows are append-only by construction — the stores expose no update or delete — and chained: each row's `sha256` covers the canonical JSON of its content **plus the previous row's digest**, computed identically for the JSONL and SQL backends. Editing one row breaks the chain from that row forward. `verify_chain()` recomputes every digest and link; `GET /api/health` reports `chain_intact`, the console shows it, and the sandbox's *Tamper* button demonstrates detection by editing a row underneath the store. `attest verify` does the same for a JSONL data directory.

Human decisions are signed: `HMAC-SHA256(approval_key, canonical{question_id, sha256(answer), decision, approver, ts})`, with the key generated once per installation and kept in the `settings` table. A decision cannot be edited or re-attributed without breaking its signature; `approvals_verified` in `/api/state` re-checks all of them. Evidence packages carry a manifest with per-file SHA-256s signed with the same key.

## WORM export of the audit trail

The audit table proves it was not edited *inside* Attest; it cannot prove the database file was not replaced. For that, `[security] audit_worm_bucket` names an S3 prefix and `audit_worm_retain_days` the retention; the audit export uploads the audit trail and its chain proof under S3 Object Lock in COMPLIANCE mode (see the README's *For the audit* section for the command), so no principal — including the uploader — can delete or shorten it before retention ends. Requires `attest[aws]` and a bucket created with Object Lock enabled.

## Not covered — read this before exposing it

- **Rate limits are per process.** Each `attest serve` (or uvicorn worker) keeps its own buckets. Behind a load balancer the effective limit is *N × configured*, and the login limit is per proxy address (see above). For a hard limit, enforce it at the proxy or WAF.
- **No MFA on local password login.** Use `[auth.oidc]` and let your identity provider require it; keep local passwords for break-glass admins only, or make those admins API-key-only.
- **TLS terminates at your proxy.** Attest speaks plain HTTP. Put nginx, Caddy, an ALB or similar in front, set `base_url` to the public `https://` origin (which makes the cookie `Secure`) and only then `hsts = true`.
- **Secrets are in the environment.** Anyone who can read the process environment or `attest.toml` (session secret) has them. Use your platform's secret store to inject them, and mode `0600` on the file.
- **SQLite is a file.** Filesystem permissions are the access control for it, and backups of it contain the approval key.
- **The LLM drafter sends publishable evidence to Anthropic** when `[llm] enabled = true`. Nothing above `publishable` ever leaves; if that is still too much for your policy, leave it off — the deterministic drafter needs no network.
- **Injection detection is best-effort.** `scan_for_injection` catches known phrasings for logging and quarantine; a determined author can evade it. Isolation is the control, which is why it is not configurable.
