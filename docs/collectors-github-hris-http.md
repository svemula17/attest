# Live collectors: GitHub org, BambooHR, and any JSON API

Three collector types that pull evidence over HTTPS instead of importing files. All of them follow the
same contract as the rest of `attest.collectors`:

- **Secrets never live in `attest.toml`.** A param such as `token_env` names the *environment variable*
  that holds the credential; the config parser rejects a literal `token`, `secret`, `password` or `api_key`.
- **Kinds come from the catalog.** A collector can only emit kinds listed in `attest/sources.py`, and unless
  it says otherwise the control ids are derived from the controls whose `required_kinds` include the kind.
- **A failing control is a successful run.** An unprotected repo or an unreviewed merge produces a `fail`
  record — the finding is the evidence. Only credentials, rate limits and unusable responses raise.
- Every module exposes `TYPE`, `collect(ctx, transport=None) -> CollectResult` and `describe()`.
  Tests inject an `httpx.MockTransport`; production uses the default transport.

Run any of them by hand with `attest collect <source-id>` once the source is in `attest.toml`.

---

## `type = "github"` — org-wide change management

`attest/collectors/github.py`. Walks every non-archived repository of an organisation (or an explicit
list) and emits **four org-level records**, each with per-repo detail in `payload.repos`.

```toml
[sources.github-org]
type = "github"
schedule = "0 */6 * * *"
[sources.github-org.params]
org = "example"                 # OR repos = ["example/api", "example/web"]
token_env = "GITHUB_TOKEN"      # optional: falls back to $GITHUB_TOKEN, then $GH_TOKEN
max_repos = 200                 # default 200
merge_sample = 20               # closed PRs sampled per repo, default 20, max 100
```

| Param | Meaning |
|---|---|
| `org` | Organisation login. Lists `GET /orgs/{org}/repos?type=all&per_page=100`, follows `Link: rel="next"`, skips `archived` repos. |
| `repos` | Alternative to `org`: list of `owner/name`. The default branch is read from `GET /repos/{r}`. |
| `token_env` | Env var holding the PAT. If absent, `$GITHUB_TOKEN` then `$GH_TOKEN`. A named-but-unset variable is an error, never a silent fallback. |
| `max_repos` | Stop listing after this many repos (default 200). |
| `merge_sample` | How many most-recently-updated closed PRs per repo feed the merge log (default 20). |

### What it reads per repo

1. `GET /repos/{r}/branches/{default}/protection` — `200` = protected; `404`, or `403` with
   "Upgrade to GitHub Pro", = **unprotected** (a finding, not an error).
2. `GET /repos/{r}/secret-scanning/alerts?state=open&per_page=100` — `404` means the feature is **off**
   for that repo, which counts as a failure ("secret scanning not enabled").
3. `GET /repos/{r}/pulls?state=closed&per_page={merge_sample}&sort=updated&direction=desc`, then for each
   PR with `merged_at` set, `GET /repos/{r}/pulls/{n}/reviews` — a merge is "reviewed" when at least one
   review is `APPROVED`.

### What it emits (source `github`)

| Kind | Control | Passes iff | Summary shape |
|---|---|---|---|
| `pr.review-required` | CTL-CHANGE-01 | every repo requires ≥ 1 approving review | `N/M repos require review; unprotected: a, b` |
| `ci.policy-gate` | CTL-CHANGE-01 | every repo has required status checks | `N/M repos require status checks; without checks: a, b` |
| `github.secret-scanning` | CTL-CHANGE-02 | enabled on every repo **and** 0 open alerts | `secret scanning enabled on N/M repos, X open alerts; secret scanning not enabled: a, b` |
| `github.merge-log` | — (no catalog control requires it yet) | ≥ 95 % of sampled merged PRs had an approved review | `X of Y sampled merges reviewed across M repos` |

`payload.repos` is a list of
`{repo, branch, protected, review_count, checks, secret_scanning, alerts, merged, reviewed}`
so an auditor can see which repo dragged the aggregate down.

### PAT scopes

Classic PAT: **`repo`**, **`security_events`** (secret-scanning alerts), **`read:org`** (org listing).
Fine-grained PAT / GitHub App: *Metadata: read*, *Administration: read* (branch protection),
*Secret scanning alerts: read*, *Pull requests: read*, and org membership to list repos.

### Failure modes

| Response | Effect |
|---|---|
| `401` anywhere | `PermissionError` naming the three scopes and GitHub's message. Nothing is written. |
| `403` with `X-RateLimit-Remaining: 0` | `RuntimeError` naming the reset time (`X-RateLimit-Reset`, UTC). Nothing is written. |
| `403` on branch protection (not the Pro upsell) | `PermissionError` — the token cannot read protection for that repo. |
| `404` on `/orgs/{org}/repos` or `/repos/{r}` | `ValueError` (typo, or the token cannot see it). |

`collect_branch_protection(store, repo, token=None, fetch=None)` and `attest pull github --repo` are
unchanged: they are the per-repo, stdlib-only path and still emit per-repo records.

---

## `type = "bamboohr"` — the HR roster

`attest/collectors/bamboohr.py`. Runs one custom report and emits **one `hris.roster` record**
(source `hris`, classification `internal`, `control_ids = ["CTL-ACCESS-02"]`) in exactly the shape the
CSV importer produces, so the HRIS × IdP join (`hris-idp-join`) consumes it unchanged.

```toml
[sources.bamboohr]
type = "bamboohr"
schedule = "0 5 * * *"
[sources.bamboohr.params]
subdomain = "example"           # https://example.bamboohr.com
token_env = "BAMBOOHR_TOKEN"    # the API key; sent as HTTP basic auth  key:x
include_contractors = false     # default false
```

Request: `POST https://api.bamboohr.com/api/gateway.php/{subdomain}/v1/reports/custom?format=JSON` with
`{"title": "attest", "fields": ["id", "displayName", "workEmail", "hireDate", "terminationDate", "status", "employmentHistoryStatus"]}`.
`employmentHistoryStatus` is requested only so contractors can be filtered; when BambooHR does not return it
(the key's user cannot see the field) no filtering happens.

Normalisation, per employee:

- `email` = `workEmail` lower-cased. **Employees without a `workEmail` are skipped** and counted in `payload.skipped`.
- Contractors (`employmentHistoryStatus` containing "Contractor", case-insensitive) are dropped unless
  `include_contractors = true`; the count is in `payload.contractors_excluded`.
- Dates are `YYYY-MM-DD`; BambooHR's `0000-00-00` (and an empty string) become `null`. Any other shape is a
  `ValueError` naming the employee — a roster with an ambiguous date is not evidence.
- `terminated` = `terminationDate` when (`status == "Inactive"` or a termination date is set) **and** the
  date is not in the future; otherwise `null`. A future-dated leaver is still staff today.

Summary: `HRIS roster: N employees, M terminated in the period`. `payload.as_of` records the date the
"in the future" test used.

### BambooHR key permissions

Create the API key as a user whose **access level can view the employee directory** and the fields
`id`, `displayName`, `workEmail`, `hireDate`, `terminationDate`, `status` (and `employmentHistoryStatus`
if you rely on the contractor filter). The key must be able to **run custom reports**. Read-only is
sufficient; nothing is written to BambooHR.

`401`/`403` → `PermissionError`; any other non-2xx → `RuntimeError` with the status.

---

## `type = "http-json"` — any JSON API, one record

`attest/collectors/http_json.py`. For the long tail of vendors with a summary endpoint and no dedicated
collector. The operator names the `kind`, a `summary` template, and **at least one check**; the record
passes iff every check holds. A check is mandatory: a collector without an assertion would be evidence
that always passes.

| Param | Default | Meaning |
|---|---|---|
| `url` | required | Endpoint to call. |
| `method` | `GET` | HTTP method. |
| `token_env` | — | Env var holding a bearer token → `Authorization: Bearer …`. |
| `header_name` + `header_env` | — | Custom auth header, e.g. `X-Api-Key` from `$UPTIME_KEY`. |
| `kind` | required | Evidence kind; must exist in `attest/sources.py` or the run fails before any request. |
| `source` | catalog owner of `kind` | Override when another catalog source is the true origin. |
| `control_ids` | every control requiring `kind` | Explicit list of control ids. |
| `classification` | `publishable` | `publishable` / `internal` / `restricted`. |
| `summary` | required | Format string over the JSON object. Dotted paths: `"{data.open_critical} critical"`, `"{results.0.uptime:.2f}%"`. |
| `checks` | required | List of `{path, op, value}`. Ops: `==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `contains`, `exists`. |
| `root` | — | Dotted path into the response when the interesting object is nested; `summary` and `checks` resolve against it. |
| `timeout` | `20` | Seconds. |

Dotted paths walk objects by key and arrays by integer index (`results.0.name`, `-1` for the last item).
**A path that is not in the response is a `ValueError` naming it** — never a silent default — except with
op `exists`, whose whole point is to test presence (`value: true` = must be present, `false` = must be absent).
`<`/`>` compare numbers as numbers (a numeric string is coerced) and strings as strings (ISO dates order
correctly); anything else is an error.

Payload: `summary`, `result`, `checks = [{path, op, value, actual, ok}]`, `url`, `method`, `status`, `root`.
`401`/`403` → `PermissionError`; other non-2xx → `RuntimeError` with the status.

### Recipe 1 — Snyk-style vulnerability summary → `vuln.findings-sla` (CTL-VULN-01)

```toml
[sources.snyk]
type = "http-json"
schedule = "0 */12 * * *"
[sources.snyk.params]
url = "https://api.snyk.io/rest/orgs/ORG_ID/issues/summary?version=2024-10-15"
token_env = "SNYK_TOKEN"
kind = "vuln.findings-sla"
summary = "{data.attributes.open_critical} critical, {data.attributes.open_high} high open; {data.attributes.sla_breaches} past SLA"
checks = [
  { path = "data.attributes.open_critical", op = "==", value = 0 },
  { path = "data.attributes.sla_breaches",  op = "==", value = 0 },
]
```

`control_ids` is omitted, so the record supports every control whose `required_kinds` include
`vuln.findings-sla` — CTL-VULN-01. Snyk's API uses `Authorization: token …` rather than `Bearer`; if your
account rejects the bearer form, use `header_name = "Authorization"` with a `header_env` whose value is
`token <key>`.

### Recipe 2 — uptime API → `uptime.availability` (CTL-AVAIL-01)

```toml
[sources.uptime]
type = "http-json"
schedule = "0 6 * * *"
[sources.uptime.params]
url = "https://uptime.example.com/api/v2/monitors/123?window=30d"
header_name = "X-Api-Key"
header_env = "UPTIME_API_KEY"
kind = "uptime.availability"
root = "data.monitor"                                  # the interesting object is nested
classification = "internal"
summary = "{name}: {uptime_30d:.2f}% over 30 days ({incidents_30d} incidents)"
checks = [
  { path = "uptime_30d", op = ">=", value = 99.9 },
  { path = "status",     op = "in", value = ["up", "operational"] },
]
```

### Recipe 3 — KnowBe4-style training completion → `training.completion` (CTL-PEOPLE-01)

```toml
[sources.training]
type = "http-json"
schedule = "0 7 * * 1"
[sources.training.params]
url = "https://us.api.knowbe4.com/v1/training/enrollments?campaign_id=987&status=summary"
token_env = "KNOWBE4_TOKEN"
kind = "training.completion"
control_ids = ["CTL-PEOPLE-01"]
summary = "Security awareness 2026: {completed} of {enrolled} completed ({completion_pct}%), {overdue} overdue"
checks = [
  { path = "completion_pct", op = ">=", value = 95 },
  { path = "overdue",        op = "<=", value = 0 },
  { path = "campaign_name",  op = "contains", value = "2026" },
]
```

CTL-PEOPLE-01 also requires `training.phishing`; a second `http-json` source pointed at the phishing
campaign summary (with its own checks) completes the control.

### Choosing checks

Assert the thing the control actually claims, on the field an auditor would read, with the threshold the
policy states. Prefer a numeric comparison over `exists`; use `exists` for "the vendor still reports this
field at all". If the endpoint cannot express the claim in one object, that is the signal to write a
dedicated collector rather than stretch `http-json`.
