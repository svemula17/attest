# AWS and Okta collectors, and signing in with OIDC

Two live collectors that turn cloud and identity-provider state into evidence records, plus the
`[auth.oidc]` block that lets people sign in to attest with the same IdP. Secrets never appear in
`attest.toml`: the AWS collector uses ambient credentials (optionally assuming a role), the Okta
collector and the OIDC client name an environment variable.

| `type` | Module | Kinds emitted | Controls fed |
|---|---|---|---|
| `aws` | `attest.collectors.aws` | storage.encrypted, kms.key.rotation, sg.no-open-ingress, s3.public-access-blocked, waf.enabled, cloudtrail.enabled, log.integrity, iam.root-usage, iam.key-age, iam.access-analyzer, guardduty.findings, securityhub.score | CTL-CRYPTO-01, CTL-NET-01, CTL-LOG-01, CTL-ACCESS-03, CTL-DETECT-01 |
| `okta` | `attest.collectors.okta` | idp.users, idp.mfa-enrollment, sso.enforced | CTL-ACCESS-02 (join input), CTL-ACCESS-01 |

Control ids are derived from the catalog in `attest/controls.py` by `emit()`; a kind that no control
consumes yet (`s3.public-access-blocked`, `iam.root-usage`, `securityhub.score`, `idp.mfa-enrollment`)
is still recorded with an empty `control_ids` list, so the evidence is there the day a control claims it.
`idp.users` is the one exception: it is a join input, so it carries `CTL-ACCESS-02` explicitly.

Run either by hand with `attest collect <source id>`; both expose `describe()` for the CLI.

---

## `type = "aws"`

```toml
[sources.aws-prod]
type = "aws"
schedule = "0 */6 * * *"
[sources.aws-prod.params]
region = "us-east-1"                                              # required
role_arn = "arn:aws:iam::123456789012:role/attest-readonly"       # optional: AssumeRole from the ambient credentials
account_label = "prod"                                            # optional: used in summaries instead of the region
max_key_age_days = 90                                             # optional: iam.key-age threshold (default 90)
```

### Credentials

Whatever boto3 finds — `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, an instance or task
role, SSO — is the *ambient* session. With `role_arn` set the collector calls `sts:AssumeRole` from
that session (session name `attest`) and reads everything through the assumed role, which is the
recommended shape: the ambient identity needs nothing but `sts:AssumeRole` on that one role, and the
role carries the read-only policy below.

Any `AccessDenied` is raised as `PermissionError` naming the call (`AWS iam:ListUsers denied …`) and
the actions to grant, so a half-configured role fails loudly instead of recording partial evidence
as a pass.

### Read-only policy for the collector role

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AttestReadOnly",
      "Effect": "Allow",
      "Action": [
        "config:Describe*",
        "iam:Get*",
        "iam:List*",
        "access-analyzer:List*",
        "cloudtrail:Describe*",
        "cloudtrail:GetTrailStatus",
        "guardduty:List*",
        "securityhub:Get*"
      ],
      "Resource": "*"
    }
  ]
}
```

The calls actually made are: `config:DescribeComplianceByConfigRule`, `iam:GetAccountSummary`,
`iam:ListUsers`, `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`, `access-analyzer:ListAnalyzers`,
`access-analyzer:ListFindings`, `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`,
`guardduty:ListDetectors`, `guardduty:ListFindings`, `securityhub:GetEnabledStandards`,
`securityhub:GetFindings`. Narrow the wildcards to exactly those if your policy review wants it.

Trust policy on the role, allowing the identity that runs attest to assume it:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::123456789012:role/attest-runner"},
    "Action": "sts:AssumeRole",
    "Condition": {"StringEquals": {"sts:RoleSessionName": "attest"}}
  }]
}
```

And on the runner identity: `{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::123456789012:role/attest-readonly"}`.

### What each kind means

| Kind | Source | Pass when | Classification |
|---|---|---|---|
| storage.encrypted | aws-config | every mapped Config rule is COMPLIANT | publishable |
| kms.key.rotation | aws-config | same | publishable |
| sg.no-open-ingress | aws-config | same | publishable |
| s3.public-access-blocked | aws-config | same | publishable |
| waf.enabled | aws-config | same | publishable |
| cloudtrail.enabled | aws-config, then cloudtrail | Config rule compliant; then ≥1 multi-region trail with `IsLogging` | publishable |
| log.integrity | aws-config, then cloudtrail | Config rule compliant; then that trail has `LogFileValidationEnabled` | publishable |
| iam.root-usage | aws-iam | root has MFA and no access keys (`GetAccountSummary`) | publishable |
| iam.key-age | aws-iam | no *Active* user access key older than `max_key_age_days`; offenders listed in `offending_users` with last-used date | internal |
| iam.access-analyzer | aws-iam | an ACTIVE analyzer exists in the region and has no ACTIVE findings | internal |
| guardduty.findings | guardduty | a detector exists and has no unarchived findings with severity ≥ 7 | publishable |
| securityhub.score | guardduty | 0 findings with ComplianceStatus FAILED, RecordState ACTIVE, WorkflowStatus NEW; skipped entirely when no standard is enabled or Security Hub is off | publishable |

CloudTrail kinds are written twice on purpose — once from the Config rule and once from the trails
themselves. The engine takes the newest record for a kind, so the direct check wins.

### Config rule → kind mapping

| Kind | Managed rule identifiers |
|---|---|
| storage.encrypted | s3-bucket-server-side-encryption-enabled, encrypted-volumes, rds-storage-encrypted, s3-default-encryption-kms |
| kms.key.rotation | cmk-backing-key-rotation-enabled |
| sg.no-open-ingress | restricted-ssh, restricted-common-ports, vpc-default-security-group-closed |
| s3.public-access-blocked | s3-account-level-public-access-blocks-periodic, s3-bucket-public-read-prohibited |
| waf.enabled | alb-waf-enabled, api-gw-associated-with-waf |
| cloudtrail.enabled | cloudtrail-enabled, multi-region-cloudtrail-enabled |
| log.integrity | cloud-trail-log-file-validation-enabled |

A rule is recognised when the identifier appears anywhere in its name, so rules that Security Hub or a
conformance pack deploys as `securityhub-encrypted-volumes-a1b2c3` count. Per kind: any NON_COMPLIANT
rule → fail; otherwise pass if at least one rule is COMPLIANT; a kind whose only rules report
INSUFFICIENT_DATA fails (nothing has proven it). NOT_APPLICABLE rules are ignored, and a kind with no
mapped rule at all gets no record from Config. Rules outside the table are only counted in the run
summary (`aws prod: 14 records; 2 config rules unmapped`).

---

## `type = "okta"`

```toml
[sources.okta]
type = "okta"
schedule = "0 5 * * *"
[sources.okta.params]
org_url = "https://acme.okta.com"     # required
token_env = "OKTA_TOKEN"              # required: the env var holding an SSWS API token
max_users = 2000                      # optional: cap on per-user factor lookups
```

### Token and scopes

Create the token in Okta Admin under **Security → API → Tokens** as a user whose admin role can read
users and policies — a **Read-only Administrator** is the least-privileged built-in choice. The
endpoints used need these scopes:

| Scope | Used for |
|---|---|
| `okta.users.read` | `GET /api/v1/users` (two passes: the default listing and `filter=status eq "DEPROVISIONED"`, because Okta omits deprovisioned users by default) and `GET /api/v1/users/{id}/factors` |
| `okta.policies.read` | `GET /api/v1/policies?type=OKTA_SIGN_ON` and `GET /api/v1/policies/{id}/rules` |

A 401 or 403 becomes a `PermissionError` that repeats this list. A 429 is retried once after
`X-Rate-Limit-Reset`.

### What each kind means

| Kind | Pass when | Classification | Payload |
|---|---|---|---|
| idp.users | always (it is data, not a check) | internal, control `CTL-ACCESS-02` | `users = [{email, status, deprovisioned_at, okta_status}]` — the IdP side of the HRIS × IdP join. ACTIVE, PROVISIONED, RECOVERY, PASSWORD_EXPIRED, LOCKED_OUT and STAGED are `active`; DEPROVISIONED and SUSPENDED are `deprovisioned` with `deprovisioned_at` = Okta's `statusChanged`, normalised to second precision |
| idp.mfa-enrollment | every Okta-ACTIVE user (first `max_users`) has ≥1 factor with status ACTIVE | publishable | `unenrolled` (first 50 emails), counts in `raw` |
| sso.enforced | some ACTIVE rule of an ACTIVE `OKTA_SIGN_ON` policy has `access = ALLOW` and `requireFactor = true` (or `factorMode = "2FA"`) | publishable, control `CTL-ACCESS-01` | the policy and rule names |

Caveats worth knowing when reading the evidence: `sso.enforced` proves a factor-requiring rule exists,
not that every group is assigned to it; on Okta Identity Engine, authentication policies
(`ACCESS_POLICY`) are not read. A PENDING_ACTIVATION factor is not enrollment. Pair `idp.users` with
an `hris.roster` source and a `hris-idp-join` source to get `access.leaver-deprovisioned`.

---

## Signing in with your IdP — `[auth.oidc]`

`attest.oidc.OIDC` runs Authorization Code + PKCE (S256) against any OpenID Connect issuer, verifies
the `id_token` locally (RS256 via the issuer's JWKS, audience = `client_id`, issuer = the discovered
`issuer`, expiry with 60 s leeway, nonce bound to the login attempt) and maps claims to an attest role.
Every failure is an `OIDCError`; no partial claims are ever returned. The client secret is read from
the environment variable named by `client_secret_env` — never from the config file — and is simply
omitted for a public client.

Roles: with `role_claim` set, each value of that claim (string or list) is looked up in `role_map`,
and the most privileged mapped role wins in the order **admin > engineer > service > auditor**.
Without `role_claim`, or when nothing maps, the user gets `default_role`. `allowed_domains`
rejects emails outside the listed domains; the email comes from `email` or `preferred_username`,
lowercased.

The configured `issuer` must equal the `issuer` in the discovery document — it is checked, so use the
exact value the IdP publishes.

### Okta

Register a **Web** application (Authorization Code, PKCE on), redirect URI
`https://attest.example.com/auth/callback`, and add a `groups` claim to the id_token on the
authorization server (**Security → API → Authorization Servers → default → Claims**, filter e.g.
`Starts with attest-`).

```toml
[auth.oidc]
issuer = "https://acme.okta.com/oauth2/default"      # the custom authorization server; or "https://acme.okta.com" for the org server
client_id = "0oa1b2c3d4e5f6g7h8i9"
client_secret_env = "ATTEST_OIDC_CLIENT_SECRET"
scopes = ["openid", "email", "profile", "groups"]
role_claim = "groups"
default_role = "auditor"
allowed_domains = ["acme.com"]
[auth.oidc.role_map]
"attest-admins" = "admin"
"security-engineering" = "engineer"
"attest-ci" = "service"
"audit" = "auditor"
```

### Microsoft Entra ID

Register an app (Web platform, same redirect URI). Prefer **App roles** over group claims: define
roles on the app registration, assign users or groups to them under Enterprise applications, and the
role *values* arrive in the `roles` claim by name. (A `groups` claim emits object IDs, which you would
have to put in `role_map` verbatim.) Use the tenant **GUID** in the issuer — the v2.0 discovery
document publishes the GUID form, and the issuer check compares against it.

```toml
[auth.oidc]
issuer = "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
client_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
client_secret_env = "ATTEST_OIDC_CLIENT_SECRET"
scopes = ["openid", "email", "profile"]
role_claim = "roles"
default_role = "auditor"
allowed_domains = ["acme.com"]
[auth.oidc.role_map]
"Attest.Admin" = "admin"
"Attest.Engineer" = "engineer"
"Attest.Service" = "service"
"Attest.Auditor" = "auditor"
```

Entra ID returns `preferred_username` for every account and `email` only when the optional claim is
configured; attest falls back to `preferred_username`, which is the UPN.

### Using it from code

```python
from attest.oidc import OIDC, OIDCError

oidc = OIDC(config.auth.oidc, redirect_uri=f"{config.server.base_url}/auth/callback")
login = oidc.start()                       # store state, nonce, code_verifier in the session; redirect to login["url"]
# … on the callback, after checking request.state == session["state"]:
claims = oidc.finish(code, session["code_verifier"], session["nonce"])
email = oidc.check_email(claims)
role = oidc.role_for(claims)
```
