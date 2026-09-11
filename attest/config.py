"""attest.toml — one file that says how this installation runs.

    [server]
    host = "127.0.0.1"
    port = 8765
    mode = "production"          # or "sandbox": seeded data + demo endpoints
    base_url = "http://127.0.0.1:8765"

    [storage]
    url = "sqlite:///attest.db"  # or postgresql+psycopg://user:pass@host/db

    [auth]
    session_secret = "…"          # written by `attest init`
    session_hours = 12

    [sources.github]
    type = "github"
    schedule = "0 */6 * * *"      # cron, UTC; omit for manual only
    enabled = true
    [sources.github.params]
    repos = ["svemula17/attest"]

    [sources.hr-roster]
    type = "csv"
    [sources.hr-roster.params]
    path = "imports/hris.csv"
    mapping = "hris.roster"

    [[acceptances]]
    control = "CTL-VENDOR-01"
    owner = "s.vemula"
    reason = "BAA execution in progress"
    expires = "2026-10-31"

    [sla_overrides]
    CTL-PEOPLE-01 = 1440           # hours

    [llm]
    enabled = false
    model = "claude-opus-5"
"""
from __future__ import annotations

import os
import secrets
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_ENV = "ATTEST_CONFIG"
DEFAULT_NAMES = ("attest.toml",)


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8765
    mode: str = "production"          # production | sandbox
    base_url: str = "http://127.0.0.1:8765"


@dataclass
class StorageConfig:
    url: str = "sqlite:///attest.db"


@dataclass
class OIDCConfig:
    """[auth.oidc] — sign in with any OpenID Connect issuer (Okta, Entra ID, Google…).
    Client secret comes from the environment variable named in client_secret_env, never the file."""
    issuer: str = ""
    client_id: str = ""
    client_secret_env: str = "ATTEST_OIDC_CLIENT_SECRET"
    scopes: list[str] = field(default_factory=lambda: ["openid", "email", "profile"])
    role_claim: str | None = None          # e.g. "groups"; values mapped through role_map
    role_map: dict[str, str] = field(default_factory=dict)   # {"sec-eng": "engineer", "audit": "auditor"}
    default_role: str = "auditor"          # role for a first-time user with no mapped claim
    allowed_domains: list[str] = field(default_factory=list)  # ["example.com"]; empty = any


@dataclass
class AuthConfig:
    session_secret: str = ""
    session_hours: int = 12
    oidc: OIDCConfig | None = None


@dataclass
class SourceConfig:
    id: str
    type: str                          # github | csv | json | aws | okta | hris-idp-join | …
    schedule: str | None = None        # 5-field cron, UTC
    enabled: bool = True
    params: dict = field(default_factory=dict)


@dataclass
class Acceptance:
    control: str
    owner: str
    reason: str
    expires: str                       # YYYY-MM-DD


@dataclass
class LLMConfig:
    enabled: bool = False
    model: str = "claude-opus-5"


@dataclass
class JiraConfig:
    """[notifications.jira] — one issue per new FAIL/finding, idempotent per control."""
    base_url: str = ""
    project: str = ""
    email: str = ""                          # Jira Cloud basic auth: email + API token
    token_env: str = "JIRA_TOKEN"
    issue_type: str = "Task"


@dataclass
class NotificationsConfig:
    """[notifications] — where a new FAIL or join finding goes, and who owns each control."""
    slack_enabled: bool = False
    slack_webhook_env: str = "SLACK_WEBHOOK_URL"
    jira: JiraConfig | None = None
    notify_on: list[str] = field(default_factory=lambda: ["FAIL", "finding"])
    owners: dict[str, str] = field(default_factory=dict)     # control id → owner email
    due_days: int = 14                        # remediation due date attached to notifications


@dataclass
class SecurityConfig:
    """[security] — request hardening for the HTTP surface."""
    login_rate_per_minute: int = 10           # per client IP on POST /api/auth/login
    api_rate_per_minute: int = 600            # per identity on /api/*
    allowed_origins: list[str] = field(default_factory=list)  # in addition to server.base_url
    hsts: bool = False                        # send Strict-Transport-Security (behind TLS only)
    audit_worm_bucket: str = ""               # s3://bucket/prefix for `attest audit-export --s3`
    audit_worm_retain_days: int = 365


@dataclass
class Config:
    path: Path | None = None
    server: ServerConfig = field(default_factory=ServerConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    sources: dict[str, SourceConfig] = field(default_factory=dict)
    acceptances: list[Acceptance] = field(default_factory=list)
    sla_overrides: dict[str, int] = field(default_factory=dict)
    llm: LLMConfig = field(default_factory=LLMConfig)
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)

    @property
    def sandbox(self) -> bool:
        return self.server.mode == "sandbox"

    @property
    def root(self) -> Path:
        return self.path.parent if self.path else Path.cwd()

    def resolve(self, p: str) -> Path:
        """Paths in the config are relative to the config file."""
        q = Path(p)
        return q if q.is_absolute() else self.root / q


class ConfigError(ValueError):
    pass


def find_config(explicit: str | None = None) -> Path | None:
    if explicit:
        return Path(explicit)
    env = os.environ.get(CONFIG_ENV)
    if env:
        return Path(env)
    for name in DEFAULT_NAMES:
        p = Path.cwd() / name
        if p.exists():
            return p
    return None


def _section(raw: dict, key: str, cls, allowed: set[str]):
    data = raw.get(key, {}) or {}
    unknown = set(data) - allowed
    if unknown:
        raise ConfigError(f"[{key}] has unknown keys: {', '.join(sorted(unknown))}")
    return cls(**data)


def parse_config(text: str, path: Path | None = None) -> Config:
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path or 'config'}: {e}") from e
    cfg = Config(path=path)
    cfg.server = _section(raw, "server", ServerConfig, {"host", "port", "mode", "base_url"})
    if cfg.server.mode not in ("production", "sandbox"):
        raise ConfigError("[server].mode must be 'production' or 'sandbox'")
    cfg.storage = _section(raw, "storage", StorageConfig, {"url"})
    auth_raw = dict(raw.get("auth", {}) or {})
    oidc_raw = auth_raw.pop("oidc", None)
    cfg.auth = _section({"auth": auth_raw}, "auth", AuthConfig, {"session_secret", "session_hours"})
    if oidc_raw:
        cfg.auth.oidc = _section({"oidc": oidc_raw}, "oidc", OIDCConfig,
                                 {"issuer", "client_id", "client_secret_env", "scopes", "role_claim", "role_map", "default_role", "allowed_domains"})
        if not cfg.auth.oidc.issuer or not cfg.auth.oidc.client_id:
            raise ConfigError("[auth.oidc] needs issuer and client_id")
        if "client_secret" in oidc_raw:
            raise ConfigError("[auth.oidc] must not contain client_secret — put it in the env var named by client_secret_env")
    cfg.llm = _section(raw, "llm", LLMConfig, {"enabled", "model"})
    notif_raw = dict(raw.get("notifications", {}) or {})
    jira_raw = notif_raw.pop("jira", None)
    cfg.notifications = _section({"n": notif_raw}, "n", NotificationsConfig,
                                 {"slack_enabled", "slack_webhook_env", "notify_on", "owners", "due_days"})
    if jira_raw:
        cfg.notifications.jira = _section({"jira": jira_raw}, "jira", JiraConfig, {"base_url", "project", "email", "token_env", "issue_type"})
        if "token" in jira_raw:
            raise ConfigError("[notifications.jira] must not contain token — use token_env")
    cfg.security = _section(raw, "security", SecurityConfig,
                            {"login_rate_per_minute", "api_rate_per_minute", "allowed_origins", "hsts", "audit_worm_bucket", "audit_worm_retain_days"})
    for sid, s in (raw.get("sources") or {}).items():
        if "type" not in s:
            raise ConfigError(f"[sources.{sid}] needs a type")
        unknown = set(s) - {"type", "schedule", "enabled", "params"}
        if unknown:
            raise ConfigError(f"[sources.{sid}] has unknown keys: {', '.join(sorted(unknown))}")
        params = dict(s.get("params") or {})
        for key in ("token", "secret", "password", "api_key", "client_secret", "secret_access_key"):
            if key in params:
                raise ConfigError(f"[sources.{sid}.params] must not contain {key!r} — set {key}_env to the name of an environment variable")
        cfg.sources[sid] = SourceConfig(id=sid, type=s["type"], schedule=s.get("schedule"),
                                        enabled=bool(s.get("enabled", True)), params=params)
    for a in raw.get("acceptances") or []:
        missing = {"control", "owner", "reason", "expires"} - set(a)
        if missing:
            raise ConfigError(f"[[acceptances]] entry missing {', '.join(sorted(missing))}")
        cfg.acceptances.append(Acceptance(a["control"], a["owner"], a["reason"], str(a["expires"])))
    cfg.sla_overrides = {k: int(v) for k, v in (raw.get("sla_overrides") or {}).items()}
    return cfg


def load_config(explicit: str | None = None) -> Config:
    path = find_config(explicit)
    if path is None:
        return Config()
    if not path.exists():
        raise ConfigError(f"config not found: {path}")
    return parse_config(path.read_text(), path=path)


def default_config_toml(mode: str = "production", storage_url: str = "sqlite:///attest.db") -> str:
    """What `attest init` writes. Comments explain every knob so the file is its own docs."""
    return f'''# attest.toml — generated by `attest init`. Every path is relative to this file.

[server]
host = "127.0.0.1"
port = 8765
mode = "{mode}"                   # "production" or "sandbox" (seeded data + demo endpoints)
base_url = "http://127.0.0.1:8765"

[storage]
url = "{storage_url}"            # SQLite file, or postgresql+psycopg://user:pass@host/attest

[auth]
session_secret = "{secrets.token_hex(32)}"
session_hours = 12

[llm]
enabled = false                    # true + ANTHROPIC_API_KEY: Claude drafts, the same guardrails validate
model = "claude-opus-5"

# ── Sources ─────────────────────────────────────────────────────────────
# Each source has a type (github | csv | json | hris-idp-join | aws | okta), an optional
# cron schedule (UTC), and type-specific params. Run one by hand with `attest collect <id>`.

[sources.hris]
type = "csv"
[sources.hris.params]
path = "imports/hris-roster.csv"   # columns: employee_id,name,email,hired,terminated
mapping = "hris.roster"

[sources.idp]
type = "csv"
[sources.idp.params]
path = "imports/idp-users.csv"     # columns: email,status,deprovisioned_at
mapping = "idp.users"

[sources.leavers]
type = "hris-idp-join"
schedule = "0 6 * * *"

[sources.evidence]
type = "json"                      # generic: a JSON array of evidence records
[sources.evidence.params]
path = "imports/evidence.json"

# [sources.github]
# type = "github"
# schedule = "0 */6 * * *"
# [sources.github.params]
# repos = ["org/repo"]             # token from GITHUB_TOKEN

# ── Risk acceptances ────────────────────────────────────────────────────
# A FAIL with a non-expired acceptance passes the CI gate; expired ones fail it.
# [[acceptances]]
# control = "CTL-VENDOR-01"
# owner = "security@example.com"
# reason = "BAA execution in progress; tracked in VEND-118"
# expires = "2026-10-31"

[sla_overrides]                    # hours; overrides the catalog's freshness SLA per control

# ── Live collectors (secrets always by environment-variable NAME) ───────
# [sources.aws]
# type = "aws"
# schedule = "0 */6 * * *"
# [sources.aws.params]
# region = "us-east-1"
# role_arn = "arn:aws:iam::123456789012:role/attest-readonly"   # optional: AssumeRole from the ambient credentials
#
# [sources.okta]
# type = "okta"
# [sources.okta.params]
# org_url = "https://example.okta.com"
# token_env = "OKTA_TOKEN"
#
# [sources.github-org]
# type = "github"
# [sources.github-org.params]
# org = "example"                    # or repos = ["org/repo"]
# token_env = "GITHUB_TOKEN"
#
# [sources.bamboohr]
# type = "bamboohr"
# [sources.bamboohr.params]
# subdomain = "example"
# token_env = "BAMBOOHR_TOKEN"
#
# [sources.snyk]                     # any JSON API → evidence, with a small mapping
# type = "http-json"
# [sources.snyk.params]
# url = "https://api.example.com/v1/summary"
# token_env = "SNYK_TOKEN"
# kind = "vuln.findings-sla"
# control_ids = ["CTL-VULN-01"]
# summary = "{{open_critical}} critical, {{open_high}} high open"   # format string over the JSON object
# result = "pass"                    # or a JSON pointer / expression the agent documents

# ── Sign in with your IdP ───────────────────────────────────────────────
# [auth.oidc]
# issuer = "https://example.okta.com"
# client_id = "0oa…"
# client_secret_env = "ATTEST_OIDC_CLIENT_SECRET"
# role_claim = "groups"
# [auth.oidc.role_map]
# "attest-admins" = "admin"
# "security-engineering" = "engineer"

# ── Notifications ───────────────────────────────────────────────────────
# [notifications]
# slack_enabled = true               # webhook URL from $SLACK_WEBHOOK_URL
# notify_on = ["FAIL", "finding"]
# due_days = 14
# [notifications.owners]
# CTL-VENDOR-01 = "vendors@example.com"
# [notifications.jira]
# base_url = "https://example.atlassian.net"
# project = "SEC"
# email = "attest@example.com"
# token_env = "JIRA_TOKEN"

[security]
login_rate_per_minute = 10
api_rate_per_minute = 600
# allowed_origins = ["https://attest.example.com"]
# audit_worm_bucket = "s3://compliance-worm/attest"
'''
