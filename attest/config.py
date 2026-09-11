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
class AuthConfig:
    session_secret: str = ""
    session_hours: int = 12


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
class Config:
    path: Path | None = None
    server: ServerConfig = field(default_factory=ServerConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    sources: dict[str, SourceConfig] = field(default_factory=dict)
    acceptances: list[Acceptance] = field(default_factory=list)
    sla_overrides: dict[str, int] = field(default_factory=dict)
    llm: LLMConfig = field(default_factory=LLMConfig)

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
    cfg.auth = _section(raw, "auth", AuthConfig, {"session_secret", "session_hours"})
    cfg.llm = _section(raw, "llm", LLMConfig, {"enabled", "model"})
    for sid, s in (raw.get("sources") or {}).items():
        if "type" not in s:
            raise ConfigError(f"[sources.{sid}] needs a type")
        unknown = set(s) - {"type", "schedule", "enabled", "params"}
        if unknown:
            raise ConfigError(f"[sources.{sid}] has unknown keys: {', '.join(sorted(unknown))}")
        cfg.sources[sid] = SourceConfig(id=sid, type=s["type"], schedule=s.get("schedule"),
                                        enabled=bool(s.get("enabled", True)), params=dict(s.get("params") or {}))
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
'''
