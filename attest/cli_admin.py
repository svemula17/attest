"""`attest init | serve | users | keys | upgrade | config` — running the real tool.

    attest init --sandbox            # attest.toml + attest.db + demo users, ready to `attest serve`
    attest init --admin-email me@x   # production: one admin, prints its API key once
    attest serve                     # migrations → scheduler → http://127.0.0.1:8765
    attest users add ci@x --role service
    attest keys create ci@x --name "github actions"
"""
from __future__ import annotations

import argparse
import getpass
import os
import secrets
import sys
from pathlib import Path

from attest.config import ConfigError, default_config_toml, load_config


def _engine_for(args: argparse.Namespace):
    from attest.db import get_engine, upgrade
    cfg = load_config(getattr(args, "config", None))
    url = cfg.storage.url
    if url.startswith("sqlite:///") and not url.startswith("sqlite:////"):  # relative SQLite path → next to the config
        url = "sqlite:///" + str(cfg.resolve(url[len("sqlite:///"):]))
    upgrade(url)
    engine = get_engine(url)
    engine.attest_url = url  # str(engine.url) masks Postgres passwords; keep the real one for migrations
    return cfg, engine


# ---- init ----------------------------------------------------------------------
def cmd_init(args: argparse.Namespace) -> int:
    from attest.api import ensure_demo_users
    from attest.auth import create_api_key, create_user, list_users
    from attest.db import get_engine, upgrade

    target = Path(args.dir).resolve()
    target.mkdir(parents=True, exist_ok=True)
    cfg_path = target / "attest.toml"
    if cfg_path.exists() and not args.force:
        print(f"{cfg_path} already exists (use --force to overwrite the config; the database is never overwritten)")
        return 1
    mode = "sandbox" if args.sandbox else args.mode
    storage_url = args.storage_url or "sqlite:///attest.db"
    cfg_path.write_text(default_config_toml(mode=mode, storage_url=storage_url))
    (target / "imports").mkdir(exist_ok=True)
    examples = Path(__file__).resolve().parent.parent / "examples" / "imports"
    if examples.exists():
        for f in examples.iterdir():
            dest = target / "imports" / f.name
            if not dest.exists():
                dest.write_bytes(f.read_bytes())
    url = storage_url
    if url.startswith("sqlite:///") and not url.startswith("sqlite:////"):
        url = "sqlite:///" + str(target / url[len("sqlite:///"):])
    upgrade(url)
    engine = get_engine(url)
    print(f"wrote {cfg_path}")
    print(f"database ready: {url}")
    if mode == "sandbox":
        ensure_demo_users(engine)
        print("sandbox users: s.vemula@attest.internal (engineer), j.okafor@auditfirm.example (auditor), vendor-portal@attest.internal (service) — password: attest")
    email = args.admin_email
    if email and email not in {u["email"] for u in list_users(engine)}:
        password = args.admin_password or os.environ.get("ATTEST_ADMIN_PASSWORD")
        if not password and sys.stdin.isatty():
            password = getpass.getpass(f"password for {email} (leave empty for API-key only): ") or None
        create_user(engine, email, "admin", name=args.admin_name or "", password=password)
        secret, row = create_api_key(engine, email, "initial")
        print(f"admin user: {email} ({'password set' if password else 'API-key only'})")
        print(f"admin API key (shown once): {secret}")
    print(f"next: cd {target} && attest serve")
    return 0


# ---- serve ------------------------------------------------------------------------
def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn
    from attest.api import create_app
    cfg = load_config(getattr(args, "config", None))
    if cfg.path is None:
        print("no attest.toml found — run `attest init` first (or set ATTEST_CONFIG)")
        return 1
    if cfg.storage.url.startswith("sqlite:///") and not cfg.storage.url.startswith("sqlite:////"):
        cfg.storage.url = "sqlite:///" + str(cfg.resolve(cfg.storage.url[len("sqlite:///"):]))
    host = args.host or os.environ.get("ATTEST_HOST") or cfg.server.host
    port = args.port or cfg.server.port
    print(f"attest {cfg.server.mode} · {cfg.storage.url.split('@')[-1]} · http://{host}:{port}  (docs at /docs)")
    uvicorn.run(create_app(cfg), host=host, port=port, log_level="info" if args.verbose else "warning")
    return 0


# ---- users / keys -------------------------------------------------------------------
def cmd_users(args: argparse.Namespace) -> int:
    from attest.auth import create_user, disable_user, list_users, set_user_role
    cfg, engine = _engine_for(args)
    if args.users_cmd == "list":
        rows = list_users(engine)
        if not rows:
            print("no users"); return 0
        w = max(len(r["email"]) for r in rows)
        for r in rows:
            print(f"{r['email']:<{w}}  {r['role']:<9} {r['login']:<8} {'disabled' if r['disabled'] else ''}")
        return 0
    if args.users_cmd == "add":
        password = args.password or (getpass.getpass("password (empty for API-key only): ") if sys.stdin.isatty() else None) or None
        row = create_user(engine, args.email, args.role, name=args.name or "", password=password)
        print(f"created {row['email']} ({row['role']})"); return 0
    if args.users_cmd == "role":
        row = set_user_role(engine, args.email, args.role); print(f"{row['email']} → {row['role']}"); return 0
    if args.users_cmd == "disable":
        disable_user(engine, args.email, True); print(f"disabled {args.email}"); return 0
    if args.users_cmd == "enable":
        disable_user(engine, args.email, False); print(f"enabled {args.email}"); return 0
    return 2


def cmd_keys(args: argparse.Namespace) -> int:
    from attest.auth import create_api_key, list_api_keys, revoke_api_key
    cfg, engine = _engine_for(args)
    if args.keys_cmd == "list":
        rows = list_api_keys(engine)
        for r in rows:
            print(f"#{r['id']:<3} {r['prefix']}…  {r['user']:<32} {r['name']:<20} {'revoked' if r['revoked_at'] else ('used ' + r['last_used_at'] if r['last_used_at'] else 'unused')}")
        if not rows:
            print("no API keys")
        return 0
    if args.keys_cmd == "create":
        secret, row = create_api_key(engine, args.email, args.name)
        print(f"{secret}\n(shown once — key #{row['id']} '{row['name']}' for {row['user']})"); return 0
    if args.keys_cmd == "revoke":
        revoke_api_key(engine, args.id); print(f"revoked key #{args.id}"); return 0
    return 2


# ---- upgrade / config --------------------------------------------------------------------
def cmd_upgrade(args: argparse.Namespace) -> int:
    from attest.db import current_revision
    cfg, engine = _engine_for(args)
    print(f"schema at revision {current_revision(engine.attest_url)} · {engine.attest_url.split('@')[-1]}")
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    try:
        cfg = load_config(getattr(args, "config", None))
    except ConfigError as e:
        print(f"config error: {e}"); return 1
    print(f"config: {cfg.path or '(defaults — no attest.toml found)'}")
    print(f"mode: {cfg.server.mode} · storage: {cfg.storage.url.split('@')[-1]} · llm: {'on' if cfg.llm.enabled else 'off'}")
    for s in cfg.sources.values():
        print(f"  source {s.id:<14} {s.type:<14} {s.schedule or 'manual':<14} {'enabled' if s.enabled else 'disabled'}")
    for a in cfg.acceptances:
        print(f"  acceptance {a.control} until {a.expires} ({a.owner})")
    return 0


def register(sub) -> None:
    p = sub.add_parser("init", help="write attest.toml, create the database and the first users")
    p.add_argument("--dir", default=".", help="directory for attest.toml, the SQLite file and imports/ (default: .)")
    p.add_argument("--sandbox", action="store_true", help="seeded data, demo users and demo endpoints")
    p.add_argument("--mode", choices=["production", "sandbox"], default="production")
    p.add_argument("--storage-url", help="SQLAlchemy URL (default sqlite:///attest.db next to the config)")
    p.add_argument("--admin-email"); p.add_argument("--admin-name"); p.add_argument("--admin-password")
    p.add_argument("--force", action="store_true", help="overwrite an existing attest.toml")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("serve", help="run migrations, start the scheduler and the HTTP server")
    p.add_argument("--host"); p.add_argument("--port", type=int); p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(fn=cmd_serve)

    p = sub.add_parser("users", help="manage people and service accounts")
    us = p.add_subparsers(dest="users_cmd", required=True)
    us.add_parser("list")
    a = us.add_parser("add"); a.add_argument("email"); a.add_argument("--role", default="engineer", choices=["admin", "engineer", "auditor", "service"]); a.add_argument("--name"); a.add_argument("--password")
    r = us.add_parser("role"); r.add_argument("email"); r.add_argument("role", choices=["admin", "engineer", "auditor", "service"])
    us.add_parser("disable").add_argument("email"); us.add_parser("enable").add_argument("email")
    p.set_defaults(fn=cmd_users)

    p = sub.add_parser("keys", help="API keys for services, CI and the MCP server")
    ks = p.add_subparsers(dest="keys_cmd", required=True)
    ks.add_parser("list")
    c = ks.add_parser("create"); c.add_argument("email"); c.add_argument("--name", default="key")
    ks.add_parser("revoke").add_argument("id", type=int)
    p.set_defaults(fn=cmd_keys)

    sub.add_parser("upgrade", help="apply database migrations").set_defaults(fn=cmd_upgrade)
    sub.add_parser("config", help="validate and print the effective configuration").set_defaults(fn=cmd_config)
