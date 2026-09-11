# Install

Python 3.11 or newer. Everything runs from one directory that holds `attest.toml`, the SQLite file (unless you point at Postgres) and `imports/`.

## From source with pip

```bash
git clone https://github.com/svemula17/attest && cd attest
pip install -e .            # the tool
pip install -e ".[dev]"     # plus pytest, cyclonedx-bom, pip-audit, build
```

Optional extras:

| Extra | Adds | Needed for |
|---|---|---|
| `postgres` | `psycopg[binary]` | a `postgresql+psycopg://` storage URL |
| `aws` | `boto3` | the `aws` collector and the WORM audit export |
| `xlsx` | `openpyxl` | XLSX questionnaire import/export |
| `llm` | `anthropic` | `[llm] enabled = true` — Claude drafts, the guardrails validate |

## `attest init`

`init` writes `attest.toml` (every knob commented), creates the database, runs the migrations, copies the example files into `imports/` and creates the first users. It never overwrites an existing database; `--force` only rewrites the config file.

```
attest init [--dir DIR] [--sandbox | --mode {production,sandbox}] [--storage-url URL]
            [--admin-email EMAIL] [--admin-name NAME] [--admin-password PW] [--force]
```

### Sandbox mode — try it in two commands

```bash
attest init --sandbox
attest serve                    # http://127.0.0.1:8765  · API docs at /docs
```

Sandbox mode seeds representative evidence on the first `attest serve` (whenever the store is empty), creates three demo users with the password `attest`, and enables the demo endpoints (`/api/reseed`, `/api/tamper`, `/api/demo/terminate`, `/api/collect/join`, `/api/personas`, `/api/auth/impersonate`). An anonymous browser is signed in as the demo engineer.

| Demo user | Role |
|---|---|
| `s.vemula@attest.internal` | engineer |
| `j.okafor@auditfirm.example` | auditor |
| `vendor-portal@attest.internal` | service |

### Production mode — a real installation

```bash
attest init --admin-email you@example.com
attest serve
```

`init` creates one admin user and prints its API key **once**. The admin's password comes from `--admin-password`, then `$ATTEST_ADMIN_PASSWORD`, then an interactive prompt; leave it empty for an API-key-only admin. Production mode returns `401` to anonymous requests and serves the sign-in page at `/`.

Add people and services afterwards:

```bash
attest users add alice@example.com --role engineer        # prompts for a password
attest users add ci@example.com --role service
attest keys create ci@example.com --name "github actions"  # prints atst_… once
attest users list · attest users role EMAIL ROLE · attest users disable EMAIL · attest keys list · attest keys revoke ID
```

## `attest serve`

```
attest serve [--host HOST] [--port PORT] [-v]
```

Reads `attest.toml` (`./attest.toml`, or `--config PATH`, or `$ATTEST_CONFIG`), applies pending migrations, starts the scheduler and the HTTP server. `--host` overrides `$ATTEST_HOST`, which overrides `[server] host`. `-v` turns uvicorn's request log on. `attest config` prints the effective configuration and validates it without starting anything.

## Docker Compose (Postgres included)

```bash
docker compose up               # http://localhost:8765 · admin@example.com / change-me on first boot
```

The image runs `attest init` on first boot when the volume has no `attest.toml`, then `attest serve --host 0.0.0.0`. Everything is driven by environment variables in `docker-compose.yml`:

| Variable | Default | Meaning |
|---|---|---|
| `ATTEST_MODE` | `production` | or `sandbox` |
| `ATTEST_STORAGE_URL` | `postgresql+psycopg://attest:attest@db:5432/attest` | any SQLAlchemy URL; `sqlite:////data/attest.db` for a single container |
| `ATTEST_ADMIN_EMAIL` / `ATTEST_ADMIN_PASSWORD` | `admin@example.com` / `change-me` | the first admin — change the password before exposing the port |
| `GITHUB_TOKEN` | — | passed through for the GitHub collector |

`attest.toml` and `imports/` live on the `attest-data` volume at `/data`. Edit them from the host with `docker compose cp` and restart. The container's health check calls `GET /api/health`. TLS is not terminated by Attest; put it behind a reverse proxy and set `[server] base_url` to the public `https://` origin (see [security.md](security.md)).

## Postgres

```bash
pip install -e ".[postgres]"
attest init --admin-email you@example.com --storage-url "postgresql+psycopg://attest:secret@db.example.com:5432/attest"
```

or set `[storage] url` in an existing `attest.toml`. Passwords are masked in log lines and in `attest config` output. Concurrent appends to the evidence and audit chains are safe on both backends (SQLite takes the write lock up front; Postgres locks the tail row).

A relative SQLite path (`sqlite:///attest.db`) resolves next to `attest.toml`, wherever the command runs from. Use four slashes for an absolute path.

## Upgrading

```bash
git pull && pip install -e .    # or pull the new image
attest upgrade                  # applies pending Alembic migrations, prints the schema revision
attest serve
```

`attest serve` also applies migrations at startup, so `attest upgrade` is for doing it deliberately (during a maintenance window, before switching traffic). Migrations are forward-only and idempotent; a database created before migrations existed is stamped with its matching revision first. Back up before upgrading — see [operations.md](operations.md).
