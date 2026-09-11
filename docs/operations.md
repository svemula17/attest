# Operations

## What to back up

| What | Where | Contains |
|---|---|---|
| the database | `attest.db` (+ `attest.db-wal`, `attest.db-shm`) next to `attest.toml`, or your Postgres database | evidence and audit chains, control history, runs, drafts and signed decisions, users and key hashes, acceptances, notifications, package manifests, and the installation's **approval signing key** (`settings.approval_key`) |
| the config | `attest.toml` | every setting and the **session secret** — treat the backup as a secret |
| inputs and outputs | `imports/`, `exports/` | files the file-backed sources read; packages and questionnaire exports |

The database backup is sufficient to restore the ledger and verify every signature; without it, past approvals cannot be re-verified.

### SQLite

The database runs in WAL mode, so a plain `cp` of a live file can be inconsistent. Either stop the server and copy all three files, or take an online backup:

```bash
sqlite3 attest.db ".backup 'backups/attest-$(date +%F).db'"
```

Restore by putting the file back (delete any stale `-wal`/`-shm` first) and starting the server; it re-applies migrations if the backup predates them.

### Postgres

```bash
pg_dump --format=custom "postgresql://attest@db.internal/attest" > backups/attest-$(date +%F).dump
pg_restore --clean --if-exists -d "postgresql://attest@db.internal/attest" backups/attest-2026-09-11.dump
```

After any restore, check `chain_intact` in `GET /api/health`.

## Migrations

Schema changes are Alembic revisions in `attest/migrations/versions/` (`0001` initial, `0002` questionnaires, notifications and package exports). They run forward only and are idempotent:

- `attest serve` applies pending revisions at startup;
- `attest upgrade` applies them deliberately and prints the current revision — run it after `pip install`/image pull and *before* switching traffic;
- a database created by the pre-Alembic `init_db()` is recognised by its `settings.schema_version` and stamped with the matching revision first.

Back up before upgrading. There is no `downgrade` command; roll back by restoring the backup and the previous version.

## The scheduler

Every `[sources.<id>]` with a `schedule` and `enabled = true` becomes an APScheduler cron job in the `attest serve` process (UTC). Runs execute as the `system` identity with trigger `schedule`, are audited (`collect.ok` / `collect.error`) and recorded in the run history. Behaviour worth knowing:

- one instance per job (`max_instances=1`) and coalescing, so a slow run never overlaps itself or piles up;
- a run missed while the process was down still fires once if it is less than an hour late (`misfire_grace_time = 3600`), then is skipped;
- an invalid cron expression fails `attest serve` at startup, naming the source;
- a collector exception is logged at WARNING and audited, never raised into the scheduler thread;
- **run one `attest serve` per database.** Two processes with the same `attest.toml` would each run every job.

`GET /api/health` lists the jobs with their next run time. To run something now: `POST /api/sources/<id>/collect` or the *Run now* button — both go through the same code path with trigger `api`.

After every collector run, import or evaluation the control engine re-evaluates and snapshots every control (`control_snapshots`), which is what the history views and the notifier diff against.

## Run history

Every collector execution and every import is a `collector_runs` row: source, trigger (`manual` | `schedule` | `api` | `import`), start/finish, status (`running` | `ok` | `error`), record count, error text and who started it. Evidence records link to the run that produced them.

- `GET /api/runs?source_id=&limit=` — newest first;
- `GET /api/sources` — each configured source with its last run;
- `attest sources list` — the same table on the command line.

A collector that records a *failing* control (an orphaned account, an unprotected branch) is still a successful run: the finding is the evidence. Only credentials, network and unusable responses produce `error`.

Note that the command-line `attest collect` and `attest import` write to the JSONL data directory (`--data`, default `./data`), not to the server's database — they exist for the file-based workflow and CI. To feed the running server, use the API or the console.

## Notifications

When a control turns FAIL, drops from PASS to DEGRADED, or the HRIS × IdP join finds an orphaned account, `[notifications]` decides who hears about it. Each delivery attempt is a `notifications` row (`GET /api/notifications`): target, status `sent`/`error`, the Jira key when one was created, owner and due date. The same transition with the same reason is delivered once per target; a failed attempt is recorded and not retried automatically (a new reason produces a new event). A notifier crash is audited as `notify.error` and never breaks the evaluation that triggered it.

## Logs

- **uvicorn** prints only warnings unless `attest serve -v`, which adds the access log.
- **`attest.scheduler`** (standard `logging`) warns on failed scheduled runs.
- **The audit table is the operational log that matters**: `auth.login`, `user.created`, `key.created`/`key.revoked`, `collect.ok`/`collect.error`, `import.ok`/`import.error`, `acceptance.added`/`acceptance.revoked`, `approval.*`, `package.built`, `notify.error`, and the `guardrail.*` feed entries. Read it with `GET /api/audit?prefix=collect.&limit=200` or the console. It is hash-chained, so it cannot be trimmed without detection.

## Health

`GET /api/health` needs no credential and returns:

```json
{"ok": true, "mode": "production", "evidence": 1284, "chain_intact": true,
 "jobs": [{"source_id": "leavers", "schedule": "0 6 * * *", "next_run": "2026-09-12T06:00:00Z"}]}
```

`chain_intact` recomputes the whole evidence chain on every call — cheap at thousands of rows, worth polling every few minutes rather than every second. The Docker image's `HEALTHCHECK` calls this endpoint.

## Resetting the sandbox

Sandbox mode reseeds whenever the evidence store is empty at startup, so:

```bash
# from the console or API, while running (deletes evidence, audit, drafts, snapshots and runs, then reseeds):
curl -X POST http://127.0.0.1:8765/api/reseed

# or from scratch:
rm attest.db attest.db-wal attest.db-shm
attest serve
```

`attest init --force` rewrites `attest.toml` only and never touches the database. None of the demo endpoints exist in production mode.

## Checklist for production

1. `mode = "production"`, `base_url` = the public `https://` origin, TLS at the proxy, then `hsts = true`.
2. Postgres, or SQLite on a volume you back up nightly with `.backup`.
3. Secrets injected as environment variables; `attest.toml` mode `0600`.
4. OIDC for people; API keys per service, named after what uses them, revoked when it stops.
5. `[notifications]` with an owner per control that matters.
6. `attest upgrade` in the deploy pipeline, backup first.
7. One `attest serve` per database.
