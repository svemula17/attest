# Evidence packages, questionnaires and the WORM audit export

Three ways the evidence leaves Attest, each with an integrity story:

| Deliverable | Command | Integrity |
|---|---|---|
| Auditor evidence package (`.zip`) | `attest package`, `attest package-verify` | sha256 per file + HMAC-SHA256 manifest signature |
| Questionnaire answers (`.csv` / `.xlsx`) | `attest questionnaire import / export / list` | every answer carries the approver's HMAC signature |
| Audit trail (`.jsonl` + proof) | `attest audit-export [--s3 …]` | chain digest in the proof; S3 Object Lock (COMPLIANCE) |

All three build the `Service` the way the admin commands do: `attest.toml` → migrations → engine.
Pass `--config path/to/attest.toml` (or set `ATTEST_CONFIG`) when not running from the install directory.

## 1. The auditor evidence package

```sh
attest package                                  # everything, all three frameworks
attest package --framework hipaa --since 2026-07-01 --out hipaa-q3.zip
attest package --include-restricted             # engineers/admins only
attest package-verify hipaa-q3.zip
```

`attest package` writes one zip and prints what went in, the evidence chain verdict and the
signature. It exits 0, or 4 when the evidence ledger's hash chain did not verify (the package is
still written and says so in `chain.json`).

### What is inside

| File | Contents |
|---|---|
| `manifest.json` | `format: attest-package/1`, `generated_at`, `generated_by`, `framework`, `since`, `include_restricted`, `files: {name: sha256}`, `counts`, `chain_verified`, `signature` |
| `controls.json` | one object per control in scope: `id`, `name`, `state` (PASS / DEGRADED / FAIL), `reason`, `evidence_ids`, `citations` (`{soc2, iso27001, hipaa}` clause ids from the catalog), `hipaa_spec` (required / addressable), `required_kinds`, `freshness_sla_hours` |
| `controls.csv` | the same as rows: `id,name,state,reason,evidence_ids,soc2,iso27001,hipaa,hipaa_spec` (lists `;`-joined) |
| `posture.json` | `{framework: [row, …]}` — one row per (control, framework citation), exactly what `ControlEngine.posture()` returns |
| `evidence.jsonl` | one evidence record per line, ledger order: `id, source, kind, control_ids, classification, collected_at, payload, sha256, prev_sha256` |
| `chain.json` | `count`, `first_id`, `last_id`, `last_sha256` of the whole ledger, `exported` (records in this package) and `verified` (the chain check at build time) |
| `audit.jsonl` | audit entries oldest first (`ts, actor, model_version, action, subject, approver, rule, detail`); console feed entries (`guardrail.*`) are left out |
| `acceptances.json` | every risk acceptance ever recorded — owner, reason, expiry, revocation |
| `README.txt` | this table in prose, plus the verification recipe |

States come from `Service.evaluate(record=False)`, so building a package does not add a snapshot
to the history. Nothing in a package is written by a model.

### Scope

- `--framework soc2|iso27001|hipaa` keeps the controls mapped to that framework, that framework's
  posture, and the evidence records citing at least one of those controls. Without it, all
  frameworks and every record.
- `--since YYYY-MM-DD` keeps evidence with `collected_at >= since` and audit entries with
  `ts >= since`. `chain.json` still describes the whole ledger.
- Restricted-classification evidence is excluded unless `--include-restricted`. Through the
  service that flag additionally requires the `manage:acceptances` grant (engineers and admins);
  auditors get the publishable + internal set. An unknown classification label is treated as
  restricted.

Every build is recorded in `package_exports` (who, scope, path, sha256 of the zip, manifest) and
audited as `package.built`; `Service.build_package(identity, out, …)` does both around
`attest.packages.build_package(service, out, …)`, which only writes the file and returns the manifest.

### Verifying

`attest package-verify FILE.zip` re-reads the zip, recomputes the sha256 of every file named in
`manifest.json`, flags files that are missing or unlisted, then recomputes the signature and
compares it in constant time. Exit 0 and a one-line summary, or exit 4 and one line per problem:

```
hipaa-q3.zip: FAILED (1 problem)
  - controls.csv: sha256 3f9a… does not match the manifest (8c21…)
```

The signature is `HMAC-SHA256(approval_key, canonical_json(manifest without "signature"))` — keys
sorted, no whitespace — made by `Service.sign_bytes`, keyed with the installation's approval key
(the same key that signs questionnaire decisions). Editing the manifest to "fix" a digest breaks
the signature, so a package cannot be re-attributed or re-scoped after the fact. Only the issuing
installation holds the key; anyone else can still check the per-file digests by hand, and ask
the installation to confirm the signature.

Programmatic use: `attest.packages.verify_package(path, signer) -> (ok, problems)` with
`signer = service.sign_bytes`.

## 2. Questionnaires

```sh
attest questionnaire import acme.xlsx --name "Acme vendor review"
attest questionnaire list
attest questionnaire export QN-0001 --out acme-answers.xlsx      # or .csv, or --format csv
```

### Import format

CSV or XLSX (first sheet). A header row with a `question` column; optional `control_ids`
(ids separated by `;` or `,`) and optional `ref` (or `id`) — the customer's own question number.
Header names are case-insensitive; a UTF-8 BOM is fine. Rows whose `question` is blank are
skipped, so section headings and spacer rows do no harm.

Every problem is reported with its row number (row 1 is the header), all at once, and nothing is
imported when there is any:

```
questionnaire import: acme.csv: 2 problems — nothing imported
  - row 3: invalid control id(s) 'CTL PRIV 01'; use ids like CTL-CRYPTO-01 separated by ';'
  - row 4: duplicate ref 'A1' (first used at row 2)
```

A clean import creates one `questionnaires` row (`QN-0001`…, status `open`) and one draft per
question through the same answer agent and guardrails as the console — so each row comes back
`READY` (with citations), `DECLINED` (no evidence cites the requested controls) or `BLOCKED`
(a guardrail refused). Drafts carry `questionnaire_id` and the customer's `ref`. The import is
audited as `questionnaire.imported`. Decide each READY draft in the console as usual; a decision
is signed exactly as before.

### Export format

Columns: `ref, question_id, question, status, answer, citations, decision, approver, signed_at, signature`.
`citations` is the `;`-joined evidence ids. A `DECLINED` or `BLOCKED` row has no answer; its
answer cell reads `NOT ANSWERED: <reason>` so a gap is never silent. The export includes READY
answers that no one has approved yet — the CLI warns and names them; filter on `decision = approve`
before anything reaches the customer. Exporting marks the questionnaire `exported` and is audited
as `questionnaire.exported`. The exported file is itself a valid import (it has `ref` and `question`
columns), which is how a re-send after redrafting works.

## 3. WORM audit export

```sh
attest audit-export --out audit-2026-09.jsonl --since 2026-09-01
attest audit-export --out audit.jsonl --s3 s3://compliance-worm/attest --retain-days 365
```

`export_audit` writes every audit entry (at or after `--since`) as JSONL, oldest first, and
`<out>.proof.json`:

```json
{
  "format": "attest-audit-proof/1",
  "file": "audit.jsonl",
  "count": 1284, "total": 1284, "since": null,
  "first_ts": "2026-06-01T08:12:40Z", "last_ts": "2026-09-11T15:02:11Z",
  "last_sha256": "…",         // chain digest at the last exported entry (== that audit row's sha256)
  "chain_verified": true,     // the store's whole chain re-verified at export time
  "sha256_of_file": "…",
  "exported_at": "2026-09-11T15:02:12Z"
}
```

`last_sha256` is recomputed from the entries the same way the audit table computes its chain, so
it equals the stored digest of that row when the table is intact and diverges when it is not
(`chain_verified` says which). `sha256_of_file` binds the proof to the exact bytes exported.

With `--s3 s3://bucket/prefix` (or `[security].audit_worm_bucket` in `attest.toml`) both files
are uploaded with `ObjectLockMode=COMPLIANCE`, `ObjectLockRetainUntilDate = now + retain-days`
(`--retain-days`, else `[security].audit_worm_retain_days`, default 365) and
`ChecksumAlgorithm=SHA256`. In COMPLIANCE mode no principal — the bucket owner included — can
delete or overwrite the objects before the retention date. The bucket must have Object Lock
enabled (chosen at bucket creation); S3 rejects the upload otherwise, the CLI reports it, and the
files on disk are still good. Needs `boto3` (`pip install 'attest[aws]'`) and the usual AWS
credential chain. The export is audited as `audit.exported`, with the S3 key and lock date when
uploaded. Exit 0, 4 when the audit chain did not verify, 1 on upload failure.

## Schema v2

Migration `0002` adds `questionnaires`, `notifications` (one row per delivery attempt, unique
`dedupe_key`), `package_exports`, and two nullable columns on `drafts`: `questionnaire_id`
(FK → `questionnaires.id`) and `ref`. `attest upgrade` (or any command; migrations run on start)
applies it. Downgrade is supported.
