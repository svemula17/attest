"""Auditor evidence packages: one signed zip with everything an auditor needs to
re-perform the assessment offline, and a verifier for it.

    manifest.json      format, scope, sha256 of every other file, HMAC-SHA256 signature
    controls.json/.csv every control in scope: state, reason, cited evidence, framework citations
    posture.json       per-framework posture rows ({framework: [row, ...]})
    evidence.jsonl     the evidence records in scope, one hash-chained record per line
    chain.json         the ledger's extent and whether its hash chain verifies
    audit.jsonl        the audit trail (guardrail feed entries excluded), oldest first
    acceptances.json   every risk acceptance, current or not
    README.txt         what the files are and how to verify them

The signature is HMAC-SHA256 over the canonical JSON (sorted keys, no whitespace)
of the manifest without its ``signature`` field, keyed with the installation's
approval key (``Service.sign_bytes``). Anyone with the key — the installation
itself, via ``attest package-verify`` — can prove a package is complete and
untouched; anyone without it can still check the per-file digests.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import re
import zipfile
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Callable

from attest.controls import FRAMEWORKS
from attest.evidence import CLASSIFICATION_ORDER
from attest.util import canonical_json, now_iso

__all__ = [
    "FORMAT",
    "MANIFEST",
    "build_package",
    "manifest_signing_bytes",
    "package_signer",
    "validate_since",
    "verify_package",
]

FORMAT = "attest-package/1"
MANIFEST = "manifest.json"
FEED_PREFIX = "guardrail."          # the console feed lives in the audit table; it is not audit evidence
RESTRICTED = "restricted"
CONTROL_CSV_COLUMNS = ("id", "name", "state", "reason", "evidence_ids", "soc2", "iso27001", "hipaa", "hipaa_spec")

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_STAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

Signer = Callable[[bytes], str]


# ---------------------------------------------------------------------------
# Helpers shared with the WORM export and the CLI
# ---------------------------------------------------------------------------
def validate_since(since: str | None) -> str | None:
    """``since`` is a UTC lower bound: 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM:SSZ'. Timestamps in the stores
    are ISO-8601 UTC strings, so a lexical ``>=`` against either form is the intended comparison."""
    if since is None or since == "":
        return None
    if not isinstance(since, str):
        raise TypeError(f"since must be a string, got {type(since).__name__}")
    since = since.strip()
    if _DATE_RE.match(since):
        fmt = "%Y-%m-%d"
    elif _STAMP_RE.match(since):
        fmt = "%Y-%m-%dT%H:%M:%SZ"
    else:
        raise ValueError(f"since must be 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM:SSZ', got {since!r}")
    try:
        datetime.strptime(since, fmt)
    except ValueError:
        raise ValueError(f"since is not a calendar date: {since!r}") from None
    return since


def package_signer(service, signer: Signer | None = None) -> Signer:
    """The function that signs manifests: an explicit ``signer``, else ``service.sign_bytes``, else
    HMAC-SHA256 with the service's approval key (``service.key``)."""
    if signer is not None:
        return signer
    fn = getattr(service, "sign_bytes", None)
    if callable(fn):
        return fn
    key = getattr(service, "key", None)
    if isinstance(key, (bytes, bytearray)) and key:
        return lambda data: hmac.new(bytes(key), data, hashlib.sha256).hexdigest()
    raise TypeError("cannot sign: the service has no sign_bytes(data: bytes) -> str and no approval key; pass signer=")


def manifest_signing_bytes(manifest: dict) -> bytes:
    """What the signature covers: the manifest without ``signature``, canonical JSON."""
    return canonical_json({k: v for k, v in manifest.items() if k != "signature"}).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Package contents
# ---------------------------------------------------------------------------
def _known_frameworks(service) -> list[str]:
    known = list(FRAMEWORKS)
    for control in service.catalog.values():
        for fw in control.mappings:
            if fw not in known:
                known.append(fw)
    return known


def _control_rows(service, results: dict, framework: str | None) -> list[dict]:
    frameworks = _known_frameworks(service)
    rows = []
    for control in service.catalog.values():
        if framework is not None and not control.mappings.get(framework):
            continue  # not mapped to the requested framework: out of scope for this package
        result = results.get(control.id)
        if result is None:
            continue
        rows.append(
            dict(
                id=control.id,
                name=control.name,
                state=result.state,
                reason=result.reason,
                evidence_ids=list(result.evidence_ids),
                citations={fw: list(control.mappings.get(fw, [])) for fw in frameworks},
                hipaa_spec=control.hipaa_spec,
                required_kinds=list(control.required_kinds),
                freshness_sla_hours=control.freshness_sla_hours,
            )
        )
    return rows


def _controls_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CONTROL_CSV_COLUMNS)
    for r in rows:
        cites = r["citations"]
        writer.writerow([
            r["id"], r["name"], r["state"], r["reason"], ";".join(r["evidence_ids"]),
            ";".join(cites.get("soc2", [])), ";".join(cites.get("iso27001", [])), ";".join(cites.get("hipaa", [])),
            r["hipaa_spec"] or "",
        ])
    return buf.getvalue()


def _evidence_in_scope(record, since: str | None, include_restricted: bool, control_scope: set[str] | None) -> bool:
    # Fail closed: a label that is not publishable/internal is treated as restricted.
    if not include_restricted and record.classification not in CLASSIFICATION_ORDER[:CLASSIFICATION_ORDER.index(RESTRICTED)]:
        return False
    if since is not None and record.collected_at < since:
        return False
    if control_scope is not None and not (set(record.control_ids or []) & control_scope):
        return False
    return True


def _readme(manifest_scope: dict) -> str:
    fw = manifest_scope["framework"] or "all frameworks (SOC 2, ISO/IEC 27001, HIPAA)"
    since = manifest_scope["since"] or "the beginning of the ledger"
    restricted = "included" if manifest_scope["include_restricted"] else "excluded"
    return f"""Attest evidence package
=======================

Generated {manifest_scope['generated_at']} by {manifest_scope['generated_by']}.
Scope: {fw}; evidence and audit entries since {since}; restricted evidence {restricted}.

Files
-----
manifest.json     Package format, scope, the sha256 of every other file, counts, and an
                  HMAC-SHA256 signature made with the issuing installation's approval key.
controls.json     One object per control in scope: id, name, state (PASS | DEGRADED | FAIL),
                  the reason, the evidence ids the state rests on, framework citations
                  (soc2 / iso27001 / hipaa clause ids), HIPAA implementation-spec type,
                  required evidence kinds and the freshness SLA in hours.
controls.csv      The same, one row per control, citations semicolon-separated.
posture.json      {{framework: [row, ...]}}: one row per (control, framework citation).
evidence.jsonl    One evidence record per line, oldest first. Each record's sha256 covers its
                  own fields plus prev_sha256, so the records chain; a package built with
                  filters is a subset of the ledger, and chain.json describes the whole ledger.
chain.json        count, first_id, last_id, last_sha256 of the ledger, how many records this
                  package exports, and whether the ledger's chain verified at build time.
audit.jsonl       Audit entries (who did what, approved by whom, model version), oldest
                  first, in scope by time. Console feed entries (guardrail.*) are omitted.
acceptances.json  Every risk acceptance ever recorded, with owner, reason, expiry and
                  revocation, so an ACCEPTED verdict can be traced to a named person.
README.txt        This file.

Verifying
---------
With the issuing installation:   attest package-verify <this file>.zip
It recomputes every file's sha256 against manifest.json, then the manifest signature.

By hand, without the key: for each entry in manifest.json "files", sha256 of that file
must equal the listed digest. The signature is HMAC-SHA256(approval key, canonical JSON
of manifest.json with the "signature" field removed — keys sorted, no whitespace).
Only the issuing installation holds the key; ask it to confirm a signature you cannot.

Nothing in this package was written by a model. Control states are computed from the
evidence records; questionnaire answers are not included.
"""


# ---------------------------------------------------------------------------
# Build / verify
# ---------------------------------------------------------------------------
def build_package(
    service,
    out: Path,
    *,
    framework: str | None = None,
    since: str | None = None,
    include_restricted: bool = False,
    created_by: str = "attest",
    signer: Signer | None = None,
) -> dict:
    """Write the package zip to ``out`` and return its manifest (with the signature).

    ``framework`` limits controls, posture and evidence to what is mapped to that framework;
    ``since`` (YYYY-MM-DD) keeps evidence collected and audit entries recorded at or after it;
    restricted evidence is left out unless ``include_restricted``. Nothing is recorded in the
    database here — the caller (``Service.build_package``) records and audits the export.
    """
    out = Path(out)
    if framework is not None and framework not in _known_frameworks(service):
        raise ValueError(f"unknown framework {framework!r}; expected one of {', '.join(_known_frameworks(service))}")
    since = validate_since(since)
    sign = package_signer(service, signer)

    generated_at = now_iso()
    results = service.evaluate(record=False)
    frameworks = [framework] if framework else _known_frameworks(service)
    controls = _control_rows(service, results, framework)
    scope = {c["id"] for c in controls} if framework else None
    posture = {fw: service.controls.posture(fw) for fw in frameworks}
    records = service.store.all()
    evidence = [r for r in records if _evidence_in_scope(r, since, include_restricted, scope)]
    chain = dict(
        count=len(records),
        first_id=records[0].id if records else None,
        last_id=records[-1].id if records else None,
        last_sha256=records[-1].sha256 if records else None,
        exported=len(evidence),
        verified=bool(service.store.verify_chain()),
    )
    audit_entries = [
        e for e in reversed(service.audit.query(limit=None))  # query() is newest first; auditors read oldest first
        if not e.action.startswith(FEED_PREFIX) and (since is None or e.ts >= since)
    ]
    acceptances = service.acceptances.all()

    scope_fields = dict(generated_at=generated_at, generated_by=created_by, framework=framework, since=since,
                        include_restricted=bool(include_restricted))
    files: dict[str, bytes] = {
        "controls.json": json.dumps(controls, indent=2, sort_keys=True).encode("utf-8"),
        "controls.csv": _controls_csv(controls).encode("utf-8"),
        "posture.json": json.dumps(posture, indent=2, sort_keys=True).encode("utf-8"),
        "evidence.jsonl": "".join(canonical_json(asdict(r)) + "\n" for r in evidence).encode("utf-8"),
        "chain.json": json.dumps(chain, indent=2, sort_keys=True).encode("utf-8"),
        "audit.jsonl": "".join(canonical_json(asdict(e)) + "\n" for e in audit_entries).encode("utf-8"),
        "acceptances.json": json.dumps(acceptances, indent=2, sort_keys=True).encode("utf-8"),
        "README.txt": _readme(scope_fields).encode("utf-8"),
    }
    states = Counter(c["state"] for c in controls)
    manifest = dict(
        format=FORMAT,
        **scope_fields,
        files={name: _sha256(data) for name, data in files.items()},
        counts=dict(
            controls=len(controls),
            states={s: states.get(s, 0) for s in ("PASS", "DEGRADED", "FAIL")},
            posture_rows=sum(len(rows) for rows in posture.values()),
            evidence=len(evidence),
            evidence_total=len(records),
            audit=len(audit_entries),
            acceptances=len(acceptances),
        ),
        chain_verified=chain["verified"],
    )
    manifest["signature"] = sign(manifest_signing_bytes(manifest))

    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(MANIFEST, json.dumps(manifest, indent=2, sort_keys=True))
        for name, data in files.items():
            zf.writestr(name, data)
    return manifest


def read_manifest(path: Path) -> dict:
    """The manifest of a package, unverified. Raises ValueError for anything that is not a package."""
    path = Path(path)
    try:
        with zipfile.ZipFile(path) as zf:
            if MANIFEST not in zf.namelist():
                raise ValueError(f"{path.name}: no {MANIFEST} inside")
            manifest = json.loads(zf.read(MANIFEST))
    except zipfile.BadZipFile:
        raise ValueError(f"{path.name}: not a zip file") from None
    except json.JSONDecodeError:
        raise ValueError(f"{path.name}: {MANIFEST} is not valid JSON") from None
    if not isinstance(manifest, dict):
        raise ValueError(f"{path.name}: {MANIFEST} is not an object")
    return manifest


def verify_package(path: Path, signer: Signer) -> tuple[bool, list[str]]:
    """Recompute every file digest and the manifest signature. Returns (ok, problems)."""
    path = Path(path)
    if not path.is_file():
        return False, [f"{path}: no such file"]
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
            if MANIFEST not in names:
                return False, [f"{MANIFEST}: missing from the package"]
            try:
                manifest = json.loads(zf.read(MANIFEST))
            except json.JSONDecodeError:
                return False, [f"{MANIFEST}: not valid JSON"]
            if not isinstance(manifest, dict):
                return False, [f"{MANIFEST}: not a JSON object"]
            problems: list[str] = []
            if manifest.get("format") != FORMAT:
                problems.append(f"{MANIFEST}: format is {manifest.get('format')!r}, expected {FORMAT!r}")
            declared = manifest.get("files")
            if not isinstance(declared, dict) or not declared:
                problems.append(f"{MANIFEST}: has no 'files' digests")
                declared = {}
            for name, digest in sorted(declared.items()):
                if name not in names:
                    problems.append(f"{name}: listed in the manifest but missing from the package")
                    continue
                actual = _sha256(zf.read(name))
                if not isinstance(digest, str) or not hmac.compare_digest(actual, digest):
                    problems.append(f"{name}: sha256 {actual[:16]}… does not match the manifest ({str(digest)[:16]}…)")
            for name in sorted(names - set(declared) - {MANIFEST}):
                problems.append(f"{name}: present in the package but not listed in the manifest")
            signature = manifest.get("signature")
            if not isinstance(signature, str) or not signature:
                problems.append(f"{MANIFEST}: has no signature")
            else:
                expected = signer(manifest_signing_bytes(manifest))
                if not hmac.compare_digest(expected, signature):
                    problems.append(f"{MANIFEST}: signature does not verify with this installation's key")
    except zipfile.BadZipFile:
        return False, [f"{path.name}: not a zip file"]
    return not problems, problems
