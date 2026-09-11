"""WORM export of the audit trail: a JSONL file plus a proof, optionally uploaded to an
S3 bucket under Object Lock (COMPLIANCE mode), so the audit log has an off-box copy that
nobody — including the bucket owner — can shorten or edit until the retention date.

    attest audit-export --out audit.jsonl --s3 s3://compliance-worm/attest --retain-days 365
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from attest.packages import validate_since
from attest.store_sql import compute_audit_sha256
from attest.util import ISO_FORMAT, canonical_json, now_iso

__all__ = ["PROOF_FORMAT", "PROOF_SUFFIX", "export_audit", "parse_bucket_uri", "proof_path", "upload_worm"]

PROOF_FORMAT = "attest-audit-proof/1"
PROOF_SUFFIX = ".proof.json"
LOCK_MODE = "COMPLIANCE"


def proof_path(out: Path) -> Path:
    """``<out>.proof.json`` next to the export."""
    out = Path(out)
    return out.with_name(out.name + PROOF_SUFFIX)


def export_audit(audit, out: Path, since: str | None = None) -> dict:
    """Write every audit entry (at or after ``since``) to ``out`` as JSONL, oldest first, plus a proof.

    The proof carries the chain digest at the last exported entry — recomputed the way the SQL
    audit table computes it, so it equals the stored ``sha256`` of that row — the sha256 of the
    file itself, and whether the store's whole chain verified at export time. Returns the proof
    with ``path`` and ``proof_path`` added.
    """
    out = Path(out)
    since = validate_since(since)
    entries = audit.all()  # chronological
    lines: list[str] = []
    prev: str | None = None
    first_ts = last_ts = last_digest = None
    for entry in entries:
        fields = asdict(entry)
        digest = compute_audit_sha256({**fields, "prev_sha256": prev})
        prev = digest
        if since is not None and entry.ts < since:
            continue
        lines.append(canonical_json(fields) + "\n")
        first_ts = first_ts or entry.ts
        last_ts, last_digest = entry.ts, digest
    data = "".join(lines).encode("utf-8")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    verify = getattr(audit, "verify_chain", None)
    proof = dict(
        format=PROOF_FORMAT,
        file=out.name,
        exported_at=now_iso(),
        since=since,
        count=len(lines),
        total=len(entries),
        first_ts=first_ts,
        last_ts=last_ts,
        last_sha256=last_digest,
        chain_verified=bool(verify()) if callable(verify) else None,
        sha256_of_file=hashlib.sha256(data).hexdigest(),
    )
    proof_path(out).write_text(json.dumps(proof, indent=2, sort_keys=True), encoding="utf-8")
    return dict(proof, path=str(out), proof_path=str(proof_path(out)))


def parse_bucket_uri(uri: str) -> tuple[str, str]:
    """``s3://bucket/prefix`` -> ('bucket', 'prefix'); the prefix may be empty."""
    if not isinstance(uri, str) or not uri.startswith("s3://"):
        raise ValueError(f"bucket must be an s3://bucket/prefix URI, got {uri!r}")
    rest = uri[len("s3://"):]
    bucket, _, prefix = rest.partition("/")
    if not bucket:
        raise ValueError(f"bucket URI names no bucket: {uri!r}")
    return bucket, prefix.strip("/")


def upload_worm(path: Path, bucket_uri: str, retain_days: int, client=None) -> dict:
    """Put the export and its proof into the bucket under a COMPLIANCE-mode Object Lock that
    expires ``retain_days`` from now, with an S3-computed SHA-256 checksum on each upload.
    The bucket must have Object Lock enabled (set at creation; S3 rejects the lock otherwise)."""
    path = Path(path)
    proof = proof_path(path)
    if not path.is_file():
        raise FileNotFoundError(str(path))
    if not proof.is_file():
        raise FileNotFoundError(f"{proof}: export the audit trail first (it writes the proof next to the file)")
    if not isinstance(retain_days, int) or retain_days < 1:
        raise ValueError(f"retain_days must be a positive integer, got {retain_days!r}")
    bucket, prefix = parse_bucket_uri(bucket_uri)
    if client is None:
        import boto3  # optional dependency: attest[aws]
        client = boto3.client("s3")
    retain_until = datetime.now(timezone.utc) + timedelta(days=retain_days)
    keys: list[str] = []
    for f in (path, proof):
        key = f"{prefix}/{f.name}" if prefix else f.name
        client.put_object(
            Bucket=bucket,
            Key=key,
            Body=f.read_bytes(),
            ObjectLockMode=LOCK_MODE,
            ObjectLockRetainUntilDate=retain_until,
            ChecksumAlgorithm="SHA256",
        )
        keys.append(key)
    return dict(bucket=bucket, keys=keys, retain_until=retain_until.strftime(ISO_FORMAT), retain_days=retain_days, mode=LOCK_MODE)
