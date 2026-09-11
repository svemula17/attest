"""SQL-backed stores: the JSONL evidence store and audit log mirrored onto the
relational model, plus the tables that only exist there (control snapshots,
collector runs, questionnaire drafts, risk acceptances).

Every store takes an Engine and opens a short session per call through
``attest.db.session_scope``. The evidence and audit tables keep the JSONL
hash-chain semantics: a row's sha256 covers its content plus the previous
row's digest, computed with the same canonical function the JSONL store uses,
so a JSONL store and a SQL store fed the same rows produce identical digests.

The first row of a chain has no predecessor. The JSONL stores encode that as
``None`` (and ``None`` is what the hash covers); the ``prev_sha256`` columns
are NOT NULL, so the genesis row stores the empty string and the two are
mapped at the boundary. Digests are therefore byte-identical to the JSONL
store's for the same rows.

Append is safe under concurrent writers. On SQLite the append transaction
opens with ``BEGIN IMMEDIATE`` so the read of the previous row and the insert
happen under the database write lock. Elsewhere (Postgres) the previous row is
locked ``FOR UPDATE`` and re-read until stable, because a writer queued behind
another is granted the lock on a row that is no longer the tail.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy import and_, func, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from attest.audit import AuditEntry
from attest.db import (Audit, CollectorRun, ControlSnapshot, Draft, Evidence, RiskAcceptance, session_scope,
                       to_dict, utcnow)
from attest.evidence import (CLASSIFICATION_ORDER, EvidenceRecord, EvidenceStore, classification_rank,
                             compute_sha256)
from attest.util import canonical_json, now_iso

__all__ = [
    "AUDIT_HASHED_FIELDS",
    "AcceptanceStore",
    "DraftStore",
    "RunStore",
    "SnapshotStore",
    "SqlAuditLog",
    "SqlEvidenceStore",
    "compute_audit_sha256",
]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _last_row(session: Session, model, *, lock: bool):
    stmt = select(model).order_by(model.seq.desc()).limit(1)
    if lock:
        stmt = stmt.with_for_update()
    return session.scalars(stmt).first()


def _tail_for_append(session: Session, model):
    """Return the current last row of ``model`` (None when empty) with writers serialized.

    SQLite: ``BEGIN IMMEDIATE`` takes the write lock up front, so the read below and
    the insert that follows in the same transaction are one atomic step. pysqlite only
    emits its own implicit BEGIN when no transaction is open, so this does not double up.

    Others (Postgres): lock the last row FOR UPDATE. A writer that waited on that lock
    is granted it after the holder committed a newer row, so re-read until the tail is
    stable. An empty table has nothing to lock; the unique index on the id column makes
    the loser of that one race fail loudly instead of forking the chain.
    """
    if session.get_bind().dialect.name == "sqlite":
        session.execute(text("BEGIN IMMEDIATE"))
        return _last_row(session, model, lock=False)
    tail = _last_row(session, model, lock=True)
    for _ in range(16):
        again = _last_row(session, model, lock=True)
        if (again is None and tail is None) or (
            again is not None and tail is not None and again.seq == tail.seq
        ):
            return again
        tail = again
    raise RuntimeError(f"could not settle the tail of {model.__tablename__} under concurrent appends")


def _prev_or_none(value: str | None) -> str | None:
    """NOT NULL column -> chain semantics: the genesis row stores '' and hashes as None."""
    return value or None


_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _validate_date(value: str, name: str) -> None:
    """Strict YYYY-MM-DD: zero-padded (strptime alone accepts '2026-9-1', which breaks lexical
    comparison against expiry dates) and a real calendar date."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a 'YYYY-MM-DD' string, got {type(value).__name__}")
    if not _DATE_RE.match(value):
        raise ValueError(f"{name} must be 'YYYY-MM-DD', got {value!r}")
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise ValueError(f"{name} is not a calendar date: {value!r}") from None


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
def _evidence_fields(row: Evidence) -> dict:
    """The hashed fields of a row, in the exact shape the JSONL store hashes."""
    return {
        "id": row.id,
        "source": row.source,
        "kind": row.kind,
        "control_ids": list(row.control_ids or []),
        "classification": row.classification,
        "collected_at": row.collected_at,
        "payload": dict(row.payload or {}),
        "prev_sha256": _prev_or_none(row.prev_sha256),
    }


def _evidence_record(row: Evidence) -> EvidenceRecord:
    return EvidenceRecord(sha256=row.sha256, **_evidence_fields(row))


class SqlEvidenceStore:
    """Evidence table with the JSONL store's interface. Append-only, hash-chained.

    Record ids are ``EV-%04d`` of the row sequence (five digits and beyond once the
    sequence grows past 9999). ``run_id`` links a record to the collector run that
    produced it and is not part of the digest, so digests match the JSONL store.
    """

    def __init__(self, engine: Engine):
        self.engine = engine

    def append(
        self,
        source: str,
        kind: str,
        control_ids: list[str],
        classification: str,
        payload: dict,
        collected_at: str | None = None,
        run_id: int | None = None,
    ) -> EvidenceRecord:
        classification_rank(classification)  # validate before touching the database
        control_ids = list(control_ids)
        payload = dict(payload)
        collected_at = collected_at or now_iso()
        canonical_json(payload)  # raise before any write if the payload is not JSON-serializable
        with session_scope(self.engine) as s:
            tail = _tail_for_append(s, Evidence)
            prev = tail.sha256 if tail is not None else None
            row = Evidence(
                id="",
                source=source,
                kind=kind,
                control_ids=control_ids,
                classification=classification,
                collected_at=collected_at,
                payload=payload,
                sha256="",
                prev_sha256=prev or "",
                run_id=run_id,
            )
            s.add(row)
            s.flush()  # the database assigns seq; the id and digest derive from it
            row.id = f"EV-{row.seq:04d}"
            row.sha256 = compute_sha256(_evidence_fields(row))
            s.flush()
            return _evidence_record(row)

    def all(self) -> list[EvidenceRecord]:
        with session_scope(self.engine) as s:
            rows = s.scalars(select(Evidence).order_by(Evidence.seq)).all()
            return [_evidence_record(r) for r in rows]

    def get(self, record_id: str) -> EvidenceRecord | None:
        with session_scope(self.engine) as s:
            row = s.scalars(select(Evidence).where(Evidence.id == record_id)).first()
            return _evidence_record(row) if row is not None else None

    def query(
        self,
        control_id: str | None = None,
        kind: str | None = None,
        max_classification: str | None = None,
    ) -> list[EvidenceRecord]:
        """Filter records. max_classification is inclusive: "publishable" returns only publishable,
        "internal" returns publishable + internal, "restricted" (or None) returns everything.
        Unknown labels stored in the table are treated as more sensitive than any known one."""
        max_rank = classification_rank(max_classification) if max_classification is not None else None
        stmt = select(Evidence).order_by(Evidence.seq)
        if kind is not None:
            stmt = stmt.where(Evidence.kind == kind)
        if max_rank is not None:
            stmt = stmt.where(Evidence.classification.in_(CLASSIFICATION_ORDER[: max_rank + 1]))
        with session_scope(self.engine) as s:
            rows = s.scalars(stmt).all()
            return [
                _evidence_record(r)
                for r in rows
                if control_id is None or control_id in (r.control_ids or [])
            ]

    def verify_chain(self) -> bool:
        """Walk rows in seq order, recompute every sha256 and check every prev_sha256 link."""
        with session_scope(self.engine) as s:
            rows = s.scalars(select(Evidence).order_by(Evidence.seq)).all()
            prev: str | None = None
            for row in rows:
                fields = _evidence_fields(row)
                if fields["prev_sha256"] != prev:
                    return False
                try:
                    if compute_sha256(fields) != row.sha256:
                        return False
                except (TypeError, ValueError):
                    return False
                prev = row.sha256
        return True

    def count(self) -> int:
        with session_scope(self.engine) as s:
            return int(s.scalar(select(func.count()).select_from(Evidence)) or 0)

    def import_jsonl(self, path: Path | str) -> int:
        """Append every record of a JSONL evidence file, preserving collected_at and payload.
        Ids and digests are re-assigned by this store's sequence. Returns the number imported."""
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(str(path))
        imported = 0
        for record in EvidenceStore(path).all():
            self.append(
                source=record.source,
                kind=record.kind,
                control_ids=record.control_ids,
                classification=record.classification,
                payload=record.payload,
                collected_at=record.collected_at,
            )
            imported += 1
        return imported

    def export_jsonl(self, path: Path | str) -> int:
        """Write every record, in chain order, in the JSONL store's on-disk format (the file is
        replaced). The result opens as a valid ``EvidenceStore`` with the same digests."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        records = self.all()
        with path.open("w", encoding="utf-8") as fh:
            for record in records:
                fh.write(canonical_json(asdict(record)) + "\n")
        return len(records)


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------
AUDIT_HASHED_FIELDS = (
    "ts",
    "actor",
    "action",
    "subject",
    "detail",
    "rule",
    "model_version",
    "approver",
    "prev_sha256",
)


def compute_audit_sha256(fields: dict) -> str:
    """Hex sha256 over the canonical JSON of an audit row's hashed fields (everything but sha256)."""
    subset = {name: fields[name] for name in AUDIT_HASHED_FIELDS}
    return hashlib.sha256(canonical_json(subset).encode("utf-8")).hexdigest()


def _audit_fields(row: Audit) -> dict:
    return {
        "ts": row.ts,
        "actor": row.actor,
        "action": row.action,
        "subject": row.subject,
        "detail": row.detail,
        "rule": row.rule,
        "model_version": row.model_version,
        "approver": row.approver,
        "prev_sha256": _prev_or_none(row.prev_sha256),
    }


def _audit_entry(row: Audit) -> AuditEntry:
    return AuditEntry(
        ts=row.ts,
        actor=row.actor,
        model_version=row.model_version,
        action=row.action,
        subject=row.subject,
        approver=row.approver,
        rule=row.rule,
        detail=row.detail,
    )


class SqlAuditLog:
    """Audit table with the JSONL log's interface, plus a hash chain over the rows."""

    def __init__(self, engine: Engine):
        self.engine = engine

    def record(
        self,
        actor: str,
        action: str,
        subject: str,
        model_version: str | None = None,
        approver: str | None = None,
        rule: str | None = None,
        detail: str = "",
    ) -> AuditEntry:
        fields = {
            "ts": now_iso(),
            "actor": actor,
            "action": action,
            "subject": subject,
            "detail": detail,
            "rule": rule,
            "model_version": model_version,
            "approver": approver,
        }
        with session_scope(self.engine) as s:
            tail = _tail_for_append(s, Audit)
            prev = tail.sha256 if tail is not None else None
            digest = compute_audit_sha256({**fields, "prev_sha256": prev})
            row = Audit(**fields, prev_sha256=prev or "", sha256=digest)
            s.add(row)
            s.flush()
            return _audit_entry(row)

    def all(self) -> list[AuditEntry]:
        with session_scope(self.engine) as s:
            rows = s.scalars(select(Audit).order_by(Audit.seq)).all()
            return [_audit_entry(r) for r in rows]

    def query(self, action_prefix: str | None = None, limit: int | None = None) -> list[AuditEntry]:
        """Newest first, optionally restricted to actions starting with ``action_prefix``."""
        stmt = select(Audit).order_by(Audit.seq.desc())
        if action_prefix is not None:
            stmt = stmt.where(Audit.action.startswith(action_prefix, autoescape=True))
        if limit is not None:
            stmt = stmt.limit(limit)
        with session_scope(self.engine) as s:
            return [_audit_entry(r) for r in s.scalars(stmt).all()]

    def verify_chain(self) -> bool:
        with session_scope(self.engine) as s:
            rows = s.scalars(select(Audit).order_by(Audit.seq)).all()
            prev: str | None = None
            for row in rows:
                fields = _audit_fields(row)
                if fields["prev_sha256"] != prev:
                    return False
                try:
                    if compute_audit_sha256(fields) != row.sha256:
                        return False
                except (TypeError, ValueError):
                    return False
                prev = row.sha256
        return True


# ---------------------------------------------------------------------------
# Control snapshots
# ---------------------------------------------------------------------------
class SnapshotStore:
    """One ControlSnapshot row per control per evaluation: the observation-window history."""

    def __init__(self, engine: Engine):
        self.engine = engine

    def record(self, results: Iterable[Any], trigger: str = "manual", evaluated_at: str | None = None) -> str:
        """Store one row per ControlResult under a single evaluated_at stamp and return that stamp."""
        evaluated_at = evaluated_at or utcnow()
        with session_scope(self.engine) as s:
            for result in results:
                s.add(
                    ControlSnapshot(
                        evaluated_at=evaluated_at,
                        control_id=result.control_id,
                        state=result.state,
                        reason=result.reason,
                        evidence_ids=list(result.evidence_ids),
                        trigger=trigger,
                    )
                )
        return evaluated_at

    def latest(self) -> dict[str, dict]:
        """The most recent snapshot of every control, keyed by control id."""
        newest = (
            select(ControlSnapshot.control_id, func.max(ControlSnapshot.evaluated_at).label("evaluated_at"))
            .group_by(ControlSnapshot.control_id)
            .subquery()
        )
        stmt = (
            select(ControlSnapshot)
            .join(
                newest,
                and_(
                    ControlSnapshot.control_id == newest.c.control_id,
                    ControlSnapshot.evaluated_at == newest.c.evaluated_at,
                ),
            )
            .order_by(ControlSnapshot.id)
        )
        out: dict[str, dict] = {}
        with session_scope(self.engine) as s:
            for row in s.scalars(stmt).all():
                out[row.control_id] = to_dict(row)  # same-second ties: the later row wins
        return out

    def history(self, control_id: str, since: str | None = None, limit: int | None = None) -> list[dict]:
        """Snapshots of one control, newest first; ``since`` is an inclusive ISO lower bound."""
        stmt = (
            select(ControlSnapshot)
            .where(ControlSnapshot.control_id == control_id)
            .order_by(ControlSnapshot.evaluated_at.desc(), ControlSnapshot.id.desc())
        )
        if since is not None:
            stmt = stmt.where(ControlSnapshot.evaluated_at >= since)
        if limit is not None:
            stmt = stmt.limit(limit)
        with session_scope(self.engine) as s:
            return [to_dict(r) for r in s.scalars(stmt).all()]

    def evaluations(self, limit: int | None = 50) -> list[str]:
        """Distinct evaluated_at stamps, newest first."""
        stmt = select(ControlSnapshot.evaluated_at).distinct().order_by(ControlSnapshot.evaluated_at.desc())
        if limit is not None:
            stmt = stmt.limit(limit)
        with session_scope(self.engine) as s:
            return [str(v) for v in s.scalars(stmt).all()]


# ---------------------------------------------------------------------------
# Collector runs
# ---------------------------------------------------------------------------
class RunStore:
    """Start/finish bookkeeping for collector executions."""

    def __init__(self, engine: Engine):
        self.engine = engine

    def start(self, source_id: str, trigger: str = "manual", started_by: str | None = None) -> int:
        with session_scope(self.engine) as s:
            run = CollectorRun(
                source_id=source_id,
                trigger=trigger,
                started_at=utcnow(),
                status="running",
                records=0,
                started_by=started_by,
            )
            s.add(run)
            s.flush()
            return run.id

    def finish(self, run_id: int, status: str, records: int = 0, error: str | None = None) -> dict:
        with session_scope(self.engine) as s:
            run = s.get(CollectorRun, run_id)
            if run is None:
                raise KeyError(run_id)
            run.finished_at = utcnow()
            run.status = status
            run.records = records
            run.error = error
            s.flush()
            return to_dict(run)

    def list(self, source_id: str | None = None, limit: int | None = 50) -> list[dict]:
        """Runs newest first, optionally for one source."""
        stmt = select(CollectorRun).order_by(CollectorRun.started_at.desc(), CollectorRun.id.desc())
        if source_id is not None:
            stmt = stmt.where(CollectorRun.source_id == source_id)
        if limit is not None:
            stmt = stmt.limit(limit)
        with session_scope(self.engine) as s:
            return [to_dict(r) for r in s.scalars(stmt).all()]

    def latest_by_source(self) -> dict[str, dict]:
        """The most recently started run of every source, keyed by source id."""
        newest = (
            select(CollectorRun.source_id, func.max(CollectorRun.started_at).label("started_at"))
            .group_by(CollectorRun.source_id)
            .subquery()
        )
        stmt = (
            select(CollectorRun)
            .join(
                newest,
                and_(CollectorRun.source_id == newest.c.source_id, CollectorRun.started_at == newest.c.started_at),
            )
            .order_by(CollectorRun.id)
        )
        out: dict[str, dict] = {}
        with session_scope(self.engine) as s:
            for row in s.scalars(stmt).all():
                out[row.source_id] = to_dict(row)  # same-second ties: the later run wins
        return out


# ---------------------------------------------------------------------------
# Questionnaire drafts
# ---------------------------------------------------------------------------
_DRAFT_COLUMNS = tuple(c.name for c in Draft.__table__.columns)
_DRAFT_REQUIRED = tuple(
    c.name for c in Draft.__table__.columns if not c.nullable and c.default is None and c.name != "question_id"
)
QUESTION_ID_FLOOR = 4474  # the PoC's demo queue ends at Q-4474, so the first stored draft is Q-4475


class DraftStore:
    """Questionnaire drafts and, once a human decides, the signed decision."""

    def __init__(self, engine: Engine):
        self.engine = engine

    @staticmethod
    def _next_question_id(session: Session) -> str:
        highest = QUESTION_ID_FLOOR
        for qid in session.scalars(select(Draft.question_id)).all():
            suffix = str(qid).rsplit("-", 1)[-1]
            if suffix.isdigit():
                highest = max(highest, int(suffix))
        return f"Q-{highest + 1}"

    def next_question_id(self) -> str:
        """``Q-<n>`` where n is one past the highest numeric suffix stored (or Q-4475 when empty)."""
        with session_scope(self.engine) as s:
            return self._next_question_id(s)

    def create(self, draft: dict) -> dict:
        """Insert a draft. Keys are Draft columns; created_at (and question_id) are filled if missing."""
        data = dict(draft)
        unknown = sorted(set(data) - set(_DRAFT_COLUMNS))
        if unknown:
            raise ValueError(f"unknown draft keys: {', '.join(unknown)}")
        missing = [name for name in _DRAFT_REQUIRED if name not in data]
        if "created_at" in missing and not data.get("created_at"):
            missing.remove("created_at")
        if missing:
            raise ValueError(f"draft is missing required keys: {', '.join(missing)}")
        data.setdefault("created_at", utcnow())
        with session_scope(self.engine) as s:
            if not data.get("question_id"):
                data["question_id"] = self._next_question_id(s)
            if s.get(Draft, data["question_id"]) is not None:
                raise ValueError(f"draft {data['question_id']} already exists")
            row = Draft(**data)
            s.add(row)
            s.flush()
            return to_dict(row)

    def get(self, question_id: str) -> dict | None:
        with session_scope(self.engine) as s:
            row = s.get(Draft, question_id)
            return to_dict(row) if row is not None else None

    def list(self, limit: int | None = None) -> list[dict]:
        """Drafts newest first."""
        stmt = select(Draft).order_by(Draft.created_at.desc(), Draft.question_id.desc())
        if limit is not None:
            stmt = stmt.limit(limit)
        with session_scope(self.engine) as s:
            return [to_dict(r) for r in s.scalars(stmt).all()]

    def decide(self, question_id: str, decision: str, approver: str, signature: str, decided_at: str) -> dict:
        """Record the human decision. A decision is final: deciding twice raises ValueError."""
        with session_scope(self.engine) as s:
            row = s.get(Draft, question_id)
            if row is None:
                raise KeyError(question_id)
            if row.decision is not None:
                raise ValueError(f"{question_id} already decided: {row.decision} by {row.approver}")
            row.decision = decision
            row.approver = approver
            row.signature = signature
            row.decided_at = decided_at
            s.flush()
            return to_dict(row)

    def count_pending(self) -> int:
        with session_scope(self.engine) as s:
            return int(s.scalar(select(func.count()).select_from(Draft).where(Draft.decision.is_(None))) or 0)


# ---------------------------------------------------------------------------
# Risk acceptances
# ---------------------------------------------------------------------------
class AcceptanceStore:
    """FAILs a named owner has accepted until a date. Expired or revoked acceptances fail the gate."""

    def __init__(self, engine: Engine):
        self.engine = engine

    def add(self, control_id: str, owner: str, reason: str, expires: str, created_by: str) -> dict:
        _validate_date(expires, "expires")
        with session_scope(self.engine) as s:
            row = RiskAcceptance(
                control_id=control_id,
                owner=owner,
                reason=reason,
                expires=expires,
                created_at=utcnow(),
                created_by=created_by,
            )
            s.add(row)
            s.flush()
            return to_dict(row)

    def all(self) -> list[dict]:
        with session_scope(self.engine) as s:
            return [to_dict(r) for r in s.scalars(select(RiskAcceptance).order_by(RiskAcceptance.id)).all()]

    def active(self, today: str) -> list[dict]:
        """Acceptances that are not revoked and expire on or after ``today`` (YYYY-MM-DD)."""
        _validate_date(today, "today")
        stmt = (
            select(RiskAcceptance)
            .where(RiskAcceptance.revoked_at.is_(None), RiskAcceptance.expires >= today)
            .order_by(RiskAcceptance.id)
        )
        with session_scope(self.engine) as s:
            return [to_dict(r) for r in s.scalars(stmt).all()]

    def revoke(self, acceptance_id: int, at: str) -> dict:
        """Mark an acceptance revoked at ``at``. Revoking twice keeps the first timestamp."""
        with session_scope(self.engine) as s:
            row = s.get(RiskAcceptance, acceptance_id)
            if row is None:
                raise KeyError(acceptance_id)
            if row.revoked_at is None:
                row.revoked_at = at
                s.flush()
            return to_dict(row)
