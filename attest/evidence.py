"""Append-only, hash-chained evidence store backed by a JSONL file.

Every record's sha256 covers all of its fields plus the previous record's
sha256, so any edit or removal of an earlier line breaks the chain.
The store exposes no update/delete methods: append-only by construction.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from attest.util import canonical_json, now_iso

CLASSIFICATION_ORDER = ["publishable", "internal", "restricted"]  # ascending sensitivity

# Fields covered by the hash, i.e. everything except sha256 itself.
_HASHED_FIELDS = (
    "id",
    "source",
    "kind",
    "control_ids",
    "classification",
    "collected_at",
    "payload",
    "prev_sha256",
)


@dataclass(frozen=True)
class EvidenceRecord:
    id: str                 # "EV-0001", zero-padded 4, sequential
    source: str             # "aws-config" | "cloudtrail" | "github" | "okta" | "vendor-registry" | ...
    kind: str               # dotted, e.g. "kms.key.rotation"
    control_ids: list[str]  # e.g. ["CTL-CRYPTO-01"]
    classification: str     # "publishable" | "internal" | "restricted"
    collected_at: str       # ISO 8601 UTC
    payload: dict
    sha256: str             # hex digest over canonical JSON of all fields except sha256 (incl. prev_sha256)
    prev_sha256: str | None


def compute_sha256(fields: dict) -> str:
    """Hex sha256 over the canonical JSON of the hashed fields of a record (or record dict)."""
    subset = {name: fields[name] for name in _HASHED_FIELDS}
    return hashlib.sha256(canonical_json(subset).encode("utf-8")).hexdigest()


def classification_rank(classification: str) -> int:
    """Index into CLASSIFICATION_ORDER; raises ValueError for unknown labels."""
    try:
        return CLASSIFICATION_ORDER.index(classification)
    except ValueError:
        raise ValueError(
            f"unknown classification {classification!r}; expected one of {CLASSIFICATION_ORDER}"
        ) from None


def _record_from_dict(d: dict) -> EvidenceRecord:
    return EvidenceRecord(
        id=d["id"],
        source=d["source"],
        kind=d["kind"],
        control_ids=list(d["control_ids"]),
        classification=d["classification"],
        collected_at=d["collected_at"],
        payload=d["payload"],
        sha256=d["sha256"],
        prev_sha256=d.get("prev_sha256"),
    )


class EvidenceStore:
    """JSONL-backed evidence store. One record per line; the file is created if missing."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._records: list[EvidenceRecord] | None = None  # loaded lazily, then kept in sync on append

    # -- loading -----------------------------------------------------------------

    def _read_disk(self) -> list[EvidenceRecord]:
        records: list[EvidenceRecord] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(_record_from_dict(json.loads(line)))
                except (json.JSONDecodeError, KeyError, TypeError) as exc:
                    raise ValueError(f"{self.path}:{lineno}: malformed evidence line") from exc
        return records

    def _loaded(self) -> list[EvidenceRecord]:
        if self._records is None:
            self._records = self._read_disk()
        return self._records

    @staticmethod
    def _next_id(records: list[EvidenceRecord]) -> str:
        if not records:
            return "EV-0001"
        last_number = int(records[-1].id.rsplit("-", 1)[1])
        return f"EV-{last_number + 1:04d}"

    # -- public API --------------------------------------------------------------

    def append(
        self,
        source: str,
        kind: str,
        control_ids: list[str],
        classification: str,
        payload: dict,
        collected_at: str | None = None,
    ) -> EvidenceRecord:
        classification_rank(classification)  # validate before touching disk
        records = self._loaded()
        fields = {
            "id": self._next_id(records),
            "source": source,
            "kind": kind,
            "control_ids": list(control_ids),
            "classification": classification,
            "collected_at": collected_at or now_iso(),
            "payload": dict(payload),
            "prev_sha256": records[-1].sha256 if records else None,
        }
        fields["sha256"] = compute_sha256(fields)  # raises before any write if payload is not JSON-serializable
        record = _record_from_dict(fields)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(canonical_json(asdict(record)) + "\n")
        records.append(record)
        return record

    def all(self) -> list[EvidenceRecord]:
        return list(self._loaded())

    def get(self, record_id: str) -> EvidenceRecord | None:
        for record in self._loaded():
            if record.id == record_id:
                return record
        return None

    def query(
        self,
        control_id: str | None = None,
        kind: str | None = None,
        max_classification: str | None = None,
    ) -> list[EvidenceRecord]:
        """Filter records. max_classification is inclusive: "publishable" returns only publishable,
        "internal" returns publishable + internal, "restricted" (or None) returns everything."""
        max_rank = classification_rank(max_classification) if max_classification is not None else None
        matches: list[EvidenceRecord] = []
        for record in self._loaded():
            if control_id is not None and control_id not in record.control_ids:
                continue
            if kind is not None and record.kind != kind:
                continue
            if max_rank is not None:
                # Fail closed: an unknown label on disk is treated as more sensitive than any known one.
                if record.classification not in CLASSIFICATION_ORDER:
                    continue
                if classification_rank(record.classification) > max_rank:
                    continue
            matches.append(record)
        return matches

    def verify_chain(self) -> bool:
        """Re-read the file from disk, recompute every sha256 and check every prev_sha256 link."""
        try:
            records = self._read_disk()
        except ValueError:
            return False
        prev: str | None = None
        for record in records:
            if record.prev_sha256 != prev:
                return False
            try:
                if compute_sha256(asdict(record)) != record.sha256:
                    return False
            except (TypeError, ValueError):
                return False
            prev = record.sha256
        return True
