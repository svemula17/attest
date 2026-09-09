"""Append-only JSONL audit log."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from attest.util import canonical_json, now_iso


@dataclass(frozen=True)
class AuditEntry:
    ts: str
    actor: str
    model_version: str | None
    action: str
    subject: str
    approver: str | None
    rule: str | None
    detail: str


class AuditLog:
    """JSONL-backed audit log. One entry per line; the file is created if missing. Append-only."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._entries: list[AuditEntry] | None = None  # loaded lazily, then kept in sync on record

    def _loaded(self) -> list[AuditEntry]:
        if self._entries is None:
            entries: list[AuditEntry] = []
            with self.path.open("r", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(AuditEntry(**json.loads(line)))
                    except (json.JSONDecodeError, TypeError) as exc:
                        raise ValueError(f"{self.path}:{lineno}: malformed audit line") from exc
            self._entries = entries
        return self._entries

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
        entry = AuditEntry(
            ts=now_iso(),
            actor=actor,
            model_version=model_version,
            action=action,
            subject=subject,
            approver=approver,
            rule=rule,
            detail=detail,
        )
        entries = self._loaded()
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(canonical_json(asdict(entry)) + "\n")
        entries.append(entry)
        return entry

    def all(self) -> list[AuditEntry]:
        return list(self._loaded())
