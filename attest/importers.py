"""CSV/JSON → evidence records, for teams with no live integrations yet.

Four mappings. Three are CSV, one is JSON:

* ``evidence``      one evidence record per row
                    columns: source,kind,control_ids,classification,collected_at,summary,result[,payload_json]
* ``hris.roster``   the whole file becomes ONE ``hris.roster`` record (input to the HRIS × IdP join)
                    columns: employee_id,name,email,hired,terminated
* ``idp.users``     the whole file becomes ONE ``idp.users`` record (the other join input)
                    columns: email,status,deprovisioned_at
* ``evidence.json`` a JSON array — or ``{"records": [...]}`` — of evidence objects
                    {source, kind, control_ids, classification, payload{summary, result, ...}, collected_at?}

With ``mapping=None`` the mapping is inferred: ``.json`` → ``evidence.json``; ``.csv`` → the header
decides (the exact hris / idp column sets pick those mappings, anything else is ``evidence``).

The whole file is validated before anything is appended: a file with one bad row writes nothing.
Problems are reported as ``"row N: …"`` where N is the physical line number of a CSV row or the
1-based index of a JSON record. CSV lines starting with ``#`` are comments (a UTF-8 BOM is fine too);
in the JSON envelope form, keys other than ``records`` are ignored so a ``"comment"`` can live there.

Works with any store exposing ``append(source, kind, control_ids, classification, payload, collected_at)``;
``run_id`` is forwarded only when the store's ``append`` accepts it.
"""
from __future__ import annotations

import csv
import inspect
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from attest.evidence import CLASSIFICATION_ORDER
from attest.sources import source_by_id
from attest.util import parse_iso

MAPPINGS = ("evidence", "hris.roster", "idp.users", "evidence.json")

EVIDENCE_REQUIRED = ("source", "kind", "control_ids", "classification", "summary", "result")
EVIDENCE_OPTIONAL = ("collected_at", "payload_json")
HRIS_COLUMNS = ("employee_id", "name", "email", "hired", "terminated")
IDP_COLUMNS = ("email", "status", "deprovisioned_at")
JSON_REQUIRED = ("source", "kind", "control_ids", "classification", "payload")
JSON_OPTIONAL = ("collected_at",)

RESULTS = ("pass", "fail")
IDP_STATUSES = ("active", "deprovisioned")
ACCESS_CONTROL = "CTL-ACCESS-02"


class ImportProblem(ValueError):
    """The file was rejected. ``problems`` lists every issue, each prefixed ``"row N: "`` (or ``"file: "``)."""

    def __init__(self, problems: list[str], path: Path | str | None = None):
        self.problems = list(problems)
        self.path = Path(path) if path is not None else None
        where = f" in {self.path.name}" if self.path else ""
        super().__init__(f"{len(self.problems)} problem(s){where}; nothing was written:\n  " + "\n  ".join(self.problems))


@dataclass
class ImportResult:
    records: int
    kinds: list[str]
    warnings: list[str] = field(default_factory=list)


@dataclass
class _Pending:
    """A validated record waiting for the all-or-nothing append."""
    source: str
    kind: str
    control_ids: list[str]
    classification: str
    payload: dict
    collected_at: str | None = None


@dataclass
class _Table:
    header: list[str]
    rows: list[tuple[int, list[str]]]  # (physical line number, cells)


# -- store adapter --------------------------------------------------------------

def _accepts_run_id(store) -> bool:
    try:
        params = inspect.signature(store.append).parameters
    except (TypeError, ValueError):
        return False
    return "run_id" in params or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


def _append_all(store, pending: list[_Pending], run_id) -> None:
    extra = {"run_id": run_id} if run_id is not None and _accepts_run_id(store) else {}
    for p in pending:
        store.append(source=p.source, kind=p.kind, control_ids=list(p.control_ids), classification=p.classification,
                     payload=p.payload, collected_at=p.collected_at, **extra)


# -- CSV reading ----------------------------------------------------------------

def _read_csv(path: Path) -> _Table:
    text = path.read_text(encoding="utf-8-sig")
    # Blank out comment lines instead of dropping them so csv's line numbers stay physical.
    lines = ["\n" if ln.lstrip().startswith("#") else ln for ln in text.splitlines(keepends=True)]
    reader = csv.reader(lines)
    header: list[str] | None = None
    rows: list[tuple[int, list[str]]] = []
    for row in reader:
        if not row or all(not c.strip() for c in row):
            continue
        if header is None:
            header = [c.strip() for c in row]
            continue
        rows.append((reader.line_num, row))
    if header is None:
        raise ImportProblem(["file: empty (no header row)"], path)
    return _Table(header, rows)


def _check_header(table: _Table, required: tuple[str, ...], optional: tuple[str, ...],
                  problems: list[str], warnings: list[str]) -> None:
    have = set(table.header)
    missing = [c for c in required if c not in have]
    if missing:
        problems.append(f"file: header is missing column(s): {', '.join(missing)} (found: {', '.join(table.header) or 'nothing'})")
    extra = [c for c in table.header if c not in required and c not in optional]
    if extra:
        warnings.append(f"file: ignoring unknown column(s): {', '.join(extra)}")
    if not table.rows:
        problems.append("file: no data rows")


def _cells(table: _Table, lineno: int, row: list[str], problems: list[str]) -> dict[str, str] | None:
    if len(row) > len(table.header):
        problems.append(f"row {lineno}: {len(row)} fields but the header has {len(table.header)}")
        return None
    row = row + [""] * (len(table.header) - len(row))
    return {name: value.strip() for name, value in zip(table.header, row)}


def _date(value: str) -> bool:
    try:
        datetime.strptime(value, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def _timestamp(value: str) -> bool:
    try:
        parse_iso(value)
        return True
    except (TypeError, ValueError):
        return False


def _warn_unknown_sources(pending: list[_Pending], warnings: list[str], where: dict[str, int]) -> None:
    for src in dict.fromkeys(p.source for p in pending):  # first-seen order, deduplicated
        if source_by_id(src) is None:
            warnings.append(f"row {where[src]}: source '{src}' is not in the source catalog (attest sources); kept as-is")


# -- mapping: evidence (CSV) -----------------------------------------------------

def _parse_evidence_csv(table: _Table, default_source: str | None, path: Path) -> tuple[list[_Pending], list[str]]:
    problems: list[str] = []
    warnings: list[str] = []
    _check_header(table, EVIDENCE_REQUIRED, EVIDENCE_OPTIONAL, problems, warnings)
    if problems:
        raise ImportProblem(problems, path)
    pending: list[_Pending] = []
    first_row_for: dict[str, int] = {}
    for lineno, row in table.rows:
        c = _cells(table, lineno, row, problems)
        if c is None:
            continue
        ok = True

        def bad(msg: str) -> None:
            nonlocal ok
            ok = False
            problems.append(f"row {lineno}: {msg}")

        source = c["source"] or (default_source or "")
        if not source:
            bad("source is blank and no default source was given")
        if not c["kind"]:
            bad("kind is blank")
        if c["classification"] not in CLASSIFICATION_ORDER:
            bad(f"classification {c['classification']!r} must be one of {', '.join(CLASSIFICATION_ORDER)}")
        collected_at = c.get("collected_at", "") or None
        if collected_at and not _timestamp(collected_at):
            bad(f"collected_at {collected_at!r} must be UTC ISO-8601 like 2026-09-10T08:00:00Z")
        if not c["summary"]:
            bad("summary is blank")
        if c["result"] not in RESULTS:
            bad(f"result {c['result']!r} must be pass or fail")
        extra: dict = {}
        raw = c.get("payload_json", "")
        if raw:
            try:
                extra = json.loads(raw)
            except ValueError as e:
                bad(f"payload_json is not valid JSON ({e})")
            else:
                if not isinstance(extra, dict):
                    bad("payload_json must be a JSON object")
        if not ok:
            continue
        control_ids = [x.strip() for x in c["control_ids"].split(";") if x.strip()]
        payload = dict(extra)
        payload.update({"summary": c["summary"], "result": c["result"]})  # the columns win over payload_json
        pending.append(_Pending(source, c["kind"], control_ids, c["classification"], payload, collected_at))
        first_row_for.setdefault(source, lineno)
    if problems:
        raise ImportProblem(problems, path)
    _warn_unknown_sources(pending, warnings, first_row_for)
    return pending, warnings


# -- mapping: hris.roster (CSV) --------------------------------------------------

def _parse_hris_csv(table: _Table, default_source: str | None, path: Path) -> tuple[list[_Pending], list[str]]:
    problems: list[str] = []
    warnings: list[str] = []
    _check_header(table, HRIS_COLUMNS, (), problems, warnings)
    if problems:
        raise ImportProblem(problems, path)
    if default_source and default_source != "hris":
        warnings.append(f"file: source '{default_source}' ignored; hris.roster records always have source 'hris'")
    employees: list[dict] = []
    seen: dict[str, int] = {}
    for lineno, row in table.rows:
        c = _cells(table, lineno, row, problems)
        if c is None:
            continue
        ok = True
        if not c["employee_id"]:
            problems.append(f"row {lineno}: employee_id is blank")
            ok = False
        if not c["email"]:
            problems.append(f"row {lineno}: email is blank (the join matches HRIS to the IdP by email)")
            ok = False
        if not _date(c["hired"]):
            problems.append(f"row {lineno}: hired {c['hired']!r} must be YYYY-MM-DD")
            ok = False
        if c["terminated"] and not _date(c["terminated"]):
            problems.append(f"row {lineno}: terminated {c['terminated']!r} must be YYYY-MM-DD or blank")
            ok = False
        if not ok:
            continue
        email = c["email"].lower()
        if email in seen:
            warnings.append(f"row {lineno}: duplicate email {c['email']} (also row {seen[email]})")
        seen.setdefault(email, lineno)
        employees.append({"id": c["employee_id"], "name": c["name"], "email": c["email"],
                          "hired": c["hired"], "terminated": c["terminated"] or None})
    if problems:
        raise ImportProblem(problems, path)
    terminated = sum(1 for e in employees if e["terminated"])
    payload = {"summary": f"HRIS roster: {len(employees)} employees, {terminated} terminated",
               "result": "pass", "employees": employees}
    return [_Pending("hris", "hris.roster", [ACCESS_CONTROL], "internal", payload)], warnings


# -- mapping: idp.users (CSV) ----------------------------------------------------

def _parse_idp_csv(table: _Table, default_source: str | None, path: Path) -> tuple[list[_Pending], list[str]]:
    problems: list[str] = []
    warnings: list[str] = []
    _check_header(table, IDP_COLUMNS, (), problems, warnings)
    if problems:
        raise ImportProblem(problems, path)
    if default_source and default_source != "okta":
        warnings.append(f"file: source '{default_source}' ignored; idp.users records always have source 'okta'")
    users: list[dict] = []
    seen: dict[str, int] = {}
    for lineno, row in table.rows:
        c = _cells(table, lineno, row, problems)
        if c is None:
            continue
        ok = True
        if not c["email"]:
            problems.append(f"row {lineno}: email is blank")
            ok = False
        if c["status"] not in IDP_STATUSES:
            problems.append(f"row {lineno}: status {c['status']!r} must be active or deprovisioned")
            ok = False
        if c["deprovisioned_at"] and not _timestamp(c["deprovisioned_at"]):
            problems.append(f"row {lineno}: deprovisioned_at {c['deprovisioned_at']!r} must be UTC ISO-8601 like 2026-08-15T09:40:00Z or blank")
            ok = False
        if not ok:
            continue
        if c["status"] == "deprovisioned" and not c["deprovisioned_at"]:
            warnings.append(f"row {lineno}: {c['email']} is deprovisioned without a deprovisioned_at; the join cannot check its SLA")
        email = c["email"].lower()
        if email in seen:
            warnings.append(f"row {lineno}: duplicate email {c['email']} (also row {seen[email]})")
        seen.setdefault(email, lineno)
        users.append({"email": c["email"], "status": c["status"], "deprovisioned_at": c["deprovisioned_at"] or None})
    if problems:
        raise ImportProblem(problems, path)
    active = sum(1 for u in users if u["status"] == "active")
    payload = {"summary": f"IdP users: {active} active, {len(users) - active} deprovisioned",
               "result": "pass", "users": users}
    return [_Pending("okta", "idp.users", [ACCESS_CONTROL], "internal", payload)], warnings


# -- mapping: evidence.json ------------------------------------------------------

def _parse_json(path: Path, default_source: str | None) -> tuple[list[_Pending], list[str]]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
    except ValueError as e:
        raise ImportProblem([f"file: not valid JSON ({e})"], path) from None
    if isinstance(doc, dict) and isinstance(doc.get("records"), list):
        items = doc["records"]
    elif isinstance(doc, list):
        items = doc
    else:
        raise ImportProblem(["file: expected a JSON array of records, or an object with a 'records' array"], path)
    if not items:
        raise ImportProblem(["file: no records"], path)

    problems: list[str] = []
    warnings: list[str] = []
    pending: list[_Pending] = []
    first_row_for: dict[str, int] = {}
    for n, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            problems.append(f"row {n}: expected an object, got {type(item).__name__}")
            continue
        ok = True

        def bad(msg: str) -> None:
            nonlocal ok
            ok = False
            problems.append(f"row {n}: {msg}")

        for key in item:
            if key not in JSON_REQUIRED and key not in JSON_OPTIONAL:
                warnings.append(f"row {n}: ignoring unknown key '{key}'")
        missing = [k for k in JSON_REQUIRED if k not in item and not (k == "source" and default_source)]
        if missing:
            bad(f"missing required key(s): {', '.join(missing)}")
            continue
        source = item.get("source") or default_source
        if not isinstance(source, str) or not source:
            bad("source must be a non-empty string")
        kind = item.get("kind")
        if not isinstance(kind, str) or not kind:
            bad("kind must be a non-empty string")
        control_ids = item.get("control_ids")
        if not isinstance(control_ids, list) or not all(isinstance(x, str) and x for x in control_ids):
            bad("control_ids must be a list of control id strings (an empty list is allowed)")
        classification = item.get("classification")
        if classification not in CLASSIFICATION_ORDER:
            bad(f"classification {classification!r} must be one of {', '.join(CLASSIFICATION_ORDER)}")
        payload = item.get("payload")
        if not isinstance(payload, dict):
            bad("payload must be an object with at least summary and result")
        else:
            if not isinstance(payload.get("summary"), str) or not payload["summary"]:
                bad("payload.summary must be a non-empty string")
            if payload.get("result") not in RESULTS:
                bad(f"payload.result {payload.get('result')!r} must be pass or fail")
        collected_at = item.get("collected_at")
        if collected_at is not None and not (isinstance(collected_at, str) and _timestamp(collected_at)):
            bad(f"collected_at {collected_at!r} must be UTC ISO-8601 like 2026-09-10T08:00:00Z")
        if not ok:
            continue
        pending.append(_Pending(source, kind, list(control_ids), classification, dict(payload), collected_at))
        first_row_for.setdefault(source, n)
    if problems:
        raise ImportProblem(problems, path)
    _warn_unknown_sources(pending, warnings, first_row_for)
    return pending, warnings


# -- entry point ----------------------------------------------------------------

_CSV_PARSERS = {"evidence": _parse_evidence_csv, "hris.roster": _parse_hris_csv, "idp.users": _parse_idp_csv}


def infer_csv_mapping(header: list[str]) -> str:
    """The exact hris / idp column sets pick those mappings; anything else is generic evidence."""
    columns = set(header)
    if columns == set(HRIS_COLUMNS):
        return "hris.roster"
    if columns == set(IDP_COLUMNS):
        return "idp.users"
    return "evidence"


def import_file(store, path, mapping: str | None = None, source: str | None = None, run_id=None) -> ImportResult:
    """Validate the whole file, then append every record (all-or-nothing).

    Raises ImportProblem (a ValueError) listing every problem when the file is rejected;
    a bad ``mapping`` name is a plain ValueError. Unknown source ids only produce warnings.
    """
    path = Path(path)
    if mapping is not None and mapping not in MAPPINGS:
        raise ValueError(f"unknown mapping {mapping!r}; expected one of {', '.join(MAPPINGS)}")
    if not path.is_file():
        raise FileNotFoundError(f"import file not found: {path}")

    table: _Table | None = None
    if mapping is None:
        suffix = path.suffix.lower()
        if suffix == ".json":
            mapping = "evidence.json"
        elif suffix == ".csv":
            table = _read_csv(path)
            mapping = infer_csv_mapping(table.header)
        else:
            raise ImportProblem([f"file: cannot infer a mapping from extension {suffix or '(none)'!r}; "
                                 f"pass mapping= (one of {', '.join(MAPPINGS)})"], path)

    if mapping == "evidence.json":
        pending, warnings = _parse_json(path, source)
    else:
        table = table or _read_csv(path)
        pending, warnings = _CSV_PARSERS[mapping](table, source, path)

    _append_all(store, pending, run_id)
    kinds = list(dict.fromkeys(p.kind for p in pending))
    return ImportResult(records=len(pending), kinds=kinds, warnings=warnings)
