"""Customer security questionnaires in (CSV / XLSX -> rows the agent drafts answers for)
and out (the decided queue -> CSV / XLSX the customer gets back).

Import format: a header row with a ``question`` column; optional ``control_ids`` (ids
separated by ';' or ','), optional ``ref`` (or ``id``) — the customer's own question
number, carried through to the export. Header names are case-insensitive. Rows whose
question is blank are skipped (section headings, spacer rows). Every problem is
reported with its row number, all at once, and nothing is imported.

Export columns: ref, question_id, question, status, answer, citations (evidence ids,
';'-joined), decision, approver, signed_at, signature. A DECLINED or BLOCKED row has no
answer; its answer cell carries ``NOT ANSWERED: <reason>`` so the gap is explicit.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Iterable

__all__ = [
    "EXPORT_COLUMNS",
    "NOT_ANSWERED",
    "QuestionnaireError",
    "export_questionnaire",
    "parse_questionnaire",
]

EXPORT_COLUMNS = ("ref", "question_id", "question", "status", "answer", "citations", "decision", "approver", "signed_at", "signature")
NOT_ANSWERED = "NOT ANSWERED: "
QUESTION = "question"
CONTROLS = "control_ids"
REFS = ("ref", "id")
MAX_QUESTION_CHARS = 4000
CSV_SUFFIXES = (".csv",)
XLSX_SUFFIXES = (".xlsx", ".xlsm")

_CONTROL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SPLIT_RE = re.compile(r"[;,]")


class QuestionnaireError(ValueError):
    """The file could not be imported. ``problems`` lists every issue, each with its row number."""

    def __init__(self, problems: Iterable[str], path: Path | None = None):
        self.problems = list(problems)
        self.path = Path(path) if path is not None else None
        where = f"{self.path.name}: " if self.path is not None else ""
        noun = "problem" if len(self.problems) == 1 else "problems"
        super().__init__(f"{where}{len(self.problems)} {noun}\n" + "\n".join(f"  - {p}" for p in self.problems))


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
def _cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))  # openpyxl hands back 3.0 for a plain 3
    return str(value).strip()


def _rows_from_csv(path: Path) -> tuple[list[str] | None, list[tuple[int, list[str]]]]:
    header: list[str] | None = None
    rows: list[tuple[int, list[str]]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        for rowno, cells in enumerate(csv.reader(fh), start=1):
            values = [_cell(c) for c in cells]
            if not any(values):
                continue
            if header is None:
                header = [v.lower() for v in values]
                continue
            rows.append((rowno, values))
    return header, rows


def _rows_from_xlsx(path: Path) -> tuple[list[str] | None, list[tuple[int, list[str]]]]:
    try:
        from openpyxl import load_workbook
    except ImportError:  # pragma: no cover - optional dependency
        raise QuestionnaireError(["reading .xlsx needs openpyxl: pip install 'attest[xlsx]'"], path) from None
    try:
        wb = load_workbook(path, read_only=True, data_only=True)
    except Exception as exc:  # openpyxl raises a zoo of exceptions for a corrupt file
        raise QuestionnaireError([f"not a readable .xlsx workbook ({exc.__class__.__name__}: {exc})"], path) from None
    try:
        ws = wb.worksheets[0]
        header: list[str] | None = None
        rows: list[tuple[int, list[str]]] = []
        for rowno, cells in enumerate(ws.iter_rows(values_only=True), start=1):
            values = [_cell(c) for c in cells]
            if not any(values):
                continue
            if header is None:
                header = [v.lower() for v in values]
                continue
            rows.append((rowno, values))
        return header, rows
    finally:
        wb.close()


def _split_controls(text: str) -> list[str]:
    return [part.strip() for part in _SPLIT_RE.split(text) if part.strip()]


def parse_questionnaire(path: Path) -> list[dict]:
    """Rows of ``{question, control_ids, ref}`` from a CSV or XLSX file, in file order.

    Raises :class:`QuestionnaireError` listing every problem with its row number (row 1 is the
    header). Blank questions are skipped rather than reported.
    """
    path = Path(path)
    if not path.is_file():
        raise QuestionnaireError([f"no such file: {path}"], path)
    suffix = path.suffix.lower()
    if suffix in CSV_SUFFIXES:
        header, rows = _rows_from_csv(path)
    elif suffix in XLSX_SUFFIXES:
        header, rows = _rows_from_xlsx(path)
    else:
        raise QuestionnaireError([f"unsupported file type {suffix or '(none)'!r}: expected .csv or .xlsx"], path)
    if header is None:
        raise QuestionnaireError([f"the file is empty: expected a header row with a '{QUESTION}' column"], path)

    columns: dict[str, int] = {}
    problems: list[str] = []
    for index, name in enumerate(header):
        if not name:
            continue
        if name in columns:
            problems.append(f"row 1: header names column {name!r} twice (columns {columns[name] + 1} and {index + 1})")
            continue
        columns[name] = index
    if QUESTION not in columns:
        found = ", ".join(repr(h) for h in header if h) or "nothing"
        problems.append(f"row 1: header has no '{QUESTION}' column (found: {found})")
    if problems:
        raise QuestionnaireError(problems, path)

    q_col = columns[QUESTION]
    ctl_col = columns.get(CONTROLS)
    ref_col = next((columns[name] for name in REFS if name in columns), None)

    def at(cells: list[str], col: int | None) -> str:
        return cells[col] if col is not None and col < len(cells) else ""

    out: list[dict] = []
    seen_refs: dict[str, int] = {}
    for rowno, cells in rows:
        question = at(cells, q_col)
        if not question:
            continue  # heading / spacer row
        ref = at(cells, ref_col) or None
        control_ids = _split_controls(at(cells, ctl_col))
        bad = [c for c in control_ids if not _CONTROL_ID_RE.match(c)]
        if bad:
            problems.append(f"row {rowno}: invalid control id(s) {', '.join(repr(b) for b in bad)}; "
                            f"use ids like CTL-CRYPTO-01 separated by ';'")
        if len(question) > MAX_QUESTION_CHARS:
            problems.append(f"row {rowno}: question is {len(question)} characters long (limit {MAX_QUESTION_CHARS})")
        if ref is not None:
            if ref in seen_refs:
                problems.append(f"row {rowno}: duplicate ref {ref!r} (first used at row {seen_refs[ref]})")
            else:
                seen_refs[ref] = rowno
        out.append(dict(question=question, control_ids=control_ids, ref=ref))
    if not out and not problems:
        problems.append(f"no questions found: every row below the header has a blank '{QUESTION}'")
    if problems:
        raise QuestionnaireError(problems, path)
    return out


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------
def _citation_ids(citations) -> str:
    ids = []
    for c in citations or []:
        cid = c.get("id") if isinstance(c, dict) else c
        if cid:
            ids.append(str(cid))
    return ";".join(ids)


def _export_row(row: dict) -> list[str]:
    status = row.get("status") or ""
    answer = row.get("answer") or ""
    if status in ("DECLINED", "BLOCKED"):
        answer = NOT_ANSWERED + (row.get("reason") or status.lower())
    signed_at = row.get("signed_at") or row.get("decided_at") or ""
    return [
        row.get("ref") or "",
        row.get("question_id") or "",
        row.get("question") or "",
        status,
        answer,
        _citation_ids(row.get("citations")),
        row.get("decision") or "",
        row.get("approver") or "",
        signed_at,
        row.get("signature") or "",
    ]


def export_questionnaire(rows: list[dict], out: Path, fmt: str | None = None) -> Path:
    """Write the queue items ``rows`` to ``out`` as CSV or XLSX (by ``fmt``, else by extension)."""
    out = Path(out)
    fmt = (fmt or ("xlsx" if out.suffix.lower() in XLSX_SUFFIXES else "csv")).lower().lstrip(".")
    if fmt not in ("csv", "xlsx"):
        raise ValueError(f"fmt must be 'csv' or 'xlsx', got {fmt!r}")
    table = [_export_row(r) for r in rows]
    out.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "csv":
        with out.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh, lineterminator="\n")
            writer.writerow(EXPORT_COLUMNS)
            writer.writerows(table)
        return out
    from openpyxl import Workbook
    from openpyxl.styles import Font
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    ws = wb.active
    ws.title = "Answers"
    ws.append(list(EXPORT_COLUMNS))
    for cell in ws[1]:
        cell.font = Font(bold=True)
    for line in table:
        ws.append(line)
    ws.freeze_panes = "A2"
    widths = {"ref": 10, "question_id": 12, "question": 60, "status": 10, "answer": 80, "citations": 24,
              "decision": 10, "approver": 28, "signed_at": 22, "signature": 24}
    for index, name in enumerate(EXPORT_COLUMNS, start=1):
        ws.column_dimensions[get_column_letter(index)].width = widths[name]
    wb.save(out)
    return out
