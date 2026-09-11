"""BambooHR roster collector -> one ``hris.roster`` record for CTL-ACCESS-02.

Runs a custom report over the BambooHR REST API (HTTP basic auth, API key as the
user name and ``x`` as the password) and normalises it into the same employee shape
the CSV importer produces, so the HRIS × IdP join consumes it unchanged:

    {"id", "name", "email", "hired", "terminated"}

``terminated`` is only set once the termination date has passed (a future-dated
leaver is still staff); BambooHR's ``0000-00-00`` means "no date". Contractors are
excluded unless ``include_contractors`` is true.
"""
from __future__ import annotations

import re
from datetime import date

import httpx

from attest.collectors.base import emit, secret
from attest.collectors.registry import CollectResult

TYPE = "bamboohr"
API = "https://api.bamboohr.com/api/gateway.php"
KIND = "hris.roster"
SOURCE = "hris"
CONTROL_IDS = ["CTL-ACCESS-02"]
CLASSIFICATION = "internal"
REPORT_FIELDS = ["id", "displayName", "workEmail", "hireDate", "terminationDate", "status", "employmentHistoryStatus"]
PERMISSIONS = ("the API key's user needs access to the employee directory and the fields id, displayName, workEmail, "
               "hireDate, terminationDate, status (and employmentHistoryStatus to filter contractors)")

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def describe() -> dict:
    return {
        "type": TYPE,
        "kinds": [KIND],
        "source": SOURCE,
        "control_ids": list(CONTROL_IDS),
        "classification": CLASSIFICATION,
        "params": {
            "subdomain": "the <subdomain> in https://<subdomain>.bamboohr.com",
            "token_env": "environment variable holding the BambooHR API key",
            "include_contractors": "keep employees whose employmentHistoryStatus contains 'Contractor' (default false)",
        },
        "secrets": ["token_env"],
        "permissions": PERMISSIONS,
    }


def _date(value, employee_id: str, field: str) -> str | None:
    """YYYY-MM-DD or None. BambooHR sends ``0000-00-00`` (or an empty string) when a date is unset."""
    if value in (None, "", "0000-00-00"):
        return None
    text = str(value).strip()
    if text.startswith("0000-"):
        return None
    if not _DATE_RE.match(text):
        raise ValueError(f"BambooHR employee {employee_id}: {field} {value!r} is not YYYY-MM-DD")
    return text


def _normalise(raw: list, include_contractors: bool, today: str) -> tuple[list[dict], int, int]:
    employees: list[dict] = []
    skipped = contractors = 0
    for e in raw:
        if not isinstance(e, dict):
            skipped += 1
            continue
        history = e.get("employmentHistoryStatus")
        if not include_contractors and isinstance(history, str) and "contractor" in history.lower():
            contractors += 1
            continue
        email = str(e.get("workEmail") or "").strip().lower()
        if not email:
            skipped += 1
            continue
        emp_id = str(e.get("id") or "")
        hired = _date(e.get("hireDate"), emp_id, "hireDate")
        term = _date(e.get("terminationDate"), emp_id, "terminationDate")
        status = str(e.get("status") or "")
        terminated = term if (status == "Inactive" or term) and term and term <= today else None
        employees.append({"id": emp_id, "name": str(e.get("displayName") or "").strip(), "email": email,
                          "hired": hired, "terminated": terminated})
    return employees, skipped, contractors


def collect(ctx, transport: httpx.BaseTransport | None = None, today: date | None = None) -> CollectResult:
    """type = "bamboohr": the HR roster as one hris.roster record (internal, CTL-ACCESS-02)."""
    params = ctx.source.params
    subdomain = params.get("subdomain")
    if not isinstance(subdomain, str) or not subdomain.strip():
        raise ValueError(f"source '{ctx.source.id}' ({TYPE}) needs params.subdomain")
    subdomain = subdomain.strip()
    token = secret(params, "token")
    include_contractors = bool(params.get("include_contractors", False))
    today_str = (today or date.today()).strftime("%Y-%m-%d")

    url = f"{API}/{subdomain}/v1/reports/custom?format=JSON"
    with httpx.Client(transport=transport, auth=httpx.BasicAuth(token, "x"),
                      headers={"Accept": "application/json", "User-Agent": "attest-collector"}, timeout=30.0) as client:
        response = client.post(url, json={"title": "attest", "fields": REPORT_FIELDS})

    if response.status_code in (401, 403):
        raise PermissionError(f"BambooHR returned {response.status_code} for {subdomain}: check params.token_env; {PERMISSIONS}")
    if not 200 <= response.status_code < 300:
        raise RuntimeError(f"BambooHR returned unexpected status {response.status_code} running the custom report for {subdomain}")
    try:
        body = response.json()
    except ValueError:
        raise RuntimeError(f"BambooHR response for {subdomain} is not JSON") from None
    raw = body.get("employees") if isinstance(body, dict) else None
    if not isinstance(raw, list):
        raise RuntimeError(f"BambooHR response for {subdomain} has no 'employees' list")

    employees, skipped, contractors = _normalise(raw, include_contractors, today_str)
    terminated = sum(1 for e in employees if e["terminated"])
    summary = f"HRIS roster: {len(employees)} employees, {terminated} terminated in the period"
    emit(ctx, kind=KIND, summary=summary, result="pass", source=SOURCE, classification=CLASSIFICATION,
         control_ids=list(CONTROL_IDS), employees=employees, skipped=skipped, contractors_excluded=contractors,
         subdomain=subdomain, as_of=today_str)
    return CollectResult(records=1, summary=summary)
