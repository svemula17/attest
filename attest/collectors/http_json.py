"""Generic collector: any JSON API -> one evidence record (type = "http-json").

The operator names the evidence ``kind`` (it must exist in attest/sources.py), a
``summary`` template rendered over the response, and at least one ``check`` —
a (dotted path, operator, value) triple. The record passes iff every check holds.
A check is mandatory: a collector with no assertion would be evidence that
always passes, which is no evidence at all.

Dotted paths walk nested objects and list indexes: ``data.open_critical``,
``results.0.uptime``. A path that is not in the response is an error naming it,
never a silent default.
"""
from __future__ import annotations

import string

import httpx

from attest.collectors.base import controls_for_kind, emit, secret
from attest.collectors.registry import CollectResult
from attest.sources import source_by_id, source_for_kind

TYPE = "http-json"
OPS = ("==", "!=", "<", "<=", ">", ">=", "in", "contains", "exists")
DEFAULT_TIMEOUT = 20
DEFAULT_CLASSIFICATION = "publishable"

_MISSING = object()


def describe() -> dict:
    return {
        "type": TYPE,
        "kinds": "any kind in attest/sources.py (params.kind)",
        "params": {
            "url": "endpoint to call (required)",
            "method": "HTTP method (default GET)",
            "token_env": "environment variable holding a bearer token → Authorization: Bearer …",
            "header_name": "custom auth header name, used with header_env (e.g. X-Api-Key)",
            "header_env": "environment variable holding the custom header's value",
            "kind": "evidence kind to emit (required; must exist in attest/sources.py)",
            "source": "evidence source id (default: the catalog owner of kind)",
            "control_ids": "controls the record supports (default: every control that requires kind)",
            "classification": f"publishable | internal | restricted (default {DEFAULT_CLASSIFICATION})",
            "summary": "format string over the JSON object; dotted paths allowed: '{data.open_critical} critical'",
            "checks": "list of {path, op, value}; ops: " + ", ".join(OPS) + "; result = pass iff all hold (required)",
            "root": "dotted path into the response when the interesting object is nested",
            "timeout": f"seconds (default {DEFAULT_TIMEOUT})",
        },
        "secrets": ["token_env", "header_env"],
        "permissions": "whatever read scope the API needs for the one endpoint; nothing is written",
    }


# ── dotted-path resolver ──────────────────────────────────────────────────

def lookup(obj, path: str):
    """Value at ``path`` or the ``_MISSING`` sentinel. Segments index dicts by key and lists by integer."""
    cur = obj
    for seg in path.split("."):
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        elif isinstance(cur, list) and seg.lstrip("-").isdigit() and -len(cur) <= int(seg) < len(cur):
            cur = cur[int(seg)]
        else:
            return _MISSING
    return cur


def resolve(obj, path: str):
    if not isinstance(path, str) or not path:
        raise ValueError("a path must be a non-empty dotted string")
    value = lookup(obj, path)
    if value is _MISSING:
        raise ValueError(f"path {path!r} is not in the response")
    return value


def render(template: str, obj) -> str:
    """str.format-style template whose field names are dotted paths ('{data.open_critical} critical')."""
    out: list[str] = []
    for literal, field, spec, conversion in string.Formatter().parse(template):
        out.append(literal)
        if field is None:
            continue
        if field == "":
            raise ValueError("summary placeholders must name a path, e.g. '{data.count}'")
        value = resolve(obj, field)
        if conversion == "r":
            value = repr(value)
        elif conversion in ("s", "a"):
            value = str(value) if conversion == "s" else ascii(value)
        out.append(format(value, spec or ""))
    return "".join(out)


# ── checks ────────────────────────────────────────────────────────────────

def _ordered(path: str, op: str, actual, value):
    """Operands for <, <=, >, >=: numbers compare as numbers, strings as strings; anything else is an error."""
    def is_num(x):
        return isinstance(x, (int, float)) and not isinstance(x, bool)
    if is_num(actual) and is_num(value):
        return actual, value
    if isinstance(actual, str) and is_num(value):
        try:
            return float(actual), value
        except ValueError:
            pass
    if isinstance(actual, str) and isinstance(value, str):
        return actual, value
    raise ValueError(f"check {path} {op} {value!r}: cannot order {actual!r} against {value!r}")


def _holds(path: str, op: str, actual, value) -> bool:
    if op == "==":
        return actual == value
    if op == "!=":
        return actual != value
    if op == "in":
        if not isinstance(value, (list, tuple, str, dict)):
            raise ValueError(f"check {path} in {value!r}: value must be a list or string")
        try:
            return actual in value
        except TypeError:
            return False
    if op == "contains":
        if not isinstance(actual, (list, tuple, str, dict)):
            raise ValueError(f"check {path} contains {value!r}: {path} is {actual!r}, not a list or string")
        try:
            return value in actual
        except TypeError:
            return False
    a, b = _ordered(path, op, actual, value)
    return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]


def _validated_checks(raw) -> list[dict]:
    if not isinstance(raw, list) or not raw:
        raise ValueError("params.checks is required — at least one {path, op, value} so the collector cannot silently pass")
    checks = []
    for i, check in enumerate(raw):
        if not isinstance(check, dict) or not isinstance(check.get("path"), str) or not check["path"]:
            raise ValueError(f"params.checks[{i}] needs a dotted 'path'")
        op = check.get("op")
        if op not in OPS:
            raise ValueError(f"params.checks[{i}] ({check['path']}): op must be one of {', '.join(OPS)}, got {op!r}")
        if op != "exists" and "value" not in check:
            raise ValueError(f"params.checks[{i}] ({check['path']} {op}) needs a 'value'")
        checks.append({"path": check["path"], "op": op, "value": check.get("value", True)})
    return checks


def evaluate(obj, checks: list[dict]) -> list[dict]:
    """Each check with its resolved ``actual`` and ``ok``. A missing path is an error unless the op is ``exists``."""
    results = []
    for check in checks:
        path, op, value = check["path"], check["op"], check["value"]
        if op == "exists":
            found = lookup(obj, path)
            present = found is not _MISSING
            ok = present if value in (True, None) else not present
            actual = None if not present else found
        else:
            actual = resolve(obj, path)
            ok = _holds(path, op, actual, value)
        results.append({"path": path, "op": op, "value": value, "actual": actual, "ok": bool(ok)})
    return results


# ── the collector ─────────────────────────────────────────────────────────

def _auth_headers(params: dict) -> dict:
    headers = {"Accept": "application/json", "User-Agent": "attest-collector"}
    if params.get("token_env"):
        headers["Authorization"] = f"Bearer {secret(params, 'token')}"
    header_name = params.get("header_name")
    if header_name:
        if not isinstance(header_name, str) or not header_name.strip():
            raise ValueError("params.header_name must be a header name, e.g. X-Api-Key")
        headers[header_name.strip()] = secret(params, "header")
    elif params.get("header_env"):
        raise ValueError("params.header_env needs params.header_name (the header to send it in)")
    return headers


def collect(ctx, transport: httpx.BaseTransport | None = None) -> CollectResult:
    """type = "http-json": call one JSON endpoint, assert on it, emit one record."""
    params = ctx.source.params
    url = params.get("url")
    if not isinstance(url, str) or not url.strip():
        raise ValueError(f"source '{ctx.source.id}' ({TYPE}) needs params.url")
    kind = params.get("kind")
    if not isinstance(kind, str) or source_for_kind(kind) is None:
        raise ValueError(f"params.kind {kind!r} is not an evidence kind in attest/sources.py")
    source = params.get("source")
    if source is not None and source_by_id(source) is None:
        raise ValueError(f"params.source {source!r} is not a source in attest/sources.py")
    template = params.get("summary")
    if not isinstance(template, str) or not template.strip():
        raise ValueError("params.summary (a format string over the response) is required")
    checks = _validated_checks(params.get("checks"))
    control_ids = params.get("control_ids")
    if control_ids is not None and (not isinstance(control_ids, list) or not all(isinstance(c, str) for c in control_ids)):
        raise ValueError("params.control_ids must be a list of control ids")
    classification = params.get("classification", DEFAULT_CLASSIFICATION)
    method = str(params.get("method", "GET")).upper()
    root = params.get("root")
    timeout = float(params.get("timeout", DEFAULT_TIMEOUT))
    headers = _auth_headers(params)  # reads the env before any request, so a missing secret fails fast

    with httpx.Client(transport=transport, headers=headers, timeout=timeout) as client:
        response = client.request(method, url)

    status = response.status_code
    if status in (401, 403):
        raise PermissionError(f"{url} returned {status}: check params.token_env / header_env and the credential's read scope")
    if not 200 <= status < 300:
        raise RuntimeError(f"{url} returned {status}")
    try:
        body = response.json()
    except ValueError:
        raise RuntimeError(f"{url} did not return JSON") from None
    obj = resolve(body, root) if root else body

    results = evaluate(obj, checks)
    summary = render(template, obj)
    result = "pass" if all(r["ok"] for r in results) else "fail"
    emit(ctx, kind=kind, summary=summary, result=result, source=source, classification=classification,
         control_ids=control_ids if control_ids is not None else controls_for_kind(kind),
         checks=results, url=url, method=method, status=status, root=root)
    return CollectResult(records=1, summary=summary)
