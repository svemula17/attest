"""GitHub branch-protection collector -> CTL-CHANGE-01 evidence.

Reads the default branch's protection rules through the REST API and appends
two records to the evidence store:

* ``pr.review-required``  pass iff at least one approving review is required
* ``ci.policy-gate``      pass iff at least one status check is required

Network access goes through an injectable ``fetch(url, token) -> (status, body)``
so tests never touch the network. Only stdlib is used.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

from attest.evidence import EvidenceRecord

API = "https://api.github.com"
API_VERSION = "2022-11-28"
USER_AGENT = "attest-collector"
COLLECTED_BY = "attest.collectors.github"
CONTROL_IDS = ["CTL-CHANGE-01"]
CLASSIFICATION = "publishable"
SOURCE = "github"

KIND_REVIEW = "pr.review-required"
KIND_CI = "ci.policy-gate"

SCOPE_HINT = (
    "the token needs the 'repo' scope (classic PAT) or "
    "'Administration: read' repository permission (fine-grained PAT / GitHub App)"
)

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

Fetch = Callable[[str, "str | None"], "tuple[int, dict]"]


def resolve_token(token: str | None = None) -> str | None:
    """Explicit argument, then $GITHUB_TOKEN, then $GH_TOKEN, else None."""
    for candidate in (token, os.environ.get("GITHUB_TOKEN"), os.environ.get("GH_TOKEN")):
        if candidate and candidate.strip():
            return candidate.strip()
    return None


def _parse_body(raw: bytes) -> dict:
    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else {}
    except (ValueError, UnicodeDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _gh_fetch(url: str) -> tuple[int, dict]:
    """Fetch through the authenticated ``gh`` CLI (its own auth and TLS trust store)."""
    endpoint = url[len(API):].lstrip("/") if url.startswith(API) else url
    proc = subprocess.run(["gh", "api", "-H", f"X-GitHub-Api-Version: {API_VERSION}", endpoint],
                          capture_output=True, text=True, timeout=30, check=False)
    if proc.returncode == 0:
        return 200, _parse_body(proc.stdout.encode())
    match = re.search(r"HTTP (\d{3})", proc.stderr)
    status = int(match.group(1)) if match else 500
    body = _parse_body(proc.stdout.encode()) if proc.stdout.strip() else {"message": proc.stderr.strip()}
    return status, body


def gh_available() -> bool:
    return shutil.which("gh") is not None


def _default_fetch(url: str, token: str | None) -> tuple[int, dict]:
    if token is None and gh_available():
        return _gh_fetch(url)
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - fixed https host
            return response.status, _parse_body(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, _parse_body(exc.read() or b"")


def _message(body: dict) -> str:
    message = body.get("message") if isinstance(body, dict) else None
    return message if isinstance(message, str) else ""


def _required_contexts(protection: dict) -> list[str]:
    """Status-check names from ``contexts`` (legacy) merged with ``checks`` (current)."""
    rsc = protection.get("required_status_checks")
    if not isinstance(rsc, dict):
        return []
    names: list[str] = []
    for ctx in rsc.get("contexts") or []:
        if isinstance(ctx, str) and ctx not in names:
            names.append(ctx)
    for check in rsc.get("checks") or []:
        ctx = check.get("context") if isinstance(check, dict) else None
        if isinstance(ctx, str) and ctx not in names:
            names.append(ctx)
    return names


def _review_count(protection: dict) -> int | None:
    """Required approving reviews, or None when PR reviews are not required at all."""
    reviews = protection.get("required_pull_request_reviews")
    if not isinstance(reviews, dict):
        return None
    count = reviews.get("required_approving_review_count", 0)
    return count if isinstance(count, int) and not isinstance(count, bool) else 0


def _assess(repo: str, branch: str, status: int, body: dict) -> list[dict]:
    """Turn the protection response into two (kind, result, summary, raw) dicts."""
    if status == 404 or (status == 403 and "Upgrade to GitHub Pro" in _message(body)):
        summary = f"no branch protection on {branch}"
        raw = {"protected": False}
        return [
            {"kind": KIND_REVIEW, "result": "fail", "summary": summary, "raw": dict(raw)},
            {"kind": KIND_CI, "result": "fail", "summary": summary, "raw": dict(raw)},
        ]
    if status in (401, 403):
        detail = f"; GitHub said: {_message(body)}" if _message(body) else ""
        raise PermissionError(
            f"GitHub returned {status} reading branch protection for {repo}@{branch}: {SCOPE_HINT}{detail}"
        )
    if status != 200:
        raise RuntimeError(f"GitHub returned unexpected status {status} reading branch protection for {repo}@{branch}")

    count = _review_count(body)
    if count is None:
        review = {
            "result": "fail",
            "summary": f"Branch protection on {branch}: pull request reviews not required",
            "raw": {"protected": True, "required_pull_request_reviews": False, "required_approving_review_count": 0},
        }
    else:
        noun = "review" if count == 1 else "reviews"
        review = {
            "result": "pass" if count >= 1 else "fail",
            "summary": f"Branch protection on {branch}: {count} approving {noun} required",
            "raw": {"protected": True, "required_pull_request_reviews": True, "required_approving_review_count": count},
        }

    contexts = _required_contexts(body)
    if contexts:
        ci = {
            "result": "pass",
            "summary": f"Branch protection on {branch}: required status checks: {', '.join(contexts)}",
            "raw": {"protected": True, "required_status_checks": True, "context_count": len(contexts)},
        }
    else:
        ci = {
            "result": "fail",
            "summary": f"Branch protection on {branch}: no required status checks",
            "raw": {"protected": True, "required_status_checks": False, "context_count": 0},
        }
    return [{"kind": KIND_REVIEW, **review}, {"kind": KIND_CI, **ci}]


def collect_branch_protection(
    store,
    repo: str,
    token: str | None = None,
    fetch: Fetch | None = None,
) -> list[EvidenceRecord]:
    """Collect default-branch protection evidence for ``repo`` ("owner/name") into ``store``.

    Raises ValueError for a bad or missing repo, PermissionError when the token
    cannot read branch protection, RuntimeError for unexpected API responses.
    """
    if not isinstance(repo, str) or not _REPO_RE.match(repo.strip()):
        raise ValueError(f"repo must look like 'owner/name', got {repo!r}")
    repo = repo.strip()
    token = resolve_token(token)
    fetch = fetch or _default_fetch

    status, body = fetch(f"{API}/repos/{repo}", token)
    if status == 404:
        raise ValueError("repo not found or not accessible")
    if status in (401, 403):
        detail = f"; GitHub said: {_message(body)}" if _message(body) else ""
        raise PermissionError(f"GitHub returned {status} reading {repo}: {SCOPE_HINT}{detail}")
    if status != 200:
        raise RuntimeError(f"GitHub returned unexpected status {status} reading {repo}")
    branch = body.get("default_branch")
    if not isinstance(branch, str) or not branch:
        raise RuntimeError(f"GitHub response for {repo} has no default_branch")

    url = f"{API}/repos/{repo}/branches/{urllib.parse.quote(branch, safe='')}/protection"
    status, body = fetch(url, token)
    findings = _assess(repo, branch, status, body)

    records: list[EvidenceRecord] = []
    for finding in findings:
        payload = {
            "summary": finding["summary"],
            "result": finding["result"],
            "repo": repo,
            "branch": branch,
            "collected_by": COLLECTED_BY,
            "raw": finding["raw"],
        }
        records.append(
            store.append(
                source=SOURCE,
                kind=finding["kind"],
                control_ids=list(CONTROL_IDS),
                classification=CLASSIFICATION,
                payload=payload,
            )
        )
    return records
