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


# ── Org-level collector (type = "github") ──────────────────────────────────
#
# ``collect(ctx)`` walks every repo of an org (or an explicit list) over httpx and
# emits four ORG-LEVEL aggregates through ``attest.collectors.base.emit``:
#
# * ``pr.review-required``     every repo requires ≥1 approving review
# * ``ci.policy-gate``         every repo requires status checks
# * ``github.secret-scanning`` enabled everywhere, 0 open alerts
# * ``github.merge-log``       ≥95 % of sampled merged PRs carried an APPROVED review
#
# Per-repo detail rides along in payload["repos"]. ``collect_branch_protection`` above
# is untouched: it is what ``attest pull github --repo`` and the registry still use.

import httpx  # noqa: E402  (kept below the stdlib collector so the module is importable without it changing)
from datetime import datetime, timezone  # noqa: E402

from attest.collectors.base import emit, secret  # noqa: E402
from attest.collectors.registry import CollectResult  # noqa: E402

TYPE = "github"
KIND_SECRET_SCANNING = "github.secret-scanning"
KIND_MERGE_LOG = "github.merge-log"
KINDS = (KIND_REVIEW, KIND_CI, KIND_SECRET_SCANNING, KIND_MERGE_LOG)
PAT_SCOPES = "the PAT needs the scopes repo, security_events and read:org"
DEFAULT_MAX_REPOS = 200
DEFAULT_MERGE_SAMPLE = 20
MERGE_REVIEW_THRESHOLD = 0.95
_NAME_CAP = 10  # how many repo names a summary lists before "(+N more)"


def describe() -> dict:
    """What this collector needs and produces — for docs, `attest sources`, and operators."""
    return {
        "type": TYPE,
        "kinds": list(KINDS),
        "source": SOURCE,
        "params": {
            "org": "GitHub organisation to walk (all non-archived repos); give this OR repos",
            "repos": "explicit list of 'owner/name' strings; give this OR org",
            "token_env": "environment variable holding the PAT (falls back to $GITHUB_TOKEN / $GH_TOKEN)",
            "max_repos": f"stop after this many repos (default {DEFAULT_MAX_REPOS})",
            "merge_sample": f"closed PRs sampled per repo for the merge log (default {DEFAULT_MERGE_SAMPLE}, max 100)",
        },
        "secrets": ["token_env"],
        "permissions": PAT_SCOPES,
    }


def _headers(token: str) -> dict:
    return {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": USER_AGENT,
        "Authorization": f"Bearer {token}",
    }


def _json(response: httpx.Response):
    try:
        return response.json()
    except ValueError:
        return {}


def _json_dict(response: httpx.Response) -> dict:
    body = _json(response)
    return body if isinstance(body, dict) else {}


def _reset_time(response: httpx.Response) -> str:
    raw = response.headers.get("X-RateLimit-Reset", "")
    if raw.isdigit():
        return datetime.fromtimestamp(int(raw), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return "unknown"


def _get(client: httpx.Client, url: str) -> httpx.Response:
    """One GET with the two failures that must stop the whole run: bad token, exhausted rate limit."""
    response = client.get(url)
    if response.status_code == 401:
        detail = f"; GitHub said: {_message(_json_dict(response))}" if _message(_json_dict(response)) else ""
        raise PermissionError(f"GitHub returned 401 for {url}: {PAT_SCOPES}{detail}")
    if response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
        raise RuntimeError(f"GitHub rate limit exhausted; it resets at {_reset_time(response)} (UTC) — rerun after that")
    return response


def _list(client: httpx.Client, url: str, limit: int | None = None) -> tuple[int, list, dict]:
    """GET a paginated list endpoint, following Link rel="next". Returns (status, items, error body)."""
    items: list = []
    while url:
        response = _get(client, url)
        if response.status_code != 200:
            return response.status_code, [], _json_dict(response)
        page = _json(response)
        if isinstance(page, list):
            items.extend(page)
        if limit is not None and len(items) >= limit:
            return 200, items[:limit], {}
        url = response.links.get("next", {}).get("url")
    return 200, items, {}


def _org_repos(client: httpx.Client, org: str, max_repos: int) -> list[tuple[str, str | None]]:
    """(full_name, default_branch) for every non-archived repo of ``org``, newest listing order, capped."""
    url = f"{API}/orgs/{urllib.parse.quote(org, safe='')}/repos?type=all&per_page=100"
    found: list[tuple[str, str | None]] = []
    while url:
        response = _get(client, url)
        if response.status_code == 404:
            raise ValueError(f"GitHub org {org!r} not found or not accessible ({PAT_SCOPES})")
        if response.status_code == 403:
            raise PermissionError(f"GitHub returned 403 listing repos of {org}: {PAT_SCOPES}")
        if response.status_code != 200:
            raise RuntimeError(f"GitHub returned unexpected status {response.status_code} listing repos of {org}")
        for repo in _json(response) or []:
            if not isinstance(repo, dict) or repo.get("archived"):
                continue
            name = repo.get("full_name")
            if isinstance(name, str) and name:
                found.append((name, repo.get("default_branch") or None))
            if len(found) >= max_repos:
                return found
        url = response.links.get("next", {}).get("url")
    return found


def _default_branch(client: httpx.Client, repo: str) -> str:
    response = _get(client, f"{API}/repos/{repo}")
    if response.status_code == 404:
        raise ValueError(f"repo {repo} not found or not accessible")
    if response.status_code == 403:
        raise PermissionError(f"GitHub returned 403 reading {repo}: {PAT_SCOPES}")
    if response.status_code != 200:
        raise RuntimeError(f"GitHub returned unexpected status {response.status_code} reading {repo}")
    branch = _json_dict(response).get("default_branch")
    if not isinstance(branch, str) or not branch:
        raise RuntimeError(f"GitHub response for {repo} has no default_branch")
    return branch


def _protection(client: httpx.Client, repo: str, branch: str) -> dict:
    """Same status semantics as ``_assess``: 404 / 403-upgrade = unprotected, other 403 = permission."""
    url = f"{API}/repos/{repo}/branches/{urllib.parse.quote(branch, safe='')}/protection"
    response = _get(client, url)
    status, body = response.status_code, _json_dict(response)
    if status == 404 or (status == 403 and "Upgrade to GitHub Pro" in _message(body)):
        return {"protected": False, "review_count": 0, "checks": []}
    if status == 403:
        detail = f"; GitHub said: {_message(body)}" if _message(body) else ""
        raise PermissionError(f"GitHub returned 403 reading branch protection for {repo}@{branch}: {SCOPE_HINT}{detail}")
    if status != 200:
        raise RuntimeError(f"GitHub returned unexpected status {status} reading branch protection for {repo}@{branch}")
    return {"protected": True, "review_count": _review_count(body) or 0, "checks": _required_contexts(body)}


def _secret_scanning(client: httpx.Client, repo: str) -> dict:
    status, alerts, body = _list(client, f"{API}/repos/{repo}/secret-scanning/alerts?state=open&per_page=100")
    if status == 200:
        return {"secret_scanning": True, "alerts": len(alerts)}
    if status == 404:
        return {"secret_scanning": False, "alerts": None}
    if status == 403:
        detail = f"; GitHub said: {_message(body)}" if _message(body) else ""
        raise PermissionError(f"GitHub returned 403 reading secret-scanning alerts for {repo}: {PAT_SCOPES}{detail}")
    raise RuntimeError(f"GitHub returned unexpected status {status} reading secret-scanning alerts for {repo}")


def _merge_log(client: httpx.Client, repo: str, sample: int) -> dict:
    url = f"{API}/repos/{repo}/pulls?state=closed&per_page={sample}&sort=updated&direction=desc"
    response = _get(client, url)
    if response.status_code != 200:
        raise RuntimeError(f"GitHub returned unexpected status {response.status_code} listing pull requests for {repo}")
    pulls = [p for p in (_json(response) or []) if isinstance(p, dict)][:sample]
    merged = [p for p in pulls if p.get("merged_at")]
    reviewed = 0
    for pull in merged:
        status, reviews, _ = _list(client, f"{API}/repos/{repo}/pulls/{pull.get('number')}/reviews?per_page=100")
        if status != 200:
            raise RuntimeError(f"GitHub returned unexpected status {status} reading reviews of {repo}#{pull.get('number')}")
        if any(isinstance(r, dict) and r.get("state") == "APPROVED" for r in reviews):
            reviewed += 1
    return {"merged": len(merged), "reviewed": reviewed}


def _inspect(client: httpx.Client, repo: str, branch: str | None, sample: int) -> dict:
    branch = branch or _default_branch(client, repo)
    detail = {"repo": repo, "branch": branch}
    detail.update(_protection(client, repo, branch))
    detail.update(_secret_scanning(client, repo))
    detail.update(_merge_log(client, repo, sample))
    return detail


def _names(repos: list[str]) -> str:
    shown = ", ".join(repos[:_NAME_CAP])
    return shown + (f" (+{len(repos) - _NAME_CAP} more)" if len(repos) > _NAME_CAP else "")


def _token(params: dict) -> str:
    token = secret(params, "token") if params.get("token_env") else resolve_token()
    if not token:
        raise PermissionError(f"no GitHub token: set params.token_env or $GITHUB_TOKEN / $GH_TOKEN; {PAT_SCOPES}")
    return token


def _targets(params: dict) -> tuple[str | None, list[str]]:
    org, repos = params.get("org"), params.get("repos")
    if org and repos:
        raise ValueError("params.org and params.repos are alternatives — give one")
    if org:
        if not isinstance(org, str) or "/" in org:
            raise ValueError(f"params.org must be an organisation login, got {org!r}")
        return org.strip(), []
    if isinstance(repos, str):
        repos = [repos]
    if not isinstance(repos, list) or not repos:
        raise ValueError("params.org or params.repos (a list of 'owner/name') is required")
    cleaned = []
    for repo in repos:
        if not isinstance(repo, str) or not _REPO_RE.match(repo.strip()):
            raise ValueError(f"repo must look like 'owner/name', got {repo!r}")
        cleaned.append(repo.strip())
    return None, cleaned


def collect(ctx, transport: httpx.BaseTransport | None = None) -> CollectResult:
    """type = "github": org-wide change-management posture as four aggregate records."""
    params = ctx.source.params
    org, repos = _targets(params)
    max_repos = max(1, int(params.get("max_repos", DEFAULT_MAX_REPOS)))
    sample = min(100, max(1, int(params.get("merge_sample", DEFAULT_MERGE_SAMPLE))))
    token = _token(params)

    with httpx.Client(transport=transport, headers=_headers(token), timeout=30.0) as client:
        targets = _org_repos(client, org, max_repos) if org else [(r, None) for r in repos[:max_repos]]
        details = [_inspect(client, name, branch, sample) for name, branch in targets]

    total = len(details)
    scope = f"org {org}" if org else "repos"
    no_review = [d["repo"] for d in details if d["review_count"] < 1]
    no_checks = [d["repo"] for d in details if not d["checks"]]
    not_scanned = [d["repo"] for d in details if not d["secret_scanning"]]
    open_alerts = sum(d["alerts"] or 0 for d in details)
    merged = sum(d["merged"] for d in details)
    reviewed = sum(d["reviewed"] for d in details)
    merge_ok = merged == 0 or reviewed / merged >= MERGE_REVIEW_THRESHOLD
    common = {"source": SOURCE, "org": org, "repos": details}

    summary = f"{total - len(no_review)}/{total} repos require review"
    if no_review:
        summary += f"; unprotected: {_names(no_review)}"
    emit(ctx, kind=KIND_REVIEW, result="fail" if no_review else "pass", summary=summary, **common)

    summary = f"{total - len(no_checks)}/{total} repos require status checks"
    if no_checks:
        summary += f"; without checks: {_names(no_checks)}"
    emit(ctx, kind=KIND_CI, result="fail" if no_checks else "pass", summary=summary, **common)

    summary = (f"secret scanning enabled on {total - len(not_scanned)}/{total} repos, "
               f"{open_alerts} open alert{'' if open_alerts == 1 else 's'}")
    if not_scanned:
        summary += f"; secret scanning not enabled: {_names(not_scanned)}"
    emit(ctx, kind=KIND_SECRET_SCANNING, result="fail" if not_scanned or open_alerts else "pass", summary=summary,
         open_alerts=open_alerts, **common)

    summary = f"{reviewed} of {merged} sampled merges reviewed across {total} repos"
    if merged == 0:
        summary += " (no merged pull requests in the sample)"
    emit(ctx, kind=KIND_MERGE_LOG, result="pass" if merge_ok else "fail", summary=summary,
         sample_per_repo=sample, threshold=MERGE_REVIEW_THRESHOLD, **common)

    return CollectResult(
        records=len(KINDS),
        summary=(f"github {scope}: {total} repos, review {total - len(no_review)}/{total}, "
                 f"checks {total - len(no_checks)}/{total}, secret scanning {total - len(not_scanned)}/{total} "
                 f"({open_alerts} open), merges {reviewed}/{merged} reviewed"),
    )
