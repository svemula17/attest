"""Okta collector: user list, MFA enrollment and sign-on policy → access-control evidence.

Three records per run, all with source ``okta``:

* ``idp.users``           every user as {email, status, deprovisioned_at} — the IdP side of the
                          HRIS × IdP join (CTL-ACCESS-02), so it carries that control id explicitly
* ``idp.mfa-enrollment``  pass iff every ACTIVE user has at least one ACTIVE factor
* ``sso.enforced``        pass iff an active OKTA_SIGN_ON policy rule requires a factor (CTL-ACCESS-01)

HTTP goes through one ``httpx.Client`` whose transport is injectable, so tests use
``httpx.MockTransport`` and never reach the network. The token is read from the environment
variable named by ``params.token_env`` and never appears in the config file or in evidence.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import httpx

from attest.collectors.base import emit, secret

if TYPE_CHECKING:  # the registry imports collectors, so the runtime import lives inside collect()
    from attest.collectors.registry import CollectContext, CollectResult

TYPE = "okta"
SOURCE = "okta"
PAGE_SIZE = 200
DEFAULT_MAX_USERS = 2000
JOIN_CONTROL = "CTL-ACCESS-02"
KINDS = ("idp.users", "idp.mfa-enrollment", "sso.enforced")

# Okta statuses that mean "this person can still get in" for the join. Everything else
# (DEPROVISIONED, SUSPENDED) is deprovisioned; STAGED users have never logged in but still exist.
ACTIVE_STATUSES = frozenset({"ACTIVE", "PROVISIONED", "RECOVERY", "PASSWORD_EXPIRED", "LOCKED_OUT", "STAGED"})
DEPROVISIONED_FILTER = 'status eq "DEPROVISIONED"'     # the default listing omits deprovisioned users

SCOPE_HINT = ("the API token needs okta.users.read and okta.policies.read "
              "(a token from a Read-only Administrator has both)")
MAX_RETRY_WAIT = 30.0
_UNENROLLED_LISTED = 50


def _sleep(seconds: float) -> None:  # monkeypatched in tests
    time.sleep(seconds)


def _iso(value: str | None) -> str | None:
    """Okta timestamps ('2026-08-01T09:15:00.000Z') → the store's second-precision UTC form."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Api:
    """GET with Okta's error and pagination conventions: Link rel="next", 429 retry, 401/403 → PermissionError."""

    def __init__(self, client: httpx.Client):
        self.client = client
        self.requests = 0

    def get(self, url: str, **params) -> httpx.Response:
        for attempt in (1, 2):
            self.requests += 1
            try:
                resp = self.client.get(url, params=params or None)
            except httpx.HTTPError as exc:
                raise RuntimeError(f"Okta request failed for GET {url}: {exc}") from exc
            if resp.status_code == 429 and attempt == 1:
                _sleep(self._wait(resp))
                continue
            break
        if resp.status_code in (401, 403):
            raise PermissionError(f"Okta returned {resp.status_code} for GET {url}: {SCOPE_HINT}{self._detail(resp)}")
        if resp.status_code != 200:
            raise RuntimeError(f"Okta returned {resp.status_code} for GET {url}{self._detail(resp)}")
        return resp

    def list(self, path: str, **params) -> list[dict]:
        """Every item across Link rel="next" pages."""
        items: list[dict] = []
        resp = self.get(path, **params)
        while True:
            body = resp.json()
            if not isinstance(body, list):
                raise RuntimeError(f"Okta returned a non-list body for GET {path}")
            items.extend(body)
            next_url = (resp.links.get("next") or {}).get("url")
            if not next_url:
                return items
            resp = self.get(next_url)

    @staticmethod
    def _wait(resp: httpx.Response) -> float:
        try:
            reset = float(resp.headers.get("X-Rate-Limit-Reset", "0"))
        except ValueError:
            reset = 0.0
        return max(1.0, min(MAX_RETRY_WAIT, reset - time.time())) if reset else 1.0

    @staticmethod
    def _detail(resp: httpx.Response) -> str:
        try:
            summary = resp.json().get("errorSummary")
        except ValueError:
            summary = None
        return f"; Okta said: {summary}" if isinstance(summary, str) and summary else ""


# -- the three checks ----------------------------------------------------------------

def _user_row(user: dict) -> dict:
    profile = user.get("profile") or {}
    email = (profile.get("login") or profile.get("email") or "").strip().lower()
    status = str(user.get("status") or "")
    active = status in ACTIVE_STATUSES
    return {"email": email, "status": "active" if active else "deprovisioned",
            "deprovisioned_at": None if active else _iso(user.get("statusChanged")), "okta_status": status}


def _list_users(api: _Api) -> list[dict]:
    seen: dict[str, dict] = {}
    for user in api.list("/api/v1/users", limit=PAGE_SIZE) + api.list("/api/v1/users", limit=PAGE_SIZE, filter=DEPROVISIONED_FILTER):
        seen.setdefault(user.get("id") or (user.get("profile") or {}).get("login") or str(len(seen)), user)
    return list(seen.values())


def _emit_users(ctx, users: list[dict], org_url: str) -> dict:
    rows = [_user_row(u) for u in users]
    active = sum(1 for r in rows if r["status"] == "active")
    counts = {"active": active, "deprovisioned": len(rows) - active}
    emit(ctx, kind="idp.users", source=SOURCE, result="pass", classification="internal", control_ids=[JOIN_CONTROL],
         summary=f"IdP users: {active} active, {len(rows) - active} deprovisioned", users=rows, raw={**counts, "org": org_url})
    return counts


def _emit_mfa(ctx, api: _Api, users: list[dict], max_users: int) -> dict:
    active = [u for u in users if u.get("status") == "ACTIVE"]
    checked = active[:max_users]
    unenrolled: list[str] = []
    for user in checked:
        factors = api.list(f"/api/v1/users/{user['id']}/factors")
        if not any(f.get("status") == "ACTIVE" for f in factors):
            unenrolled.append(_user_row(user)["email"])
    enrolled = len(checked) - len(unenrolled)
    summary = f"MFA enrolled on {enrolled}/{len(checked)} active users"
    capped = len(active) > len(checked)
    if capped:
        summary += f" (first {max_users} of {len(active)} checked; raise params.max_users)"
    emit(ctx, kind="idp.mfa-enrollment", source=SOURCE, result="fail" if unenrolled else "pass", classification="publishable",
         summary=summary, unenrolled=unenrolled[:_UNENROLLED_LISTED],
         raw={"active": len(active), "checked": len(checked), "enrolled": enrolled, "unenrolled": len(unenrolled), "capped": capped})
    return {"enrolled": enrolled, "checked": len(checked)}


def _rule_requires_factor(rule: dict) -> bool:
    signon = ((rule.get("actions") or {}).get("signon") or {})
    if rule.get("status") != "ACTIVE" or signon.get("access", "ALLOW") != "ALLOW":
        return False
    return signon.get("requireFactor") is True or signon.get("factorMode") == "2FA"


def _emit_sso(ctx, api: _Api) -> str:
    policies = [p for p in api.list("/api/v1/policies", type="OKTA_SIGN_ON") if p.get("status") == "ACTIVE"]
    enforcing: list[tuple[str, str]] = []
    for policy in policies:
        for rule in api.list(f"/api/v1/policies/{policy['id']}/rules"):
            if _rule_requires_factor(rule):
                enforcing.append((policy.get("name") or policy["id"], rule.get("name") or rule.get("id") or "?"))
    if enforcing:
        policy, rule = enforcing[0]
        summary = f'MFA required by sign-on policy "{policy}" rule "{rule}"'
        if len(enforcing) > 1:
            summary += f" (+{len(enforcing) - 1} more)"
    else:
        summary = f"no active sign-on policy rule requires a factor ({len(policies)} active policies checked)"
    result = "pass" if enforcing else "fail"
    emit(ctx, kind="sso.enforced", source=SOURCE, result=result, classification="publishable", summary=summary,
         raw={"policies": len(policies), "enforcing_rules": len(enforcing),
              "enforcing": [{"policy": p, "rule": r} for p, r in enforcing]})
    return result


# -- entry points --------------------------------------------------------------------

def collect(ctx: CollectContext, transport=None) -> CollectResult:
    """type = "okta": users, MFA enrollment and sign-on policy from params.org_url."""
    from attest.collectors.registry import CollectResult

    params = ctx.source.params
    org_url = str(params.get("org_url") or "").strip().rstrip("/")
    if not org_url.startswith("https://"):
        raise ValueError(f"source '{ctx.source.id}' ({TYPE}) needs params.org_url like https://example.okta.com")
    max_users = int(params.get("max_users", DEFAULT_MAX_USERS))
    token = secret(params, "token")

    with httpx.Client(base_url=org_url, transport=transport, timeout=30.0,
                      headers={"Authorization": f"SSWS {token}", "Accept": "application/json", "User-Agent": "attest-collector"}) as client:
        api = _Api(client)
        users = _list_users(api)
        counts = _emit_users(ctx, users, org_url)
        mfa = _emit_mfa(ctx, api, users, max_users)
        sso = _emit_sso(ctx, api)

    host = org_url[len("https://"):]
    return CollectResult(records=len(KINDS), summary=(f"okta {host}: {len(KINDS)} records; {counts['active']} active users, "
                                                      f"{mfa['enrolled']}/{mfa['checked']} MFA-enrolled, sso {sso}"))


def describe() -> dict:
    return {
        "type": TYPE,
        "params": {
            "org_url": "https://<org>.okta.com (required)",
            "token_env": "name of the environment variable holding an SSWS API token (required)",
            "max_users": f"optional: cap on per-user factor lookups (default {DEFAULT_MAX_USERS})",
        },
        "scopes": ["okta.users.read", "okta.policies.read"],
        "kinds": list(KINDS),
        "endpoints": ["/api/v1/users", "/api/v1/users/{id}/factors", "/api/v1/policies?type=OKTA_SIGN_ON", "/api/v1/policies/{id}/rules"],
    }
