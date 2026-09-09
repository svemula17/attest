"""HRIS × IdP join: find accounts still active after someone left.

Reads the newest HR roster (hire/termination dates) and the newest identity-
provider user list from the evidence store, and writes one record for
CTL-ACCESS-02: pass when every leaver was deprovisioned inside the SLA, fail
with the orphans listed otherwise. Nothing here trusts an access review.
"""
from __future__ import annotations

from datetime import datetime, timezone

from attest.evidence import EvidenceRecord
from attest.util import parse_iso

INPUT_ROSTER = "hris.roster"
INPUT_IDP = "idp.users"
OUTPUT = "access.leaver-deprovisioned"
CONTROL = "CTL-ACCESS-02"


def _day(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)


def run_join(store, now: datetime | None = None, sla_hours: int = 24) -> EvidenceRecord:
    now = now or datetime.now(timezone.utc)
    rosters = store.query(kind=INPUT_ROSTER)
    idps = store.query(kind=INPUT_IDP)
    if not rosters:
        raise ValueError(f"no {INPUT_ROSTER} record in the store")
    if not idps:
        raise ValueError(f"no {INPUT_IDP} record in the store")
    employees = rosters[-1].payload.get("employees", [])
    users = {u.get("email"): u for u in idps[-1].payload.get("users", [])}

    orphans, checked = [], 0
    for e in employees:
        terminated = e.get("terminated")
        if not terminated:
            continue
        checked += 1
        user = users.get(e.get("email"))
        if user is None:
            continue  # never had an account — nothing to deprovision
        term_at = _day(terminated)
        status = user.get("status")
        deprovisioned_at = user.get("deprovisioned_at")
        late = False
        if status == "active":
            late = True
        elif deprovisioned_at:
            late = (parse_iso(deprovisioned_at) - term_at).total_seconds() > sla_hours * 3600
        if late:
            orphans.append({
                "name": e.get("name"), "email": e.get("email"), "terminated": terminated,
                "idp_status": status, "days_open": max(0, (now - term_at).days),
            })

    if orphans:
        o = orphans[0]
        extra = f" (+{len(orphans) - 1} more)" if len(orphans) > 1 else ""
        summary = (f"{len(orphans)} leaver{'s' if len(orphans) > 1 else ''} still active {o['days_open']} days after termination: "
                   f"{o['name']} <{o['email']}> (terminated {o['terminated']}){extra}")
    else:
        summary = f"0 leavers with active accounts; {checked} deprovisioned within {sla_hours}h"
    return store.append(
        source="okta", kind=OUTPUT, control_ids=[CONTROL], classification="internal",
        payload={"summary": summary, "result": "fail" if orphans else "pass",
                 "orphans": orphans, "checked": checked, "sla_hours": sla_hours},
    )
