"""attest.notify — tell someone when a control turns red.

    events = diff_states(previous, current, reasons)          # state transitions → NotifyEvent
    Notifier(cfg, store).dispatch(events)                     # Slack webhook and/or Jira issue per event

Every delivery is recorded through the NotificationStore (``already_sent`` /
``record``): one row per (control, kind, summary digest, target), so a transition
reaches each target once and a delivery failure is a row with status "error",
never an exception out of the collector or scheduler that triggered it. Secrets
come from the environment variables named in ``[notifications]``, never from
attest.toml.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import date, timedelta

import httpx

from attest.config import Config

__all__ = ["NotifyEvent", "diff_states", "Notifier", "dedupe_key", "record_key", "slack_payload", "jira_body"]

KINDS = ("FAIL", "DEGRADED", "finding")
TARGET_SLACK = "slack"
TARGET_JIRA = "jira"
HTTP_TIMEOUT = 10


@dataclass
class NotifyEvent:
    kind: str                       # "FAIL" | "DEGRADED" | "finding"
    control_id: str
    title: str
    summary: str
    evidence_ids: list[str] = field(default_factory=list)


def diff_states(previous: dict[str, str], current: dict[str, str], reasons: dict[str, str]) -> list[NotifyEvent]:
    """Transitions worth telling someone about, in ``current`` order.

    * FAIL now and not FAIL before (PASS, DEGRADED or unseen) → kind "FAIL"
    * DEGRADED now and PASS before                             → kind "DEGRADED"
    * anything recovering, or unchanged, produces nothing.
    """
    events: list[NotifyEvent] = []
    for control_id, state in current.items():
        before = previous.get(control_id)
        reason = reasons.get(control_id, "")
        if state == "FAIL" and before != "FAIL":
            events.append(NotifyEvent("FAIL", control_id, f"{control_id} is failing", reason, []))
        elif state == "DEGRADED" and before == "PASS":
            events.append(NotifyEvent("DEGRADED", control_id, f"{control_id} is degraded", reason, []))
    return events


def dedupe_key(event: NotifyEvent) -> str:
    """``<control>:<kind>:<sha256(summary)[:16]>`` — the same transition with the same reason is one event."""
    digest = hashlib.sha256(event.summary.encode("utf-8")).hexdigest()[:16]
    return f"{event.control_id}:{event.kind}:{digest}"


def record_key(event: NotifyEvent, target: str) -> str:
    """The store's ``dedupe_key`` column is unique and ``record`` is idempotent on it, so each
    target gets its own row under ``<dedupe_key>:<target>``; ``already_sent`` is asked per target."""
    return f"{dedupe_key(event)}:{target}"


# ---- payloads (pure, so tests can assert on them) -----------------------------
def slack_payload(event: NotifyEvent, owner: str, due: str) -> dict:
    """Block Kit message: a header and one section whose fields are Control / Owner / Due / Evidence."""
    headline = f"[Attest] {event.kind}: {event.title}"
    section: dict = {
        "type": "section",
        "fields": [
            {"type": "mrkdwn", "text": f"*Control*\n{event.control_id}"},
            {"type": "mrkdwn", "text": f"*Owner*\n{owner}"},
            {"type": "mrkdwn", "text": f"*Due*\n{due}"},
            {"type": "mrkdwn", "text": f"*Evidence*\n{', '.join(event.evidence_ids) or 'none'}"},
        ],
    }
    if event.summary:
        section["text"] = {"type": "mrkdwn", "text": event.summary}
    return {
        "text": f"{headline} — {event.summary}" if event.summary else headline,
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": headline[:150]}},
            section,
        ],
    }


def _adf_paragraph(text: str) -> dict:
    return {"type": "paragraph", "content": [{"type": "text", "text": text}]}


def jira_body(cfg: Config, event: NotifyEvent, owner: str, due: str) -> dict:
    """Jira Cloud REST v3 issue body; the description is Atlassian Document Format."""
    jira = cfg.notifications.jira
    assert jira is not None
    return {
        "fields": {
            "project": {"key": jira.project},
            "issuetype": {"name": jira.issue_type},
            "summary": f"[Attest] {event.control_id}: {event.title}",
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    _adf_paragraph(event.summary or "(no detail recorded)"),
                    _adf_paragraph(f"Owner: {owner}"),
                    _adf_paragraph(f"Due: {due}"),
                    _adf_paragraph(f"Evidence: {', '.join(event.evidence_ids) or 'none'}"),
                ],
            },
            "duedate": due,
        }
    }


# ---- delivery ------------------------------------------------------------------
class Notifier:
    """Fan one event out to every enabled target and record what happened.

    ``store`` is a NotificationStore: ``already_sent(dedupe_key) -> bool`` and
    ``record(control_id, kind, dedupe_key, target, status, detail="", external_id=None,
    owner=None, due=None) -> dict``. ``transport`` is an httpx transport (tests pass a
    MockTransport); ``today`` pins the due-date arithmetic.
    """

    def __init__(self, cfg: Config, store, transport=None, today: date | None = None):
        self.cfg = cfg
        self.store = store
        self.transport = transport
        self.today = today or date.today()

    def dispatch(self, events: list[NotifyEvent]) -> list[dict]:
        n = self.cfg.notifications
        out: list[dict] = []
        with httpx.Client(transport=self.transport, timeout=HTTP_TIMEOUT) as client:
            for event in events:
                if event.kind not in n.notify_on:
                    continue
                owner = n.owners.get(event.control_id, "unassigned")
                due = (self.today + timedelta(days=n.due_days)).isoformat()
                targets = []
                if n.slack_enabled:
                    targets.append((TARGET_SLACK, self._slack))
                if n.jira is not None:
                    targets.append((TARGET_JIRA, self._jira))
                for target, deliver in targets:
                    key = record_key(event, target)
                    if self.store.already_sent(key):
                        continue  # delivered (or attempted) before: no new row, no new message
                    out.append(deliver(client, event, key, owner, due))
        return out

    def _record(self, event: NotifyEvent, key: str, target: str, status: str, detail: str = "",
                external_id: str | None = None, owner: str | None = None, due: str | None = None) -> dict:
        return self.store.record(event.control_id, event.kind, key, target, status, detail=detail,
                                 external_id=external_id, owner=owner, due=due)

    def _slack(self, client: httpx.Client, event: NotifyEvent, key: str, owner: str, due: str) -> dict:
        env = self.cfg.notifications.slack_webhook_env
        url = os.environ.get(env)
        if not url:
            return self._record(event, key, TARGET_SLACK, "error", f"environment variable {env} is not set", owner=owner, due=due)
        try:
            r = client.post(url, json=slack_payload(event, owner, due))
        except httpx.HTTPError as e:
            return self._record(event, key, TARGET_SLACK, "error", f"{type(e).__name__}: {e}", owner=owner, due=due)
        if r.status_code >= 400:
            return self._record(event, key, TARGET_SLACK, "error", f"HTTP {r.status_code}: {r.text[:200]}", owner=owner, due=due)
        return self._record(event, key, TARGET_SLACK, "sent", f"HTTP {r.status_code}", owner=owner, due=due)

    def _jira(self, client: httpx.Client, event: NotifyEvent, key: str, owner: str, due: str) -> dict:
        jira = self.cfg.notifications.jira
        token = os.environ.get(jira.token_env)
        if not token:
            return self._record(event, key, TARGET_JIRA, "error", f"environment variable {jira.token_env} is not set", owner=owner, due=due)
        if not jira.base_url or not jira.project:
            return self._record(event, key, TARGET_JIRA, "error", "[notifications.jira] needs base_url and project", owner=owner, due=due)
        url = f"{jira.base_url.rstrip('/')}/rest/api/3/issue"
        try:
            r = client.post(url, json=jira_body(self.cfg, event, owner, due), auth=(jira.email, token),
                            headers={"Accept": "application/json"})
        except httpx.HTTPError as e:
            return self._record(event, key, TARGET_JIRA, "error", f"{type(e).__name__}: {e}", owner=owner, due=due)
        if r.status_code >= 400:
            return self._record(event, key, TARGET_JIRA, "error", f"HTTP {r.status_code}: {r.text[:200]}", owner=owner, due=due)
        try:
            issue_key = r.json().get("key")
        except ValueError:
            issue_key = None
        if not issue_key:
            return self._record(event, key, TARGET_JIRA, "error", f"HTTP {r.status_code}: response has no issue key", owner=owner, due=due)
        return self._record(event, key, TARGET_JIRA, "sent", f"{issue_key} created", external_id=str(issue_key), owner=owner, due=due)
