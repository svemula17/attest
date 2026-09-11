"""Notifications: state diffing, Slack/Jira payloads over a mock transport, dedupe, and failure rows."""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import date

import httpx
import pytest

from attest.config import parse_config
from attest.notify import Notifier, NotifyEvent, dedupe_key, diff_states, record_key

TODAY = date(2026, 9, 11)


class FakeStore:
    """The NotificationStore contract: already_sent(dedupe_key) is true once any row carries the key
    (whatever its status), and record(...) is idempotent on the unique dedupe_key column."""

    def __init__(self):
        self.rows: list[dict] = []

    def already_sent(self, key: str) -> bool:
        return any(r["dedupe_key"] == key for r in self.rows)

    def record(self, control_id, kind, dedupe_key, target, status, detail="", external_id=None, owner=None, due=None) -> dict:
        for existing in self.rows:
            if existing["dedupe_key"] == dedupe_key:
                return existing
        row = dict(id=len(self.rows) + 1, control_id=control_id, kind=kind, dedupe_key=dedupe_key, target=target,
                   status=status, detail=detail, external_id=external_id, owner=owner, due=due)
        self.rows.append(row)
        return row


def config(extra: str = "") -> "Config":
    return parse_config(f"""
[notifications]
slack_enabled = true
slack_webhook_env = "TEST_SLACK_URL"
notify_on = ["FAIL", "finding"]
due_days = 14
[notifications.owners]
CTL-ACCESS-02 = "iam@example.com"
[notifications.jira]
base_url = "https://example.atlassian.net"
project = "SEC"
email = "attest@example.com"
token_env = "TEST_JIRA_TOKEN"
issue_type = "Task"
{extra}
""")


def fail_event(summary="orphan account j.doe still active") -> NotifyEvent:
    return NotifyEvent("FAIL", "CTL-ACCESS-02", "Leaver still active", summary, ["EV-0012", "EV-0013"])


class Recorder:
    """A MockTransport that captures every request and answers per host."""

    def __init__(self, slack_status=200, jira_status=201, jira_body=None):
        self.requests: list[httpx.Request] = []
        self.slack_status, self.jira_status = slack_status, jira_status
        self.jira_body = jira_body if jira_body is not None else {"id": "10001", "key": "SEC-42"}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == "hooks.slack.com":
            return httpx.Response(self.slack_status, text="ok" if self.slack_status == 200 else "invalid_payload")
        if request.url.host == "example.atlassian.net":
            return httpx.Response(self.jira_status, json=self.jira_body)
        return httpx.Response(404)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("TEST_SLACK_URL", "https://hooks.slack.com/services/T0/B0/xyz")
    monkeypatch.setenv("TEST_JIRA_TOKEN", "jira-secret")


# ---- diff_states ------------------------------------------------------------------
def test_diff_states_reports_new_failures_and_pass_to_degraded_only():
    previous = {"A": "PASS", "B": "PASS", "C": "FAIL", "D": "DEGRADED", "E": "FAIL", "F": "DEGRADED"}
    current = {"A": "FAIL", "B": "DEGRADED", "C": "FAIL", "D": "FAIL", "E": "PASS", "F": "PASS", "G": "FAIL", "H": "DEGRADED"}
    reasons = {"A": "kms.key.rotation missing", "B": "tls.policy stale", "D": "now failing", "G": "brand new"}
    events = diff_states(previous, current, reasons)
    assert [(e.control_id, e.kind) for e in events] == [("A", "FAIL"), ("B", "DEGRADED"), ("D", "FAIL"), ("G", "FAIL")]
    assert events[0].summary == "kms.key.rotation missing" and events[0].evidence_ids == []
    assert "A" in events[0].title and events[3].summary == "brand new"


def test_diff_states_is_quiet_when_nothing_changed():
    states = {"A": "PASS", "B": "FAIL", "C": "DEGRADED"}
    assert diff_states(states, dict(states), {}) == []
    assert diff_states({}, {}, {}) == []


def test_diff_states_unseen_degraded_control_is_not_an_event():
    assert diff_states({}, {"X": "DEGRADED"}, {}) == []          # no PASS before → not a PASS→DEGRADED transition
    assert diff_states({"X": "FAIL"}, {"X": "DEGRADED"}, {}) == []  # recovering, partly


# ---- dispatch: Slack ---------------------------------------------------------------
def test_slack_payload_shape_and_record(env):
    store, rec = FakeStore(), Recorder()
    cfg = config()
    cfg.notifications.jira = None
    rows = Notifier(cfg, store, transport=rec.transport(), today=TODAY).dispatch([fail_event()])

    assert len(rec.requests) == 1
    req = rec.requests[0]
    assert req.method == "POST" and str(req.url) == "https://hooks.slack.com/services/T0/B0/xyz"
    body = json.loads(req.content)
    assert body["text"].startswith("[Attest] FAIL: Leaver still active")
    header, section = body["blocks"]
    assert header["type"] == "header" and header["text"]["type"] == "plain_text" and "FAIL" in header["text"]["text"]
    assert section["type"] == "section" and section["text"]["text"] == "orphan account j.doe still active"
    labels = [f["text"].split("\n")[0] for f in section["fields"]]
    assert labels == ["*Control*", "*Owner*", "*Due*", "*Evidence*"]
    values = [f["text"].split("\n")[1] for f in section["fields"]]
    assert values == ["CTL-ACCESS-02", "iam@example.com", "2026-09-25", "EV-0012, EV-0013"]

    assert rows == store.rows and len(rows) == 1
    row = rows[0]
    assert row["target"] == "slack" and row["status"] == "sent" and row["owner"] == "iam@example.com" and row["due"] == "2026-09-25"
    assert dedupe_key(fail_event()) == "CTL-ACCESS-02:FAIL:" + hashlib.sha256(b"orphan account j.doe still active").hexdigest()[:16]
    assert row["dedupe_key"] == record_key(fail_event(), "slack") == dedupe_key(fail_event()) + ":slack"


def test_slack_http_error_is_a_row_not_an_exception(env):
    store, rec = FakeStore(), Recorder(slack_status=400)
    cfg = config(); cfg.notifications.jira = None
    rows = Notifier(cfg, store, transport=rec.transport(), today=TODAY).dispatch([fail_event()])
    assert rows[0]["status"] == "error" and "HTTP 400" in rows[0]["detail"] and "invalid_payload" in rows[0]["detail"]


def test_slack_transport_failure_is_a_row_not_an_exception(env):
    def boom(request):
        raise httpx.ConnectError("connection refused", request=request)
    store = FakeStore()
    cfg = config(); cfg.notifications.jira = None
    rows = Notifier(cfg, store, transport=httpx.MockTransport(boom), today=TODAY).dispatch([fail_event()])
    assert rows[0]["status"] == "error" and "ConnectError" in rows[0]["detail"]


def test_missing_slack_env_records_error_and_continues_to_jira(env, monkeypatch):
    monkeypatch.delenv("TEST_SLACK_URL")
    store, rec = FakeStore(), Recorder()
    rows = Notifier(config(), store, transport=rec.transport(), today=TODAY).dispatch([fail_event()])
    assert [r["target"] for r in rows] == ["slack", "jira"]
    assert rows[0]["status"] == "error" and "TEST_SLACK_URL" in rows[0]["detail"]
    assert rows[1]["status"] == "sent" and rows[1]["external_id"] == "SEC-42"
    assert [r.url.host for r in rec.requests] == ["example.atlassian.net"]


# ---- dispatch: Jira ----------------------------------------------------------------
def test_jira_body_auth_and_external_id(env):
    store, rec = FakeStore(), Recorder()
    cfg = config(); cfg.notifications.slack_enabled = False
    rows = Notifier(cfg, store, transport=rec.transport(), today=TODAY).dispatch([fail_event()])

    req = rec.requests[0]
    assert req.method == "POST" and str(req.url) == "https://example.atlassian.net/rest/api/3/issue"
    expected = "Basic " + base64.b64encode(b"attest@example.com:jira-secret").decode()
    assert req.headers["authorization"] == expected
    body = json.loads(req.content)["fields"]
    assert body["project"] == {"key": "SEC"} and body["issuetype"] == {"name": "Task"}
    assert body["summary"] == "[Attest] CTL-ACCESS-02: Leaver still active" and body["duedate"] == "2026-09-25"
    doc = body["description"]
    assert doc["type"] == "doc" and doc["version"] == 1
    texts = [p["content"][0]["text"] for p in doc["content"]]
    assert all(p["type"] == "paragraph" for p in doc["content"])
    assert texts == ["orphan account j.doe still active", "Owner: iam@example.com", "Due: 2026-09-25", "Evidence: EV-0012, EV-0013"]

    assert rows == [store.rows[0]]
    assert rows[0]["target"] == "jira" and rows[0]["status"] == "sent" and rows[0]["external_id"] == "SEC-42"


def test_jira_missing_token_env_is_an_error_row(env, monkeypatch):
    monkeypatch.delenv("TEST_JIRA_TOKEN")
    store, rec = FakeStore(), Recorder()
    cfg = config(); cfg.notifications.slack_enabled = False
    rows = Notifier(cfg, store, transport=rec.transport(), today=TODAY).dispatch([fail_event()])
    assert rows[0]["status"] == "error" and "TEST_JIRA_TOKEN" in rows[0]["detail"] and rec.requests == []


def test_jira_4xx_and_keyless_response_are_error_rows(env):
    cfg = config(); cfg.notifications.slack_enabled = False
    rec = Recorder(jira_status=403, jira_body={"errorMessages": ["no permission"]})
    rows = Notifier(cfg, FakeStore(), transport=rec.transport(), today=TODAY).dispatch([fail_event()])
    assert rows[0]["status"] == "error" and "HTTP 403" in rows[0]["detail"] and "no permission" in rows[0]["detail"]
    rec = Recorder(jira_status=201, jira_body={"id": "1"})
    rows = Notifier(cfg, FakeStore(), transport=rec.transport(), today=TODAY).dispatch([fail_event()])
    assert rows[0]["status"] == "error" and "no issue key" in rows[0]["detail"] and rows[0]["external_id"] is None


# ---- dedupe, filters, owners ---------------------------------------------------------
def test_dedupe_skips_already_sent_without_writing_a_row(env):
    rec = Recorder()
    store = FakeStore()
    notifier = Notifier(config(), store, transport=rec.transport(), today=TODAY)
    first = notifier.dispatch([fail_event()])
    assert len(first) == 2 and len(rec.requests) == 2
    assert [r["dedupe_key"] for r in store.rows] == [record_key(fail_event(), "slack"), record_key(fail_event(), "jira")]
    again = notifier.dispatch([fail_event()])
    assert again == [] and len(store.rows) == 2 and len(rec.requests) == 2  # nothing sent, nothing recorded

    changed = fail_event(summary="a different orphan")  # new summary → new key → delivered
    assert len(notifier.dispatch([changed])) == 2 and len(rec.requests) == 4


def test_dedupe_is_per_target_and_error_rows_are_not_retried(env, monkeypatch):
    monkeypatch.delenv("TEST_JIRA_TOKEN")
    rec, store = Recorder(), FakeStore()
    notifier = Notifier(config(), store, transport=rec.transport(), today=TODAY)
    rows = notifier.dispatch([fail_event()])
    assert [(r["target"], r["status"]) for r in rows] == [("slack", "sent"), ("jira", "error")]
    monkeypatch.setenv("TEST_JIRA_TOKEN", "now-set")
    assert notifier.dispatch([fail_event()]) == []          # the attempt was made; the row is the record
    assert len(rec.requests) == 1


def test_dedupe_key_is_control_kind_and_summary_digest():
    a = NotifyEvent("finding", "CTL-ACCESS-02", "t", "same", [])
    b = NotifyEvent("finding", "CTL-ACCESS-02", "other title", "same", ["EV-1"])
    assert dedupe_key(a) == dedupe_key(b)                                   # title and evidence do not matter
    assert dedupe_key(a) != dedupe_key(NotifyEvent("FAIL", "CTL-ACCESS-02", "t", "same", []))
    assert dedupe_key(a) != dedupe_key(NotifyEvent("finding", "CTL-ACCESS-01", "t", "same", []))


def test_notify_on_filters_kinds(env):
    rec = Recorder()
    cfg = config()
    cfg.notifications.notify_on = ["finding"]
    rows = Notifier(cfg, FakeStore(), transport=rec.transport(), today=TODAY).dispatch([
        fail_event(), NotifyEvent("DEGRADED", "CTL-LOG-01", "stale", "cloudtrail.enabled 30h old", []),
        NotifyEvent("finding", "CTL-ACCESS-02", "Leaver", "j.doe active 9 days after termination", ["EV-0044"]),
    ])
    assert {r["kind"] for r in rows} == {"finding"} and len(rows) == 2 and len(rec.requests) == 2


def test_unassigned_owner_and_due_days(env):
    rec = Recorder()
    cfg = config(); cfg.notifications.due_days = 3; cfg.notifications.jira = None
    ev = NotifyEvent("FAIL", "CTL-NET-01", "Open ingress", "0.0.0.0/0 on 22", [])
    rows = Notifier(cfg, FakeStore(), transport=rec.transport(), today=TODAY).dispatch([ev])
    assert rows[0]["owner"] == "unassigned" and rows[0]["due"] == "2026-09-14"
    fields = json.loads(rec.requests[0].content)["blocks"][1]["fields"]
    assert fields[1]["text"] == "*Owner*\nunassigned" and fields[3]["text"] == "*Evidence*\nnone"


def test_nothing_enabled_sends_nothing(env):
    rec = Recorder()
    cfg = config(); cfg.notifications.slack_enabled = False; cfg.notifications.jira = None
    store = FakeStore()
    assert Notifier(cfg, store, transport=rec.transport(), today=TODAY).dispatch([fail_event()]) == []
    assert store.rows == [] and rec.requests == []


def test_config_refuses_inline_jira_token():
    from attest.config import ConfigError
    with pytest.raises(ConfigError, match="token"):
        parse_config('[notifications.jira]\nbase_url = "https://x"\nproject = "P"\nemail = "e"\ntoken = "secret"\n')
