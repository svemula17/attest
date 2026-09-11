"""Cron scheduling over APScheduler: jobs only for scheduled sources, bad cron rejected, trigger() runs now."""
import logging
import threading
from datetime import datetime, timezone

import pytest

from attest.config import ConfigError, parse_config
from attest.scheduler import Scheduler
from attest.util import parse_iso

CONFIG = """
[sources.leavers]
type = "hris-idp-join"
schedule = "0 6 * * *"

[sources.github]
type = "github"
schedule = "*/15 * * * *"
[sources.github.params]
repos = ["acme/widgets"]

[sources.hris]
type = "csv"
[sources.hris.params]
path = "imports/hris-roster.csv"

[sources.paused]
type = "json"
schedule = "0 0 * * *"
enabled = false
[sources.paused.params]
path = "imports/evidence.json"
"""


class Recorder:
    def __init__(self, fail=False):
        self.calls = []
        self.event = threading.Event()
        self.fail = fail

    def __call__(self, source_id, trigger):
        self.calls.append((source_id, trigger))
        self.event.set()
        if self.fail:
            raise RuntimeError("boom")

    def wait(self):
        assert self.event.wait(5), "runner was not called within 5s"
        self.event.clear()


@pytest.fixture
def config():
    return parse_config(CONFIG)


@pytest.fixture
def scheduler(config):
    runner = Recorder()
    s = Scheduler(config, runner)
    yield s, runner
    s.stop()


def test_jobs_only_for_enabled_scheduled_sources(scheduler):
    s, _ = scheduler
    assert s.jobs() == [{"source_id": "leavers", "schedule": "0 6 * * *", "next_run": None},
                        {"source_id": "github", "schedule": "*/15 * * * *", "next_run": None}]
    assert not s.running
    s.start()
    s.start()  # idempotent
    assert s.running
    jobs = {j["source_id"]: j for j in s.jobs()}
    assert set(jobs) == {"leavers", "github"}
    for j in jobs.values():
        assert parse_iso(j["next_run"]) > datetime.now(timezone.utc)
    assert jobs["leavers"]["next_run"].endswith("T06:00:00Z")
    s.stop()
    assert not s.running


@pytest.mark.parametrize("bad", ["every day", "99 * * * *", "* * * * * *"])
def test_invalid_cron_is_a_config_error_naming_the_source(bad):
    config = parse_config(f'[sources.leavers]\ntype = "hris-idp-join"\n[sources.nightly]\ntype = "json"\nschedule = "{bad}"\n')
    with pytest.raises(ConfigError) as exc:
        Scheduler(config, lambda sid, trig: None)
    assert str(exc.value).startswith(f"[sources.nightly] schedule {bad!r} is not a valid 5-field cron expression")


def test_trigger_runs_the_runner_now_on_the_executor(scheduler):
    s, runner = scheduler
    s.start()
    job_id = s.trigger("hris")  # not a scheduled source; any configured source can be kicked
    assert isinstance(job_id, str)
    runner.wait()
    assert runner.calls == [("hris", "manual")]
    assert [j["source_id"] for j in s.jobs()] == ["leavers", "github"]  # one-shots are not listed
    s.trigger("leavers", trigger="api")
    runner.wait()
    assert runner.calls[-1] == ("leavers", "api")


def test_trigger_refusals(scheduler):
    s, runner = scheduler
    with pytest.raises(RuntimeError, match="not running"):
        s.trigger("hris")
    s.start()
    with pytest.raises(ValueError, match="unknown source 'nope'"):
        s.trigger("nope")
    assert runner.calls == []


def test_scheduled_job_passes_the_schedule_trigger(scheduler):
    s, runner = scheduler
    s.start()
    s._scheduler.get_job("leavers").modify(next_run_time=datetime.now(timezone.utc))
    runner.wait()
    assert runner.calls == [("leavers", "schedule")]
    assert s.jobs()[0]["next_run"].endswith("T06:00:00Z")  # back on its cron cadence


def test_runner_failures_are_logged_and_do_not_stop_the_scheduler(config, caplog):
    runner = Recorder(fail=True)
    s = Scheduler(config, runner)
    s.start()
    try:
        with caplog.at_level(logging.WARNING, logger="attest.scheduler"):
            s.trigger("hris")
            runner.wait()
            s.trigger("github")
            runner.wait()
    finally:
        s.stop()
    assert runner.calls == [("hris", "manual"), ("github", "manual")]
    assert any("boom" in rec.message and "hris" in rec.message for rec in caplog.records)
