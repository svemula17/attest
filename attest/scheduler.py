"""Cron scheduling for configured sources, on APScheduler's BackgroundScheduler.

    sched = Scheduler(config, runner=lambda source_id, trigger: run_source(config, source_id, store, audit, trigger=trigger))
    sched.start()
    sched.jobs()            # [{"source_id": "leavers", "schedule": "0 6 * * *", "next_run": "2026-09-12T06:00:00Z"}]
    sched.trigger("hris")   # run one source now, on the scheduler's executor (any source, scheduled or not)
    sched.stop()

Every ``[sources.<id>] schedule`` is a 5-field cron expression in UTC. Sources without a
schedule (or disabled ones) get no job; an invalid expression is a ConfigError at
construction, naming the source, so a bad config fails before the server is up.
"""
from __future__ import annotations

import logging
from datetime import timezone
from typing import Callable

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from attest.config import Config, ConfigError
from attest.util import ISO_FORMAT

log = logging.getLogger("attest.scheduler")

TRIGGER_SCHEDULE = "schedule"
TRIGGER_MANUAL = "manual"
MISFIRE_GRACE_SECONDS = 3600  # a run missed while the process was down still fires within the hour, once


class Scheduler:
    def __init__(self, config: Config, runner: Callable[[str, str], None]):
        self._config = config
        self._runner = runner
        self._schedules: dict[str, str] = {}
        self._scheduler = BackgroundScheduler(timezone="UTC")
        for sid, src in config.sources.items():
            if not src.schedule or not src.enabled:
                continue
            try:
                trigger = CronTrigger.from_crontab(src.schedule, timezone="UTC")
            except ValueError as e:
                raise ConfigError(f"[sources.{sid}] schedule {src.schedule!r} is not a valid 5-field cron expression: {e}") from e
            self._scheduler.add_job(self._run, trigger=trigger, args=[sid, TRIGGER_SCHEDULE], id=sid, name=sid,
                                    coalesce=True, max_instances=1, misfire_grace_time=MISFIRE_GRACE_SECONDS)
            self._schedules[sid] = src.schedule

    # -- lifecycle -------------------------------------------------------------

    @property
    def running(self) -> bool:
        return bool(self._scheduler.running)

    def start(self) -> None:
        if not self._scheduler.running:
            self._scheduler.start()

    def stop(self, wait: bool = True) -> None:
        if self._scheduler.running:
            self._scheduler.shutdown(wait=wait)

    # -- inspection and manual runs ----------------------------------------------

    def jobs(self) -> list[dict]:
        """One entry per scheduled source, in config order. next_run is None until start()."""
        out = []
        for sid, schedule in self._schedules.items():
            job = self._scheduler.get_job(sid)
            nxt = getattr(job, "next_run_time", None) if job is not None else None
            out.append({"source_id": sid, "schedule": schedule,
                        "next_run": nxt.astimezone(timezone.utc).strftime(ISO_FORMAT) if nxt else None})
        return out

    def trigger(self, source_id: str, trigger: str = TRIGGER_MANUAL) -> str:
        """Run ``source_id`` now on the scheduler's executor. Returns the one-shot job id."""
        if source_id not in self._config.sources:
            known = ", ".join(sorted(self._config.sources)) or "none configured"
            raise ValueError(f"unknown source '{source_id}' (known: {known})")
        if not self._scheduler.running:
            raise RuntimeError("scheduler is not running; call start() first")
        job = self._scheduler.add_job(self._run, args=[source_id, trigger], name=f"{source_id} ({trigger})",
                                      misfire_grace_time=None)
        return job.id

    def _run(self, source_id: str, trigger: str) -> None:
        try:
            self._runner(source_id, trigger)
        except Exception as e:  # noqa: BLE001 - the runner has already audited it; keep the scheduler thread quiet
            log.warning("source %s (%s) failed: %s", source_id, trigger, e)
