from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from dapptility_app.config import settings
from dapptility_app.database import SessionLocal
from dapptility_app.services.discovery.sync import run_discovery_sync

logger = logging.getLogger(__name__)
_scheduler: BackgroundScheduler | None = None


def _discovery_job() -> None:
    if not settings.discovery_enabled:
        return
    db = SessionLocal()
    try:
        run = run_discovery_sync(db, actor="scheduler")
        logger.info(
            "Discovery run %s complete: new=%s updated=%s promoted=%s",
            run.id,
            run.leads_new,
            run.leads_updated,
            run.leads_promoted,
        )
    except Exception:
        logger.exception("Scheduled discovery run failed")
    finally:
        db.close()


def start_scheduler() -> None:
    global _scheduler
    if not settings.discovery_enabled:
        return
    if _scheduler is not None:
        return
    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.add_job(
        _discovery_job,
        CronTrigger(hour=settings.discovery_hour_utc, minute=0),
        id="daily_discovery",
        replace_existing=True,
    )
    _scheduler.start()
    logger.info("Discovery scheduler started (daily at %02d:00 UTC)", settings.discovery_hour_utc)


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
