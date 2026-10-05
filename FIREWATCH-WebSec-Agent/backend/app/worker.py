from __future__ import annotations

import asyncio
import logging
import time

from sqlalchemy import select

from .db import SessionLocal, init_db
from .models import Scan, ScanStatus
from .orchestrator import ScanOrchestrator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("firewatch.worker")


def claim_one() -> str | None:
    db = SessionLocal()
    try:
        scan = db.scalar(
            select(Scan)
            .where(Scan.status == ScanStatus.QUEUED)
            .order_by(Scan.created_at.asc())
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        if not scan:
            return None
        scan.status = ScanStatus.RUNNING
        db.commit()
        return scan.id
    finally:
        db.close()


async def process(scan_id: str):
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        # Orchestrator sets RUNNING as well; the claim reduces duplicate pickup.
        await ScanOrchestrator(db).run(scan)
    finally:
        db.close()


def main():
    init_db()
    logger.info("FIREWATCH worker started")
    while True:
        scan_id = claim_one()
        if scan_id:
            logger.info("processing scan %s", scan_id)
            try:
                asyncio.run(process(scan_id))
            except Exception:
                logger.exception("scan %s failed", scan_id)
        else:
            time.sleep(1.5)


if __name__ == "__main__":
    main()
