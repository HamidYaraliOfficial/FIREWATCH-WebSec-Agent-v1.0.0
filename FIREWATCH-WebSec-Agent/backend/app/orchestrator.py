from __future__ import annotations

from datetime import datetime, timezone
import logging
from pathlib import Path

from sqlalchemy import select, delete
from sqlalchemy.orm import Session

from .browser import BrowserDiscovery
from .config import settings
from .crawler import Crawler
from .evidence import normalize_candidate
from .models import Evidence, Finding, Page, Report, Scan, ScanStatus
from .planner import PlannerProtocol
from .report import render_html, render_json
from .risk import calculate_risk
from .rules.registry import run_rules
from .scope import ScopePolicy

logger = logging.getLogger(__name__)


def utcnow():
    return datetime.now(timezone.utc)


class ScanOrchestrator:
    def __init__(self, db: Session):
        self.db = db
        self.planner = PlannerProtocol()

    async def run(self, scan: Scan) -> None:
        scan.status = ScanStatus.RUNNING
        scan.started_at = utcnow()
        self.db.commit()
        try:
            config = scan.config or {}
            policy = ScopePolicy.from_root(
                scan.target_url,
                exclusions=config.get("exclusions", []),
                allow_private_targets=settings.allow_private_targets,
            )
            plan = self.planner.plan(
                enable_browser=bool(config.get("enable_browser", False)),
                enable_zap=bool(config.get("enable_zap", False)),
                passive_only=bool(config.get("passive_only", True)),
            )
            crawler = Crawler(
                policy,
                max_pages=int(config.get("max_pages", settings.max_pages)),
                max_depth=int(config.get("max_depth", settings.max_depth)),
                delay_ms=int(config.get("request_delay_ms", settings.request_delay_ms)),
                respect_robots=bool(config.get("respect_robots", settings.respect_robots)),
            )
            snapshots = await crawler.crawl()
            seen: set[str] = set()
            for snap in snapshots:
                page = Page(
                    scan_id=scan.id,
                    url=snap.url,
                    method="GET",
                    status_code=snap.observation.status_code,
                    content_type=snap.observation.content_type,
                    title=snap.title,
                    depth=snap.depth,
                    headers=snap.observation.headers,
                    links=snap.links,
                    technologies=snap.technologies,
                    body_sha256=snap.observation.body_sha256,
                )
                self.db.add(page)
                for candidate in run_rules(snap):
                    normalized = normalize_candidate(candidate)
                    if normalized.dedupe_key in seen:
                        continue
                    # Query DB as well so reruns/restarts remain idempotent.
                    existing = self.db.scalar(select(Finding).where(Finding.scan_id == scan.id, Finding.dedupe_key == normalized.dedupe_key))
                    if existing:
                        seen.add(normalized.dedupe_key)
                        continue
                    f = Finding(
                        scan_id=scan.id,
                        rule_id=candidate.rule_id,
                        title=candidate.title,
                        severity=candidate.severity,
                        confidence=max(0.0, min(1.0, candidate.confidence)),
                        risk_score=calculate_risk(candidate.severity, candidate.confidence),
                        endpoint=candidate.endpoint,
                        description=candidate.description,
                        impact=candidate.impact,
                        remediation=candidate.remediation,
                        references=candidate.references,
                        evidence_summary=candidate.evidence_summary,
                        dedupe_key=normalized.dedupe_key,
                    )
                    self.db.add(f)
                    self.db.flush()
                    self.db.add(Evidence(finding_id=f.id, kind="rule-observation", data=candidate.evidence or {"summary": candidate.evidence_summary}))
                    seen.add(normalized.dedupe_key)
                self.db.commit()

            if plan.browser_discovery:
                try:
                    browser_results = await BrowserDiscovery(policy).discover()
                    for br in browser_results:
                        # Browser-derived links are stored as a lightweight Page row only for traceability.
                        self.db.add(Page(
                            scan_id=scan.id,
                            url=br.url,
                            method="BROWSER",
                            status_code=0,
                            content_type="text/html",
                            title=br.title,
                            depth=0,
                            headers={},
                            links=br.links,
                            technologies=br.technologies,
                            body_sha256=None,
                        ))
                    self.db.commit()
                except Exception as exc:
                    logger.warning("browser discovery failed: %s", exc)

            scan.status = ScanStatus.COMPLETED
            scan.finished_at = utcnow()
            self.db.commit()
            await self._write_reports(scan)
        except Exception as exc:
            logger.exception("scan failed")
            scan.status = ScanStatus.FAILED
            scan.error = str(exc)
            scan.finished_at = utcnow()
            self.db.commit()
            raise

    async def _write_reports(self, scan: Scan) -> None:
        report_dir = Path(settings.report_dir) / scan.id
        report_dir.mkdir(parents=True, exist_ok=True)
        findings = list(self.db.scalars(select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.risk_score.desc())))
        html_path = report_dir / "report.html"
        json_path = report_dir / "report.json"
        render_html(scan, findings, str(html_path))
        render_json(scan, findings, str(json_path))
        self.db.query(Report).filter(Report.scan_id == scan.id).delete(synchronize_session=False)
        self.db.add_all([
            Report(scan_id=scan.id, format="html", path=str(html_path)),
            Report(scan_id=scan.id, format="json", path=str(json_path)),
        ])
        self.db.commit()
