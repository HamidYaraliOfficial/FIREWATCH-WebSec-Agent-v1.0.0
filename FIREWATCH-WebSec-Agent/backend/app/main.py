from __future__ import annotations

from pathlib import Path

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db, init_db
from .models import Finding, Page, Project, Scan, ScanStatus
from .schemas import FindingOut, ScanCreate, ScanDetail, ScanSummary
from .scope import ScopePolicy, ScopeViolation

@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(title=settings.app_name, version="1.0.0", docs_url="/docs", redoc_url="/redoc", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[x.strip() for x in settings.cors_origins.split(",") if x.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


@app.get("/health")
def health():
    return {"status": "ok", "service": "firewatch-api", "version": "1.0.0"}


@app.post("/api/v1/scans", response_model=ScanSummary, status_code=201)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db)):
    target = str(payload.target_url)
    try:
        ScopePolicy.from_root(target, exclusions=payload.exclusions, allow_private_targets=settings.allow_private_targets)
    except ScopeViolation as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    scan = Scan(
        project_id=payload.project_id,
        target_url=target,
        config=payload.model_dump(exclude={"target_url", "project_id"}),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@app.get("/api/v1/scans", response_model=list[ScanSummary])
def list_scans(limit: int = 50, db: Session = Depends(get_db)):
    limit = min(max(limit, 1), 200)
    return list(db.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(limit)))


@app.get("/api/v1/scans/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    pages_count = db.scalar(select(func.count()).select_from(Page).where(Page.scan_id == scan.id)) or 0
    findings_count = db.scalar(select(func.count()).select_from(Finding).where(Finding.scan_id == scan.id)) or 0
    return ScanDetail.model_validate({
        **{c.name: getattr(scan, c.name) for c in Scan.__table__.columns},
        "pages_count": pages_count,
        "findings_count": findings_count,
    })


@app.get("/api/v1/scans/{scan_id}/findings", response_model=list[FindingOut])
def list_findings(scan_id: str, db: Session = Depends(get_db)):
    if not db.get(Scan, scan_id):
        raise HTTPException(404, "Scan not found")
    return list(db.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.risk_score.desc())))


@app.get("/api/v1/scans/{scan_id}/report")
def report(scan_id: str, format: str = "html", db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    reports = [r for r in scan.reports if r.format == format]
    if not reports:
        raise HTTPException(404, "Requested report is not available")
    path = Path(reports[0].path)
    if not path.exists():
        raise HTTPException(404, "Report file is missing")
    media = "text/html" if format == "html" else "application/json"
    return FileResponse(path, media_type=media, filename=path.name)
