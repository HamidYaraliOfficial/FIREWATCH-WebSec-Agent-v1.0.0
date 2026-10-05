from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field, HttpUrl, ConfigDict

from .models import ScanStatus, Severity


class ScanCreate(BaseModel):
    target_url: HttpUrl
    project_id: str | None = None
    max_pages: int = Field(default=100, ge=1, le=1000)
    max_depth: int = Field(default=6, ge=0, le=20)
    request_delay_ms: int = Field(default=250, ge=0, le=10000)
    max_concurrency: int = Field(default=4, ge=1, le=20)
    enable_browser: bool = False
    enable_zap: bool = False
    passive_only: bool = True
    respect_robots: bool = True
    exclusions: list[str] = Field(default_factory=list, max_length=100)


class ScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    target_url: str
    status: ScanStatus
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    rule_id: str
    title: str
    severity: Severity
    confidence: float
    risk_score: float
    status: str
    endpoint: str
    description: str
    impact: str
    remediation: str
    references: list[Any]
    evidence_summary: str


class ScanDetail(ScanSummary):
    config: dict[str, Any]
    pages_count: int = 0
    findings_count: int = 0
