from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ..crawler import PageSnapshot
from ..models import Severity


@dataclass
class FindingCandidate:
    rule_id: str
    title: str
    severity: Severity
    confidence: float
    endpoint: str
    description: str
    impact: str
    remediation: str
    evidence_summary: str
    references: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)


class Rule(Protocol):
    id: str
    name: str

    def run(self, page: PageSnapshot) -> list[FindingCandidate]: ...
