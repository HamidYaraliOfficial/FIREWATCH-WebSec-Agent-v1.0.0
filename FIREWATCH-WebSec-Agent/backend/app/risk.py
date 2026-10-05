from __future__ import annotations

from .models import Severity

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 0.5,
}


def calculate_risk(severity: Severity, confidence: float) -> float:
    confidence = max(0.0, min(1.0, confidence))
    return round(SEVERITY_WEIGHT[severity] * confidence, 2)
