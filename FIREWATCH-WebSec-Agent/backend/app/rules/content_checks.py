from __future__ import annotations

import re
from urllib.parse import urlparse

from ..crawler import PageSnapshot
from ..models import Severity
from .base import FindingCandidate

BACKUP_EXTENSIONS = (".bak", ".old", ".orig", ".backup", ".zip", ".tar", ".gz", ".sql")


def run_content_rules(page: PageSnapshot) -> list[FindingCandidate]:
    findings: list[FindingCandidate] = []
    if page.mixed_content:
        findings.append(FindingCandidate(
            "FW-CONTENT-001", "HTTPS page references HTTP resources", Severity.MEDIUM, 0.98, page.url,
            "The HTTPS document references one or more resources over plain HTTP.",
            "Mixed content can weaken confidentiality/integrity and may be blocked or altered depending on resource type and browser behavior.",
            "Serve all security-sensitive resources over HTTPS and update hard-coded HTTP references.",
            f"Found {len(page.mixed_content)} HTTP resource references.", ["OWASP WSTG"], {"resources": page.mixed_content[:20]}
        ))
    lower = page.observation.body.lower()
    if "sourceMappingURL=" in page.observation.body:
        findings.append(FindingCandidate(
            "FW-CONTENT-002", "Source map reference exposed", Severity.LOW, 0.88, page.url,
            "The page references a JavaScript source map.",
            "Source maps can expose original client-side source and internal paths when publicly retrievable.",
            "Ensure production source maps are not publicly accessible unless intentionally published and sanitized.",
            "sourceMappingURL marker detected in response body.", ["OWASP WSTG"]
        ))
    linked = [u for u in page.links if any(u.lower().split("?", 1)[0].endswith(ext) for ext in BACKUP_EXTENSIONS)]
    if linked:
        findings.append(FindingCandidate(
            "FW-CONTENT-003", "Backup/archive file linked from application", Severity.MEDIUM, 0.9, page.url,
            "The page links to a file whose extension commonly indicates a backup or archive.",
            "Backup artifacts can contain source code, configuration or database data.",
            "Remove unintended backup/archive artifacts from web-accessible locations or protect them appropriately.",
            f"Discovered links: {linked[:10]}", ["OWASP WSTG"], {"links": linked[:20]}
        ))
    return findings
