from __future__ import annotations

from ..crawler import PageSnapshot
from ..models import Severity
from .base import FindingCandidate


def run_cors_rules(page: PageSnapshot) -> list[FindingCandidate]:
    h = page.observation.headers
    findings: list[FindingCandidate] = []
    acao = h.get("access-control-allow-origin")
    acac = h.get("access-control-allow-credentials", "").lower()
    if acao == "*":
        findings.append(FindingCandidate(
            "FW-CORS-001", "Wildcard CORS policy", Severity.LOW, 0.95, page.url,
            "The response permits requests from any origin via Access-Control-Allow-Origin: *.",
            "Cross-origin JavaScript can read responses where the resource is intended to be private; severity depends on endpoint sensitivity and browser credential rules.",
            "Restrict Access-Control-Allow-Origin to trusted origins and avoid wildcard policies for sensitive APIs.",
            "Access-Control-Allow-Origin is `*`.", ["OWASP API Security Top 10"], {"acao": acao}
        ))
    if acao and acao != "*" and "origin" in h:
        # The presence of a non-wildcard ACAO alone is not proof of reflection. Mark as inventory evidence.
        findings.append(FindingCandidate(
            "FW-CORS-002", "CORS allows a specific origin", Severity.INFO, 0.72, page.url,
            "A specific cross-origin access policy is advertised by the response.",
            "A specific CORS allow-list can be safe, but origin reflection and credentialed access require validation.",
            "Review whether the allowed origin is intentional and whether credentials are permitted only for trusted origins.",
            f"Access-Control-Allow-Origin: {acao}", ["OWASP API Security Top 10"], {"acao": acao}
        ))
    if acao == "*" and acac == "true":
        findings.append(FindingCandidate(
            "FW-CORS-003", "Wildcard CORS combined with credential flag", Severity.MEDIUM, 0.93, page.url,
            "The response advertises wildcard CORS together with Access-Control-Allow-Credentials: true.",
            "Browsers restrict credentialed wildcard CORS in standard fetch behavior, but this configuration is inconsistent and should be reviewed at proxy/framework layers.",
            "Replace wildcard CORS with an explicit allow-list and keep credentialed cross-origin access tightly scoped.",
            "ACAO is `*` and ACAC is `true`.", ["OWASP API Security Top 10"], {"acao": acao, "acac": acac}
        ))
    return findings
