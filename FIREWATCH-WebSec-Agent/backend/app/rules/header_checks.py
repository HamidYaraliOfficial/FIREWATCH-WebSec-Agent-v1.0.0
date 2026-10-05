from __future__ import annotations

from ..crawler import PageSnapshot
from ..models import Severity
from .base import FindingCandidate


def _has_csp(headers: dict[str, str]) -> bool:
    return "content-security-policy" in headers


def run_header_rules(page: PageSnapshot) -> list[FindingCandidate]:
    findings: list[FindingCandidate] = []
    h = page.observation.headers
    endpoint = page.url

    if "content-security-policy" not in h:
        findings.append(FindingCandidate(
            "FW-HTTP-001", "Content-Security-Policy header missing", Severity.MEDIUM, 0.95, endpoint,
            "The response does not send a Content-Security-Policy header. This removes a major browser-side mitigation for script injection and unsafe content execution.",
            "A successful client-side injection may have fewer browser-enforced constraints.",
            "Deploy a CSP appropriate for the application. Start with Report-Only where needed, then enforce a restrictive policy using nonces/hashes for scripts.",
            "No Content-Security-Policy header was present in the HTTP response.",
            ["OWASP Top 10", "OWASP WSTG"]
        ))
    if page.url.lower().startswith("https://") and "strict-transport-security" not in h:
        findings.append(FindingCandidate(
            "FW-HTTP-002", "HSTS header missing on HTTPS response", Severity.MEDIUM, 0.98, endpoint,
            "An HTTPS response does not advertise HTTP Strict Transport Security.",
            "Users may be more exposed to protocol-downgrade or first-visit transport attacks.",
            "Deploy Strict-Transport-Security with a suitable max-age; consider includeSubDomains/preload only after validating all subdomains.",
            "HTTPS response lacks Strict-Transport-Security.",
            ["OWASP WSTG"]
        ))
    if "x-content-type-options" not in h:
        findings.append(FindingCandidate(
            "FW-HTTP-003", "X-Content-Type-Options header missing", Severity.LOW, 0.97, endpoint,
            "The response does not set X-Content-Type-Options.",
            "Browsers may perform MIME sniffing in circumstances where explicit content types are safer.",
            "Set X-Content-Type-Options: nosniff.",
            "Header not present.", ["OWASP WSTG"]
        ))
    if "referrer-policy" not in h:
        findings.append(FindingCandidate(
            "FW-HTTP-004", "Referrer-Policy header missing", Severity.LOW, 0.96, endpoint,
            "No explicit Referrer-Policy was observed.",
            "Sensitive path or query information can be leaked through the Referer header depending on browser defaults and navigation context.",
            "Set a deliberate policy such as strict-origin-when-cross-origin or stricter according to application requirements.",
            "Header not present.", ["OWASP WSTG"]
        ))
    if "permissions-policy" not in h:
        findings.append(FindingCandidate(
            "FW-HTTP-005", "Permissions-Policy header missing", Severity.LOW, 0.92, endpoint,
            "No Permissions-Policy header was observed.",
            "Browser capabilities remain governed primarily by default policy rather than an explicit application allow-list.",
            "Define Permissions-Policy according to the features the application actually uses.",
            "Header not present.", ["OWASP WSTG"]
        ))
    if "x-frame-options" not in h and "content-security-policy" in h and "frame-ancestors" not in h["content-security-policy"].lower():
        findings.append(FindingCandidate(
            "FW-HTTP-006", "Clickjacking protection not detected", Severity.MEDIUM, 0.93, endpoint,
            "Neither X-Frame-Options nor a CSP frame-ancestors directive was detected.",
            "The page may be embeddable by another origin, increasing clickjacking risk where sensitive actions exist.",
            "Use CSP frame-ancestors and/or X-Frame-Options according to browser/application compatibility requirements.",
            "No X-Frame-Options and no CSP frame-ancestors directive observed.", ["OWASP WSTG"]
        ))
    if "server" in h or "x-powered-by" in h:
        disclosed = {k: h[k] for k in ("server", "x-powered-by") if k in h}
        findings.append(FindingCandidate(
            "FW-HTTP-007", "Technology banner disclosure", Severity.INFO, 0.91, endpoint,
            "Response headers disclose server/framework information.",
            "Technology details can make targeted fingerprinting easier.",
            "Minimize unnecessary banner information and remove framework signatures where practical.",
            f"Disclosed headers: {disclosed}", ["OWASP WSTG"], {"headers": disclosed}
        ))
    allow = h.get("allow", "")
    dangerous = [m for m in ("TRACE", "CONNECT") if m in {x.strip().upper() for x in allow.split(",")}]
    if dangerous:
        findings.append(FindingCandidate(
            "FW-HTTP-008", "Potentially unnecessary HTTP methods advertised", Severity.LOW, 0.88, endpoint,
            "The server advertises TRACE or CONNECT in the Allow response header.",
            "Unnecessary methods can widen the attack surface depending on server/proxy behavior.",
            "Disable methods that the application does not require at the application server, reverse proxy, and gateway layers.",
            f"Allow header advertises: {', '.join(dangerous)}", ["OWASP WSTG"]
        ))
    return findings
