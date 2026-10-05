from __future__ import annotations

from urllib.parse import urlparse

from ..crawler import PageSnapshot
from ..models import Severity
from .base import FindingCandidate


def run_form_rules(page: PageSnapshot) -> list[FindingCandidate]:
    findings: list[FindingCandidate] = []
    for form in page.forms:
        types = {(i.get("type") or "").lower() for i in form.get("inputs", [])}
        names = {(i.get("name") or "").lower() for i in form.get("inputs", []) if i.get("name")}
        has_password = "password" in types
        action = form.get("action") or page.url
        if has_password and urlparse(action).scheme == "http":
            findings.append(FindingCandidate(
                "FW-FORM-001", "Password form submits over HTTP", Severity.HIGH, 0.99, page.url,
                "A form containing a password input submits to an HTTP action.",
                "Credentials can be exposed to network interception.",
                "Submit authentication forms only over HTTPS and redirect/disable cleartext HTTP at the edge.",
                f"Password input found with HTTP form action: {action}", ["OWASP WSTG"], {"action": action}
            ))
        if has_password and not any(k in names for k in ("csrf", "csrf_token", "_csrf", "xsrf", "_token")):
            findings.append(FindingCandidate(
                "FW-FORM-002", "Password form lacks an obvious CSRF token field", Severity.INFO, 0.65, page.url,
                "A password-bearing form does not contain an input with a common CSRF token name.",
                "This is a review candidate only; modern frameworks can provide CSRF protection through headers, cookies or other mechanisms.",
                "Verify server-side CSRF defenses for state-changing authentication flows. Do not rely on field-name heuristics as proof of absence.",
                "No common CSRF token field name was found in the form inputs.", ["OWASP WSTG"], {"action": action}
            ))
    return findings
