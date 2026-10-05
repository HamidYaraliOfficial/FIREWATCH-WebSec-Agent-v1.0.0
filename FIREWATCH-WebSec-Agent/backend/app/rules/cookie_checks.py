from __future__ import annotations

from ..crawler import PageSnapshot
from ..models import Severity
from .base import FindingCandidate


def run_cookie_rules(page: PageSnapshot) -> list[FindingCandidate]:
    raw = page.observation.headers.get("set-cookie")
    if not raw:
        return []
    # A conservative parser: split on the common attribute delimiter only when another cookie name starts.
    cookies = [part.strip() for part in raw.split(",") if part.strip()]
    findings: list[FindingCandidate] = []
    for cookie in cookies:
        name = cookie.split("=", 1)[0].strip()
        low = cookie.lower()
        session_like = any(k in name.lower() for k in ("session", "sess", "auth", "token", "jwt", "sid"))
        if page.url.startswith("https://") and "secure" not in low:
            findings.append(FindingCandidate(
                "FW-COOKIE-001", "Cookie missing Secure attribute", Severity.MEDIUM if session_like else Severity.LOW, 0.93,
                page.url, f"Cookie `{name}` is set without the Secure attribute on an HTTPS page.",
                "The browser may send the cookie over a non-HTTPS request in some contexts.",
                "Add Secure to cookies that should only traverse HTTPS.",
                f"Set-Cookie for `{name}` does not contain the Secure attribute.", ["OWASP WSTG"], {"cookie": name}
            ))
        if session_like and "httponly" not in low:
            findings.append(FindingCandidate(
                "FW-COOKIE-002", "Session-like cookie missing HttpOnly", Severity.MEDIUM, 0.92, page.url,
                f"Cookie `{name}` appears session/auth related but does not contain HttpOnly.",
                "Client-side scripts may be able to read a session credential if an XSS issue exists.",
                "Add HttpOnly to cookies that do not need JavaScript access.",
                f"Set-Cookie for `{name}` does not contain HttpOnly.", ["OWASP WSTG"], {"cookie": name}
            ))
        if "samesite=" not in low:
            findings.append(FindingCandidate(
                "FW-COOKIE-003", "Cookie missing SameSite attribute", Severity.LOW, 0.9, page.url,
                f"Cookie `{name}` does not explicitly declare SameSite.",
                "Cross-site cookie behavior relies on browser defaults rather than an explicit policy.",
                "Set SameSite=Lax or Strict where application flows allow; use SameSite=None only with Secure when cross-site use is required.",
                f"Set-Cookie for `{name}` has no SameSite attribute.", ["OWASP WSTG"], {"cookie": name}
            ))
    return findings
