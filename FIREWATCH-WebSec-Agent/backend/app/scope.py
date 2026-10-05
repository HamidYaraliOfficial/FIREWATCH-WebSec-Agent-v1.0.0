from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket
from urllib.parse import urljoin, urlparse, urlunparse


class ScopeViolation(ValueError):
    pass


@dataclass(frozen=True)
class ScopePolicy:
    root_url: str
    allowed_hosts: frozenset[str]
    root_scheme: str
    root_port: int
    exclusions: tuple[str, ...] = ()
    allow_private_targets: bool = False

    @classmethod
    def from_root(cls, root_url: str, exclusions: list[str] | None = None, allow_private_targets: bool = False) -> "ScopePolicy":
        parsed = urlparse(root_url)
        if parsed.scheme not in {"http", "https"}:
            raise ScopeViolation("Only http:// and https:// targets are allowed")
        if not parsed.hostname:
            raise ScopeViolation("Target URL must contain a hostname")
        host = parsed.hostname.lower().rstrip(".")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        policy = cls(root_url=urlunparse(parsed._replace(fragment="")), allowed_hosts=frozenset({host}), root_scheme=parsed.scheme, root_port=port, exclusions=tuple(exclusions or ()), allow_private_targets=allow_private_targets)
        policy.validate_url(policy.root_url)
        return policy

    def _hostname_is_private(self, hostname: str) -> bool:
        try:
            ip = ipaddress.ip_address(hostname)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(hostname, None)
            for info in infos:
                addr = info[4][0]
                ip = ipaddress.ip_address(addr)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                    return True
        except OSError:
            # Hostname resolution errors are left to the HTTP layer.
            return False
        return False

    def is_allowed(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                return False
            candidate_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if parsed.scheme != self.root_scheme or candidate_port != self.root_port:
                return False
            host = parsed.hostname.lower().rstrip(".")
            if host not in self.allowed_hosts:
                return False
            candidate = parsed.path or "/"
            full = parsed.geturl()
            if any(pattern and pattern in full for pattern in self.exclusions):
                return False
            if not self.allow_private_targets and self._hostname_is_private(host):
                return False
            return True
        except Exception:
            return False

    def validate_url(self, url: str) -> str:
        parsed = urlparse(url)
        if not self.is_allowed(url):
            raise ScopeViolation(f"URL is outside the configured scope: {url}")
        normalized = urlunparse(parsed._replace(fragment=""))
        return normalized

    def join(self, base: str, href: str) -> str | None:
        joined = urljoin(base, href)
        try:
            return self.validate_url(joined)
        except ScopeViolation:
            return None
