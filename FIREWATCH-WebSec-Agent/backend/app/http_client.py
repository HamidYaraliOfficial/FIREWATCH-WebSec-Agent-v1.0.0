from __future__ import annotations

import asyncio
from dataclasses import dataclass
from hashlib import sha256
import time
from typing import Mapping

import httpx

from .config import settings
from .scope import ScopePolicy, ScopeViolation


@dataclass
class HTTPObservation:
    requested_url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed_ms: float
    content_type: str
    body_sha256: str
    error: str | None = None


class SafeHTTPClient:
    def __init__(self, scope: ScopePolicy, timeout: float | None = None, delay_ms: int | None = None):
        self.scope = scope
        self.timeout = timeout if timeout is not None else settings.request_timeout_seconds
        self.delay_ms = delay_ms if delay_ms is not None else settings.request_delay_ms
        self.client: httpx.AsyncClient | None = None
        self._last_request_at = 0.0
        self._throttle_lock = asyncio.Lock()

    async def __aenter__(self):
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            headers={"User-Agent": settings.user_agent, "Accept": "text/html,application/json,text/plain,*/*"},
            verify=True,
            trust_env=False,
        )
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.client:
            await self.client.aclose()

    async def _throttle(self):
        target_gap = max(0, self.delay_ms) / 1000.0
        async with self._throttle_lock:
            elapsed = time.monotonic() - self._last_request_at
            if elapsed < target_gap:
                await asyncio.sleep(target_gap - elapsed)
            self._last_request_at = time.monotonic()

    async def request(self, method: str, url: str, headers: Mapping[str, str] | None = None) -> HTTPObservation:
        if not self.client:
            raise RuntimeError("SafeHTTPClient must be used as an async context manager")
        clean_url = self.scope.validate_url(url)
        await self._throttle()
        start = time.perf_counter()
        try:
            response = await self.client.request(method.upper(), clean_url, headers=dict(headers or {}))
            elapsed = (time.perf_counter() - start) * 1000
            body = response.text[:2_000_000]
            return HTTPObservation(
                requested_url=clean_url,
                final_url=str(response.url),
                status_code=response.status_code,
                headers={k.lower(): v for k, v in response.headers.items()},
                body=body,
                elapsed_ms=round(elapsed, 2),
                content_type=response.headers.get("content-type", ""),
                body_sha256=sha256(body.encode("utf-8", errors="replace")).hexdigest(),
            )
        except (httpx.HTTPError, ScopeViolation) as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return HTTPObservation(
                requested_url=clean_url,
                final_url=clean_url,
                status_code=0,
                headers={},
                body="",
                elapsed_ms=round(elapsed, 2),
                content_type="",
                body_sha256=sha256(b"").hexdigest(),
                error=str(exc),
            )
