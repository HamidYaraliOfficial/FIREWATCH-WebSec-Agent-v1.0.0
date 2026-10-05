from __future__ import annotations

from dataclasses import dataclass
import importlib.util
from urllib.parse import urlparse

from .scope import ScopePolicy


@dataclass
class BrowserResult:
    url: str
    links: list[str]
    title: str | None
    technologies: list[str]


class BrowserDiscovery:
    def __init__(self, scope: ScopePolicy):
        self.scope = scope

    async def discover(self) -> list[BrowserResult]:
        if importlib.util.find_spec("playwright") is None:
            raise RuntimeError("Playwright is not installed")
        from playwright.async_api import async_playwright

        results: list[BrowserResult] = []
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=False, user_agent="FIREWATCH-WebSec-Agent/1.0 (+authorized-security-testing)")
            page = await context.new_page()

            async def route_guard(route):
                request_url = route.request.url
                scheme = urlparse(request_url).scheme.lower()
                if scheme in {"data", "blob", "about"} or self.scope.is_allowed(request_url):
                    await route.continue_()
                else:
                    await route.abort()

            await page.route("**/*", route_guard)
            await page.goto(self.scope.root_url, wait_until="domcontentloaded", timeout=30_000)
            links = await page.locator("a[href]").evaluate_all("els => els.map(e => e.href)")
            safe_links = []
            for link in links:
                try:
                    safe = self.scope.validate_url(link)
                except Exception:
                    continue
                if safe not in safe_links:
                    safe_links.append(safe)
            scripts = await page.locator("script[src]").evaluate_all("els => els.map(e => e.src)")
            tech = []
            source = " ".join(scripts)
            if "/_next/" in source: tech.append("Next.js")
            if "react" in source.lower(): tech.append("React")
            if "vue" in source.lower(): tech.append("Vue")
            results.append(BrowserResult(self.scope.root_url, safe_links[:500], await page.title(), sorted(set(tech))))
            await context.close()
            await browser.close()
        return results
