from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse
from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup

from .http_client import HTTPObservation, SafeHTTPClient
from .scope import ScopePolicy


@dataclass
class PageSnapshot:
    url: str
    depth: int
    observation: HTTPObservation
    title: str | None
    links: list[str]
    forms: list[dict]
    technologies: list[str]
    mixed_content: list[str]


class Crawler:
    def __init__(self, scope: ScopePolicy, max_pages: int, max_depth: int, delay_ms: int, respect_robots: bool = True):
        self.scope = scope
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.delay_ms = delay_ms
        self.respect_robots = respect_robots

    async def crawl(self) -> list[PageSnapshot]:
        snapshots: list[PageSnapshot] = []
        queue = deque([(self.scope.root_url, 0)])
        visited: set[str] = set()
        robot_parser = await self._load_robots() if self.respect_robots else None
        async with SafeHTTPClient(self.scope, delay_ms=self.delay_ms) as client:
            while queue and len(snapshots) < self.max_pages:
                batch: list[tuple[str, int]] = []
                while queue and len(batch) < self._batch_size():
                    url, depth = queue.popleft()
                    if url in visited or depth > self.max_depth:
                        continue
                    if robot_parser is not None and not robot_parser.can_fetch("FIREWATCH-WebSec-Agent", url):
                        continue
                    visited.add(url)
                    batch.append((url, depth))
                if not batch:
                    continue
                results = await __import__("asyncio").gather(*(client.request("GET", url) for url, _ in batch))
                for (url, depth), obs in zip(batch, results):
                    if obs.error:
                        continue
                    snapshot = self._snapshot(url, depth, obs)
                    snapshots.append(snapshot)
                    if depth >= self.max_depth or not self._is_html(obs.content_type):
                        continue
                    for link in snapshot.links:
                        if link not in visited:
                            queue.append((link, depth + 1))
                    if len(snapshots) >= self.max_pages:
                        break
        return snapshots

    def _batch_size(self) -> int:
        from .config import settings
        return max(1, int(settings.max_concurrency))


    async def _load_robots(self) -> RobotFileParser | None:
        parsed = urlparse(self.scope.root_url)
        robots_url = urlunparse((parsed.scheme, parsed.netloc, "/robots.txt", "", "", ""))
        try:
            async with SafeHTTPClient(self.scope, delay_ms=self.delay_ms) as client:
                obs = await client.request("GET", robots_url)
            if obs.error or obs.status_code >= 400:
                return None
            rp = RobotFileParser()
            rp.set_url(robots_url)
            rp.parse(obs.body.splitlines())
            return rp
        except Exception:
            return None

    def _is_html(self, content_type: str) -> bool:
        ct = content_type.lower()
        return "text/html" in ct or "application/xhtml+xml" in ct

    def _snapshot(self, url: str, depth: int, obs: HTTPObservation) -> PageSnapshot:
        soup = BeautifulSoup(obs.body, "html.parser")
        title = soup.title.get_text(" ", strip=True)[:500] if soup.title else None
        links: list[str] = []
        for tag in soup.find_all(["a", "link", "script", "img", "iframe", "form"], href=True):
            href = tag.get("href")
            joined = self.scope.join(url, href)
            if joined and joined not in links:
                links.append(joined)
        for tag in soup.find_all(["script", "img", "iframe", "source"], src=True):
            src = tag.get("src")
            joined = self.scope.join(url, src)
            if joined and joined not in links:
                links.append(joined)
        forms = []
        for form in soup.find_all("form"):
            action = self.scope.join(url, form.get("action") or url) or url
            method = (form.get("method") or "get").lower()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name": inp.get("name"),
                    "type": inp.get("type"),
                })
            forms.append({"action": action, "method": method, "inputs": inputs})
        technologies = self._fingerprint(obs.headers, soup)
        mixed = []
        if urlparse(url).scheme == "https":
            for attr in ["src", "href"]:
                for tag in soup.find_all(attrs={attr: True}):
                    val = str(tag.get(attr))
                    if val.startswith("http://"):
                        mixed.append(val)
        return PageSnapshot(url, depth, obs, title, links[:500], forms[:100], technologies, mixed[:100])

    def _fingerprint(self, headers, soup) -> list[str]:
        tech: set[str] = set()
        server = headers.get("server", "").lower()
        powered = headers.get("x-powered-by", "").lower()
        if "nginx" in server: tech.add("Nginx")
        if "apache" in server: tech.add("Apache")
        if "iis" in server: tech.add("IIS")
        if "express" in powered: tech.add("Express")
        if "php" in powered: tech.add("PHP")
        scripts = " ".join(str(x.get("src")) for x in soup.find_all("script"))
        html = str(soup)
        if re.search(r"/_next/|__next_data__", html, re.I): tech.add("Next.js")
        if re.search(r"react|react-dom", scripts, re.I): tech.add("React")
        if re.search(r"angular", scripts, re.I): tech.add("Angular")
        if re.search(r"vue(?:\.min)?\.js", scripts, re.I): tech.add("Vue")
        return sorted(tech)
