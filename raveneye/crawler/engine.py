from __future__ import annotations
import asyncio, json
from time import monotonic
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urljoin

from .filters import Scope
from .extractors import extract_html
from .dedup import SimHashIndex
from .classifier import classify
from .api_discovery import discover_api_urls
from .discovery import discover_from_robots, well_known_urls
from .jsonl import write_jsonl
from .frontier import URLFrontier
from .js_analysis import analyze_javascript
from .retry import request_with_retry
from .telemetry import CrawlTelemetry
from ..network.session import AsyncSession
from ..network.scope_guard import ScopeGuard


class Crawler:
    """Bounded producer/consumer discovery pipeline.

    Discovery is deliberately non-destructive: only GET requests are issued and
    forms are extracted but never submitted. Queue sizes provide backpressure
    so a very large site cannot grow memory without bound.
    """

    def __init__(self, config, *, scope: Scope | None = None):
        self.config = config
        self.scope = scope or Scope()
        self.seen: set[str] = set()
        self.content_hashes = SimHashIndex(max_entries=getattr(config, "dedup_cache_size", 8192))
        self.forms: list[dict] = []
        self.telemetry = CrawlTelemetry()

    def _guard(self) -> ScopeGuard:
        return ScopeGuard(
            domains=self.scope.domains or set(),
            paths=tuple(self.scope.paths),
            regex=tuple(self.scope.regex),
            excludes=tuple(self.scope.excludes | (self.scope.exclude or set())),
        )

    def _seed_urls(self, seeds: Iterable[str]) -> list[str]:
        out: list[str] = []
        for seed in seeds:
            if not self.scope.allows(seed):
                continue
            out.append(seed)
            for url in (*well_known_urls(seed), urljoin(seed, "/robots.txt")):
                if self.scope.allows(url):
                    out.append(url)
        return list(dict.fromkeys(out))

    async def crawl(self, seeds: list[str], output=None):
        max_pages = self.config.max_pages
        queue_limit = max(32, min(max_pages, getattr(self.config, "queue_size", 512)))
        workers = max(1, min(self.config.concurrency, getattr(self.config, "worker_count", 50)))
        body_limit = getattr(self.config, "max_response_bytes", 2_000_000)
        frontier = URLFrontier(max_depth=getattr(self.config, "crawl_max_depth", 8), max_items=max_pages)
        results: list[dict] = []
        results_lock = asyncio.Lock()
        produced = 0
        scheduled: set[str] = set()
        schedule_lock = asyncio.Lock()

        async def schedule(url: str, depth: int = 0) -> bool:
            nonlocal produced
            if produced >= max_pages or depth > getattr(self.config, "crawl_max_depth", 8) or not self.scope.allows(url):
                return False
            async with schedule_lock:
                if produced >= max_pages or url in scheduled:
                    return False
                if await frontier.put(url, depth):
                    scheduled.add(url)
                    produced += 1
                    self.telemetry.event("urls_scheduled")
                    return True
            self.telemetry.event("urls_skipped")
            return False

        for url in self._seed_urls(seeds):
            if produced >= max_pages:
                break
            await schedule(url)

        guard = self._guard()
        async with AsyncSession(
            user_agent=self.config.user_agent,
            timeout=self.config.timeout_seconds,
            verify_tls=self.config.verify_tls,
            allowed_domains=self.scope.domains,
            requests_per_second=self.config.requests_per_second,
            scope_guard=guard,
            connector_limit=getattr(self.config, "connection_limit", 200),
        ) as session:
            async def worker() -> None:
                while True:
                    item = await frontier.get()
                    try:
                        if item is None:
                            return
                        url, depth = item.url, item.depth
                        try:
                            self.telemetry.event("requests")
                            began = monotonic()
                            response, retries = await request_with_retry(
                                session, url,
                                attempts=getattr(self.config, "retry_attempts", 2),
                                backoff=getattr(self.config, "retry_backoff_seconds", 0.25),
                            )
                            async with response as r:
                                body = await r.content.read(body_limit + 1)
                                truncated = len(body) > body_limit
                                body = body[:body_limit]
                                text = body.decode(r.charset or "utf-8", errors="replace")
                                row = {
                                    "url": str(r.url),
                                    "status": r.status,
                                    "content_type": r.headers.get("content-type", ""),
                                    "location": r.headers.get("location"),
                                    "truncated": truncated,
                                    "depth": depth,
                                    "retries": retries,
                                }
                                self.telemetry.response(r.status, monotonic() - began, len(body))
                        except Exception as exc:
                            self.telemetry.event("errors")
                            row = {"url": url, "error": str(exc)}
                            async with results_lock:
                                results.append(row)
                            continue

                        if not truncated and "text/html" in row["content_type"].lower():
                            duplicate = self.content_hashes.add(text)
                        else:
                            duplicate = False
                        ctype = row["content_type"].lower()
                        ex = extract_html(row["url"], text) if "text/html" in ctype else {
                            "urls": [], "forms": [], "apis": [], "websockets": [],
                            "scripts": [], "js_endpoints": [],
                        }
                        if "javascript" in ctype or row["url"].lower().split("?", 1)[0].endswith(".js"):
                            js = analyze_javascript(row["url"], text)
                            ex["urls"].extend(js["urls"] + js["source_maps"])
                            ex["websockets"].extend(js["websockets"])
                            self.telemetry.event("js_discoveries", len(js["urls"]))
                        if "robots.txt" in row["url"].lower() and ("text" in ctype or "plain" in ctype):
                            ex["urls"].extend(discover_from_robots(text, row["url"]))
                        if "xml" in ctype or "sitemap" in row["url"].lower():
                            from .sitemaps import parse_sitemap
                            ex["urls"].extend(parse_sitemap(text, row["url"]))
                        if "text/html" in ctype:
                            ex["urls"].extend(discover_api_urls(row["url"], text))
                        self.forms.extend(ex["forms"])
                        row.update({
                            "duplicate": duplicate,
                            "discovered": len(ex["urls"]),
                            "forms_found": len(ex["forms"]),
                            "websockets": ex["websockets"],
                            "type": classify(row["url"], ctype, row.get("status")),
                            "scripts": ex["scripts"][:100],
                        })
                        if row.get("status") in {301, 302, 303, 307, 308} and row.get("location"):
                            ex["urls"].append(urljoin(row["url"], row["location"]))
                        self.telemetry.event("forms", len(ex["forms"]))
                        self.telemetry.event("websocket_discoveries", len(ex["websockets"]))
                        for nxt in dict.fromkeys(ex["urls"]):
                            await schedule(nxt, depth + 1)
                        async with results_lock:
                            results.append(row)
                    finally:
                        frontier.task_done()

            tasks = [asyncio.create_task(worker()) for _ in range(workers)]
            await frontier.join()
            await frontier.stop(workers)
            await asyncio.gather(*tasks)

        if output:
            write_jsonl(results, output)
            forms_path = str(output).replace(".jsonl", "_forms.jsonl")
            with open(forms_path, "w", encoding="utf-8") as f:
                for form in self.forms:
                    f.write(json.dumps(form, ensure_ascii=False) + "\n")
        self.telemetry.event("urls_crawled", len(results))
        # Preserve the historical list return shape; telemetry is additive.
        for row in results:
            row.setdefault("telemetry", self.telemetry.snapshot())
        return results
