from __future__ import annotations
import asyncio, json
from contextlib import AsyncExitStack
from time import monotonic
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from .filters import Scope
from .extractors import extract_html
from .dedup import SimHashIndex
from .classifier import classify
from .api_discovery import discover_api_urls
from .discovery import well_known_urls
from .sitemaps import parse_robots, robots_allows
from .frontier import URLFrontier
from .js_analysis import analyze_javascript, analyze_source_map
from .retry import request_with_retry
from .telemetry import CrawlTelemetry
from .renderers import ScopedPlaywrightRenderer, looks_like_spa
from ..network.session import AsyncSession
from ..network.scope_guard import ScopeGuard
from ..scanner.evidence import sanitize_url


async def _read_response_body(content, limit: int) -> tuple[bytes, bool]:
    """Read a response incrementally without exceeding the configured cap.

    ``aiohttp`` may return fewer than ``n`` bytes from ``read(n)`` as soon as
    some bytes are available. A single read therefore cannot be used to decide
    that the response body is complete. Iterating chunks preserves all links
    in large-but-allowed documents and still bounds retained response memory.
    """
    cap = max(0, int(limit))
    chunks: list[bytes] = []
    total = 0
    async for chunk in content.iter_chunked(min(64 * 1024, cap + 1)):
        remaining = cap + 1 - total
        if remaining <= 0:
            break
        kept = chunk[:remaining]
        chunks.append(kept)
        total += len(kept)
        if total > cap:
            break
    body = b"".join(chunks)
    return body[:cap], len(body) > cap


class Crawler:
    """Bounded producer/consumer discovery pipeline.

    Discovery is deliberately non-destructive: only GET requests are issued and
    forms are extracted but never submitted. Queue sizes provide backpressure
    so a very large site cannot grow memory without bound.
    """

    def __init__(self, config, *, scope: Scope | None = None):
        self.config = config
        self.scope = scope or Scope()
        self._active_scope = self.scope
        self.seen: set[str] = set()
        self.content_hashes = SimHashIndex(max_entries=getattr(config, "dedup_cache_size", 8192))
        self.forms: list[dict] = []
        self.telemetry = CrawlTelemetry()
        self.frontier: URLFrontier | None = None

    def _guard(self) -> ScopeGuard:
        return ScopeGuard(
            domains=self._active_scope.domains or set(),
            exact_hosts=set(self._active_scope.exact_hosts),
            paths=tuple(self._active_scope.paths),
            regex=tuple(self._active_scope.regex),
            excludes=tuple(self._active_scope.excludes | (self._active_scope.exclude or set())),
        )

    def _seed_urls(self, seeds: Iterable[str]) -> list[str]:
        out: list[str] = []
        for seed in seeds:
            if not self._active_scope.allows(seed):
                continue
            out.append(seed)
            for url in well_known_urls(seed):
                if self._active_scope.allows(url):
                    out.append(url)
        return list(dict.fromkeys(out))

    async def crawl(self, seeds: list[str], output=None, *, append_output: bool = False,
                    retain_results: bool = True, retain_forms: bool = True):
        crawl_started = monotonic()
        crawl_deadline = crawl_started + max(1, int(getattr(self.config, "max_runtime_seconds", 900)))
        max_pages = self.config.max_pages
        queue_limit = max(1, min(max_pages, getattr(self.config, "queue_size", 512)))
        workers = max(1, min(self.config.concurrency, getattr(self.config, "worker_count", 50)))
        body_limit = getattr(self.config, "max_response_bytes", 2_000_000)
        self.forms = []
        self.telemetry = CrawlTelemetry()
        self.content_hashes = SimHashIndex(max_entries=getattr(self.config, "dedup_cache_size", 8192))
        # An omitted scope is constrained to the explicit seed host(s), never the
        # entire public Internet. A caller can opt into subdomains with *.domain.
        if not self.scope.domains:
            seed_domains = {
                (urlsplit(seed).hostname or "").lower().rstrip(".")
                for seed in seeds if urlsplit(seed).hostname
            }
            self._active_scope = Scope(
                exact_hosts=seed_domains, excludes=set(self.scope.excludes),
                exclude=set(self.scope.exclude or ()), regex=list(self.scope.regex),
                paths=list(self.scope.paths),
            )
        else:
            self._active_scope = self.scope
        frontier = URLFrontier(
            max_depth=getattr(self.config, "crawl_max_depth", 8),
            max_items=max_pages, queue_size=queue_limit,
        )
        self.frontier = frontier
        results: list[dict] = []
        results_lock = asyncio.Lock()
        rows_file = forms_file = None
        if output:
            out_path = Path(output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            mode = "a" if append_output else "w"
            rows_file = out_path.open(mode, encoding="utf-8", buffering=1)
            forms_path = out_path.with_name(f"{out_path.stem}_forms.jsonl")
            forms_file = forms_path.open(mode, encoding="utf-8", buffering=1)
        produced = 0
        robots_policy: dict[tuple[str, str, int], tuple[str, list[dict]] | str] = {}
        preloaded_robots: set[str] = set()
        schedule_lock = asyncio.Lock()
        api_hint_origins: set[tuple[str, str, int]] = set()
        api_hint_lock = asyncio.Lock()

        async def schedule(url: str, depth: int = 0) -> bool:
            nonlocal produced
            if monotonic() >= crawl_deadline or produced >= max_pages or depth > getattr(self.config, "crawl_max_depth", 8) or not self._active_scope.allows(url):
                return False
            if url in preloaded_robots:
                return False
            parsed = urlsplit(url)
            origin = (parsed.scheme.lower(), (parsed.hostname or "").lower().rstrip("."), parsed.port or (443 if parsed.scheme.lower() == "https" else 80))
            policy = robots_policy.get(origin, "not-loaded")
            if policy == "deny-all" or (policy != "not-loaded" and not robots_allows(url, policy[0], policy[1])):
                self.telemetry.event("robots_blocked")
                return False
            async with schedule_lock:
                if produced >= max_pages:
                    return False
                if await frontier.put(url, depth):
                    produced += 1
                    self.telemetry.event("urls_scheduled")
                    return True
            self.telemetry.event("urls_skipped")
            return False

        async def record_row(row: dict, forms: list[dict] | None = None) -> None:
            row.setdefault("schema_version", "1.0")
            row.setdefault("telemetry", self.telemetry.snapshot())
            async with results_lock:
                if retain_results:
                    results.append(row)
                if rows_file:
                    rows_file.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
                if forms_file:
                    for form in forms or []:
                        forms_file.write(json.dumps({"schema_version": "1.0", **form}, ensure_ascii=False, separators=(",", ":")) + "\n")
                self.telemetry.event("urls_crawled")

        guard = self._guard()
        request_timeout = min(float(self.config.timeout_seconds), max(0.1, float(getattr(self.config, "max_runtime_seconds", 900))))
        async with AsyncExitStack() as stack:
            renderer = None
            if getattr(self.config, "headless_rendering", False):
                renderer = await stack.enter_async_context(ScopedPlaywrightRenderer(
                    self._active_scope,
                    user_agent=self.config.user_agent,
                    timeout_ms=getattr(self.config, "headless_timeout_ms", 5_000),
                    wait_ms=getattr(self.config, "headless_wait_ms", 750),
                    max_pages=getattr(self.config, "headless_max_pages", 50),
                    max_events=getattr(self.config, "headless_max_events", 500),
                    concurrency=getattr(self.config, "headless_concurrency", 2),
                ))
            session = await stack.enter_async_context(AsyncSession(
                user_agent=self.config.user_agent,
                timeout=request_timeout,
                verify_tls=self.config.verify_tls,
                allowed_domains=self._active_scope.domains,
                requests_per_second=self.config.requests_per_second,
                scope_guard=guard,
                connector_limit=getattr(self.config, "connection_limit", 200),
                per_host_limit=getattr(self.config, "per_host_concurrency", 4),
                per_host_requests_per_second=getattr(self.config, "per_host_requests_per_second", 4.0),
                concurrency=workers,
                adaptive_concurrency=getattr(self.config, "adaptive_concurrency", True),
            ))
            sitemap_seeds: list[str] = []
            robot_urls = list(dict.fromkeys(
                urljoin(seed, "/robots.txt") for seed in seeds
                if self._active_scope.allows(seed)
            ))
            for robots_url in robot_urls:
                if monotonic() >= crawl_deadline:
                    break
                parsed_robot = urlsplit(robots_url)
                origin = (parsed_robot.scheme.lower(), (parsed_robot.hostname or "").lower().rstrip("."), parsed_robot.port or (443 if parsed_robot.scheme.lower() == "https" else 80))
                preloaded_robots.add(robots_url)
                try:
                    current_robots_url = robots_url
                    redirects: list[str] = []
                    retries_total = 0
                    while True:
                        self.telemetry.event("requests")
                        began = monotonic()
                        response, retries = await asyncio.wait_for(
                            request_with_retry(
                                session, current_robots_url,
                                attempts=getattr(self.config, "retry_attempts", 2),
                                backoff=getattr(self.config, "retry_backoff_seconds", 0.25),
                                deadline=crawl_deadline,
                            ),
                            timeout=max(0.01, crawl_deadline - monotonic()),
                        )
                        retries_total += retries
                        async with response as r:
                            location = r.headers.get("location")
                            if 300 <= r.status < 400 and location:
                                next_robots_url = urljoin(current_robots_url, location)
                                if len(redirects) >= 5:
                                    self.telemetry.response(r.status, monotonic() - began)
                                    robots_policy[origin] = "deny-all"
                                    row = {
                                        "url": robots_url, "status": r.status,
                                        "error": "robots redirect limit exceeded",
                                        "robots_final_url": sanitize_url(current_robots_url),
                                        "robots_redirects": redirects,
                                        "robots_policy": "fail-closed", "depth": 0,
                                        "retries": retries_total, "type": "robots",
                                    }
                                    break
                                if not self._active_scope.allows(next_robots_url):
                                    self.telemetry.response(r.status, monotonic() - began)
                                    robots_policy[origin] = "deny-all"
                                    row = {
                                        "url": robots_url, "status": r.status,
                                        "error": "robots redirect outside configured scope",
                                        "robots_final_url": sanitize_url(current_robots_url),
                                        "robots_redirects": redirects,
                                        "robots_policy": "fail-closed", "depth": 0,
                                        "retries": retries_total, "type": "robots",
                                    }
                                    break
                                redirects.append(sanitize_url(next_robots_url))
                                current_robots_url = next_robots_url
                                self.telemetry.response(r.status, monotonic() - began)
                                continue

                            cap = min(body_limit, 512_000)
                            body, truncated = await _read_response_body(r.content, cap)
                            content = body.decode(r.charset or "utf-8", errors="replace")
                            row = {
                                "url": robots_url, "status": r.status,
                                "content_type": r.headers.get("content-type", ""),
                                "truncated": truncated, "depth": 0,
                                "retries": retries_total,
                                "retry_deferred": bool(getattr(r, "_raveneye_retry_deferred", False)),
                                "robots_final_url": sanitize_url(current_robots_url),
                                "robots_redirects": redirects, "type": "robots",
                            }
                            self.telemetry.response(r.status, monotonic() - began, len(body))
                            if r.status == 200 and not truncated:
                                parsed_policy = parse_robots(content, robots_url, self.config.user_agent)
                                robots_policy[origin] = (robots_url, parsed_policy["rules"])
                                row["robots_allow"] = [urlsplit(x).path for x in parsed_policy["allow"]]
                                row["robots_disallow"] = [urlsplit(x).path for x in parsed_policy["disallow"]]
                                row["sitemaps"] = parsed_policy["sitemaps"]
                                sitemap_seeds.extend(parsed_policy["sitemaps"])
                            elif r.status in {401, 403, 429} or r.status >= 500 or 300 <= r.status < 400:
                                robots_policy[origin] = "deny-all"
                                row["robots_policy"] = "fail-closed"
                            else:
                                robots_policy[origin] = (robots_url, [])
                                row["robots_policy"] = "no-rules"
                            break
                    await record_row(row)
                except Exception as exc:
                    self.telemetry.event("errors")
                    robots_policy[origin] = "deny-all"
                    await record_row({
                        "url": robots_url, "status": None,
                        "error": f"robots.txt unavailable: {type(exc).__name__}",
                        "type": "robots", "robots_policy": "fail-closed", "depth": 0,
                    })
            for url in dict.fromkeys(self._seed_urls(seeds) + sitemap_seeds):
                if produced >= max_pages or monotonic() >= crawl_deadline:
                    break
                await schedule(url)

            async def worker() -> None:
                while True:
                    item = await frontier.get()
                    try:
                        if item.stop:
                            return
                        url, depth = item.url, item.depth
                        if monotonic() >= crawl_deadline:
                            self.telemetry.event("requests_deferred")
                            await record_row({"url": url, "status": None, "error": "crawl runtime limit reached", "deferred": True, "depth": depth})
                            continue
                        try:
                            self.telemetry.event("requests")
                            began = monotonic()
                            response, retries = await asyncio.wait_for(
                                request_with_retry(
                                    session, url,
                                    attempts=getattr(self.config, "retry_attempts", 2),
                                    backoff=getattr(self.config, "retry_backoff_seconds", 0.25),
                                    deadline=crawl_deadline,
                                ),
                                timeout=max(0.01, crawl_deadline - monotonic()),
                            )
                            async with response as r:
                                body, truncated = await _read_response_body(r.content, body_limit)
                                text = body.decode(r.charset or "utf-8", errors="replace")
                                row = {
                                    "url": str(r.url),
                                    "status": r.status,
                                    "content_type": r.headers.get("content-type", ""),
                                    "location": r.headers.get("location"),
                                    "truncated": truncated,
                                    "depth": depth,
                                    "retries": retries,
                                    "retry_deferred": bool(getattr(r, "_raveneye_retry_deferred", False)),
                                    "retry_after_seconds": getattr(r, "_raveneye_retry_after", None),
                                }
                                self.telemetry.response(r.status, monotonic() - began, len(body))
                        except Exception as exc:
                            self.telemetry.event("errors")
                            row = {"url": url, "error": str(exc)}
                            await record_row(row)
                            continue

                        ctype = row["content_type"].lower()
                        ex = extract_html(row["url"], text) if "text/html" in ctype else {
                            "urls": [], "forms": [], "apis": [], "websockets": [],
                            "scripts": [], "js_endpoints": [], "route_templates": [],
                        }
                        classification_body = text
                        if (renderer is not None and not truncated and "text/html" in ctype
                                and looks_like_spa(text)):
                            self.telemetry.event("headless_candidates")
                            try:
                                render_result = await asyncio.wait_for(
                                    renderer.render(row["url"]),
                                    timeout=max(0.01, crawl_deadline - monotonic()),
                                )
                            except asyncio.TimeoutError:
                                self.telemetry.event("headless_timeouts")
                                row["render_error"] = "TimeoutError"
                            except Exception as exc:
                                self.telemetry.event("headless_errors")
                                row["render_error"] = type(exc).__name__
                            else:
                                rendered_body = render_result.get("body") or ""
                                rendered_url = str(render_result.get("url") or row["url"])
                                row["rendered"] = bool(rendered_body)
                                row["rendered_url"] = sanitize_url(rendered_url)
                                if render_result.get("status") is not None:
                                    row["render_status"] = render_result["status"]
                                row["blocked_browser_requests"] = int(
                                    render_result.get("blocked_requests", 0) or 0
                                )
                                if render_result.get("error"):
                                    row["render_error"] = str(render_result["error"])
                                    self.telemetry.event("headless_errors")
                                if render_result.get("skipped"):
                                    row["render_skipped"] = str(render_result["skipped"])
                                if rendered_body:
                                    self.telemetry.event("headless_pages_rendered")
                                    classification_body = rendered_body
                                    rendered_ex = extract_html(rendered_url, rendered_body)
                                    for key in ("urls", "forms", "apis", "websockets", "scripts", "js_endpoints", "route_templates"):
                                        for item in rendered_ex.get(key, []):
                                            if item not in ex[key]:
                                                ex[key].append(item)
                                    runtime_requests = []
                                    for event in render_result.get("requests", []):
                                        if not isinstance(event, dict):
                                            continue
                                        raw_url = str(event.get("url") or "")
                                        method = str(event.get("method") or "GET").upper()
                                        if not raw_url or not self._active_scope.allows(raw_url):
                                            continue
                                        runtime_requests.append({
                                            "url": sanitize_url(raw_url),
                                            "method": method,
                                            "resource_type": str(event.get("resource_type") or ""),
                                            "status": event.get("status"),
                                        })
                                        if method == "GET":
                                            ex["urls"].append(raw_url)
                                    if runtime_requests:
                                        row["runtime_requests"] = runtime_requests[:getattr(self.config, "headless_max_events", 500)]
                                    for socket_url in render_result.get("websockets", []):
                                        if self._active_scope.allows(str(socket_url).replace("wss://", "https://", 1).replace("ws://", "http://", 1)):
                                            ex["websockets"].append(sanitize_url(socket_url))
                        if not truncated and "text/html" in ctype:
                            duplicate = self.content_hashes.add(
                                self.content_hashes.main_text(classification_body)
                            )
                        else:
                            duplicate = False
                        clean_path = row["url"].lower().split("?", 1)[0]
                        if "javascript" in ctype or clean_path.endswith((".js", ".mjs")):
                            js = analyze_javascript(row["url"], text)
                            ex["urls"].extend(js["urls"] + js["source_maps"] + js["scripts"])
                            ex["scripts"].extend(js["scripts"])
                            ex["websockets"].extend(js["websockets"])
                            ex["route_templates"].extend(js["route_templates"])
                            self.telemetry.event("js_discoveries", len(js["urls"]))
                            self.telemetry.event("js_module_discoveries", len(js["scripts"]))
                        elif clean_path.endswith(".map"):
                            mapped = analyze_source_map(row["url"], text)
                            ex["urls"].extend(mapped["urls"] + mapped["scripts"])
                            ex["scripts"].extend(mapped["scripts"])
                            ex["websockets"].extend(mapped["websockets"])
                            ex["route_templates"].extend(mapped["route_templates"])
                            row["source_map_sources_analyzed"] = mapped["sources_analyzed"]
                            self.telemetry.event("source_map_js_discoveries", len(mapped["urls"]))
                        if "xml" in ctype or "sitemap" in row["url"].lower():
                            from .sitemaps import parse_sitemap
                            ex["urls"].extend(parse_sitemap(text, row["url"]))
                        if "text/html" in ctype:
                            parsed_url = urlsplit(row["url"])
                            html_origin = (
                                parsed_url.scheme.lower(),
                                (parsed_url.hostname or "").lower().rstrip("."),
                                parsed_url.port or (443 if parsed_url.scheme.lower() == "https" else 80),
                            )
                            async with api_hint_lock:
                                include_common_hints = html_origin not in api_hint_origins
                                api_hint_origins.add(html_origin)
                            ex["urls"].extend(discover_api_urls(
                                row["url"], text, include_common_hints=include_common_hints,
                            ))
                        if retain_forms:
                            self.forms.extend(ex["forms"])
                        row.update({
                            "duplicate": duplicate,
                            "discovered": len(ex["urls"]),
                            "forms_found": len(ex["forms"]),
                            "websockets": ex["websockets"],
                            "js_route_templates": list(dict.fromkeys(
                                sanitize_url(template) for template in ex["route_templates"]
                                if self._active_scope.allows(template)
                            ))[:100],
                            "type": classify(row["url"], ctype, row.get("status"), classification_body, ex["forms"]),
                            "scripts": list(dict.fromkeys(ex["scripts"]))[:100],
                        })
                        if row.get("status") in {301, 302, 303, 307, 308} and row.get("location"):
                            ex["urls"].append(urljoin(row["url"], row["location"]))
                        self.telemetry.event("forms", len(ex["forms"]))
                        self.telemetry.event("websocket_discoveries", len(ex["websockets"]))
                        for nxt in dict.fromkeys(ex["urls"]):
                            await schedule(nxt, depth + 1)
                        await record_row(row, ex["forms"])
                    finally:
                        frontier.task_done()

            tasks = [asyncio.create_task(worker()) for _ in range(workers)]
            try:
                await asyncio.wait_for(frontier.join(), timeout=max(0.01, crawl_deadline - monotonic()))
            except asyncio.TimeoutError:
                self.telemetry.event("crawl_deadline_reached")
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            else:
                await frontier.stop(workers)
                await asyncio.gather(*tasks)

        frontier.close()
        if rows_file:
            rows_file.close()
        if forms_file:
            forms_file.close()
        # Preserve the historical list return shape unless the caller explicitly
        # opts into bounded-memory file streaming.
        for row in results:
            row.setdefault("telemetry", self.telemetry.snapshot())
        return results
