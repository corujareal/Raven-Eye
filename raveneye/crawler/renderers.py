from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ..core.browser import launch_chromium_async
from ..network.browser_proxy import SafeSocksProxy


_SPA_MARKERS = (
    'id="root"', "id='root'",
    'id="__next"', "id='__next'", 'id="__nuxt"', "id='__nuxt'",
    "<app-root", "data-reactroot", "ng-version=", "__next_data__",
)


def looks_like_spa(html: str) -> bool:
    """Return true for strong shell markers; vendor names alone are too noisy."""
    if not isinstance(html, str) or len(html) >= 200_000:
        return False
    body = html.lower()
    if any(marker in body for marker in _SPA_MARKERS):
        return True
    # `id="app"` is common in both SPAs and server-rendered pages. Treat it as
    # a shell only when little visible text exists, avoiding needless browsers
    # for ordinary pages that happen to use that generic container name.
    if 'id="app"' not in body and "id='app'" not in body:
        return False
    without_code = re.sub(r"<(script|style)\b[^>]*>.*?</\1\s*>", " ", body,
                          flags=re.IGNORECASE | re.DOTALL)
    visible_text = re.sub(r"<[^>]+>", " ", without_code)
    return len(" ".join(visible_text.split())) <= 160


def _scope_url(url: str) -> str:
    parsed = urlsplit(url)
    scheme = {"ws": "http", "wss": "https"}.get(parsed.scheme.lower(), parsed.scheme.lower())
    return urlunsplit((scheme, parsed.netloc, parsed.path, parsed.query, ""))


def _render_method_is_safe(method: str) -> bool:
    """Only allow methods that cannot normally mutate target state."""
    return str(method).upper() in {"GET", "HEAD"}


class ScopedPlaywrightRenderer:
    """Render SPA shells in a bounded browser with host and URL scope guards.

    The SOCKS proxy resolves and pins public IPs. Browser routing enforces path,
    regex, and exclusion rules before requests leave the browser. Service workers
    are blocked so they cannot bypass the route handler. WebSockets are observed
    but mocked; no messages are sent to a remote WebSocket server.
    """

    def __init__(
        self,
        scope,
        *,
        user_agent: str = "RavenEye/6.6.6",
        timeout_ms: int = 5_000,
        wait_ms: int = 750,
        max_pages: int = 50,
        max_events: int = 500,
        concurrency: int = 2,
    ):
        self.scope = scope
        self.user_agent = str(user_agent)
        self.timeout_ms = min(30_000, max(1_000, int(timeout_ms)))
        self.wait_ms = min(5_000, max(0, int(wait_ms)))
        self.max_pages = min(1_000, max(1, int(max_pages)))
        self.max_events = min(5_000, max(10, int(max_events)))
        self.proxy = SafeSocksProxy(
            set(getattr(scope, "domains", None) or ()),
            exact_hosts=set(getattr(scope, "exact_hosts", set())),
        )
        self._playwright = None
        self._browser = None
        self._startup_error: str | None = None
        self._start_lock = asyncio.Lock()
        self._render_slots = asyncio.Semaphore(max(1, min(8, int(concurrency))))
        self._rendered_pages = 0
        self._blocked_requests = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        await self.close()

    def _allows(self, url: str) -> bool:
        try:
            parsed = urlsplit(url)
            scheme = parsed.scheme.lower()
            if scheme in {"data", "blob", "about"}:
                return True
            if scheme not in {"http", "https", "ws", "wss"}:
                return False
            return self.proxy.allows_url(url) and bool(self.scope.allows(_scope_url(url)))
        except (TypeError, ValueError, UnicodeError):
            return False

    async def _ensure_browser(self) -> None:
        if self._browser is not None:
            return
        if self._startup_error:
            raise RuntimeError(self._startup_error)
        async with self._start_lock:
            if self._browser is not None:
                return
            if self._startup_error:
                raise RuntimeError(self._startup_error)
            try:
                from playwright.async_api import async_playwright
            except ImportError as exc:
                self._startup_error = "Playwright ausente"
                raise RuntimeError(
                    "Playwright ausente; instale o runtime completo com installer/install.sh."
                ) from exc

            try:
                self.proxy.start()
                self._playwright = await async_playwright().start()
                self._browser = await launch_chromium_async(
                    self._playwright.chromium,
                    headless=True,
                    chromium_sandbox=True,
                    proxy={"server": self.proxy.url, "bypass": ""},
                    args=["--proxy-bypass-list=<-loopback>", "--disable-background-networking",
                          "--disable-component-update", "--disable-sync", "--no-first-run"],
                )
            except Exception as exc:
                reason = " ".join(str(exc).split())[:500]
                self._startup_error = f"Playwright indisponível ({type(exc).__name__}): {reason}"
                await self.close()
                raise RuntimeError(
                    f"Playwright não iniciou com sandbox e proxy seguros ({type(exc).__name__}): {reason}"
                ) from None

    async def close(self) -> None:
        browser, playwright = self._browser, self._playwright
        self._browser = self._playwright = None
        if browser is not None:
            try:
                await browser.close()
            except Exception:
                pass
        if playwright is not None:
            try:
                await playwright.stop()
            except Exception:
                pass
        self.proxy.close()

    async def render(self, url: str) -> dict[str, Any]:
        if not self._allows(url):
            return {"url": url, "body": "", "requests": [], "websockets": [],
                    "error": "out_of_scope"}
        async with self._render_slots:
            if self._rendered_pages >= self.max_pages:
                return {"url": url, "body": "", "requests": [], "websockets": [],
                        "skipped": "headless_page_limit"}
            self._rendered_pages += 1
            await self._ensure_browser()
            return await self._render_page(url)

    async def _render_page(self, url: str) -> dict[str, Any]:
        context = await self._browser.new_context(
            user_agent=self.user_agent,
            service_workers="block",
        )
        requests: list[dict[str, Any]] = []
        websockets: list[str] = []
        request_records: dict[int, dict[str, Any]] = {}
        response = None
        page = None
        blocked_before = self._blocked_requests

        async def route_request(route) -> None:
            request = route.request
            method = str(request.method).upper()
            if not self._allows(request.url):
                self._blocked_requests += 1
                await route.abort("blockedbyclient")
                return
            # Rendering observes application JavaScript but never sends its
            # state-changing HTTP requests to the target.
            if not _render_method_is_safe(method):
                self._blocked_requests += 1
                await route.abort("blockedbyclient")
                return
            if getattr(request, "resource_type", "") in {"image", "media", "font"}:
                await route.abort("blockedbyclient")
                return
            await route.continue_()

        async def route_websocket(websocket) -> None:
            ws_url = str(websocket.url)
            if self._allows(ws_url):
                if len(websockets) < self.max_events and ws_url not in websockets:
                    websockets.append(ws_url)
                # Do not call connect_to_server(): the page gets a local stub,
                # so its messages cannot cause remote side effects.
            else:
                self._blocked_requests += 1
                await websocket.close(code=1008, reason="Out of scope")

        def record_request(request) -> None:
            resource = str(getattr(request, "resource_type", "")).lower()
            if resource not in {"xhr", "fetch"} or not self._allows(request.url):
                return
            if len(requests) >= self.max_events:
                return
            item = {
                "url": str(request.url),
                "method": str(request.method).upper(),
                "resource_type": resource,
                "status": None,
            }
            requests.append(item)
            request_records[id(request)] = item

        def record_response(result) -> None:
            request = result.request
            item = request_records.get(id(request))
            if item is not None:
                item["status"] = int(result.status)

        try:
            await context.route("**/*", route_request)
            # Added in Playwright 1.48; the project dependency floor is kept in
            # sync so WebSocket paths can be scoped and connections mocked.
            if not callable(getattr(context, "route_web_socket", None)):
                raise RuntimeError("Playwright 1.48+ é necessário para escopar WebSockets.")
            await context.route_web_socket("**/*", route_websocket)
            context.on("request", record_request)
            context.on("response", record_response)
            page = await context.new_page()
            response = await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            if self.wait_ms:
                await page.wait_for_timeout(self.wait_ms)
            body = await page.content()
            final_url = str(page.url)
        except Exception as exc:
            try:
                body = await page.content() if page is not None else ""
                final_url = str(page.url) if page is not None else url
            except Exception:
                body, final_url = "", url
            error = type(exc).__name__
        else:
            error = None
        finally:
            await asyncio.shield(context.close())

        return {
            "url": final_url,
            "status": int(response.status) if response is not None else None,
            "content_type": "text/html",
            "body": body,
            "requests": requests,
            "websockets": websockets,
            "blocked_requests": self._blocked_requests - blocked_before,
            **({"error": error} if error else {}),
        }


async def render(url: str, *, timeout_ms: int = 5_000,
                 wait_until: str = "domcontentloaded") -> dict[str, Any]:
    """Compatibility helper retained for existing direct renderer callers."""
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Playwright ausente; instale o runtime completo com installer/install.sh."
        ) from exc
    async with async_playwright() as pw:
        browser = await launch_chromium_async(pw.chromium, headless=True)
        try:
            page = await browser.new_page()
            await page.goto(url, wait_until=wait_until, timeout=timeout_ms)
            return {"url": page.url, "status": None,
                    "content_type": "text/html", "body": await page.content()}
        finally:
            await browser.close()
