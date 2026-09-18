from __future__ import annotations

"""Cliente HTTP assíncrono para os módulos novos do RavenEye.

Mantém escopo, SSRF, timeout e limite de resposta antes de qualquer request.
"""
import asyncio
from dataclasses import dataclass
from urllib.parse import urlparse
import aiohttp
from raveneye_pkg.network import is_safe_url

@dataclass(slots=True)
class AsyncResponse:
    status: int
    url: str
    headers: dict[str, str]
    text: str
    elapsed: float

class AsyncHttpClient:
    def __init__(self, *, scope_host: str, timeout: float = 30, concurrency: int = 20, max_bytes: int = 2_000_000):
        self.scope_host = scope_host.lower()
        self.timeout = min(30.0, max(1.0, float(timeout)))
        self.max_bytes = max(1024, int(max_bytes))
        self._sem = asyncio.Semaphore(max(1, int(concurrency)))
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout), raise_for_status=False)
        return self

    async def __aexit__(self, *exc):
        if self._session:
            await self._session.close()
            self._session = None

    def _allowed(self, url: str) -> bool:
        try:
            p = urlparse(url)
            host = (p.hostname or "").lower().rstrip(".")
            scope = self.scope_host.lower().rstrip(".")
            # Exact host or a real subdomain; never accept a suffix collision
            # such as evil-example.com for example.com.
            in_scope = host == scope or host.endswith("." + scope)
            return p.scheme in {"http", "https"} and bool(host) and in_scope and is_safe_url(url)
        except Exception:
            return False

    async def get(self, url: str, *, headers: dict[str, str] | None = None) -> AsyncResponse | None:
        if not self._allowed(url) or self._session is None:
            return None
        async with self._sem:
            loop = asyncio.get_running_loop()
            started = loop.time()
            try:
                async with self._session.get(url, headers=headers, allow_redirects=False) as r:
                    raw = await r.content.read(self.max_bytes + 1)
                    text = raw[:self.max_bytes].decode(r.charset or "utf-8", "replace")
                    return AsyncResponse(r.status, str(r.url), dict(r.headers), text, loop.time()-started)
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return None
