from __future__ import annotations

from urllib.parse import urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver
from aiohttp.resolver import DefaultResolver

from .ssrf_guard import validate_url_async
from .scope_guard import ScopeGuard
from ..core.rate_limit import TokenBucket


class _PinnedResolver(AbstractResolver):
    """Resolve only to addresses already validated by SSRF protection.

    Pins are refreshed per request after the URL passes the SSRF guard. The
    resolver remains attached to the session, so every hostname used by the
    same async scan gets its own validated address set.
    """

    def __init__(self, fallback: AbstractResolver):
        self._validated: dict[str, list[str]] = {}
        self._fallback = fallback

    def pin(self, host: str, ips: list[str]) -> None:
        self._validated[host.lower().rstrip('.')] = list(dict.fromkeys(ips))

    async def resolve(self, host, port=0, family=0):
        key = host.lower().rstrip('.')
        ips = self._validated.get(key)
        if not ips:
            raise RuntimeError(f"Host não validado pelo SSRF guard: {host}")
        return [
            {
                "hostname": host,
                "host": ip,
                "port": port,
                "family": family or 0,
                "proto": 0,
                "flags": 0,
            }
            for ip in ips
        ]

    async def close(self):
        await self._fallback.close()


class AsyncSession:
    """Async HTTP session with scope/SSRF/rate-limit enforcement.

    DNS addresses are validated before each request and pinned into the
    connector resolver, reducing DNS-rebinding exposure between validation and
    the actual connection.
    """

    def __init__(
        self,
        *,
        user_agent: str,
        timeout: float,
        verify_tls: bool = True,
        allowed_domains: set[str] | None = None,
        requests_per_second: float = 10.0,
        scope_guard: ScopeGuard | None = None,
        connector_limit: int = 200,
    ):
        self.allowed_domains = allowed_domains or set()
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.verify_tls = verify_tls
        self.connector_limit = connector_limit
        self.user_agent = user_agent
        self.bucket = TokenBucket(requests_per_second)
        self.scope_guard = scope_guard
        self.session: aiohttp.ClientSession | None = None
        self._resolver: _PinnedResolver | None = None

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self._resolver = _PinnedResolver(DefaultResolver())
            connector = aiohttp.TCPConnector(
                ssl=self.verify_tls,
                ttl_dns_cache=0,
                limit=self.connector_limit,
                resolver=self._resolver,
            )
            self.session = aiohttp.ClientSession(
                timeout=self.timeout,
                connector=connector,
                headers={'User-Agent': self.user_agent},
            )
        return self.session

    async def __aenter__(self):
        await self._ensure_session()
        return self

    async def __aexit__(self, *exc):
        await self.close()

    async def close(self):
        if self.session is not None and not self.session.closed:
            await self.session.close()
        self._resolver = None

    async def request(self, method: str, url: str, **kwargs):
        if self.scope_guard:
            self.scope_guard.check(url)
        host = (urlsplit(url).hostname or '').lower().rstrip('.')
        validated_ips = await validate_url_async(url, self.allowed_domains or None)
        await self.bucket.acquire()
        await self._ensure_session()
        assert self._resolver is not None
        self._resolver.pin(host, validated_ips)
        return await self.session.request(method, url, **kwargs)
