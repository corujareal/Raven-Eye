from __future__ import annotations

import asyncio
import hashlib
import time
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
        per_host_limit: int = 4,
        concurrency: int = 50,
        adaptive_concurrency: bool = True,
        per_host_requests_per_second: float = 4.0,
    ):
        self.allowed_domains = allowed_domains or set()
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.verify_tls = verify_tls
        self.connector_limit = connector_limit
        self.per_host_limit = max(1, per_host_limit)
        self.user_agent = user_agent
        self.requests_per_second = requests_per_second
        self.bucket = TokenBucket(requests_per_second)
        # Fixed stripes bound limiter state even when an explicitly scoped crawl
        # encounters many subdomains. Hash collisions only reduce throughput.
        self._host_buckets = [TokenBucket(max(0.1, per_host_requests_per_second)) for _ in range(256)]
        self._host_cooldowns = [0.0] * 256
        self._host_cooldown_locks = [asyncio.Lock() for _ in range(256)]
        self._adaptive = adaptive_concurrency
        self._max_concurrency = max(1, concurrency)
        self._current_concurrency = self._max_concurrency
        self._inflight_requests = 0
        self._successful_streak = 0
        self._concurrency_condition = asyncio.Condition()
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
                limit_per_host=self.per_host_limit,
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

    @staticmethod
    def _host_index(host: str) -> int:
        return int.from_bytes(hashlib.blake2s(host.encode(), digest_size=2).digest(), "big") % 256

    async def wait_host(self, host: str) -> None:
        index = self._host_index(host.lower().rstrip('.'))
        while True:
            async with self._host_cooldown_locks[index]:
                delay = self._host_cooldowns[index] - time.monotonic()
            if delay <= 0:
                return
            await asyncio.sleep(delay)

    async def defer_host(self, host: str, seconds: float) -> None:
        index = self._host_index(host.lower().rstrip('.'))
        async with self._host_cooldown_locks[index]:
            self._host_cooldowns[index] = max(self._host_cooldowns[index], time.monotonic() + max(0.0, seconds))

    async def observe_status(self, status: int) -> None:
        if not self._adaptive:
            return
        async with self._concurrency_condition:
            if status in {429, 503}:
                self._current_concurrency = max(1, self._current_concurrency // 2)
                self._successful_streak = 0
            elif 200 <= status < 400:
                self._successful_streak += 1
                if self._successful_streak >= 20:
                    self._current_concurrency = min(self._max_concurrency, self._current_concurrency + 1)
                    self._successful_streak = 0
            self._concurrency_condition.notify_all()

    async def request(self, method: str, url: str, **kwargs):
        if self.scope_guard:
            self.scope_guard.check(url)
        host = (urlsplit(url).hostname or '').lower().rstrip('.')
        validated_ips = await validate_url_async(url, self.allowed_domains or None)
        await self.wait_host(host)
        await self.bucket.acquire()
        index = self._host_index(host)
        await self._host_buckets[index].acquire()
        await self._ensure_session()
        assert self._resolver is not None
        self._resolver.pin(host, validated_ips)
        async with self._concurrency_condition:
            await self._concurrency_condition.wait_for(lambda: self._inflight_requests < self._current_concurrency)
            self._inflight_requests += 1
        try:
            return await self.session.request(method, url, **kwargs)
        finally:
            async with self._concurrency_condition:
                self._inflight_requests = max(0, self._inflight_requests - 1)
                self._concurrency_condition.notify_all()
