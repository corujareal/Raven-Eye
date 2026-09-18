"""Bounded, normalized URL frontier used by the crawler scheduler."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def normalize_url(url: str) -> str:
    """Return a stable HTTP URL suitable for duplicate suppression.

    Fragments never affect an HTTP resource. Query keys are sorted but repeated
    values are retained, avoiding the false positives caused by dropping params.
    """
    p = urlsplit(url)
    scheme = p.scheme.lower()
    host = (p.hostname or "").lower().rstrip(".")
    if not scheme or not host:
        return url
    port = p.port
    authority = host if port is None or (scheme, port) in {("http", 80), ("https", 443)} else f"{host}:{port}"
    path = p.path or "/"
    query = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)), doseq=True)
    return urlunsplit((scheme, authority, path, query, ""))


@dataclass(order=True, slots=True)
class FrontierItem:
    priority: tuple[int, int, int]
    sequence: int
    url: str = field(compare=False)
    depth: int = field(compare=False)


class URLFrontier:
    """Priority frontier with canonical deduplication and depth bounds."""
    def __init__(self, *, max_depth: int, max_items: int):
        self.max_depth, self.max_items = max_depth, max_items
        self._queue: asyncio.PriorityQueue[FrontierItem | None] = asyncio.PriorityQueue()
        self._seen: set[str] = set()
        self._sequence = 0

    @staticmethod
    def _priority(url: str, depth: int) -> tuple[int, int, int]:
        lower = url.lower()
        # High-discovery resources first; depth remains the stable main bound.
        discovery_rank = 0 if any(x in lower for x in (".js", "api", "graphql", "openapi", "swagger", "sitemap", "robots")) else 1
        parameter_rank = 1 if "?" in url else 0
        return (depth, discovery_rank, parameter_rank)

    async def put(self, url: str, depth: int) -> bool:
        canonical = normalize_url(url)
        if depth > self.max_depth or len(self._seen) >= self.max_items or canonical in self._seen:
            return False
        self._seen.add(canonical)
        self._sequence += 1
        await self._queue.put(FrontierItem(self._priority(canonical, depth), self._sequence, canonical, depth))
        return True

    async def get(self) -> FrontierItem | None:
        return await self._queue.get()

    async def stop(self, workers: int) -> None:
        for _ in range(workers):
            await self._queue.put(None)

    def task_done(self) -> None:
        self._queue.task_done()

    async def join(self) -> None:
        await self._queue.join()

    @property
    def seen_count(self) -> int:
        return len(self._seen)
