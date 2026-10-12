"""Bounded in-memory URL frontier with a temporary SQLite overflow spool."""
from __future__ import annotations

import asyncio
import os
import sqlite3
import sys
import tempfile
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit


def normalize_url(url: str) -> str:
    """Canonicalize only URL parts that are safe to treat as equivalent."""
    try:
        p = urlsplit(url)
        scheme = p.scheme.lower()
        host = (p.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
        if not scheme or not host or p.username is not None or p.password is not None:
            return url
        port = p.port
        authority_host = f"[{host}]" if ":" in host else host
        authority = authority_host if port is None or (scheme, port) in {("http", 80), ("https", 443)} else f"{authority_host}:{port}"
        path = p.path or "/"
        # Query is application data: parameter order, duplicate-key order, and
        # encoding can affect server behavior. Preserve it verbatim so
        # deduplication cannot silently drop a distinct route.
        return urlunsplit((scheme, authority, path, p.query, ""))
    except (UnicodeError, ValueError):
        return url


@dataclass(order=True, slots=True)
class FrontierItem:
    priority: tuple[int, int, int]
    sequence: int
    url: str = field(compare=False)
    depth: int = field(compare=False)
    stop: bool = field(default=False, compare=False)


class URLFrontier:
    """Priority queue with a fixed RAM ceiling and disk-backed deduplication.

    Only queued work occupies RAM. Excess accepted URLs are sorted in a
    per-crawl SQLite database and promoted as workers make queue space.
    """
    def __init__(self, *, max_depth: int, max_items: int, queue_size: int = 512):
        self.max_depth = max_depth
        self.max_items = max(0, max_items)
        self.queue_size = max(1, queue_size)
        self._queue: asyncio.PriorityQueue[FrontierItem] = asyncio.PriorityQueue(maxsize=self.queue_size)
        fd, self._db_path = tempfile.mkstemp(prefix="raveneye-frontier-", suffix=".sqlite3")
        os.close(fd)
        self._db = sqlite3.connect(self._db_path)
        self._db.execute("PRAGMA journal_mode=OFF")
        self._db.execute("PRAGMA synchronous=OFF")
        self._db.execute("CREATE TABLE seen (canonical TEXT PRIMARY KEY)")
        self._db.execute("""CREATE TABLE overflow (
            p0 INTEGER NOT NULL, p1 INTEGER NOT NULL, p2 INTEGER NOT NULL,
            sequence INTEGER NOT NULL, url TEXT NOT NULL, depth INTEGER NOT NULL
        )""")
        self._db.execute("CREATE INDEX overflow_priority ON overflow(p0,p1,p2,sequence)")
        self._db.commit()
        self._sequence = 0
        self._count = 0
        self._peak_in_memory = 0
        self._mutations_since_commit = 0
        self._lock = asyncio.Lock()
        self._closed = False

    def _commit_if_needed(self, *, force: bool = False) -> None:
        self._mutations_since_commit += 1
        if force or self._mutations_since_commit >= 128:
            self._db.commit()
            self._mutations_since_commit = 0

    def _observe_queue_peak(self) -> None:
        self._peak_in_memory = max(self._peak_in_memory, self._queue.qsize())

    @staticmethod
    def _priority(url: str, depth: int) -> tuple[int, int, int]:
        lower = url.lower()
        discovery_rank = 0 if any(x in lower for x in (".js", "api", "graphql", "openapi", "swagger", "sitemap", "robots")) else 1
        parameter_rank = 1 if "?" in url else 0
        return (depth, discovery_rank, parameter_rank)

    async def put(self, url: str, depth: int) -> bool:
        canonical = normalize_url(url)
        if depth > self.max_depth or self._count >= self.max_items or self._closed:
            return False
        async with self._lock:
            if self._count >= self.max_items:
                return False
            try:
                self._db.execute("INSERT INTO seen(canonical) VALUES (?)", (canonical,))
            except sqlite3.IntegrityError:
                return False
            self._sequence += 1
            self._count += 1
            item = FrontierItem(self._priority(canonical, depth), self._sequence, canonical, depth)
            try:
                self._queue.put_nowait(item)
                self._observe_queue_peak()
            except asyncio.QueueFull:
                p0, p1, p2 = item.priority
                self._db.execute(
                    "INSERT INTO overflow(p0,p1,p2,sequence,url,depth) VALUES (?,?,?,?,?,?)",
                    (p0, p1, p2, item.sequence, item.url, item.depth),
                )
            self._commit_if_needed()
            return True

    async def get(self) -> FrontierItem:
        item = await self._queue.get()
        async with self._lock:
            row = self._db.execute(
                "SELECT p0,p1,p2,sequence,url,depth FROM overflow ORDER BY p0,p1,p2,sequence LIMIT 1"
            ).fetchone()
            if row and not self._queue.full():
                self._db.execute(
                    "DELETE FROM overflow WHERE sequence = ?", (row[3],)
                )
                self._queue.put_nowait(FrontierItem((row[0], row[1], row[2]), row[3], row[4], row[5]))
                self._observe_queue_peak()
                self._commit_if_needed()
        return item

    async def stop(self, workers: int) -> None:
        for _ in range(workers):
            await self._queue.put(FrontierItem((sys.maxsize, sys.maxsize, sys.maxsize), sys.maxsize, "", -1, True))

    def task_done(self) -> None:
        self._queue.task_done()

    async def join(self) -> None:
        await self._queue.join()

    @property
    def seen_count(self) -> int:
        return self._count

    @property
    def queued_in_memory(self) -> int:
        return self._queue.qsize()

    @property
    def peak_in_memory(self) -> int:
        return self._peak_in_memory

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._db.commit()
        self._db.close()
        try:
            os.unlink(self._db_path)
        except FileNotFoundError:
            pass

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
