from __future__ import annotations
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

@dataclass(slots=True)
class Event:
    topic: str
    data: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class EventBus:
    def __init__(self, maxsize: int = 10000):
        self.queue: asyncio.PriorityQueue[tuple[int,int,Event]] = asyncio.PriorityQueue(maxsize=maxsize)
        self._sequence = 0
        self._subscribers: dict[str,list[Callable[[Event], Awaitable[None] | None]]] = {}
    def subscribe(self, topic: str, callback: Callable[[Event], Awaitable[None] | None]) -> None:
        self._subscribers.setdefault(topic, []).append(callback)
    async def publish(self, event: Event, priority: int = 50) -> None:
        self._sequence += 1
        await self.queue.put((priority, self._sequence, event))
    async def next(self) -> Event:
        return (await self.queue.get())[2]
    async def dispatch_one(self) -> Event:
        event = await self.next()
        for cb in self._subscribers.get(event.topic, ()):
            result = cb(event)
            if asyncio.iscoroutine(result): await result
        for cb in self._subscribers.get('*', ()):
            result = cb(event)
            if asyncio.iscoroutine(result): await result
        return event
