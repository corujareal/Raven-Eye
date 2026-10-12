from __future__ import annotations
import asyncio, time

class TokenBucket:
    def __init__(self, rate: float = 10.0, capacity: float | None = None):
        if rate <= 0: raise ValueError('rate must be > 0')
        self.rate = float(rate); self.capacity = float(capacity or max(1.0, rate)); self.tokens = self.capacity; self.updated = time.monotonic(); self._lock = asyncio.Lock()
    async def acquire(self, tokens: float = 1.0):
        while True:
            async with self._lock:
                now=time.monotonic(); self.tokens=min(self.capacity, self.tokens+(now-self.updated)*self.rate); self.updated=now
                if self.tokens >= tokens:
                    self.tokens -= tokens; return
                wait=(tokens-self.tokens)/self.rate
            await asyncio.sleep(wait)
