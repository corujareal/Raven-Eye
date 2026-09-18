"""Conservative retry policy for idempotent crawler requests."""
from __future__ import annotations
import asyncio, random

RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}

async def request_with_retry(session, url: str, *, attempts: int, backoff: float):
    """Issue GET with exponential backoff; never retries non-idempotent work."""
    for attempt in range(attempts + 1):
        try:
            response = await session.request("GET", url, allow_redirects=False)
            if response.status not in RETRYABLE_STATUS or attempt >= attempts:
                return response, attempt
            response.release()
        except (asyncio.TimeoutError, OSError):
            if attempt >= attempts:
                raise
        await asyncio.sleep(backoff * (2 ** attempt) + random.uniform(0, max(backoff, 0.001)))
    raise RuntimeError("retry loop exhausted")
