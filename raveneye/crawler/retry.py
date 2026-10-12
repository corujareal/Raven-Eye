"""Conservative retry policy for idempotent crawler requests."""
from __future__ import annotations

import asyncio
import random
import time
from datetime import timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit


# A generic 500 response may contain a useful, crawlable error page and does
# not by itself signal temporary unavailability. Keep the body on the first
# response; explicit throttling/temporary gateway statuses remain retryable.
RETRYABLE_STATUS = {408, 425, 429, 502, 503, 504}
MAX_LOCAL_BACKOFF = 30.0


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(int(value.strip())))
    except (TypeError, ValueError):
        try:
            parsed = parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return max(0.0, parsed.timestamp() - time.time())
        except (TypeError, ValueError, OverflowError):
            return None


async def request_with_retry(session, url: str, *, attempts: int, backoff: float,
                             deadline: float | None = None):
    """Retry only GET; Retry-After is a minimum and is shared per host."""
    host = urlsplit(url).hostname or ""
    retries = max(0, attempts)
    for attempt in range(retries + 1):
        try:
            response = await session.request("GET", url, allow_redirects=False)
        except (asyncio.TimeoutError, OSError):
            if attempt >= retries:
                raise
            local_cap = min(MAX_LOCAL_BACKOFF, max(0.0, backoff) * (2 ** attempt))
            delay = random.uniform(0.0, local_cap) if local_cap else 0.0
            if deadline is not None and time.monotonic() + delay >= deadline:
                raise
            await asyncio.sleep(delay)
            continue

        if hasattr(session, "observe_status"):
            await session.observe_status(response.status)
        if response.status not in RETRYABLE_STATUS or attempt >= retries:
            return response, attempt

        retry_after = _retry_after_seconds(response.headers.get("Retry-After"))
        local_cap = min(MAX_LOCAL_BACKOFF, max(0.0, backoff) * (2 ** attempt))
        jitter = random.uniform(0.0, local_cap) if local_cap else 0.0
        delay = max(retry_after or 0.0, jitter)
        if deadline is not None and time.monotonic() + delay >= deadline:
            # Return the throttling response with metadata instead of retrying early.
            response._raveneye_retry_deferred = True
            response._raveneye_retry_after = retry_after
            return response, attempt

        response.release()
        if retry_after is not None and hasattr(session, "defer_host"):
            await session.defer_host(host, delay)
        if hasattr(session, "wait_host"):
            await session.wait_host(host)
        elif delay:
            await asyncio.sleep(delay)
        if retry_after is None and jitter:
            await asyncio.sleep(jitter)
    raise RuntimeError("retry loop exhausted")
