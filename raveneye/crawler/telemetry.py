"""Small dependency-free crawl telemetry collector."""
from __future__ import annotations
from collections import Counter
from time import monotonic

class CrawlTelemetry:
    def __init__(self):
        self.started = monotonic(); self.counts: Counter[str] = Counter(); self.latencies: list[float] = []
    def event(self, name: str, count: int = 1) -> None: self.counts[name] += count
    def response(self, status: int | None, latency: float, size: int = 0) -> None:
        self.event("responses"); self.event("bytes", size); self.latencies.append(latency)
        if status: self.event(f"http_{status}")
        if status == 429: self.event("rate_limited")
        if status and status >= 500: self.event("server_errors")
    def snapshot(self) -> dict:
        elapsed = max(monotonic() - self.started, 0.000001)
        return {**dict(self.counts), "elapsed_seconds": round(elapsed, 4), "requests_per_second": round(self.counts["requests"] / elapsed, 3), "average_latency_ms": round((sum(self.latencies) / len(self.latencies) * 1000) if self.latencies else 0, 2)}
