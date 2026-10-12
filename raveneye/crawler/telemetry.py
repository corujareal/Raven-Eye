"""Bounded crawl telemetry with a reservoir sample of response latency."""
from __future__ import annotations

import random
from bisect import bisect_left, insort
from collections import Counter
from time import monotonic


class CrawlTelemetry:
    def __init__(self, latency_sample_size: int = 2048):
        self.started = monotonic()
        self.counts: Counter[str] = Counter()
        self.latencies: list[float] = []
        self._sorted_latencies: list[float] = []
        self._latency_sum = 0.0
        self.latency_sample_size = max(1, latency_sample_size)
        self._latency_seen = 0

    def event(self, name: str, count: int = 1) -> None:
        self.counts[name] += count

    def response(self, status: int | None, latency: float, size: int = 0) -> None:
        self.event("responses")
        self.event("bytes", size)
        self._latency_seen += 1
        if len(self.latencies) < self.latency_sample_size:
            sample = max(0.0, latency)
            self.latencies.append(sample)
            insort(self._sorted_latencies, sample)
            self._latency_sum += sample
        else:
            slot = random.randrange(self._latency_seen)
            if slot < self.latency_sample_size:
                old = self.latencies[slot]
                self._sorted_latencies.pop(bisect_left(self._sorted_latencies, old))
                self._latency_sum -= old
                sample = max(0.0, latency)
                self.latencies[slot] = sample
                insort(self._sorted_latencies, sample)
                self._latency_sum += sample
        if status:
            self.event(f"http_{status}")
        if status == 429:
            self.event("rate_limited")
        if status and status >= 500:
            self.event("server_errors")

    def snapshot(self) -> dict:
        elapsed = max(monotonic() - self.started, 0.000001)
        n = len(self._sorted_latencies)
        median = (self._sorted_latencies[(n - 1) // 2] + self._sorted_latencies[n // 2]) / 2 if n else 0.0
        p95 = self._sorted_latencies[min(n - 1, int(0.95 * n))] if n else 0.0
        return {
            **dict(self.counts),
            "elapsed_seconds": round(elapsed, 4),
            "requests_per_second": round(self.counts["requests"] / elapsed, 3),
            "latency_samples": n,
            "latency_sample_capacity": self.latency_sample_size,
            "average_latency_ms": round((self._latency_sum / n * 1000) if n else 0, 2),
            "median_latency_ms": round(median * 1000, 2),
            "p95_latency_ms": round(p95 * 1000, 2),
        }
