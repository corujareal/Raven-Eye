"""Isolated RavenEye worker used by the local Katana comparison harness."""
from __future__ import annotations

import asyncio
import json
import resource
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from raveneye.core.config import RavenConfig
from raveneye.crawler.engine import Crawler
from raveneye.crawler.filters import Scope
from raveneye.network import session as session_module
from raveneye.network import browser_proxy as browser_proxy_module


def current_rss_kib() -> int:
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)


def main() -> int:
    if len(sys.argv) != 5:
        print("expected origin, output, max_pages, headless_flag", file=sys.stderr)
        return 2
    origin, output_raw, pages_raw, headless_raw = sys.argv[1:]
    pages = max(1, int(pages_raw))
    cfg = RavenConfig(
        max_pages=pages, crawl_max_depth=3, concurrency=20, worker_count=20,
        per_host_concurrency=20, connection_limit=40, requests_per_second=200,
        per_host_requests_per_second=200, queue_size=128, timeout_seconds=4,
        max_runtime_seconds=max(600, int(pages / 20) + 60), adaptive_concurrency=True,
        headless_rendering=headless_raw == "1", headless_max_pages=10,
        headless_wait_ms=250, headless_timeout_ms=5_000,
    )
    original_validate = session_module.validate_url_async
    original_browser_resolve = browser_proxy_module.resolve_public_ips
    port = urlsplit(origin).port

    async def fixture_only_validation(url: str, allowed_domains=None):
        parsed = urlsplit(url)
        if parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port == port:
            return ["127.0.0.1"]
        return await original_validate(url, allowed_domains)

    async def fixture_browser_resolution(host: str, target_port: int):
        if host == "127.0.0.1" and target_port == port:
            return ["127.0.0.1"]
        return await original_browser_resolve(host, target_port)

    session_module.validate_url_async = fixture_only_validation
    browser_proxy_module.resolve_public_ips = fixture_browser_resolution
    crawler = Crawler(cfg, scope=Scope(domains={"127.0.0.1"}))
    # The parent uses this point to establish an initialized-process RSS baseline.
    print(json.dumps({"ready": True, "rss_kib": current_rss_kib()}), flush=True)
    started = time.perf_counter()
    asyncio.run(crawler.crawl(
        [origin + "/"], output_raw, retain_results=False, retain_forms=False,
    ))
    elapsed = time.perf_counter() - started
    print(json.dumps({
        "elapsed_seconds": elapsed,
        "rss_peak_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "frontier_peak_capacity": crawler.frontier.peak_in_memory if crawler.frontier else 0,
        "queue_ram_limit": cfg.queue_size,
        "telemetry": crawler.telemetry.snapshot(),
    }), flush=True)
    session_module.validate_url_async = original_validate
    browser_proxy_module.resolve_public_ips = original_browser_resolve
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
