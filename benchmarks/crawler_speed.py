"""Small reproducible crawler benchmark harness.

Usage: python benchmarks/crawler_speed.py https://example.com --pages 100
It measures completed GET discoveries, not application throughput.
"""
from __future__ import annotations
import argparse, asyncio, time
from pathlib import Path
from raveneye.core.config import RavenConfig
from raveneye.crawler.engine import Crawler
from raveneye.crawler.filters import Scope

async def main(target: str, pages: int) -> None:
    cfg = RavenConfig(max_pages=pages)
    started = time.perf_counter()
    rows = await Crawler(cfg, scope=Scope()).crawl([target])
    elapsed = max(time.perf_counter() - started, 1e-9)
    ok = sum(1 for r in rows if not r.get('error'))
    print(f"pages={len(rows)} successful={ok} elapsed={elapsed:.3f}s req_per_sec={len(rows)/elapsed:.2f}")

if __name__ == '__main__':
    p=argparse.ArgumentParser()
    p.add_argument('target')
    p.add_argument('--pages', type=int, default=100)
    a=p.parse_args()
    asyncio.run(main(a.target, a.pages))
