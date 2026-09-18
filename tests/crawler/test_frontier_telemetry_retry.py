import asyncio
from raveneye.crawler.frontier import URLFrontier, normalize_url
from raveneye.crawler.js_analysis import analyze_javascript
from raveneye.crawler.telemetry import CrawlTelemetry

def test_normalize_url_sorts_query_and_removes_fragment():
    assert normalize_url("HTTPS://Example.TEST:443/a?z=2&a=1#section") == "https://example.test/a?a=1&z=2"

def test_frontier_prioritizes_shallow_discovery_resources():
    async def run():
        frontier = URLFrontier(max_depth=2, max_items=10)
        assert await frontier.put("https://example.test/page", 1)
        assert await frontier.put("https://example.test/app.js", 0)
        first = await frontier.get()
        frontier.task_done()
        assert first and first.url.endswith("app.js")
    asyncio.run(run())

def test_static_javascript_analysis_never_executes_source():
    found = analyze_javascript("https://example.test/static/app.js", "fetch('/api/users'); new WebSocket('wss://ws.example.test'); //# sourceMappingURL=app.js.map")
    assert "https://example.test/api/users" in found["urls"]
    assert found["websockets"] == ["wss://ws.example.test"]
    assert found["source_maps"] == ["https://example.test/static/app.js.map"]

def test_telemetry_has_stable_metrics():
    telemetry = CrawlTelemetry(); telemetry.event("requests"); telemetry.response(200, .01, 10)
    assert telemetry.snapshot()["responses"] == 1
