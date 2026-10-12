import asyncio
from datetime import datetime, timezone
from email.utils import format_datetime
from raveneye.crawler.frontier import URLFrontier, normalize_url
from raveneye.crawler.js_analysis import analyze_javascript
from raveneye.crawler.telemetry import CrawlTelemetry
from raveneye.crawler import retry as retry_module

def test_normalize_url_preserves_query_order_and_removes_fragment():
    assert normalize_url("HTTPS://Example.TEST:443/a?z=2&a=1#section") == "https://example.test/a?z=2&a=1"
    assert normalize_url("https://example.test/a?b=2&a=1") != normalize_url("https://example.test/a?a=1&b=2")


def test_normalize_url_preserves_order_of_repeated_query_parameters():
    assert normalize_url("https://example.test/a?tag=red&tag=blue") != normalize_url(
        "https://example.test/a?tag=blue&tag=red"
    )


def test_frontier_keeps_query_order_variants_as_distinct_routes():
    async def run():
        frontier = URLFrontier(max_depth=2, max_items=10)
        assert await frontier.put("https://example.test/a?b=2&a=1", 1)
        assert await frontier.put("https://example.test/a?a=1&b=2", 1)
        assert frontier.seen_count == 2
        frontier.close()
    asyncio.run(run())

def test_frontier_prioritizes_shallow_discovery_resources():
    async def run():
        frontier = URLFrontier(max_depth=2, max_items=10)
        assert await frontier.put("https://example.test/page", 1)
        assert await frontier.put("https://example.test/app.js", 0)
        first = await frontier.get()
        frontier.task_done()
        assert first and first.url.endswith("app.js")
    asyncio.run(run())

def test_frontier_bounds_ram_spills_to_sqlite_and_cleans_up():
    async def run():
        frontier = URLFrontier(max_depth=2, max_items=10, queue_size=1)
        db_path = frontier._db_path
        for index in range(10):
            assert await frontier.put(f"https://example.test/page/{index}", 1)
        assert frontier.queued_in_memory <= 1
        assert frontier.peak_in_memory <= 1
        for _ in range(10):
            item = await frontier.get()
            assert item is not None
            frontier.task_done()
        await frontier.join()
        frontier.close()
        assert not __import__("pathlib").Path(db_path).exists()
    asyncio.run(run())

def test_static_javascript_analysis_never_executes_source():
    found = analyze_javascript("https://example.test/static/app.js", "fetch('/api/users'); new WebSocket('wss://ws.example.test'); //# sourceMappingURL=app.js.map")
    assert "https://example.test/api/users" in found["urls"]
    assert found["websockets"] == ["wss://ws.example.test"]
    assert found["source_maps"] == ["https://example.test/static/app.js.map"]


def test_static_javascript_finds_literal_module_and_worker_imports():
    source = r"""
      import './entry.js?v=4';
      import { shared } from "./static/shared.js";
      export { default } from '../widgets/card.mjs';
      const lazy = import(`./chunks/lazy.js`);
      importScripts('/sw/bootstrap.js', './sw/one.js');
      new Worker(new URL('./worker.js', import.meta.url));
      const example = "import './not-a-module.js'";
      // import './commented-out.js';
      /* export * from './also-commented.js'; */
      import(`./chunks/${chunkName}.js`);
      import(packageName);
      import('bare-package-name');
    """

    found = analyze_javascript("https://example.test/assets/app.js", source)

    assert found["scripts"] == [
        "https://example.test/assets/chunks/lazy.js",
        "https://example.test/assets/entry.js?v=4",
        "https://example.test/assets/static/shared.js",
        "https://example.test/assets/sw/one.js",
        "https://example.test/assets/worker.js",
        "https://example.test/sw/bootstrap.js",
        "https://example.test/widgets/card.mjs",
    ]


def test_javascript_comment_routes_do_not_become_endpoints():
    found = analyze_javascript(
        "https://example.test/app.js",
        "// fetch('/api/commented')\rfetch('/api/live'); /* '/api/also-commented' */",
    )

    assert found["urls"] == ["https://example.test/api/live"]


def test_javascript_examples_nested_in_strings_do_not_become_network_endpoints():
    source = r"""
      const documentation = "Example: fetch('/api/not-live') and new WebSocket('wss://ws.example.test/not-live')";
      const routeNote = "/api/not-live is a documented endpoint";
      const urlNote = "Open https://api.example.test/not-live in your browser";
      const routePattern = /"\/api\/regex-only"/;
      const socketPattern = /"wss:\/\/ws\.example\.test\/regex-only"/;
      fetch('/api/live');
      fetch(`/api/users/${userId}?token=${token}`);
      new WebSocket('/socket/live');
    """

    found = analyze_javascript("https://example.test/app.js", source)

    assert found["urls"] == ["https://example.test/api/live"]
    assert found["websockets"] == ["wss://example.test/socket/live"]
    assert found["route_templates"] == ["https://example.test/api/users/{param}"]


def test_source_map_reference_must_be_in_a_comment():
    found = analyze_javascript(
        "https://example.test/assets/app.js",
        'const example = "//# sourceMappingURL=fake.map"; '
        '/*# sourceMappingURL=real.map */',
    )

    assert found["source_maps"] == ["https://example.test/assets/real.map"]


def test_static_javascript_finds_xhr_client_config_and_relative_websocket_routes():
    source = """
      const xhr = new XMLHttpRequest(); xhr.open('GET', '/api/users');
      const client = axios.create({baseURL: '/v1/items'});
      const route = '/graphql';
      fetch(`/api/static`);
      fetch(`/api/users/${userId}`);
      new WebSocket('/socket');
    """

    found = analyze_javascript("https://example.test/app.js", source)

    assert "https://example.test/api/users" in found["urls"]
    assert "https://example.test/v1/items" in found["urls"]
    assert "https://example.test/graphql" in found["urls"]
    assert "https://example.test/api/static" in found["urls"]
    assert not any("userId" in url for url in found["urls"])
    assert found["websockets"] == ["wss://example.test/socket"]

def test_telemetry_has_stable_metrics():
    telemetry = CrawlTelemetry(); telemetry.event("requests"); telemetry.response(200, .01, 10)
    assert telemetry.snapshot()["responses"] == 1

def test_telemetry_percentiles_stay_consistent_after_reservoir_replacement(monkeypatch):
    monkeypatch.setattr("raveneye.crawler.telemetry.random.randrange", lambda _size: 0)
    telemetry = CrawlTelemetry(latency_sample_size=2)
    for latency in (.1, .2, .3, .4):
        telemetry.response(200, latency)

    snapshot = telemetry.snapshot()
    assert snapshot["latency_samples"] == 2
    assert snapshot["average_latency_ms"] == 300
    assert snapshot["median_latency_ms"] == 300
    assert snapshot["p95_latency_ms"] == 400

def test_retry_after_accepts_seconds_and_http_date(monkeypatch):
    now = 1_700_000_000
    monkeypatch.setattr(retry_module.time, "time", lambda: now)
    http_date = format_datetime(datetime.fromtimestamp(now + 45, timezone.utc), usegmt=True)
    assert retry_module._retry_after_seconds("7") == 7
    assert retry_module._retry_after_seconds(http_date) == 45
    assert retry_module._retry_after_seconds("invalid") is None

def test_retry_after_is_shared_with_host_before_retry():
    class Response:
        def __init__(self, status, headers=None):
            self.status = status
            self.headers = headers or {}
            self.released = False
        def release(self):
            self.released = True

    class Session:
        def __init__(self):
            self.calls = 0
            self.cooldowns = []
            self.waited = []
        async def request(self, *_args, **_kwargs):
            self.calls += 1
            return Response(429, {"Retry-After": "3"}) if self.calls == 1 else Response(200)
        async def observe_status(self, _status):
            pass
        async def defer_host(self, host, seconds):
            self.cooldowns.append((host, seconds))
        async def wait_host(self, host):
            self.waited.append(host)

    async def run():
        session = Session()
        response, retries = await retry_module.request_with_retry(
            session, "https://example.test/a", attempts=1, backoff=0,
        )
        assert response.status == 200
        assert retries == 1
        assert session.cooldowns == [("example.test", 3.0)]
        assert session.waited == ["example.test"]
    asyncio.run(run())


def test_generic_http_500_is_retained_without_redundant_retry():
    class Response:
        status = 500
        headers = {}

        def __init__(self):
            self.released = False

        def release(self):
            self.released = True

    class Session:
        def __init__(self):
            self.calls = 0
            self.response = Response()

        async def request(self, *_args, **_kwargs):
            self.calls += 1
            return self.response

        async def observe_status(self, _status):
            pass

    async def run():
        session = Session()
        response, retries = await retry_module.request_with_retry(
            session, "https://example.test/error-page", attempts=2, backoff=0,
        )

        assert response is session.response
        assert response.status == 500
        assert retries == 0
        assert session.calls == 1
        assert not response.released

    asyncio.run(run())
