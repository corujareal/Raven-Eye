import asyncio
import json

from raveneye.core.config import RavenConfig
from raveneye.crawler.engine import Crawler
from raveneye.crawler.filters import Scope
from raveneye.crawler import engine as engine_module


class _Content:
    def __init__(self, body: bytes):
        self.body = body

    async def iter_chunked(self, _size):
        yield self.body


class _Response:
    def __init__(self, url: str, status: int, content_type: str, body: str):
        self.url = url
        self.status = status
        self.headers = {"content-type": content_type}
        self.charset = "utf-8"
        self.content = _Content(body.encode())

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None


class _Session:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None


def test_async_crawler_fetches_imported_module_under_scope(monkeypatch):
    page = "https://example.test/app"
    bundle = "https://example.test/assets/app.js?v=7"
    chunk = "https://example.test/assets/chunk.js"
    source_map = "https://example.test/assets/app.js.map"
    outside = "https://outside.test/private.js"
    requested = []
    bodies = {
        page: ('text/html', '<script src="/assets/app.js?v=7"></script>'),
        bundle: (
            "application/javascript",
            "import './chunk.js'; import 'https://outside.test/private.js'; fetch('/api/bundle'); "
            "fetch(`/api/users/${userId}?token=${token}`); "
            "//# sourceMappingURL=app.js.map",
        ),
        chunk: ("application/javascript", "fetch('/api/chunk');"),
        source_map: (
            "text/plain",
            json.dumps({
                "version": 3,
                "sources": ["src.js"],
                "sourcesContent": ["import './from-map-module.js'; fetch('/api/from-map'); fetch(`/api/users/${userId}`);"],
            }),
        ),
    }

    async def fake_request_with_retry(_session, url, **_kwargs):
        requested.append(url)
        content_type, body = bodies.get(url, ("text/plain", ""))
        status = 200 if url in bodies else 404
        return _Response(url, status, content_type, body), 0

    monkeypatch.setattr(engine_module, "AsyncSession", lambda **_kwargs: _Session())
    monkeypatch.setattr(engine_module, "request_with_retry", fake_request_with_retry)
    config = RavenConfig(
        max_pages=20, queue_size=32, concurrency=1, worker_count=1,
        max_runtime_seconds=10, requests_per_second=100,
        per_host_requests_per_second=100,
    )

    rows = asyncio.run(Crawler(config, scope=Scope(exact_hosts={"example.test"})).crawl([page]))

    assert chunk in requested
    assert source_map in requested
    assert "https://example.test/api/from-map" in requested
    assert "https://example.test/assets/from-map-module.js" in requested
    assert outside not in requested
    assert not any("{param}" in url for url in requested)
    bundle_row = next(row for row in rows if row.get("url") == bundle)
    assert chunk in bundle_row["scripts"]
    assert bundle_row["js_route_templates"] == ["https://example.test/api/users/{param}"]
    map_row = next(row for row in rows if row.get("url") == source_map)
    assert map_row["js_route_templates"] == ["https://example.test/api/users/{param}"]
