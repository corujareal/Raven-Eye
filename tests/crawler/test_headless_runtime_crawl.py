import asyncio

from raveneye.core.config import RavenConfig
from raveneye.crawler import engine as engine_module
from raveneye.crawler.engine import Crawler
from raveneye.crawler.filters import Scope


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


def test_async_crawler_queues_only_in_scope_runtime_gets_and_records_no_bodies(monkeypatch):
    seed = "https://example.test/spa"
    runtime_get = "https://example.test/api/runtime?id=secret-value"
    runtime_post = "https://example.test/api/mutate"
    outside = "https://outside.test/private"
    requested = []

    class _Renderer:
        def __init__(self, _scope, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def render(self, _url):
            return {
                "url": seed,
                "status": 200,
                "body": '<div id="root"><a href="/from-dom">loaded</a></div>',
                "requests": [
                    {"url": runtime_get, "method": "GET", "resource_type": "fetch", "status": 200},
                    {"url": runtime_post, "method": "POST", "resource_type": "fetch", "status": None},
                    {"url": outside, "method": "GET", "resource_type": "xhr", "status": 200},
                ],
                "websockets": ["wss://example.test/app/socket"],
                "blocked_requests": 1,
            }

    async def fake_request_with_retry(_session, url, **_kwargs):
        requested.append(url)
        content_type = "text/html" if url == seed else "text/plain"
        body = '<div id="root"></div>' if url == seed else ""
        return _Response(url, 200 if url == seed else 404, content_type, body), 0

    monkeypatch.setattr(engine_module, "AsyncSession", lambda **_kwargs: _Session())
    monkeypatch.setattr(engine_module, "request_with_retry", fake_request_with_retry)
    monkeypatch.setattr(engine_module, "ScopedPlaywrightRenderer", _Renderer)
    monkeypatch.setattr(engine_module, "discover_api_urls", lambda *_args, **_kwargs: [])
    config = RavenConfig(
        max_pages=12, queue_size=32, concurrency=1, worker_count=1,
        max_runtime_seconds=10, requests_per_second=100,
        per_host_requests_per_second=100, headless_rendering=True,
    )

    rows = asyncio.run(Crawler(config, scope=Scope(exact_hosts={"example.test"})).crawl([seed]))

    assert runtime_get in requested
    assert runtime_post not in requested
    assert outside not in requested
    assert "https://example.test/from-dom" in requested
    row = next(item for item in rows if item.get("url") == seed)
    assert row["rendered"] is True
    assert row["blocked_browser_requests"] == 1
    assert any(item["method"] == "POST" for item in row["runtime_requests"])
    assert all("secret-value" not in item["url"] for item in row["runtime_requests"])
    assert "wss://example.test/app/socket" in row["websockets"]
