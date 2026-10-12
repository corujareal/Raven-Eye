import asyncio

from raveneye.crawler.discovery import well_known_urls, discover_from_robots
from raveneye.core.config import RavenConfig
from raveneye.crawler.engine import Crawler
from raveneye.crawler.filters import Scope
from raveneye.crawler import engine as engine_module
from raveneye.crawler.jsonl import write_jsonl, iter_jsonl
from raveneye.crawler.sitemaps import parse_robots, robots_allows


class _Content:
    def __init__(self, body: bytes):
        self.body = body

    async def iter_chunked(self, _size):
        yield self.body


class _Response:
    def __init__(self, url: str, status: int, body: str = "", location: str | None = None):
        self.url = url
        self.status = status
        self.headers = {"content-type": "text/plain"}
        if location:
            self.headers["location"] = location
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


def _crawl_with_responses(monkeypatch, response_map, scope):
    requested = []

    async def fake_request_with_retry(_session, url, **_kwargs):
        requested.append(url)
        status, body, location = response_map.get(url, (404, "", None))
        return _Response(url, status, body, location), 0

    monkeypatch.setattr(engine_module, "AsyncSession", lambda **_kwargs: _Session())
    monkeypatch.setattr(engine_module, "request_with_retry", fake_request_with_retry)
    config = RavenConfig(
        max_pages=20, queue_size=32, concurrency=1, worker_count=1,
        max_runtime_seconds=10, requests_per_second=100,
        per_host_requests_per_second=100,
    )
    rows = asyncio.run(Crawler(config, scope=scope).crawl(["https://example.test/app"]))
    return requested, rows


def test_well_known_urls():
    urls = well_known_urls('https://example.com/start')
    assert 'https://example.com/.well-known/security.txt' in urls


def test_robots_discovery():
    text='''User-agent: *\nAllow: /public\nDisallow: /private\nSitemap: https://example.com/sitemap.xml\n'''
    found=discover_from_robots(text,'https://example.com/robots.txt')
    assert 'https://example.com/public' in found
    assert 'https://example.com/private' in found
    assert 'https://example.com/sitemap.xml' in found

def test_robots_selects_specific_agent_and_longest_rule_allow_ties():
    policy = parse_robots(
        "User-agent: *\nDisallow: /\nUser-agent: RavenEye\nDisallow: /private\nAllow: /private/public\n",
        "https://example.com/robots.txt", "RavenEye/6.6.6",
    )
    assert not robots_allows("https://example.com/private/x", "https://example.com/robots.txt", policy["rules"])
    assert robots_allows("https://example.com/private/public", "https://example.com/robots.txt", policy["rules"])
    assert robots_allows("https://example.com/other", "https://example.com/robots.txt", policy["rules"])


def test_crawler_follows_same_scope_robots_redirect_and_applies_rules(monkeypatch):
    robots = "https://example.test/robots.txt"
    redirected_robots = "https://example.test/policy/robots.txt"
    page = "https://example.test/app"
    private = "https://example.test/private/secret"
    requested, rows = _crawl_with_responses(
        monkeypatch,
        {
            robots: (302, "", "/policy/robots.txt"),
            redirected_robots: (200, "User-agent: *\nDisallow: /private\n", None),
            page: (200, '<html><a href="/private/secret">private</a></html>', None),
        },
        Scope(exact_hosts={"example.test"}),
    )

    assert requested[:2] == [robots, redirected_robots]
    assert page in requested
    assert private not in requested
    robots_row = next(row for row in rows if row.get("type") == "robots")
    assert robots_row["robots_final_url"] == redirected_robots
    assert robots_row["robots_redirects"] == [redirected_robots]


def test_crawler_does_not_follow_robots_redirect_outside_scope(monkeypatch):
    robots = "https://example.test/robots.txt"
    page = "https://example.test/app"
    external = "https://outside.test/robots.txt"
    requested, rows = _crawl_with_responses(
        monkeypatch,
        {robots: (302, "", external)},
        Scope(exact_hosts={"example.test"}),
    )

    assert requested == [robots]
    assert external not in requested
    assert page not in requested
    robots_row = next(row for row in rows if row.get("type") == "robots")
    assert robots_row["robots_policy"] == "fail-closed"
    assert robots_row["error"] == "robots redirect outside configured scope"


def test_crawler_caps_robots_redirects_at_five(monkeypatch):
    urls = ["https://example.test/robots.txt"] + [
        f"https://example.test/robots-{index}.txt" for index in range(1, 7)
    ]
    response_map = {
        urls[index]: (302, "", urls[index + 1])
        for index in range(6)
    }
    requested, rows = _crawl_with_responses(
        monkeypatch,
        response_map,
        Scope(exact_hosts={"example.test"}),
    )

    assert requested == urls[:6]
    robots_row = next(row for row in rows if row.get("type") == "robots")
    assert robots_row["robots_policy"] == "fail-closed"
    assert robots_row["error"] == "robots redirect limit exceeded"
    assert len(robots_row["robots_redirects"]) == 5


def test_jsonl_roundtrip(tmp_path):
    p=tmp_path/'rows.jsonl'
    write_jsonl(p,[{'url':'https://example.com','status':200},{'url':'https://example.com/a'}])
    assert list(iter_jsonl(p))[1]['url'].endswith('/a')
