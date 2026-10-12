from raveneye_pkg import crawler as crawler_module
from raveneye_pkg.crawler import RavenCrawler


def test_legacy_crawler_follows_literal_imports_recursively(monkeypatch):
    page = "https://example.test/start"
    bundle = "https://example.test/assets/app.js?v=1"
    chunk = "https://example.test/assets/chunk.js"
    nested = "https://example.test/assets/nested.js"
    outside = "https://outside.test/private.js"
    outside_script = "https://outside.test/remote.js"
    bodies = {
        page: '<script src="/assets/app.js?v=1"></script>'
              '<script src="https://outside.test/remote.js"></script>',
        bundle: "import './chunk.js'; import 'https://outside.test/private.js'; fetch('/api/root'); "
                "fetch(`/api/users/${userId}`);",
        chunk: "import './nested.js'; fetch('/api/chunk');",
        nested: "fetch('/api/nested');",
    }
    requested = []
    request_options = {}

    def fake_request_url(url, **kwargs):
        requested.append(url)
        request_options[url] = kwargs
        if url not in bodies:
            return None, "not found"
        return bodies[url], None

    monkeypatch.setattr(crawler_module, "request_url", fake_request_url)
    monkeypatch.setattr(crawler_module, "_sleep", lambda *_args, **_kwargs: None)
    crawler = RavenCrawler(page, max_pages=20, max_depth=5, delay=0)

    crawler._crawl_single(page, 0)
    assert chunk in [item[0] for item in crawler.to_crawl]
    assert outside not in requested and outside_script not in requested
    assert request_options[bundle]["exact_hosts"] == {"example.test"}

    crawler._crawl_single(chunk, 1)

    assert nested in [item[0] for item in crawler.to_crawl]
    assert crawler.js_urls == [bundle, chunk, nested]
    assert crawler.js_route_templates == ["https://example.test/api/users/{param}"]


def test_legacy_crawler_extracts_source_map_routes_and_modules_without_placeholder_requests(monkeypatch):
    source_map = "https://example.test/assets/app.js.map"
    module = "https://example.test/assets/map-module.js"
    content = '{"version":3,"sourcesContent":["import \'./map-module.js\'; fetch(`/api/users/${userId}`);"]}'
    requested = []

    def fake_request_url(url, **_kwargs):
        requested.append(url)
        return (content, None) if url == source_map else (None, "not found")

    monkeypatch.setattr(crawler_module, "request_url", fake_request_url)
    monkeypatch.setattr(crawler_module, "_sleep", lambda *_args, **_kwargs: None)
    crawler = RavenCrawler(source_map, max_pages=10, max_depth=3, delay=0)

    crawler._crawl_single(source_map, 0)

    assert crawler.js_route_templates == ["https://example.test/api/users/{param}"]
    assert module in [item[0] for item in crawler.to_crawl]
    assert "https://example.test/api/users/{param}" not in requested
    assert crawler.visited[0]["source_map_sources_analyzed"] == 1
