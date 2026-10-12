import hashlib

from raveneye_pkg import crawler as crawler_module
from raveneye_pkg import network as network_module
from raveneye_pkg import scanners as scanners_module
from raveneye_pkg.crawler import RavenCrawler


def test_legacy_crawler_rejects_non_http_and_userinfo_targets():
    crawler = RavenCrawler("https://example.test/", max_pages=5, max_depth=1, delay=0)

    assert not crawler._is_in_scope("ftp://example.test/file")
    assert not crawler._is_in_scope("https://user:pass@example.test/")
    assert not crawler._is_in_scope("https://example.test:invalid/")


def test_legacy_crawler_out_of_scope_seed_stops_before_network(monkeypatch):
    def unexpected_request(*_args, **_kwargs):
        raise AssertionError("out-of-scope seed must not issue a request")

    monkeypatch.setattr(crawler_module, "request_url", unexpected_request)
    monkeypatch.setattr(crawler_module, "fetch_robots_and_sitemap", unexpected_request)
    crawler = RavenCrawler(
        "https://outside.test/", max_pages=5, max_depth=1, delay=0,
        scope_domains=["inside.test"],
    )

    result = crawler.crawl()

    assert result["pages"] == 0
    assert result["metrics"]["requests"] == 0
    assert result["metrics"]["errors"] == 1


def test_baseline_and_parameter_probes_carry_scope(monkeypatch):
    calls = []

    def fake_request(url, **kwargs):
        calls.append((url, kwargs))
        return "x" * 200, None

    monkeypatch.setattr(crawler_module, "request_url", fake_request)
    monkeypatch.setattr(crawler_module.state, "config", {"param_probe_limit": 1}, raising=False)
    monkeypatch.setattr(crawler_module.state, "QUIET_MODE", True, raising=False)
    crawler = RavenCrawler(
        "https://example.test/", max_pages=5, max_depth=1, delay=0,
        scope_domains=["example.test"], scope_excludes=["/private/*"],
    )
    crawler._establish_baseline()
    crawler.baseline_404 = {"length": 100, "hash": hashlib.sha256(b"baseline").hexdigest()}

    crawler._probe_parameters()

    assert len(calls) == 2
    for _url, options in calls:
        assert options["allowed_domains"] == {"example.test"}
        assert options["exclude_patterns"] == {"/private/*"}
        assert options["exact_hosts"] == set()


def test_robots_and_sitemap_preflight_uses_scoped_safe_client(monkeypatch):
    calls = []

    def fake_request(url, **kwargs):
        calls.append((url, kwargs))
        return "User-agent: *\nSitemap: https://outside.test/sitemap.xml\n", None

    monkeypatch.setattr(scanners_module, "request_url", fake_request)

    result = scanners_module.fetch_robots_and_sitemap("https://example.test/app")

    assert [url for url, _options in calls] == ["https://example.test/robots.txt"]
    assert calls[0][1]["allowed_domains"] == set()
    assert calls[0][1]["exact_hosts"] == {"example.test"}
    assert result["sitemap_urls"] == ["https://outside.test/sitemap.xml"]


def test_request_url_rejects_non_http_and_userinfo_before_dns(monkeypatch):
    resolved = []
    monkeypatch.setattr(
        network_module, "_resolve_safe_ip",
        lambda url: resolved.append(url) or ("93.184.216.34", True),
    )

    for url in ("ftp://example.test/file", "https://user:secret@example.test/"):
        body, error = network_module.request_url(url, max_retries=1)
        assert body is None
        assert error == "URL fora do escopo"
    assert resolved == []
