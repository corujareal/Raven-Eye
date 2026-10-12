import asyncio

import pytest

from raveneye.network.browser_proxy import SafeSocksProxy
from raveneye.network.ssrf_guard import SSRFBlocked, resolve_public_ips
from raveneye_pkg import network
from raveneye_pkg import crawler as legacy_crawler
from raveneye_pkg.crawler import RavenCrawler


def test_socks_proxy_allows_only_http_targets_inside_scope():
    proxy = SafeSocksProxy(set(), exact_hosts={"example.test"})

    assert proxy.allows_url("https://example.test/app")
    assert not proxy.allows_url("https://api.example.test/app")
    assert not proxy.allows_url("https://example.test.attacker.invalid/app")
    assert not proxy.allows_url("file:///etc/passwd")
    assert not proxy.allows_url("https://user:password@example.test/")
    assert SafeSocksProxy({"example.test"}).allows_url("https://api.example.test/app")


def test_legacy_crawler_defaults_to_exact_seed_host(monkeypatch):
    monkeypatch.setattr(legacy_crawler.state, "config", {"max_workers": 2}, raising=False)
    default_scope = RavenCrawler("https://example.test/", 10, 2, 0)
    explicit_scope = RavenCrawler("https://example.test/", 10, 2, 0, scope_domains=["example.test"])

    assert default_scope._is_in_scope("https://example.test/page")
    assert not default_scope._is_in_scope("https://api.example.test/page")
    assert explicit_scope._is_in_scope("https://api.example.test/page")


def test_socks_proxy_private_destination_is_rejected():
    with pytest.raises(SSRFBlocked):
        asyncio.run(resolve_public_ips("127.0.0.1", 8080))


def test_legacy_crawler_redirect_scope_is_rechecked(monkeypatch):
    calls = []

    class Response:
        def __init__(self, status_code, headers=None, text=""):
            self.status_code = status_code
            self.headers = headers or {}
            self.text = text

    class Session:
        def get(self, url, **_kwargs):
            calls.append(url)
            return Response(302, {"Location": "https://outside.invalid/"})

    monkeypatch.setattr(network.state, "config", {"proxy": ""}, raising=False)
    monkeypatch.setattr(network.state, "_SESSION", Session(), raising=False)
    monkeypatch.setattr(network, "_resolve_safe_ip", lambda _url: ("93.184.216.34", True))

    body, error = network.request_url(
        "https://example.test/", max_retries=1, allowed_domains={"example.test"}
    )

    assert body is None
    assert error == "Redirect fora do escopo"
    assert calls == ["https://example.test/"]


def test_legacy_crawler_redirect_exclusion_is_rechecked(monkeypatch):
    calls = []

    class Response:
        status_code = 302
        headers = {"Location": "/private/secret"}

    class Session:
        def get(self, url, **_kwargs):
            calls.append(url)
            return Response()

    monkeypatch.setattr(network.state, "config", {"proxy": ""}, raising=False)
    monkeypatch.setattr(network.state, "_SESSION", Session(), raising=False)
    monkeypatch.setattr(network, "_resolve_safe_ip", lambda _url: ("93.184.216.34", True))

    body, error = network.request_url(
        "https://example.test/", max_retries=1, allowed_domains={"example.test"},
        exclude_patterns={"/private/*"},
    )

    assert body is None
    assert error == "Redirect fora do escopo"
    assert calls == ["https://example.test/"]
