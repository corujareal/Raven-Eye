import json
import sqlite3
from pathlib import Path

import pytest

from raveneye_pkg import state
from raveneye_pkg import database
from raveneye_pkg.config_io import load_config
from raveneye_pkg.network import normalize_url, classify_link, is_safe_url
from raveneye_pkg.vuln_scanner import RavenVulnScanner
from raveneye_pkg.reports import save_release_audit


class FakeResponse:
    def __init__(self, text="", status_code=200, headers=None, url="https://example.com/"):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "text/html"}
        self.url = url
        self.cookies = []


@pytest.fixture(autouse=True)
def clean_state(tmp_path, monkeypatch):
    state.config = {
        "database_path": str(tmp_path / "raveneye.db"),
        "scanner_rate_limit": 1000,
        "scanner_max_workers": 2,
        "scan_cache_ttl": 60,
        "delay": 0,
        "proxy": "",
        "stealth_mode": False,
    }
    database.close()
    yield
    database.close()


def test_database_auto_init_cache_and_integrity():
    path = database.initialize(state.config)
    assert path.exists()
    assert database.integrity_check()
    database.put_scan("k", {"ok": True}, ttl=60)
    assert database.get_scan("k") == {"ok": True}


def test_network_normalization_and_scope(monkeypatch):
    assert normalize_url("https://example.com/a#frag") == "https://example.com/a"
    assert classify_link("https://example.com/app.js") == "[Comum]"
    monkeypatch.setattr("raveneye_pkg.network.resolve_host", lambda host: "93.184.216.34")
    assert is_safe_url("https://example.com")
    assert not is_safe_url("http://127.0.0.1")


def test_scanner_reflection_and_sql_error(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        if "RAVENEYE_" in url and "q=%27" not in url:
            marker = url.split("q=", 1)[1]
            return FakeResponse(f"<html>{marker}</html>", 200, url=url)
        if "q=%27" in url or "q='" in url:
            return FakeResponse("SQL syntax error near quote", 500, url=url)
        return FakeResponse("<html>baseline</html>", 200, url=url)

    monkeypatch.setattr(state._SESSION, "get", fake_get)
    monkeypatch.setattr("raveneye_pkg.vuln_scanner.is_safe_url", lambda url: True)
    monkeypatch.setattr(
        "raveneye_pkg.vuln_scanner.check_security_headers",
        lambda url: [],
    )
    monkeypatch.setattr(
        "raveneye_pkg.vuln_scanner.check_cors",
        lambda urls, limit=30: [],
    )
    monkeypatch.setattr(
        "raveneye_pkg.vuln_scanner.check_open_redirect",
        lambda urls: [],
    )
    monkeypatch.setattr(
        "raveneye_pkg.vuln_scanner.check_directory_listing",
        lambda urls: [],
    )
    monkeypatch.setattr(
        "raveneye_pkg.vuln_scanner.check_error_disclosure",
        lambda urls: [],
    )
    monkeypatch.setattr(
        "raveneye_pkg.vuln_scanner.check_jwt_weaknesses",
        lambda url: [],
    )
    monkeypatch.setattr(
        "raveneye_pkg.vuln_scanner.check_http_request_smuggling",
        lambda url, timeout=8: [],
    )
    monkeypatch.setattr(
        "raveneye_pkg.vuln_scanner.get_tech",
        lambda url: {"servidor": "Desconhecido", "linguagens": [], "cms": None, "frameworks": [], "waf": None, "cdn": None},
    )
    monkeypatch.setattr(
        "raveneye_pkg.vuln_scanner.get_exploitdb_search",
        lambda q: [],
    )

    monkeypatch.setattr("raveneye_pkg.vuln_scanner.socket.gethostbyname", lambda host: "93.184.216.34")
    monkeypatch.setattr("raveneye_pkg.vuln_scanner.socket.create_connection", lambda *a, **k: (_ for _ in ()).throw(OSError()))
    scanner = RavenVulnScanner(
        "https://example.com/?q=hello",
        urls=["https://example.com/?q=hello"],
        active=True,
    )
    result = scanner.run()
    cats = {x["category"] for x in result["findings"]}
    assert "xss" in cats
    assert "sql_injection" in cats
    assert result["summary"]["ALTO"] >= 1


def test_scanner_candidate_categories_do_not_claim_confirmation(monkeypatch):
    monkeypatch.setattr(
        state._SESSION, "get",
        lambda url, **kwargs: FakeResponse("<html>ok</html>", 200, url=url),
    )
    monkeypatch.setattr("raveneye_pkg.vuln_scanner.is_safe_url", lambda url: True)
    for name in [
        "check_security_headers", "check_cors", "check_open_redirect",
        "check_directory_listing", "check_error_disclosure",
        "check_jwt_weaknesses",
    ]:
        monkeypatch.setattr(f"raveneye_pkg.vuln_scanner.{name}", lambda *a, **k: [])
    monkeypatch.setattr(
        "raveneye_pkg.vuln_scanner.check_http_request_smuggling",
        lambda *a, **k: [],
    )
    monkeypatch.setattr(
        "raveneye_pkg.vuln_scanner.get_tech",
        lambda url: {"servidor": "Example/1.0", "linguagens": [], "cms": None, "frameworks": [], "waf": None, "cdn": None},
    )
    monkeypatch.setattr("raveneye_pkg.vuln_scanner.get_exploitdb_search", lambda q: [])
    monkeypatch.setattr("raveneye_pkg.vuln_scanner.socket.gethostbyname", lambda host: "93.184.216.34")
    monkeypatch.setattr("raveneye_pkg.vuln_scanner.socket.create_connection", lambda *a, **k: (_ for _ in ()).throw(OSError()))
    result = RavenVulnScanner(
        "https://example.com/?url=https%3A%2F%2Fexample.org",
        urls=["https://example.com/?url=https%3A%2F%2Fexample.org"],
        active=False,
    ).run()
    ssrf = [f for f in result["findings"] if f["category"] == "ssrf"]
    assert ssrf and ssrf[0]["confidence"] == "LOW"


def test_release_audit(tmp_path):
    out = tmp_path / "audit.txt"
    save_release_audit({"vulnerability_scan": {"findings": [], "summary": {}}}, str(out), {
        "executados": 5, "aprovados": 5, "falhos": 0, "cobertura": "N/A"
    })
    text = out.read_text()
    assert "RELATÓRIO RAVENEYE 6.6.6" in text
    assert "MATRIZ DE REGRESSÃO" in text


def test_menu_and_ascii_contracts():
    menu = Path("raveneye_pkg/menus.py").read_text()
    art = Path("raveneye_pkg/ascii_art.py").read_text()
    assert "1 - Scanner de vulnerabilidade + CVE entregue" in menu
    assert "2 - Scanner de vulnerabilidade solo" in menu
    assert "3 - NUKE + Scanner" in menu
    assert "4 - C4 + Scanner" in menu
    assert "SALAO PRINCIPAL" in art
    assert "6.6.7" not in Path("RavenEye.py").read_text()

def test_cve_enrichment_requires_product_version_match(monkeypatch):
    monkeypatch.setattr("raveneye_pkg.vuln_scanner.is_safe_url", lambda url: True)
    monkeypatch.setattr(
        state._SESSION, "get",
        lambda url, **kwargs: FakeResponse("ok", 200, headers={"Content-Type": "text/html", "Server": "Apache/2.4.49"}, url=url),
    )
    for name in [
        "check_security_headers", "check_cors", "check_open_redirect",
        "check_directory_listing", "check_error_disclosure",
        "check_jwt_weaknesses",
    ]:
        monkeypatch.setattr(f"raveneye_pkg.vuln_scanner.{name}", lambda *a, **k: [])
    monkeypatch.setattr("raveneye_pkg.vuln_scanner.check_http_request_smuggling", lambda *a, **k: [])
    monkeypatch.setattr("raveneye_pkg.vuln_scanner.socket.gethostbyname", lambda host: "93.184.216.34")
    monkeypatch.setattr("raveneye_pkg.vuln_scanner.socket.create_connection", lambda *a, **k: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr(
        "raveneye_pkg.vuln_scanner.get_tech",
        lambda url: {"servidor": "Apache/2.4.49", "linguagens": [], "cms": None, "frameworks": [], "waf": None, "cdn": None},
    )
    monkeypatch.setattr(
        "raveneye_pkg.vuln_scanner.get_exploitdb_search",
        lambda q: [{"id": "CVE-2021-41773", "titulo": "Apache HTTP Server 2.4.49 path traversal", "url": "https://www.exploit-db.com/exploits/50383"}],
    )
    result = RavenVulnScanner("https://example.com", urls=["https://example.com"], active=False).run()
    matches = [f for f in result["findings"] if f["category"] == "vulnerable_components"]
    assert matches and matches[0]["cve"] == "CVE-2021-41773"


def test_nuke_menu_has_http_enumeration(monkeypatch):
    from raveneye_pkg import menus
    src = Path(menus.__file__).read_text(encoding="utf-8")
    assert 'enumerate_paths(target' in src
    assert 'enumerate_endpoints(target' in src
    assert 'enumerate_parameters(target' in src
    assert 'preflight_enumeration=enum_results' in src
