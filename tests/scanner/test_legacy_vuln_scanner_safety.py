from contextlib import nullcontext
import hashlib
from urllib.parse import parse_qsl, urlsplit

import raveneye_pkg.vuln_scanner as vuln_module
from raveneye_pkg import state
from raveneye_pkg.vuln_scanner import RavenVulnScanner


class FakeResponse:
    def __init__(self, body=b"", status=200, headers=None, url=""):
        self._content = body if isinstance(body, bytes) else str(body).encode()
        self.status_code = status
        self.headers = headers or {"Content-Type": "text/html; charset=utf-8"}
        self.url = url
        self._content_consumed = True
        self.closed = False

    @property
    def text(self):
        return self._content.decode("utf-8", "replace")

    def iter_content(self, chunk_size=65536):
        for offset in range(0, len(self._content), chunk_size):
            yield self._content[offset:offset + chunk_size]

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, make_response):
        self.make_response = make_response
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.make_response(url)


def _patch_network(monkeypatch, session):
    monkeypatch.setattr(vuln_module, "get_proxies", lambda: None)
    monkeypatch.setattr(vuln_module, "_resolve_safe_ip", lambda _url: ("93.184.216.34", True))
    monkeypatch.setattr(vuln_module, "_pin_dns_to", lambda _ip: nullcontext())
    monkeypatch.setattr(state, "_SESSION", session)


def test_legacy_request_stops_redirect_before_out_of_scope_request(monkeypatch):
    first_response = FakeResponse(
        status=302,
        headers={"Location": "http://127.0.0.1/admin"},
        url="https://example.test/start",
    )
    session = FakeSession(lambda _url: first_response)
    _patch_network(monkeypatch, session)
    scanner = RavenVulnScanner("https://example.test/", rate_limit=1000)

    result = scanner._request("https://example.test/start")

    assert result is None
    assert len(session.calls) == 1
    assert first_response.closed
    assert "redirect_out_of_scope" in scanner._blocked_network_events


def test_target_without_scheme_defaults_to_its_host_scope_and_redacts_query_value():
    scanner = RavenVulnScanner("site.test/item?page=RAVENEYE_page_probe", rate_limit=1000)

    assert scanner.target.startswith("https://site.test/")
    assert scanner._in_scope("https://site.test/item?page=RAVENEYE_page_probe")
    assert scanner._in_scope("https://site.test:443/item")
    assert scanner._in_scope("http://site.test/item")
    assert not scanner._in_scope("https://api.site.test/item")
    assert not scanner._in_scope("https://site.test:8443/item")

    scanner._add(category="xss", name="reflection", severity="INFO", confidence="LOW",
                 url=scanner.target, evidence="benign marker reflected")
    finding = scanner.findings[0].to_dict()
    assert "RAVENEYE_page_probe" not in repr(finding)
    assert "[redacted]" in finding["url"] or "%5Bredacted%5D" in finding["url"]


def test_cookie_findings_are_possible_and_session_name_controls_confidence(monkeypatch):
    class Cookie:
        def __init__(self, name):
            self.name = name
            self.secure = False
            self._rest = {}

    class Response:
        cookies = [Cookie("analytics"), Cookie("sessionid")]

    scanner = RavenVulnScanner("https://fixture.test/", rate_limit=1000)
    monkeypatch.setattr(scanner, "_request", lambda _url: Response())

    scanner._check_cookies()

    rows = [finding.to_dict() for finding in scanner.findings]
    assert rows
    assert {row["stage"] for row in rows} == {"POSSIBLE"}
    analytics = [row for row in rows if "analytics" in row["name"]]
    session = [row for row in rows if "sessionid" in row["name"]]
    assert analytics and all(row["confidence"] == "LOW" and row["severity"] == "INFO" for row in analytics)
    assert session and all(row["confidence"] == "MEDIUM" for row in session)


def test_explicit_scanner_scope_allows_only_configured_domain_rules():
    scanner = RavenVulnScanner(
        "https://site.test/", scope_domains={"*.example.test"},
        scope_excludes={"/private/*"}, rate_limit=1000,
    )

    assert not scanner._in_scope("https://site.test/")
    assert scanner._in_scope("https://api.example.test/public")
    assert not scanner._in_scope("https://example.test/public")
    assert not scanner._in_scope("https://api.example.test/private/key")


def test_legacy_request_fails_closed_for_private_address_and_proxy(monkeypatch):
    session = FakeSession(lambda url: FakeResponse(url=url))
    _patch_network(monkeypatch, session)
    scanner = RavenVulnScanner("http://169.254.169.254/", rate_limit=1000)
    monkeypatch.setattr(vuln_module, "_resolve_safe_ip", lambda _url: (None, False))

    assert scanner._request("http://169.254.169.254/latest/meta-data/") is None
    assert session.calls == []
    assert "destination_blocked_by_ssrf_guard" in scanner._blocked_network_events

    monkeypatch.setattr(vuln_module, "get_proxies", lambda: {"http": "http://proxy.test:8080"})
    scanner = RavenVulnScanner("https://example.test/", rate_limit=1000)
    assert scanner._request("https://example.test/") is None
    assert session.calls == []
    assert "scanner_proxy_disabled_by_default" in scanner._blocked_network_events


def test_open_redirect_stores_response_hash_without_canary_value(monkeypatch):
    from raveneye_pkg import scanners

    target = "https://example.test/continue?next=%2Fhome"
    session = FakeSession(lambda url: FakeResponse(
        status=302,
        headers={"Location": "https://evil.com/raveneye-openredirect"},
        url=url,
    ))
    _patch_network(monkeypatch, session)
    for name in ("check_cors", "check_directory_listing", "check_error_disclosure", "check_jwt_weaknesses"):
        monkeypatch.setattr(vuln_module, name, lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        vuln_module, "check_open_redirect",
        lambda urls, requester=None: scanners.check_open_redirect(urls, requester=requester),
    )
    monkeypatch.setattr(vuln_module, "check_http_request_smuggling", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("raw socket called")))
    scanner = RavenVulnScanner(target, urls=[target], rate_limit=1000)

    scanner._existing_checks()

    finding = next(item for item in scanner.findings if item.category == "open_redirect").to_dict()
    assert finding["stage"] == "PROBABLE"
    assert finding["evidence_metadata"]["response"]["status"] == 302
    assert len(finding["evidence_metadata"]["response"]["sha256"]) == 64
    assert "evil.com" not in repr(finding)
    assert "raveneye-openredirect" not in repr(finding)
    assert len(session.calls) == 1
    assert "request_smuggling_not_run_by_default" in scanner._blocked_network_events


def test_port_scan_connects_only_to_prevalidated_ip(monkeypatch):
    attempted = []
    monkeypatch.setattr(vuln_module, "_resolve_safe_ip", lambda _url: ("93.184.216.34", True))
    monkeypatch.setattr(vuln_module.socket, "create_connection", lambda address, timeout: (
        attempted.append(address) or (_ for _ in ()).throw(ConnectionRefusedError())
    ))
    scanner = RavenVulnScanner("https://example.test/", rate_limit=1000)

    scanner._check_open_ports()

    assert len(attempted) == 15
    assert all(host == "93.184.216.34" for host, _port in attempted)


def test_open_redirect_match_uses_exact_canary_host_and_redacts_response():
    from raveneye_pkg.scanners import check_open_redirect

    url = "https://example.test/continue?next=%2Fhome"

    class RedirectResponse:
        def __init__(self, location):
            self.headers = {"Location": location}

    accepted = check_open_redirect(
        [url], requester=lambda *_args, **_kwargs: RedirectResponse(
            "https://evil.com/raveneye-openredirect"
        ),
    )
    spoofed = check_open_redirect(
        [url], requester=lambda *_args, **_kwargs: RedirectResponse(
            "https://evil.com.attacker.invalid/raveneye-openredirect"
        ),
    )

    assert len(accepted) == 1
    assert accepted[0]["location"] == "<redacted>"
    assert len(accepted[0]["request_sha256"]) == 64
    assert spoofed == []


def test_legacy_response_body_is_capped_and_hashes_mark_truncation(monkeypatch):
    session = FakeSession(lambda url: FakeResponse(b"x" * 4096, url=url))
    _patch_network(monkeypatch, session)
    monkeypatch.setitem(state.config, "scanner_max_response_bytes", 1024)
    scanner = RavenVulnScanner("https://example.test/", rate_limit=1000)

    response = scanner._request("https://example.test/?token=secret")

    assert len(response.text) == 1024
    metadata = scanner._response_evidence["https://example.test/?token=secret"]
    assert metadata["response"]["truncated"] is True
    assert len(metadata["response"]["sha256"]) == 64
    assert "secret" not in repr(metadata)


def test_heuristic_only_finding_has_request_hash_but_no_fake_response_hash():
    scanner = RavenVulnScanner("https://example.test/", rate_limit=1000)
    scanner._add(
        category="ssrf", name="URL parameter candidate", severity="INFO",
        confidence="LOW", url="https://example.test/?url=http%3A%2F%2Fsecret.invalid",
    )

    finding = scanner.findings[0].to_dict()
    metadata = finding["evidence_metadata"]

    assert len(metadata["request"]["sha256"]) == 64
    assert metadata["response"]["observed"] is False
    assert metadata["response"]["sha256"] == ""
    assert finding["stage"] == "POSSIBLE"
    assert "secret.invalid" not in repr(finding)
    assert finding["observed_at"].endswith("+00:00")


def test_sql_probe_requires_clean_baseline_and_repeated_differential(monkeypatch):
    baseline_body = "ordinary response"

    def response_for(url):
        value = dict(parse_qsl(urlsplit(url).query)).get("q", "")
        if value.startswith("RAVENEYE_"):
            return FakeResponse(f"reflected {value}".encode(), url=url)
        if value == "'":
            return FakeResponse(
                b"You have an error in your SQL syntax near input", status=500, url=url
            )
        return FakeResponse(baseline_body.encode(), url=url)

    session = FakeSession(response_for)
    _patch_network(monkeypatch, session)
    scanner = RavenVulnScanner(
        "https://example.test/search?q=normal", urls=["https://example.test/search?q=normal"],
        rate_limit=1000,
    )

    scanner._check_xss_and_sql()

    findings = [finding.to_dict() for finding in scanner.findings]
    xss = next(item for item in findings if item["category"] == "xss")
    sql = next(item for item in findings if item["category"] == "sql_injection")
    assert xss["stage"] == "POSSIBLE"
    assert sql["stage"] == "PROBABLE"
    assert sql["evidence_metadata"]["delta"]["compared"] is True
    assert sql["evidence_metadata"]["score_factors"]["repeatable"] == 10
    assert "RAVENEYE_" not in repr(findings)
    assert "SQL syntax near input" not in repr(findings)


def test_sql_probe_rejects_error_already_present_in_baseline(monkeypatch):
    body = b"You have an error in your SQL syntax"

    def response_for(url):
        value = dict(parse_qsl(urlsplit(url).query)).get("q", "")
        if value.startswith("RAVENEYE_"):
            return FakeResponse(b"ordinary response", url=url)
        return FakeResponse(body, status=500, url=url)

    session = FakeSession(response_for)
    _patch_network(monkeypatch, session)
    scanner = RavenVulnScanner(
        "https://example.test/search?q=normal", urls=["https://example.test/search?q=normal"],
        rate_limit=1000,
    )

    scanner._check_xss_and_sql()

    assert not [finding for finding in scanner.findings if finding.category == "sql_injection"]


def test_labeled_sql_fixtures_meet_precision_and_recall_gates(monkeypatch):
    url = "https://fixture.test/item?q=ordinary"
    fixtures = [
        {"label": True, "baseline": "normal page", "probes": [(500, "You have an error in your SQL syntax near input")] * 2},
        {"label": True, "baseline": "normal page", "probes": [(500, "SQLite error: malformed query")] * 2},
        {"label": True, "baseline": "normal page", "probes": [(500, "PostgreSQL syntax error at or near token")] * 2},
        {"label": True, "baseline": "normal page", "probes": [(500, "Unclosed quotation mark after the character string")] * 2},
        {"label": False, "baseline": "SQL syntax error from a static help page", "probes": [(200, "SQL syntax error from a static help page")] * 2},
        {"label": False, "baseline": "PostgreSQL version 16 documentation", "probes": [(200, "PostgreSQL version 16 documentation")] * 2},
        {"label": False, "baseline": "normal page", "probes": [(500, "SQL syntax error once"), (200, "normal page")]},
        {"label": False, "baseline": "normal page", "probes": [(500, "SQL syntax error repeats"), (502, "SQL syntax error repeats with gateway response")]},
    ]
    predictions = []

    for case in fixtures:
        probe_index = 0

        def make_response(request_url):
            nonlocal probe_index
            value = dict(parse_qsl(urlsplit(request_url).query)).get("q", "")
            if value == "ordinary":
                return FakeResponse(case["baseline"], status=200, url=request_url)
            if value.startswith("RAVENEYE_"):
                return FakeResponse("no reflection", status=200, url=request_url)
            status, body = case["probes"][probe_index]
            probe_index += 1
            return FakeResponse(body, status=status, url=request_url)

        session = FakeSession(make_response)
        _patch_network(monkeypatch, session)
        scanner = RavenVulnScanner(url, urls=[url], rate_limit=1000)
        scanner._check_xss_and_sql()
        predictions.append(any(f.category == "sql_injection" for f in scanner.findings))

    tp = sum(label and prediction for label, prediction in zip((case["label"] for case in fixtures), predictions))
    fp = sum(not label and prediction for label, prediction in zip((case["label"] for case in fixtures), predictions))
    fn = sum(label and not prediction for label, prediction in zip((case["label"] for case in fixtures), predictions))
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    assert tp == 4 and fp == 0 and fn == 0
    assert precision >= 0.95 and recall >= 0.90 and f1 == 1.0


def test_labeled_reflection_fixtures_only_report_unique_new_markers(monkeypatch):
    url = "https://fixture.test/item?q=ordinary"
    marker = f"RAVENEYE_{hashlib.sha1(f'{url}|q'.encode()).hexdigest()[:10]}"
    fixtures = [
        {"label": True, "baseline": "normal page", "probe": f"echo {marker}"},
        {"label": True, "baseline": "normal page", "probe": f"<p>{marker}</p>"},
        {"label": False, "baseline": "normal page", "probe": "static page"},
        {"label": False, "baseline": f"cached {marker}", "probe": f"cached {marker}"},
    ]
    predictions = []

    for case in fixtures:
        def make_response(request_url):
            value = dict(parse_qsl(urlsplit(request_url).query)).get("q", "")
            if value == "ordinary":
                return FakeResponse(case["baseline"], status=200, url=request_url)
            if value.startswith("RAVENEYE_"):
                return FakeResponse(case["probe"], status=200, url=request_url)
            return FakeResponse("normal response", status=200, url=request_url)

        session = FakeSession(make_response)
        _patch_network(monkeypatch, session)
        scanner = RavenVulnScanner(url, urls=[url], rate_limit=1000)
        scanner._check_xss_and_sql()
        predictions.append(any(f.category == "xss" for f in scanner.findings))

    labels = [case["label"] for case in fixtures]
    tp = sum(label and prediction for label, prediction in zip(labels, predictions))
    fp = sum(not label and prediction for label, prediction in zip(labels, predictions))
    fn = sum(label and not prediction for label, prediction in zip(labels, predictions))
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    assert (tp, fp, fn) == (2, 0, 0)
    assert (precision, recall, f1) == (1.0, 1.0, 1.0)
