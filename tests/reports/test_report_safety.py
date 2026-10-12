import asyncio
import json
from pathlib import Path

import pytest

from raveneye.database.async_repository import AsyncScanRepository
from raveneye.reports.html import render as html_render
from raveneye.reports.txt import render as txt_render
from raveneye.scanner.pipeline import _safe_active_findings
from raveneye_pkg.reports import _scan_event_records, save_scan_events
from raveneye_pkg import reports as report_exports, state
from raveneye.reports.dork_results import sanitize_dork_results


def test_report_does_not_contain_implementation_prompt_language():
    findings=[{'id':'xss.reflection','name':'User Input Reflected','severity':'INFO','confidence':'HIGH','url':'https://example.test/?q=x','evidence':'marker','remediation':'Encode output.'}]
    out=txt_render('https://example.test',findings)
    assert 'def ' not in out
    assert 'import ' not in out
    assert 'Implementation Notes' not in out
    assert 'RAVENEYE v6.6.6' in out


def test_html_report_has_no_external_dependency_and_has_clean_sections():
    out=html_render('https://example.test',[{'severity':'HIGH','name':'Test','url':'https://example.test/x','confidence':'HIGH'}])
    assert 'self-contained report' in out
    assert '<script src=' not in out
    assert 'RavenEye v6.6.6' in out
    assert '<th>Severity</th>' in out


def test_scan_event_log_keeps_docker_responses_and_real_finding_stages(tmp_path):
    payload = "DORK_PAYLOAD_SENTINEL"
    secret = "RAW_JS_SECRET_SENTINEL"
    report = {
        "target": {"domain": "example.test", "url": "https://example.test/start?token=private-target-token"},
        "elapsed": 12.5,
        "crawler": {"list": [{"url": "a"}, {"url": "b"}], "endpoints": ["https://example.test/api/x?token=private"],
                    "js_urls": ["https://example.test/app.js?signature=private"],
                    "js_route_templates": ["https://example.test/api/users/{param}"],
                    "metrics": {"requests": 9, "errors": 1}},
        "vulnerabilities": {"exposed_admin": ["https://example.test/admin"], "backup_files": ["https://example.test/db.bak"]},
        "secrets_js": [{"tipo": "API Key generica", "url": "https://example.test/app.js?token=private-js-url", "valor": secret, "severity": "ALTO"}],
        "google_dorks": [f"site:example.test filetype:env {payload}"],
        "google_dorks_results": {
            "provider": "SearXNG local (Docker)", "dorks_executados": 1,
            "total_bruto": 1, "total_em_escopo": 1, "total_interessantes": 1,
            "interessantes": [{
                "titulo": "Docker response title", "link": "https://example.test/.env",
                "snippet": "Docker response body summary", "provider": "SearXNG local (Docker)",
                "motivo": "arquivo potencialmente sensível", "confidence": "alta", "score": 6,
                "evidencias": ["extensão ou caminho sensível na URL"], "confirmed": False,
                "engines": "fixture-engine",
            }],
        },
        "asset_intelligence": {"censys": {"status": "connected", "http_status": 200, "message": "fixture summary"}},
        "vulnerability_scan": {"findings": [
            {"id": "confirmed.fixture", "name": "Confirmed fixture", "severity": "HIGH", "stage": "CONFIRMED",
             "confidence": "HIGH", "confidence_score": 96, "url": "https://example.test/api?token=secret-url-value",
             "evidence_metadata": {"schema_version": "1.0", "source": "fixture", "request": {"method": "GET", "sha256": "a" * 64},
                                   "response": {"status": 200, "sha256": "b" * 64, "body_sha256": "c" * 64}}},
            {"id": "possible.fixture", "name": "Possible fixture", "severity": "INFO", "stage": "POSSIBLE", "confidence": "LOW"},
        ]},
    }

    records = _scan_event_records(report)
    out = tmp_path / "RavenEye_events.jsonl"
    save_scan_events(report, str(out))
    text = out.read_text(encoding="utf-8")
    parsed = [json.loads(line) for line in text.splitlines()]
    summary = next(row["data"] for row in parsed if row["event"] == "scan.summary")
    assert summary["vulnerability_findings"]["by_stage"] == {"CONFIRMED": 1, "PROBABLE": 0, "POSSIBLE": 1}
    assert summary["api_integrations"]["censys"]["status"] == "connected"
    assert any(row["event"] == "search.response" and row["data"]["titulo"] == "Docker response title" for row in parsed)
    assert any(row["event"] == "vulnerability.confirmed" for row in parsed)
    assert any(row["event"] == "vulnerability.candidate" for row in parsed)
    assert any(row["event"] == "javascript.secret_hint" and row["data"]["value"] == "[REDACTED]" for row in parsed)
    crawl = next(row["data"] for row in parsed if row["event"] == "crawl.summary")
    assert crawl["pages"] == 2 and crawl["requests"] == 9
    assert crawl["javascript_route_templates"] == 1
    assert crawl["javascript_route_template_examples"] == ["https://example.test/api/users/{param}"]
    assert "private" not in json.dumps(crawl)
    hints = [row for row in parsed if row["event"] == "surface.hint"]
    assert len(hints) == 2
    assert "not verified" in hints[0]["data"]["validation"]
    assert not any(row["event"] == "vulnerability.confirmed" and "admin" in json.dumps(row) for row in parsed)
    assert payload not in text
    assert "private-target-token" not in text
    assert "secret-url-value" not in text
    assert secret not in text and "private-js-url" not in text
    assert "Docker response body summary" in text
    assert "https://example.test/app.js?signature=%5Bredacted%5D" in text
    assert len(records) == len(parsed)
    assert out.stat().st_mode & 0o077 == 0


def test_dork_response_export_omits_query_echo_and_unscoped_results():
    payload = "DORK_PAYLOAD_SENTINEL"
    query = f"site:example.test filetype:env {payload}"
    report = {
        "target": {"domain": "example.test"},
        "google_dorks": [query],
        "google_dorks_results": {
            "provider": "SearXNG local (Docker)", "dorks_executados": 1,
            "total_bruto": 2, "interessantes": [
                {"titulo": f"Engine echoed: {query}", "link": "https://example.test/.env",
                 "snippet": f"Response contained {query}", "confidence": "alta", "confirmed": True},
                {"titulo": "Out of scope", "link": "https://elsewhere.test/.env", "snippet": "drop this"},
            ],
        },
    }
    exported = sanitize_dork_results(report)
    text = json.dumps(exported, ensure_ascii=False)
    assert payload not in text
    assert "Engine echoed" in text
    assert "Out of scope" not in text
    assert exported["total_interessantes"] == 1
    assert exported["interessantes"][0]["confirmed"] is False


def test_legacy_report_formats_keep_search_responses_and_redact_query_values(tmp_path):
    query_marker = "DORK_PAYLOAD_SENTINEL"
    js_secret = "RAW_JS_SECRET_SENTINEL"
    report = {
        "target": {"domain": "example.test", "url": "https://example.test/start?token=target-secret"},
        "crawler": {
            "list": [{"url": "https://example.test/?q=page-secret"}],
            "all_urls": ["https://example.test/path?q=crawl-secret"],
            "endpoints": ["https://example.test/api?token=endpoint-secret"],
        },
        "google_dorks": [f"site:example.test {query_marker}"],
        "google_dorks_results": {
            "provider": "SearXNG local (Docker)", "dorks_executados": 1,
            "total_bruto": 1, "total_em_escopo": 1, "total_interessantes": 1,
            "interessantes": [{
                "titulo": "Docker response", "link": "https://example.test/.env",
                "snippet": "Safe engine response", "confidence": "alta",
                "provider": "SearXNG local (Docker)", "motivo": "arquivo potencialmente sensível",
            }],
        },
        "secrets_js": [{"tipo": "API key pattern", "url": "https://example.test/app.js?token=js-url-secret", "valor": js_secret}],
    }

    outputs = {
        "txt": tmp_path / "scan.txt", "json": tmp_path / "scan.json",
        "csv": tmp_path / "scan.csv", "wordlist": tmp_path / "urls.txt",
        "endpoints": tmp_path / "endpoints.txt",
    }
    report_exports.save_report(report, str(outputs["txt"]), 200)
    report_exports.save_report_json(report, str(outputs["json"]))
    report_exports.save_report_csv(report, str(outputs["csv"]))
    report_exports.save_wordlist(report, str(outputs["wordlist"]))
    report_exports.save_endpoints(report, str(outputs["endpoints"]))

    for path in outputs.values():
        text = path.read_text(encoding="utf-8")
        assert query_marker not in text and js_secret not in text
        for private_value in ("target-secret", "page-secret", "crawl-secret", "endpoint-secret", "js-url-secret"):
            assert private_value not in text
    for name in ("txt", "json", "csv"):
        text = outputs[name].read_text(encoding="utf-8")
        assert "Docker response" in text and "Safe engine response" in text
    parsed = json.loads(outputs["json"].read_text(encoding="utf-8"))
    assert parsed["summary"]["google_dorks"] == 1
    assert parsed["findings"]["secrets_js"][0]["valor"] == "[REDACTED]"


def test_event_and_text_reports_survive_missing_pdf_backend(tmp_path, monkeypatch, capsys):
    base = str(tmp_path / "RavenEye_fixture")
    calls = []
    for name in (
        "save_report", "save_wordlist", "save_endpoints", "save_report_json",
        "save_report_html", "save_report_markdown", "save_report_csv", "save_release_audit",
    ):
        monkeypatch.setattr(report_exports, name, lambda *args, _name=name: calls.append(_name))
    monkeypatch.setattr(report_exports, "save_dorks_file", lambda *args: calls.append("save_dorks_file"))
    monkeypatch.setattr(report_exports, "save_report_pdf", lambda *_args: (_ for _ in ()).throw(RuntimeError("PDF fixture failure")))
    monkeypatch.setattr(state, "config", {"report_link_limit": 200})
    monkeypatch.setattr(state, "QUIET_MODE", True)

    report_exports.save_all_reports({"target": {"domain": "fixture.test"}, "vulnerability_scan": {"findings": []}}, base)

    event_file = Path(base + "_events.jsonl")
    assert event_file.is_file()
    assert "save_dorks_file" in calls
    assert str(event_file) in capsys.readouterr().out

@pytest.mark.asyncio
async def test_safe_active_checks_report_reflection_without_claiming_xss():
    async def fake_request(url):
        from urllib.parse import parse_qs, urlsplit
        value=parse_qs(urlsplit(url).query).get('q',[''])[0]
        if value == "'":
            return 'SQL syntax error near q'
        return f'<html>{value}</html>'
    findings=await _safe_active_findings('https://example.test/?q=hello','<html>hello</html>',None,fake_request)
    ids={f['id'] for f in findings}
    assert 'xss.reflection' in ids
    assert 'sqli.error-differential' in ids
    assert not any(f['name'].lower().startswith('confirmed xss') for f in findings)


@pytest.mark.asyncio
async def test_safe_active_report_redacts_probe_values_from_urls_and_evidence():
    from urllib.parse import parse_qs, urlsplit

    seen_values = []

    async def fake_request(url):
        value = parse_qs(urlsplit(url).query).get("q", [""])[0]
        seen_values.append(value)
        if value == "'":
            return {"body": "ordinary response", "status": 200}
        return {"body": f"reflected value: {value}", "status": 200}

    findings = await _safe_active_findings(
        "https://example.test/search?q=original-value",
        "ordinary response", type("Response", (), {"status": 200, "headers": {}})(),
        fake_request,
    )

    serialized = json.dumps(findings, ensure_ascii=False)
    assert any(value.startswith("RAVENEYE_") for value in seen_values)
    assert "RAVENEYE_" not in serialized
    assert "original-value" not in serialized
    assert "[redacted]" in serialized or "%5Bredacted%5D" in serialized


@pytest.mark.asyncio
async def test_safe_active_sql_rejects_unstable_repeated_error():
    responses = iter([
        {"body": "normal page", "status": 200},
        {"body": "SQL syntax error near quote", "status": 500},
        {"body": "SQL syntax error near quote with unrelated gateway text", "status": 502},
    ])

    async def fake_request(_url):
        return next(responses)

    findings = await _safe_active_findings(
        "https://example.test/?q=hello", "normal page", type("Response", (), {"status": 200, "headers": {}})(),
        fake_request,
    )
    assert not any(item["id"] == "sqli.error-differential" for item in findings)

@pytest.mark.asyncio
async def test_finding_history_persists_across_scans(tmp_path):
    repo=AsyncScanRepository(tmp_path/'raven.db')
    finding={'id':'demo','name':'Demo Finding','severity':'MEDIUM','confidence':'HIGH','url':'https://example.test/x'}
    await repo.save_scan('https://example.test',[finding],4.0)
    await repo.save_scan('https://example.test',[finding],4.0)
    history=await repo.finding_history('https://example.test')
    assert len(history)==1
    assert history[0]['occurrences']==2
