import json
import logging

from raveneye.core.logger import JsonlHandler, RedactionFilter, redact, redact_data
from raveneye.cli.log_viewer import _matches_category, _pdf_report_from_events, _safe_log_line, export_report_file


def test_redaction_hides_url_queries_and_keeps_docker_responses():
    marker = "DORK_PAYLOAD_SENTINEL"
    value = {
        "provider": "SearXNG local (Docker)",
        "dorks": [marker],
        "response": {"title": "Useful Docker response", "url": f"https://example.test/?q={marker}&view=api"},
    }
    cleaned = redact_data(value)
    rendered = json.dumps(cleaned, ensure_ascii=False)
    assert marker not in rendered
    assert cleaned["response"]["title"] == "Useful Docker response"
    assert "[QUERY OMITTED]" in rendered
    assert "%5BREDACTED%5D" in rendered
    assert "site%3Aexample.test" not in redact("https://example.test/search?site%3Aexample.test")
    assert marker not in redact(f"query: {marker}; token=private-value")
    secret_fields = redact_data({"api_key": "private-api-key", "nested": {"access_token": "private-token", "status": "connected"}})
    assert secret_fields["api_key"] == "[REDACTED]"
    assert secret_fields["nested"]["access_token"] == "[REDACTED]"
    assert secret_fields["nested"]["status"] == "connected"
    json_message = redact('{"api_key":"private-json-key","query":"site:example.test secret","response":"useful"}')
    assert "private-json-key" not in json_message and "site:example.test secret" not in json_message
    assert "useful" in json_message
    watched = _safe_log_line(json.dumps(value))
    assert marker not in watched
    assert "Useful Docker response" in watched


def test_legacy_log_export_redacts_old_dork_fields_and_query_urls(tmp_path):
    marker = "DORK_PAYLOAD_SENTINEL"
    source = tmp_path / "old.jsonl"
    source.write_text(json.dumps({
        "category": "dork search",
        "dork": marker,
        "response": "Docker returned a matching API document",
        "url": f"https://example.test/search?q={marker}",
    }) + "\n", encoding="utf-8")
    out = export_report_file(str(source), str(tmp_path / "safe"), "jsonl")
    text = out.read_text(encoding="utf-8")
    assert marker not in text
    assert "Docker returned a matching API document" in text


def test_legacy_logging_filter_redacts_before_file_handler(tmp_path):
    path = tmp_path / "events.jsonl"
    handler = JsonlHandler(path)
    handler.addFilter(RedactionFilter())
    record = logging.LogRecord("test", logging.WARNING, __file__, 1, "query=%s url=%s", ("site:example.test secret", "https://example.test/?q=private"), None)
    handler.handle(record)
    saved = path.read_text(encoding="utf-8")
    assert "site:example.test secret" not in saved
    assert "q=private" not in saved


def test_structured_scan_log_view_and_pdf_export_keep_event_types_distinct():
    rows = [
        {"schema_version": "1.0", "timestamp": "2026-10-09T12:00:00Z", "event": "scan.summary", "target": "example.test",
         "data": {"pages_crawled": 4, "endpoints": 8, "vulnerability_findings": {"by_stage": {"CONFIRMED": 1, "PROBABLE": 0, "POSSIBLE": 1}}}},
        {"schema_version": "1.0", "timestamp": "2026-10-09T12:00:01Z", "event": "vulnerability.confirmed", "target": "example.test",
         "data": {"name": "Confirmed fixture", "stage": "CONFIRMED", "severity": "HIGH", "url": "https://example.test/a"}},
        {"schema_version": "1.0", "timestamp": "2026-10-09T12:00:02Z", "event": "vulnerability.candidate", "target": "example.test",
         "data": {"name": "Possible fixture", "stage": "POSSIBLE", "severity": "INFO", "url": "https://example.test/b"}},
        {"schema_version": "1.0", "timestamp": "2026-10-09T12:00:03Z", "event": "search.summary", "target": "example.test",
         "data": {"provider": "SearXNG local (Docker)", "dorks_executados": 1, "total_bruto": 1, "total_em_escopo": 1}},
        {"schema_version": "1.0", "timestamp": "2026-10-09T12:00:04Z", "event": "search.response", "target": "example.test",
         "data": {"provider": "SearXNG local (Docker)", "titulo": "Docker response", "link": "https://example.test/.env", "snippet": "safe response"}},
        {"schema_version": "1.0", "timestamp": "2026-10-09T12:00:05Z", "event": "crawl.summary", "target": "example.test",
         "data": {"pages": 4, "endpoints": 8, "javascript_files": 2, "errors": 1, "javascript_urls": ["https://example.test/app.js"]}},
        {"schema_version": "1.0", "timestamp": "2026-10-09T12:00:06Z", "event": "surface.hint", "target": "example.test",
         "data": {"category": "backup_files", "url": "https://example.test/db.bak", "validation": "URL pattern only; endpoint response was not verified"}},
        {"schema_version": "1.0", "timestamp": "2026-10-09T12:00:07Z", "event": "javascript.secret_hint", "target": "example.test",
         "data": {"type": "API key pattern", "url": "https://example.test/app.js", "value": "[REDACTED]"}},
    ]

    assert sum(_matches_category(row, "scanner") for row in rows) == 3
    assert sum(_matches_category(row, "dorks") for row in rows) == 2
    assert sum(_matches_category(row, "crawler") for row in rows) == 2
    display = _safe_log_line(json.dumps(rows[4]))
    assert "Docker response" in display and "SearXNG local (Docker)" in display
    report = _pdf_report_from_events(rows, "events.jsonl")
    assert len(report["findings"]) == 2
    assert {item["stage"] for item in report["findings"]} == {"CONFIRMED", "POSSIBLE"}
    assert report["google_dorks_results"]["interessantes"][0]["titulo"] == "Docker response"
    assert report["surface"]["endpoints"] == 8
    assert report["surface"]["javascript_files"] == 2
    assert report["surface_hints"][0]["category"] == "backup_files"
    assert report["javascript_secrets"][0]["type"] == "API key pattern"


def test_log_viewer_removes_terminal_control_codes():
    line = json.dumps({"event": "other.event", "data": {"response": "clean\x1b[31m text\x9b31m"}}, ensure_ascii=False)
    rendered = _safe_log_line(line)
    assert "\x1b" not in rendered
    assert "\x9b" not in rendered
    assert "clean" in rendered and "text" in rendered
