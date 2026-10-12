import json

from raveneye_pkg import scanners
from raveneye_pkg.reports import (
    save_dorks_file,
    save_report,
    save_report_csv,
    save_report_html,
    save_report_json,
    save_report_markdown,
)


def test_searxng_results_are_scoped_and_response_secrets_redacted(monkeypatch):
    requests_seen = []

    class Response:
        status_code = 200

        def json(self):
            return {"results": [
                {
                    "title": f"Potential API listing — site:example.test {marker}",
                    "url": "https://example.test/api?access_token=private-token&view=public#fragment",
                    "content": f"site:example.test {marker}; api_key=secret-value-1234&access_token%3Dencoded-secret-5678",
                    "engines": ["fixture"],
                },
                {"title": "out of scope", "url": "https://example.test.attacker.invalid/leak", "content": ""},
                {"title": "query echo", "url": f"https://example.test/search?q=site%3Aexample.test+{marker}", "content": ""},
            ]}

    class Session:
        trust_env = True

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def post(self, url, **kwargs):
            requests_seen.append((url, kwargs, self.trust_env))
            return Response()

    monkeypatch.setattr(scanners.requests, "Session", Session)
    marker = "DORK_PAYLOAD_SENTINEL"
    result = scanners.run_searxng_dorks_search([f"site:example.test {marker}"], "example.test")

    assert result["total_bruto"] == 3
    assert result["total_em_escopo"] == 1
    assert result["total_fora_de_escopo"] == 1
    assert result["total_payload_echoes_omitidos"] == 1
    assert result["interessantes"][0]["link"] == "https://example.test/api?access_token=%5BREDACTED%5D&view=public"
    assert "secret-value-1234" not in result["interessantes"][0]["snippet"]
    assert "encoded-secret-5678" not in result["interessantes"][0]["snippet"]
    assert marker not in result["interessantes"][0]["titulo"]
    assert marker not in result["interessantes"][0]["snippet"]
    assert "fragment" not in result["interessantes"][0]["link"]
    assert requests_seen[0][0] == "http://127.0.0.1:8080/search"
    assert requests_seen[0][1]["allow_redirects"] is False
    assert requests_seen[0][1]["data"]["q"].endswith(marker)
    assert "?" not in requests_seen[0][0]
    assert requests_seen[0][2] is False


def test_dork_payloads_never_reach_supported_report_exports(tmp_path):
    marker = "DORK_PAYLOAD_SENTINEL"
    report = {
        "target": {"domain": "example.test"},
        "crawler": {},
        "google_dorks": [f'site:example.test "{marker}"'],
        "google_dorks_results": {
            "provider": "SearXNG local (Docker)",
            "dorks_executados": 1,
            "total_bruto": 1,
            "total_em_escopo": 1,
            "total_fora_de_escopo": 0,
            "total_duplicados": 0,
            "interessantes": [{
                "titulo": "<script>alert('inert')</script> API documentation",
                "link": "https://example.test/openapi?token=secret-token",
                "snippet": f'site:example.test "{marker}" API endpoint ![x](javascript:alert(2)) documentation',
                "provider": "SearXNG local (Docker)",
                "motivo": "documentação ou endpoint de API",
                "confidence": "média",
                "score": 3,
                "evidencias": ["caminho de API reconhecível"],
                "confirmed": False,
                "dork": marker,
            }],
            "erros": [marker],
        },
    }
    paths = {
        "json": tmp_path / "report.json",
        "txt": tmp_path / "report.txt",
        "html": tmp_path / "report.html",
        "markdown": tmp_path / "report.md",
        "csv": tmp_path / "report.csv",
        "dorks": tmp_path / "dork-responses.txt",
    }
    save_report_json(report, str(paths["json"]))
    save_report(report, str(paths["txt"]), 30)
    save_report_html(report, str(paths["html"]))
    save_report_markdown(report, str(paths["markdown"]))
    save_report_csv(report, str(paths["csv"]))
    save_dorks_file(report, str(paths["dorks"]))

    for path in paths.values():
        text = path.read_text(encoding="utf-8")
        assert marker not in text
        assert "secret-token" not in text
        if path.suffix in {".html", ".md"}:
            assert "<script>" not in text
        if path.suffix == ".md":
            assert "![x]" not in text
    data = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert "google_dorks" not in data["findings"]
    assert "dork" not in data["findings"]["google_dorks_results"]["interessantes"][0]


def test_dork_export_drops_results_when_target_scope_is_missing(tmp_path):
    report = {
        "google_dorks_results": {
            "provider": "SearXNG local (Docker)",
            "interessantes": [{"link": "https://attacker.example/leak", "snippet": "response"}],
        },
    }
    path = tmp_path / "report.json"
    save_report_json(report, str(path))
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["findings"]["google_dorks_results"]["interessantes"] == []


def test_asset_api_statuses_and_compact_data_appear_in_text_report(tmp_path):
    path = tmp_path / "report.txt"
    html_path = tmp_path / "report.html"
    markdown_path = tmp_path / "report.md"
    report = {
        "target": {"domain": "example.test", "ip": "203.0.113.8"},
        "crawler": {"list": [], "endpoints": [], "file_urls": []},
        "asset_intelligence": {
            "censys": {
                "provider": "Censys", "status": "organization_id_required",
                "message": "Configure CENSYS_ORGANIZATION_ID.",
            },
            "netlas": {
                "provider": "Netlas", "status": "ok<script>", "http_status": 200,
                "data": {
                    "ip": "203.0.113.8", "ports": [443, 8443],
                    "banner": "must not be serialized",
                },
            },
            "leakix": {"provider": "LeakIX", "status": "rate_limited", "http_status": 429},
        },
    }

    save_report(report, str(path), 30)
    save_report_html(report, str(html_path))
    save_report_markdown(report, str(markdown_path))

    output = path.read_text(encoding="utf-8")
    assert "INTELIGENCIA DE ATIVOS" in output
    assert "Censys: organization_id_required" in output
    assert "Netlas: ok<script> | HTTP 200" in output
    assert "ports: 443, 8443" in output
    assert "LeakIX: rate_limited | HTTP 429" in output
    assert "must not be serialized" not in output

    html_output = html_path.read_text(encoding="utf-8")
    assert "Inteligência de ativos — APIs" in html_output
    assert "&lt;script&gt;" in html_output
    assert "<td>ok<script></td>" not in html_output
    assert "must not be serialized" not in html_output

    markdown_output = markdown_path.read_text(encoding="utf-8")
    assert "Inteligência de ativos — APIs" in markdown_output
    assert "ok&lt;script&gt;" in markdown_output
    assert "must not be serialized" not in markdown_output
