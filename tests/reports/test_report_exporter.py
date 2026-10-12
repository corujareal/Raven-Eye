from pathlib import Path
import pytest
from raveneye.cli.log_viewer import export_report_file


def test_pdf_source_only_exports_to_pdf(tmp_path: Path):
    src = tmp_path / "report.pdf"
    src.write_bytes(b"%PDF-1.4\nminimal test fixture\n%%EOF\n")
    out = export_report_file(str(src), str(tmp_path / "copy.pdf"), "pdf")
    assert out.suffix == ".pdf"
    assert out.read_bytes().startswith(b"%PDF")

    with pytest.raises(ValueError):
        export_report_file(str(src), str(tmp_path / "bad.csv"), "csv")


def test_export_report_accepts_report_catalog_extensions(tmp_path: Path):
    for suffix in (".txt", ".json", ".jsonl", ".html", ".csv", ".md"):
        src = tmp_path / f"RavenEye_sample{suffix}"
        src.write_text("category,content\nINFO,fixture\n", encoding="utf-8")
        out = export_report_file(str(src), str(tmp_path / f"out{suffix}"), "jsonl")
        assert out.suffix == ".jsonl"
        assert out.read_text(encoding="utf-8").strip()


def test_json_scan_report_pdf_keeps_scan_sections_and_omits_dork_payload(tmp_path: Path, monkeypatch):
    import json
    import raveneye.reports.pdf as pdf
    import raveneye_pkg.reports as report_exports

    marker = "DORK_PAYLOAD_SENTINEL"
    source = tmp_path / "scan_report.json"
    source.write_text(json.dumps({
        "target": {"domain": "example.test"},
        "google_dorks": [f"site:example.test {marker}"],
        "google_dorks_results": {
            "provider": "SearXNG local (Docker)", "dorks_executados": 1,
            "total_bruto": 1, "interessantes": [{
                "titulo": f"Docker response: site:example.test {marker}", "link": "https://example.test/.env",
                "snippet": f"Filtered response echo: site:example.test {marker}", "confidence": "alta",
            }],
        },
        "vulnerability_scan": {"findings": [{
            "name": "Confirmed fixture", "severity": "HIGH", "stage": "CONFIRMED",
            "url": "https://example.test/security?token=private-value",
        }]},
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    rendered = {}

    def fake_render(report, filename):
        rendered.update(report)
        Path(filename).write_bytes(b"%PDF-1.4\nfixture\n")

    monkeypatch.setattr(pdf, "render_pdf", fake_render)
    monkeypatch.setattr(report_exports, "_publish_pdf_for_easy_access", lambda _path: None)

    output = export_report_file(str(source), str(tmp_path / "scan_export"), "pdf")

    serialized = json.dumps(rendered, ensure_ascii=False)
    assert output.read_bytes().startswith(b"%PDF")
    assert marker not in serialized and "private-value" not in serialized
    assert rendered["google_dorks_results"]["interessantes"][0]["titulo"].startswith("Docker response:")
    assert "[CONSULTA OMITIDA]" in serialized
    assert rendered["vulnerability_scan"]["findings"][0]["stage"] == "CONFIRMED"
