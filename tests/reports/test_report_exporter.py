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
