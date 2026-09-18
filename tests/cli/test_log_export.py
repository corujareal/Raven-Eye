import asyncio
import json
from pathlib import Path

from raveneye.cli.log_viewer import export_category, safe_delete


def test_safe_delete_requires_exact_confirmation_and_moves(tmp_path):
    src = tmp_path / "raveneye.log"
    src.write_text("hello\n", encoding="utf-8")
    try:
        safe_delete(str(src), trash=str(tmp_path / ".trash"), confirmation="sim")
    except PermissionError:
        pass
    else:
        raise AssertionError("delete must require exact SIM confirmation")
    dest = safe_delete(str(src), trash=str(tmp_path / ".trash"), confirmation="SIM")
    assert not src.exists()
    assert dest.exists()
    assert dest.read_text(encoding="utf-8") == "hello\n"


def test_export_category_supports_csv_and_jsonl(tmp_path):
    src = tmp_path / "raveneye.log"
    rows = [
        {"category": "scanner", "severity": "HIGH", "id": 1},
        {"category": "crawler", "severity": "INFO", "id": 2},
    ]
    src.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    csv_out = export_category(str(src), "scanner", str(tmp_path / "out.csv"))
    json_out = export_category(str(src), "scanner", str(tmp_path / "out.jsonl"))
    assert csv_out.exists() and "HIGH" in csv_out.read_text(encoding="utf-8")
    exported = json_out.read_text(encoding="utf-8").splitlines()
    assert len(exported) == 1 and json.loads(exported[0])["id"] == 1


def test_pdf_export_appends_pdf_extension_and_is_real_pdf(tmp_path):
    src = tmp_path / "raveneye.log"
    src.write_text(json.dumps({"category": "scanner", "severity": "HIGH", "event": "synthetic"}) + "\n", encoding="utf-8")
    out = export_category(str(src), "scanner", str(tmp_path / "report"), fmt="pdf")
    assert out.name == "report.pdf"
    assert out.exists() and out.stat().st_size > 0
    assert out.read_bytes()[:4] == b"%PDF"


def test_pdf_export_never_writes_pdf_bytes_to_wrong_extension(tmp_path):
    src = tmp_path / "raveneye.log"
    src.write_text(json.dumps({"category": "scanner", "severity": "INFO", "event": "synthetic"}) + "\n", encoding="utf-8")
    out = export_category(str(src), "scanner", str(tmp_path / "report.txt"), fmt="pdf")
    assert out.name == "report.pdf"
    assert not (tmp_path / "report.txt").exists()
    assert out.read_bytes()[:4] == b"%PDF"


def test_guided_report_export_handles_plain_text(tmp_path):
    from raveneye.cli.log_viewer import export_report_file
    src = tmp_path / "RavenEye_report.txt"
    src.write_text("RAVENEYE REPORT\nHIGH finding\n", encoding="utf-8")
    csv_out = export_report_file(str(src), str(tmp_path / "exported"), "csv")
    assert csv_out.suffix == ".csv" and "HIGH finding" in csv_out.read_text(encoding="utf-8")
    json_out = export_report_file(str(src), str(tmp_path / "exported2"), "jsonl")
    assert json_out.suffix == ".jsonl" and "HIGH finding" in json_out.read_text(encoding="utf-8")
    pdf_out = export_report_file(str(src), str(tmp_path / "exported3"), "pdf")
    assert pdf_out.suffix == ".pdf" and pdf_out.read_bytes()[:4] == b"%PDF"
