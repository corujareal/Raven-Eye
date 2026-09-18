from pathlib import Path
from raveneye_pkg.reports import _publish_pdf_for_easy_access

def test_publish_pdf_for_easy_access(tmp_path):
    src = tmp_path / 'scan_report.pdf'
    src.write_bytes(b'%PDF-1.4\nTEST')
    dest_dir = tmp_path / 'reports' / 'PDF'
    dest = Path(_publish_pdf_for_easy_access(str(src), str(dest_dir)))
    assert dest.is_file()
    assert dest.read_bytes().startswith(b'%PDF')
    assert (dest_dir / 'LATEST.pdf').is_file()
    assert (dest_dir / 'LATEST.pdf').read_bytes().startswith(b'%PDF')
    assert 'scan_report.pdf' in (dest_dir / 'INDEX.txt').read_text(encoding='utf-8')
