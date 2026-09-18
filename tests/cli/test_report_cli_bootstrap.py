from pathlib import Path
import subprocess, sys

ROOT = Path(__file__).resolve().parents[2]

def test_cli_report_lists_pdf_without_colorama():
    p = subprocess.run([sys.executable, str(ROOT/'RavenEye.py'), 'report', '--version'], capture_output=True, text=True)
    assert p.returncode == 0
    assert 'PDF' in p.stdout

