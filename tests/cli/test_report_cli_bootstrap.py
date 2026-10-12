from pathlib import Path
import subprocess, sys
import os

ROOT = Path(__file__).resolve().parents[2]

def test_cli_report_lists_pdf_without_colorama():
    p = subprocess.run([sys.executable, str(ROOT/'RavenEye.py'), 'report', '--version'], capture_output=True, text=True)
    assert p.returncode == 0
    assert 'PDF' in p.stdout


def test_informational_cli_does_not_initialize_a_working_directory_database(tmp_path):
    env = os.environ.copy()
    p = subprocess.run(
        [sys.executable, str(ROOT / "RavenEye.py"), "report", "--version"],
        cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
    )
    assert p.returncode == 0, p.stderr
    assert "PDF" in p.stdout
    assert not (tmp_path / "data" / "raveneye.db").exists()
