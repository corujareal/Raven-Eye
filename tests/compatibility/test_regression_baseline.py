from pathlib import Path
import asyncio

def test_canonical_launcher_exists():
    assert Path("RavenEye.py").exists()

def test_report_does_not_contain_source_notes():
    text=Path("examples/sample_report.txt").read_text(encoding="utf-8").lower()
    assert "def " not in text
    assert "import " not in text
    assert "pyproject" not in text

def test_ssrf_is_fail_closed():
    text=Path("raveneye_pkg/network.py").read_text(encoding="utf-8")
    assert "return None, False" in text

def test_requirements_have_async_runtime():
    text=Path("installer/install.sh").read_text()
    for dep in ("aiohttp", "httpx", "aiosqlite", "pydantic"):
        assert dep in text

def test_scanner_is_distinct_from_crawler_menu():
    text=Path("raveneye_pkg/menus.py").read_text()
    assert "def _run_vulnerability_scanner" in text
    assert "_run_vulnerability_scanner(target, root_mode=root_mode)" in text

def test_no_7_version():
    for p in (Path("RavenEye.py"), Path("raveneye_pkg/constants.py")):
        assert "v7.0.0" not in p.read_text(encoding="utf-8")

def test_poetry_has_legacy_and_async_dependencies():
    text=Path("pyproject.toml").read_text(encoding="utf-8")
    for dep in ("requests", "aiohttp", "httpx", "aiosqlite", "pydantic"):
        assert dep in text

def test_optional_headless():
    text=Path("pyproject.toml").read_text(encoding="utf-8")
    assert "headless" in text and "optional = true" in text

def test_sudo_venv_bootstrap():
    text=Path("RavenEye.py").read_text(encoding="utf-8")
    assert ".venv" in text and "bin" in text and "python3" in text and "os.execv" in text
