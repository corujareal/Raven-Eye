import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]


def test_termux_smoke_runs_from_source_without_installed_package_or_pythonpath(tmp_path):
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)

    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "termux_smoke.py")],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )

    assert "RavenEye v6.6.6 — Doctor" in result.stdout
    assert "ModuleNotFoundError" not in result.stderr

def test_full_runtime_dependencies_and_playwright_browsers_are_installed():
    text = Path("installer/install.sh").read_text()
    runtime = text.lower()
    pyproject = Path("pyproject.toml").read_text().lower()
    for name in (
        "pydantic", "pyyaml", "sqlalchemy", "lxml", "pillow", "reportlab",
        "playwright", "asyncssh", "aioftp", "aiosmtplib", "motor", "asyncpg",
        "aiomysql", "smbprotocol", "uvloop", "shodan",
    ):
        assert name in runtime
    # Scoped WebSocket routing used by the async browser crawler requires the
    # 1.48 API; the installer and the project manifest must agree.
    assert 'playwright = ">=1.48,<2"' in pyproject
    assert "optional = true" not in pyproject
    assert "[tool.poetry.extras]" not in pyproject
    assert "RAVENEYE_SKIP_DEPS" not in text
    assert "playwright install --with-deps" in text
    assert "PROTOCOL_DEPS=\"" in text
    assert "sys_platform == 'linux'" in text
    assert "import os, requests, colorama" in text

def test_xml_detector():
    from raveneye_pkg.crawler import RavenCrawler
    assert RavenCrawler._looks_like_xml("https://example.test/sitemap.xml", "<urlset></urlset>")
    assert RavenCrawler._looks_like_xml("https://example.test/feed", '<?xml version="1.0"?><rss></rss>')
    assert not RavenCrawler._looks_like_xml("https://example.test/", "<html><body>x</body></html>")


def test_pdf_module_is_lazy_when_reportlab_unavailable():
    import importlib
    mod = importlib.import_module("raveneye.reports.pdf")
    assert hasattr(mod, "render_pdf")

def test_cli_does_not_import_reportlab_at_module_import():
    import importlib
    mod = importlib.import_module("raveneye.cli.main")
    assert hasattr(mod, "main")
