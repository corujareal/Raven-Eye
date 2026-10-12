from pathlib import Path
import asyncio
import re

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
    assert "scope_domains=scanner_scope" in text

def test_no_7_version():
    for p in (Path("RavenEye.py"), Path("raveneye_pkg/constants.py")):
        assert "v7.0.0" not in p.read_text(encoding="utf-8")

def test_poetry_has_legacy_and_async_dependencies():
    text=Path("pyproject.toml").read_text(encoding="utf-8")
    for dep in ("requests", "aiohttp", "httpx", "aiosqlite", "pydantic"):
        assert dep in text

def test_full_runtime_dependencies_are_mandatory():
    import tomllib

    manifest = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    dependencies = {name.lower().replace("_", "-") for name in manifest["tool"]["poetry"]["dependencies"]}
    installer = Path("installer/install.sh").read_text(encoding="utf-8").lower()
    for distribution in (
        "pydantic", "pyyaml", "lxml", "sqlalchemy", "reportlab", "pillow", "playwright",
        "asyncssh", "aioftp", "aiosmtplib", "motor", "asyncpg", "aiomysql", "smbprotocol", "uvloop",
    ):
        assert distribution in dependencies
        assert distribution in installer
    assert "optional = true" not in Path("pyproject.toml").read_text(encoding="utf-8")
    assert "playwright install --with-deps" in installer


def test_installer_covers_every_pyproject_runtime_and_dev_dependency():
    import tomllib

    manifest = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    expected = set(manifest["tool"]["poetry"]["dependencies"])
    expected.update(manifest["tool"]["poetry"]["group"]["dev"]["dependencies"])
    expected.discard("python")
    canonical = lambda name: re.sub(r"[-_.]+", "-", name).lower()
    expected = {canonical(name) for name in expected}

    installer = Path("installer/install.sh").read_text(encoding="utf-8")
    sections = re.findall(
        r"(?ms)^(?:CORE_DEPS|FULL_DEPS|PROTOCOL_DEPS|TEST_DEPS)=(?:'|\")\n(.*?)\n(?:'|\")",
        installer,
    )
    installed = set()
    for section in sections:
        for line in section.splitlines():
            requirement = line.strip().split(maxsplit=1)[0] if line.strip() else ""
            if requirement and not requirement.startswith("#"):
                name = re.match(r"[A-Za-z0-9._-]+", requirement)
                if name:
                    installed.add(canonical(name.group(0)))

    assert sections
    assert expected <= installed

def test_sudo_venv_bootstrap():
    text=Path("RavenEye.py").read_text(encoding="utf-8")
    assert ".venv" in text and "bin" in text and "python3" in text and "os.execv" in text
