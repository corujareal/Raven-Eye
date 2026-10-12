from __future__ import annotations

"""Local health checks for the complete RavenEye runtime. No network access."""
import importlib.util
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Any

from raveneye.core.browser import chromium_runtime_smoke, system_chromium_executable


# Import names are mapped explicitly to distribution names because PyPI and
# Python often spell a package differently (Pillow/PIL, PyYAML/yaml,
# beautifulsoup4/bs4). The dependency manifest tests require every runtime
# dependency in pyproject.toml to appear here and in installer/install.sh.
RUNTIME_IMPORTS_BY_DISTRIBUTION: dict[str, tuple[str, ...]] = {
    "requests": ("requests",),
    "pysocks": ("socks",),
    "aiohttp": ("aiohttp",),
    "httpx": ("httpx",),
    "pydantic": ("pydantic",),
    "pydantic-settings": ("pydantic_settings",),
    "pyyaml": ("yaml",),
    "rich": ("rich",),
    "colorama": ("colorama",),
    "click": ("click",),
    "beautifulsoup4": ("bs4",),
    "lxml": ("lxml",),
    "aiosqlite": ("aiosqlite",),
    "sqlalchemy": ("sqlalchemy",),
    "playwright": ("playwright",),
    "python-dotenv": ("dotenv",),
    "dnspython": ("dns",),
    "python-whois": ("whois",),
    "pyjwt": ("jwt",),
    "jsbeautifier": ("jsbeautifier",),
    "tqdm": ("tqdm",),
    "reportlab": ("reportlab",),
    "pillow": ("PIL",),
    "shodan": ("shodan",),
    "asyncssh": ("asyncssh",),
    "aioftp": ("aioftp",),
    "aiosmtplib": ("aiosmtplib",),
    "motor": ("motor",),
    "asyncpg": ("asyncpg",),
    "aiomysql": ("aiomysql",),
    "smbprotocol": ("smbprotocol",),
    "uvloop": ("uvloop",),  # Linux only, matching pyproject's marker.
}
REQUIRED_DEPENDENCIES = tuple(
    module
    for distribution, modules in RUNTIME_IMPORTS_BY_DISTRIBUTION.items()
    if distribution != "uvloop"
    for module in modules
)
REQUIRED_PLAYWRIGHT_BROWSERS: tuple[str, ...] = ()
OPTIONAL_PLAYWRIGHT_BROWSERS = ("chromium",)


def _available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _browser_locations() -> list[Path]:
    """Return installer and standard Playwright cache locations."""
    configured = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    locations = [Path(configured).expanduser()] if configured else []
    package_root = Path(__file__).resolve().parents[1]
    locations.extend((package_root / ".playwright-browsers", Path.home() / ".cache" / "ms-playwright"))
    return list(dict.fromkeys(locations))


def _playwright_browser_executables() -> dict[str, Path]:
    """Ask the installed Playwright version for its exact browser binaries.

    Directory names alone are not evidence of an installed browser: an
    interrupted download can leave an empty ``chromium-*`` directory behind.
    Playwright's public ``executable_path`` property resolves the version and
    cache location used by the current runtime.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {}
    try:
        with sync_playwright() as playwright:
            return {
                engine: Path(getattr(playwright, engine).executable_path)
                for engine in ("chromium", "firefox", "webkit")
            }
    except Exception:
        # Doctor is also a bootstrap diagnostic. A broken/missing driver should
        # be reported as unavailable capability rather than crash the CLI.
        return {}


def _is_browser_executable(path: Path | None) -> bool:
    if path is None:
        return False
    try:
        return path.is_file() and (os.name == "nt" or os.access(path, os.X_OK))
    except OSError:
        return False


def _browser_inventory() -> dict[str, bool]:
    executables = _playwright_browser_executables()
    inventory = {
        engine: _is_browser_executable(executables.get(engine))
        for engine in ("chromium", "firefox", "webkit")
    }
    if not inventory["chromium"]:
        inventory["chromium"] = system_chromium_executable() is not None
    return inventory


def run_doctor(config: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = config or {}
    db = Path(str(cfg.get("database_path", "data/raveneye.db"))).expanduser()
    dependencies = {name: _available(name) for name in REQUIRED_DEPENDENCIES}
    if sys.platform == "linux":
        dependencies["uvloop"] = _available("uvloop")
    browsers = _browser_inventory()
    headless_configured = bool(cfg.get("headless_rendering", False)) or (
        os.environ.get("RAVENEYE_HEADLESS_RENDERING", "").strip().lower()
        in {"1", "true", "yes", "on"}
    )
    headless_available, headless_diagnostic = chromium_runtime_smoke()
    checks: dict[str, Any] = {
        "python": {
            "version": platform.python_version(),
            "supported": (3, 10) <= sys.version_info[:2] < (3, 15),
        },
        "environment": {
            "termux": bool(os.environ.get("TERMUX_VERSION") or "com.termux" in os.environ.get("PREFIX", "")),
            "venv": bool(os.environ.get("VIRTUAL_ENV")),
            "executable": sys.executable,
        },
        "runtime_dependencies": dependencies,
        "playwright_browsers": browsers,
        "required_playwright_browsers": list(REQUIRED_PLAYWRIGHT_BROWSERS),
        "optional_playwright_browsers": list(OPTIONAL_PLAYWRIGHT_BROWSERS),
        "headless_rendering": {
            "configured": headless_configured,
            "available": headless_available,
            "optional": True,
            "diagnostic": headless_diagnostic,
        },
        "system_chromium": system_chromium_executable(),
        "filesystem": {
            "cwd_writable": os.access(Path.cwd(), os.W_OK),
            "database_parent_writable": os.access(db.parent if db.parent.exists() else db.parent.parent, os.W_OK),
            "browser_locations": [str(path) for path in _browser_locations()],
        },
        "tools": {"python3": shutil.which("python3"), "git": shutil.which("git"), "nmap": shutil.which("nmap")},
    }
    checks["ok"] = (
        checks["python"]["supported"]
        and all(dependencies.values())
        and all(browsers.get(engine, False) for engine in REQUIRED_PLAYWRIGHT_BROWSERS)
        and (headless_available or not headless_configured)
        and checks["filesystem"]["cwd_writable"]
    )
    return checks


def render_doctor(result: dict[str, Any]) -> str:
    lines = ["RavenEye v6.6.6 — Doctor", "=" * 32]
    lines.append(f"Status: {'OK' if result.get('ok') else 'INCOMPLETO'}")
    lines.append(f"Python: {result['python']['version']} ({'OK' if result['python']['supported'] else 'incompatível'})")
    env = result['environment']
    lines.append(f"Ambiente: {'Termux' if env['termux'] else 'Unix'} | {'venv' if env['venv'] else 'sistema'}")
    missing = [name for name, available in result['runtime_dependencies'].items() if not available]
    lines.append("Dependências runtime: OK" if not missing else "Dependências ausentes: " + ", ".join(missing))
    browsers = result['playwright_browsers']
    browser_summary = ", ".join(f"{name}={'OK' if present else 'AUSENTE'}" for name, present in browsers.items())
    lines.append("Playwright: " + browser_summary)
    if result.get("system_chromium"):
        lines.append(f"Chromium do sistema: {result['system_chromium']}")
    headless = result.get("headless_rendering", {})
    if headless.get("available"):
        lines.append("Chromium headless: executável encontrado")
    elif headless.get("configured"):
        lines.append("Chromium headless: NÃO INICIADO, mas exigido pela configuração")
        if headless.get("diagnostic"):
            lines.append(f"Diagnóstico headless: {headless['diagnostic']}")
    else:
        lines.append("Chromium headless: opcional e indisponível; crawler estático permanece disponível")
    fs = result['filesystem']
    lines.append(f"Diretório atual gravável: {'OK' if fs['cwd_writable'] else 'NÃO'}")
    lines.append("Cache de browsers: " + ", ".join(fs["browser_locations"]))
    return "\n".join(lines)
