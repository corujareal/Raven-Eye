from __future__ import annotations

"""Local health checks for venv/Termux deployments. No network access is performed."""
import importlib.util
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Any

CORE = (
    "aiohttp", "httpx", "aiosqlite", "rich", "click", "bs4", "dotenv",
)
OPTIONAL = (
    "pydantic", "yaml", "lxml", "sqlalchemy", "reportlab", "PIL",
    "playwright", "asyncssh", "aioftp", "aiosmtplib", "motor", "asyncpg",
    "aiomysql", "smbprotocol", "uvloop",
)

def _available(name: str) -> bool:
    return importlib.util.find_spec(name) is not None

def run_doctor(config: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = config or {}
    db = Path(str(cfg.get("database_path", "data/raveneye.db"))).expanduser()
    checks: dict[str, Any] = {
        "python": {"version": platform.python_version(), "supported": sys.version_info >= (3, 10)},
        "environment": {"termux": bool(os.environ.get("TERMUX_VERSION")), "venv": bool(os.environ.get("VIRTUAL_ENV")), "executable": sys.executable},
        "core_dependencies": {name: _available(name) for name in CORE},
        "optional_dependencies": {name: _available(name) for name in OPTIONAL},
        "filesystem": {
            "cwd_writable": os.access(Path.cwd(), os.W_OK),
            "database_parent_writable": os.access(db.parent if db.parent.exists() else db.parent.parent, os.W_OK),
            "chromium_cache": str(Path.home() / ".cache" / "ms-playwright"),
            "chromium_cache_exists": (Path.home() / ".cache" / "ms-playwright").exists(),
        },
        "tools": {"python3": shutil.which("python3"), "git": shutil.which("git"), "nmap": shutil.which("nmap")},
    }
    checks["ok"] = (
        checks["python"]["supported"]
        and all(checks["core_dependencies"].values())
        and checks["filesystem"]["cwd_writable"]
    )
    return checks

def render_doctor(result: dict[str, Any]) -> str:
    lines = ["RavenEye v6.6.6 — Doctor", "=" * 32]
    lines.append(f"Status: {'OK' if result.get('ok') else 'ATENÇÃO'}")
    lines.append(f"Python: {result['python']['version']} ({'OK' if result['python']['supported'] else 'incompatível'})")
    env = result['environment']
    lines.append(f"Ambiente: {'Termux' if env['termux'] else 'Linux/Unix'} | {'venv' if env['venv'] else 'sistema'}")
    missing = [k for k,v in result['core_dependencies'].items() if not v]
    lines.append("Dependências core: OK" if not missing else "Dependências ausentes: " + ", ".join(missing))
    optional = [k for k,v in result['optional_dependencies'].items() if v]
    lines.append("Opcionais disponíveis: " + (", ".join(optional) if optional else "nenhum"))
    fs = result['filesystem']
    lines.append(f"Diretório gravável: {'OK' if fs['cwd_writable'] else 'NÃO'}")
    lines.append(f"Playwright cache: {'presente' if fs['chromium_cache_exists'] else 'não instalado'}")
    return "\n".join(lines)
