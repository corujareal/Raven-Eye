"""Chromium launch helpers with a distro-native executable fallback."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
from typing import Any


_SYSTEM_CHROMIUM_NAMES = (
    "chromium",
    "chromium-browser",
    "google-chrome-stable",
    "google-chrome",
    "chrome",
)


def system_chromium_executable() -> str | None:
    """Return an executable Chromium supplied by the host OS, if present."""
    configured = os.environ.get("RAVENEYE_CHROMIUM_EXECUTABLE", "").strip()
    candidates = [configured] if configured else []
    candidates.extend(
        path for name in _SYSTEM_CHROMIUM_NAMES
        if (path := shutil.which(name))
    )
    if os.name == "nt":
        candidates.extend(
            path for name in ("chrome.exe", "chromium.exe")
            if (path := shutil.which(name))
        )

    for candidate in candidates:
        path = Path(candidate).expanduser()
        try:
            if path.is_file() and os.access(path, os.X_OK):
                return str(path.resolve())
        except OSError:
            continue
    return None


def launch_chromium_sync(browser_type: Any, **options: Any) -> Any:
    """Launch Playwright Chromium, retrying with a system browser if needed."""
    try:
        return browser_type.launch(**options)
    except Exception as bundled_error:
        executable = system_chromium_executable()
        if not executable:
            raise
        try:
            return browser_type.launch(executable_path=executable, **options)
        except Exception as system_error:
            raise RuntimeError(
                "Chromium Playwright e o Chromium do sistema falharam. "
                f"Browser Playwright: {bundled_error}; "
                f"browser do sistema ({executable}): {system_error}"
            ) from system_error


def chromium_runtime_smoke(timeout_ms: int = 8_000) -> tuple[bool, str]:
    """Verify the Playwright driver and a browser with a local HTML fixture.

    This does not make a network request. The distro browser is tried even
    when Playwright's bundled browser launches but fails to render the fixture.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        return False, f"Playwright driver indisponível: {type(exc).__name__}: {exc}"

    candidates: list[tuple[str, str | None]] = [("Chromium Playwright", None)]
    system_browser = system_chromium_executable()
    if system_browser:
        candidates.append((f"Chromium do sistema ({system_browser})", system_browser))

    failures: list[str] = []
    try:
        with sync_playwright() as playwright:
            for label, executable in candidates:
                browser = None
                try:
                    options: dict[str, Any] = {
                        "headless": True,
                        "chromium_sandbox": True,
                        "timeout": timeout_ms,
                    }
                    if executable:
                        options["executable_path"] = executable
                    browser = playwright.chromium.launch(**options)
                    page = browser.new_page()
                    page.set_content("<!doctype html><title>RavenEye local smoke</title><main>ok</main>")
                    if page.title() != "RavenEye local smoke" or page.locator("main").inner_text() != "ok":
                        raise RuntimeError("fixture HTML local não foi renderizado corretamente")
                    return True, f"{label}: fixture HTML local renderizado."
                except Exception as exc:
                    failures.append(f"{label}: {type(exc).__name__}: {exc}")
                finally:
                    if browser is not None:
                        try:
                            browser.close()
                        except Exception:
                            pass
    except Exception as exc:
        failures.append(f"Playwright driver: {type(exc).__name__}: {exc}")

    detail = "; ".join(failures) or "nenhum executável Chromium foi detectado"
    return False, detail[:1600]


async def launch_chromium_async(browser_type: Any, **options: Any) -> Any:
    """Async counterpart of :func:`launch_chromium_sync`."""
    try:
        return await browser_type.launch(**options)
    except Exception as bundled_error:
        executable = system_chromium_executable()
        if not executable:
            raise
        try:
            return await browser_type.launch(executable_path=executable, **options)
        except Exception as system_error:
            raise RuntimeError(
                "Chromium Playwright e o Chromium do sistema falharam. "
                f"Browser Playwright: {bundled_error}; "
                f"browser do sistema ({executable}): {system_error}"
            ) from system_error
