from __future__ import annotations

import asyncio
from pathlib import Path
import sys
from types import ModuleType

import pytest

from raveneye.core.browser import (
    launch_chromium_async,
    launch_chromium_sync,
    chromium_runtime_smoke,
    system_chromium_executable,
)


def _executable(path: Path) -> Path:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_system_chromium_respects_explicit_executable(monkeypatch, tmp_path):
    executable = _executable(tmp_path / "chromium-custom")
    monkeypatch.setenv("RAVENEYE_CHROMIUM_EXECUTABLE", str(executable))

    assert system_chromium_executable() == str(executable.resolve())


def test_sync_launch_falls_back_to_system_chromium_and_preserves_options(monkeypatch, tmp_path):
    executable = _executable(tmp_path / "chromium")
    monkeypatch.setenv("RAVENEYE_CHROMIUM_EXECUTABLE", str(executable))

    class BrowserType:
        def __init__(self):
            self.calls = []

        def launch(self, **options):
            self.calls.append(options)
            if "executable_path" not in options:
                raise RuntimeError("bundled ABI unavailable")
            return "system-browser"

    browser_type = BrowserType()
    result = launch_chromium_sync(
        browser_type,
        headless=True,
        chromium_sandbox=True,
        proxy={"server": "socks5://127.0.0.1:43123"},
    )

    assert result == "system-browser"
    assert browser_type.calls == [
        {
            "headless": True,
            "chromium_sandbox": True,
            "proxy": {"server": "socks5://127.0.0.1:43123"},
        },
        {
            "headless": True,
            "chromium_sandbox": True,
            "proxy": {"server": "socks5://127.0.0.1:43123"},
            "executable_path": str(executable.resolve()),
        },
    ]


def test_async_launch_falls_back_to_system_chromium(monkeypatch, tmp_path):
    executable = _executable(tmp_path / "chromium")
    monkeypatch.setenv("RAVENEYE_CHROMIUM_EXECUTABLE", str(executable))

    class BrowserType:
        def __init__(self):
            self.calls = []

        async def launch(self, **options):
            self.calls.append(options)
            if "executable_path" not in options:
                raise RuntimeError("bundled ABI unavailable")
            return "system-browser"

    browser_type = BrowserType()
    result = asyncio.run(launch_chromium_async(browser_type, headless=True))

    assert result == "system-browser"
    assert browser_type.calls[-1] == {
        "headless": True,
        "executable_path": str(executable.resolve()),
    }


def test_sync_launch_keeps_original_failure_when_no_system_browser_exists(monkeypatch):
    monkeypatch.delenv("RAVENEYE_CHROMIUM_EXECUTABLE", raising=False)
    monkeypatch.setattr("raveneye.core.browser.shutil.which", lambda _name: None)

    class BrowserType:
        def launch(self, **_options):
            raise RuntimeError("original launch failure")

    with pytest.raises(RuntimeError, match="original launch failure"):
        launch_chromium_sync(BrowserType(), headless=True)


def test_local_smoke_retries_system_chromium_and_checks_rendered_fixture(monkeypatch):
    calls = []

    class Page:
        def set_content(self, _content):
            return None

        def title(self):
            return "RavenEye local smoke"

        def locator(self, selector):
            assert selector == "main"
            return self

        def inner_text(self):
            return "ok"

    class Browser:
        def new_page(self):
            return Page()

        def close(self):
            return None

    class Chromium:
        def launch(self, **options):
            calls.append(options)
            if "executable_path" not in options:
                raise RuntimeError("bundled browser ABI mismatch")
            return Browser()

    class PlaywrightContext:
        chromium = Chromium()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    sync_api = ModuleType("playwright.sync_api")
    sync_api.sync_playwright = PlaywrightContext
    package = ModuleType("playwright")
    package.__path__ = []
    monkeypatch.setitem(sys.modules, "playwright", package)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
    monkeypatch.setattr("raveneye.core.browser.system_chromium_executable", lambda: "/usr/bin/chromium")

    ok, detail = chromium_runtime_smoke()

    assert ok is True
    assert "fixture HTML local renderizado" in detail
    assert len(calls) == 2
    assert calls[0]["chromium_sandbox"] is True
    assert calls[1]["executable_path"] == "/usr/bin/chromium"
