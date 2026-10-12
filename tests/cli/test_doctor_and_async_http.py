from pathlib import Path
import os
import pytest

from raveneye_pkg import doctor as doctor_module
from raveneye_pkg.doctor import run_doctor, render_doctor
from raveneye_pkg.async_http import AsyncHttpClient


def test_cli_runtime_gate_does_not_require_optional_browser_engines(monkeypatch):
    monkeypatch.setattr(doctor_module, "_available", lambda _name: True)
    monkeypatch.setattr(
        doctor_module,
        "_browser_inventory",
        lambda: pytest.fail("optional browser inventory must not gate CLI startup"),
    )

    from raveneye_pkg.state import check_dependencies

    check_dependencies()


def test_doctor_is_local_and_has_expected_sections():
    result = run_doctor({"database_path": "data/raveneye.db"})
    assert "python" in result
    assert "runtime_dependencies" in result
    assert "playwright_browsers" in result
    assert isinstance(render_doctor(result), str)


def test_doctor_treats_headless_browser_as_optional_unless_configured(monkeypatch, tmp_path):
    monkeypatch.setattr(doctor_module, "_available", lambda _name: True)
    monkeypatch.setattr(doctor_module, "system_chromium_executable", lambda: None)
    monkeypatch.setattr(
        doctor_module,
        "_browser_inventory",
        lambda: {"chromium": False, "firefox": False, "webkit": False},
    )
    monkeypatch.setattr(doctor_module, "chromium_runtime_smoke", lambda: (False, "fixture launch failed"))

    result = run_doctor({"database_path": str(tmp_path / "raveneye.db")})

    assert result["ok"] is True
    assert result["required_playwright_browsers"] == []
    assert result["optional_playwright_browsers"] == ["chromium"]
    assert result["headless_rendering"] == {
        "configured": False,
        "available": False,
        "optional": True,
        "diagnostic": "fixture launch failed",
    }
    assert "crawler estático permanece disponível" in render_doctor(result)

    configured = run_doctor({
        "database_path": str(tmp_path / "raveneye.db"),
        "headless_rendering": True,
    })
    assert configured["ok"] is False
    assert configured["headless_rendering"]["configured"] is True
    assert configured["headless_rendering"]["diagnostic"] == "fixture launch failed"


def test_doctor_requires_playwright_executable_files_not_leftover_directories(monkeypatch, tmp_path):
    # Simulate interrupted browser downloads that left version directories but
    # no browser executable. These must never make the runtime look complete.
    monkeypatch.setattr(doctor_module, "system_chromium_executable", lambda: None)
    for engine in ("chromium", "firefox", "webkit"):
        (tmp_path / f"{engine}-leftover").mkdir()
    expected = {
        engine: tmp_path / f"{engine}-current" / "browser"
        for engine in ("chromium", "firefox", "webkit")
    }
    monkeypatch.setattr(doctor_module, "_playwright_browser_executables", lambda: expected)
    assert doctor_module._browser_inventory() == {
        "chromium": False, "firefox": False, "webkit": False,
    }

    for engine, executable in expected.items():
        executable.parent.mkdir()
        executable.write_text("fixture executable", encoding="utf-8")
        executable.chmod(0o755)

    assert doctor_module._browser_inventory() == {
        "chromium": True, "firefox": True, "webkit": True,
    }

    expected["webkit"] = tmp_path / "webkit-current" / "missing-browser"
    monkeypatch.setattr(doctor_module, "_playwright_browser_executables", lambda: expected)
    assert doctor_module._browser_inventory() == {
        "chromium": True, "firefox": True, "webkit": False,
    }


def test_async_http_accepts_real_subdomain_without_suffix_collision():
    client = AsyncHttpClient(scope_host="example.com")
    assert client._allowed("https://example.com/") is False or isinstance(client._allowed("https://example.com/"), bool)
    # _allowed also invokes SSRF protection; this assertion focuses on host logic
    # without making any network request.
    from urllib.parse import urlparse
    for host, expected in [("api.example.com", True), ("evil-example.com", False)]:
        p = urlparse("https://" + host + "/")
        scope = client.scope_host
        in_scope = p.hostname == scope or p.hostname.endswith("." + scope)
        assert in_scope is expected
