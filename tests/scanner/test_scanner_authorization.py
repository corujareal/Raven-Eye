import pytest

from raveneye_pkg import menus
from raveneye_pkg.crawler import RavenCrawler


def test_crawler_refuses_embedded_scanner_without_explicit_authorization():
    with pytest.raises(PermissionError, match="autorização explícita"):
        RavenCrawler(
            "https://authorized.example/",
            max_pages=1,
            max_depth=0,
            delay=0,
            include_vuln_scanner=True,
        )


def test_vulnerability_menu_stops_when_scanner_authorization_is_declined(
    monkeypatch, tmp_path
):
    answers = iter(["2", "não", "00"])
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus, "ascii_anarchy", lambda: None)
    monkeypatch.setattr(menus, "_get_targets_for_safe_operation", lambda: ["https://authorized.example/"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    def forbidden_scanner(*_args, **_kwargs):
        raise AssertionError("scanner must not be created when authorization is declined")

    monkeypatch.setattr(menus, "RavenVulnScanner", forbidden_scanner)
    menus.menu_vulnerability_scanner()

    audit = (tmp_path / "raveneye_audit_log.txt").read_text(encoding="utf-8")
    assert "modulo=RavenVulnScanner" in audit
    assert "autorizado=NAO" in audit


def test_nuke_plus_scanner_requires_scanner_specific_authorization(monkeypatch, capsys):
    answers = iter(["4", "00"])
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus, "ascii_radiation", lambda: None)
    monkeypatch.setattr(menus, "_get_target", lambda: "https://authorized.example/")
    monkeypatch.setattr(menus, "_confirm_aggressive", lambda _target: True)
    monkeypatch.setattr(menus, "_confirm_vulnerability_scanner", lambda _target: False)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    def forbidden_crawl(*_args, **_kwargs):
        raise AssertionError("the combined run must stop when scanner consent is declined")

    monkeypatch.setattr(menus, "_run_crawler", forbidden_crawl)
    menus.menu_nuke()

    assert "autorização do Scanner não confirmada" in capsys.readouterr().out


def test_configured_scanner_scope_is_loaded_and_passed_to_engine(monkeypatch, tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("# authorized hosts\nExample.test\n*.example.test\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(menus.state, "config", {"scope_file": str(scope_file)})
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus, "ascii_anarchy", lambda: None)
    monkeypatch.setattr(menus, "_get_targets_for_safe_operation", lambda: ["https://example.test/"])
    monkeypatch.setattr(menus, "_run_vulnerability_scanner", lambda *a, **kw: calls.append(kw))
    answers = iter(["2", "SIM", "00"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    calls = []

    menus.menu_vulnerability_scanner()

    assert calls == [{"root_mode": False, "scope_domains": {"example.test", "*.example.test"}}]


def test_invalid_configured_scanner_scope_fails_closed(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(menus.state, "config", {"scope_file": str(tmp_path / "missing-scope.txt")})
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus, "ascii_anarchy", lambda: None)
    monkeypatch.setattr(menus, "_get_targets_for_safe_operation", lambda: ["https://example.test/"])
    monkeypatch.setattr(
        menus, "_confirm_vulnerability_scanner",
        lambda _target: (_ for _ in ()).throw(AssertionError("invalid scope must block before scanner consent")),
    )
    answers = iter(["2", "00"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    menus.menu_vulnerability_scanner()

    assert "Arquivo de escopo do scanner indisponível" in capsys.readouterr().out
