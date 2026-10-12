import pytest
import contextlib
import io
import re
from types import SimpleNamespace

from raveneye_pkg import menus
from raveneye_pkg.constants import DEFAULT_CONFIG
from raveneye.wordlists import WordlistInfo


def test_offensive_login_choice_opens_governed_bruteforce_menu(monkeypatch):
    called = []
    answers = iter(["4", "00"])
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus, "ascii_skull", lambda: None)
    monkeypatch.setattr(menus, "menu_bruteforce", lambda: called.append(True))
    monkeypatch.setattr(menus, "_get_target", lambda: (_ for _ in ()).throw(AssertionError("unexpected target prompt")))
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    menus.menu_ofensivo()

    assert called == [True]


def test_main_hall_has_stable_numbering_and_00_is_the_only_back_choice(monkeypatch, capsys):
    opened = []
    answers = iter(["8", "9", "00"])
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus, "ascii_main_hall", lambda: None)
    monkeypatch.setattr(menus, "menu_google_hacking", lambda: opened.append("dorks"))
    monkeypatch.setattr(menus, "menu_vulnerability_scanner", lambda: opened.append("scanner"))
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    menus._menu_sala_principal()

    rendered = capsys.readouterr().out
    assert opened == ["dorks", "scanner"]
    assert "  3. FORÇA BRUTA" in rendered
    assert "  7. VIRUSTOTAL\n  8. GOOGLE HACKING\n  9. SCANNER DE VULNERABILIDADES\n\n  00. VOLTAR" in rendered
    assert "99. MANUAL" not in rendered


def test_configuration_menu_separates_api_keys_and_has_compact_numbering(monkeypatch, capsys):
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus.state, "config", DEFAULT_CONFIG.copy())
    menus.state.config["google_hacking_mode"] = "scan"
    monkeypatch.setattr("builtins.input", lambda _prompt="": "00")

    menus.menu_config()

    rendered = capsys.readouterr().out
    assert "  13 - Arquivo de escopo:" in rendered
    assert "  14 - Renderização JS:" in rendered
    assert "  31 - Configurar chaves e IDs de API" in rendered
    assert "  32 - Salvar configurações" in rendered
    assert "  8  - Chave Shodan" not in rendered
    assert rendered.endswith("  99 - Manual\n  00 - Voltar\n")
    assert rendered.index("  99 - Manual") < rendered.index("  00 - Voltar")


def test_configuration_menu_selects_subdomain_wordlist_as_a_saved_default(monkeypatch, tmp_path, capsys):
    answers = iter(["30", "D", "00"])
    wordlist_manager_factory = menus.get_wordlist_manager
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus.state, "config", DEFAULT_CONFIG.copy())
    monkeypatch.setattr(menus, "get_wordlist_manager", lambda: wordlist_manager_factory(tmp_path / "wordlists"))
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    menus.menu_config()

    rendered = capsys.readouterr().out
    assert "  30 - Wordlist de subdomínios: RavenEye common subdomains" in rendered
    assert menus.state.config["subdomain_wordlist_id"] == "builtin_subdomains"
    assert "Use 32 para salvar" in rendered


def test_subdomain_wordlist_chooser_hides_manual_but_other_categories_keep_it(monkeypatch, capsys):
    manager = SimpleNamespace(list=lambda _category: [])
    answers = iter(["99", "00", "99", "00"])
    manuals = []
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    monkeypatch.setattr(menus, "show_manual", lambda context: manuals.append(context))

    assert menus._choose_wordlist(manager, "subdomains") is None
    subdomains = capsys.readouterr().out
    assert "99. Manual" not in subdomains
    assert "Opção inválida." in subdomains
    assert menus._choose_wordlist(manager, "directories") is None
    assert manuals == ["wordlists"]


def test_corrupt_import_manifest_keeps_builtin_subdomain_list_visible_in_menu(monkeypatch, tmp_path, capsys):
    manager = menus.get_wordlist_manager(tmp_path / "wordlists")
    manager.root.mkdir(parents=True)
    manager.manifest_path.write_text("{broken", encoding="utf-8")
    calls = []
    answers = iter(["3", "fixture.test", "D", "SIM", "00"])
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus, "ascii_bruteforce", lambda: None)
    monkeypatch.setattr(menus, "get_wordlist_manager", lambda: manager)
    monkeypatch.setattr(menus, "_load_scanner_scope", lambda: None)
    monkeypatch.setattr(menus, "_confirm_aggressive", lambda target: True)
    monkeypatch.setattr(
        menus, "brute_subdomains",
        lambda domain, *, wordlist, scope_rules: calls.append((domain, wordlist, scope_rules)) or [],
    )
    monkeypatch.setattr(menus.state, "config", DEFAULT_CONFIG.copy())
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    menus.menu_bruteforce()

    rendered = capsys.readouterr().out
    assert "Catálogo de wordlists importadas inválido" in rendered
    assert "RavenEye common subdomains" in rendered
    assert len(calls) == 1
    assert calls[0][0] == "fixture.test"
    assert calls[0][1] == manager.read("builtin_subdomains")


def test_corrupt_import_manifest_keeps_wordlist_setting_selectable(monkeypatch, tmp_path, capsys):
    manager = menus.get_wordlist_manager(tmp_path / "wordlists")
    manager.root.mkdir(parents=True)
    manager.manifest_path.write_text("{broken", encoding="utf-8")
    answers = iter(["30", "D", "00"])
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus.state, "config", DEFAULT_CONFIG.copy())
    monkeypatch.setattr(menus, "get_wordlist_manager", lambda: manager)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    menus.menu_config()

    rendered = capsys.readouterr().out
    assert "Wordlist de subdomínios: RavenEye common subdomains" in rendered
    assert "Catálogo de wordlists importadas inválido" in rendered
    assert menus.state.config["subdomain_wordlist_id"] == "builtin_subdomains"
    assert "Use 32 para salvar" in rendered


def test_bruteforce_manual_lists_choices_in_numeric_order(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _prompt="": "")

    menus.show_manual("bruteforce")

    rendered = capsys.readouterr().out
    positions = [rendered.index(f"  {number:<3} -") for number in range(1, 8)]
    assert positions == sorted(positions)


def test_every_menu_manual_context_has_a_rendered_entry(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _prompt="": "")
    contexts = (
        "principal", "hall", "google_hacking", "virustotal", "nmap", "exports",
        "wordlists", "config", "api_keys", "logs", "crawler", "ofensivo", "bruteforce",
        "vulnerability", "nuke",
    )

    for context in contexts:
        menus.show_manual(context)

    output = capsys.readouterr().out
    assert "Manual não disponível" not in output
    assert "MANUAL - NMAP" in output
    assert "MANUAL - CONFIGURAÇÕES" in output


def test_scanner_consent_prompts_and_audit_logs_redact_query_values(monkeypatch, capsys, tmp_path):
    target = "https://site.test/item?page=RAVENEYE_page_probe"
    answers = iter(["SIM", "SIM"])
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    assert menus._confirm_aggressive(target)
    assert menus._confirm_vulnerability_scanner(target)

    rendered = capsys.readouterr().out
    audit = (tmp_path / "raveneye_audit_log.txt").read_text(encoding="utf-8")
    assert "site.test/item?page=%5Bredacted%5D" in rendered
    assert "RAVENEYE_page_probe" not in rendered
    assert "RAVENEYE_page_probe" not in audit
    assert "alvo=https://site.test" in audit


def test_aggressive_confirmation_shows_a_bare_dns_target(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "SIM")

    assert menus._confirm_aggressive("example.test")

    assert "example.test" in capsys.readouterr().out
    assert "alvo=example.test" in (tmp_path / "raveneye_audit_log.txt").read_text(encoding="utf-8")


def test_standalone_vulnerability_menu_cancels_when_consent_is_denied(monkeypatch):
    answers = iter(["2", "00"])
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus, "ascii_anarchy", lambda: None)
    monkeypatch.setattr(menus, "_get_targets_for_safe_operation", lambda: ["https://fixture.test/"])
    monkeypatch.setattr(menus, "_load_scanner_scope", lambda: None)
    monkeypatch.setattr(menus, "_confirm_vulnerability_scanner", lambda _target: False)
    monkeypatch.setattr(menus, "_run_vulnerability_scanner", lambda *_args, **_kwargs: pytest.fail("scanner started without consent"))
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    menus.menu_vulnerability_scanner()


def test_nuke_scanner_requires_its_own_consent_after_aggressive_confirmation(monkeypatch):
    answers = iter(["4", "00"])
    calls = []
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus, "ascii_radiation", lambda: None)
    monkeypatch.setattr(menus, "_load_scanner_scope", lambda: None)
    monkeypatch.setattr(menus, "_get_target", lambda: "https://fixture.test/")
    monkeypatch.setattr(menus, "_confirm_aggressive", lambda _target: True)
    monkeypatch.setattr(menus, "_confirm_vulnerability_scanner", lambda _target: calls.append("scanner") or False)
    monkeypatch.setattr(menus, "_run_crawler", lambda *_args, **_kwargs: pytest.fail("scanner path continued without consent"))
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    menus.menu_nuke()

    assert calls == ["scanner"]


def test_bruteforce_menu_executes_through_async_http_adapter_after_confirmation(monkeypatch, capsys, tmp_path):
    path = tmp_path / "fixture-passwords.txt"
    path.write_text("fixture-only\n", encoding="utf-8")
    info = WordlistInfo(
        "fixture-passwords", "passwords", "Fixture passwords", "a" * 64, 1, "imported",
    )
    answers = iter([
        "1", "http://127.0.0.1:8080/login", "fixture-user",
        "", "", "", "1", "1", "8", "10", "S", "n", "00",
    ])
    calls = []

    class FakeEngine:
        def __init__(self, policy, *, wordlist_manager):
            calls.append(("engine", policy, wordlist_manager))

    class FakeAdapter:
        def __init__(self, engine):
            calls.append(("adapter", engine))

        async def audit(self, login_url, username, **options):
            calls.append(("audit", login_url, username, options))
            return SimpleNamespace(status="completed", attempts=0)

    manager = object()
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus, "ascii_bruteforce", lambda: None)
    monkeypatch.setattr(menus, "get_wordlist_manager", lambda: manager)
    monkeypatch.setattr(menus, "_choose_wordlist", lambda *_args, **_kwargs: (str(path), info))
    monkeypatch.setattr(menus, "_confirm_aggressive", lambda _target: True)
    monkeypatch.setattr(menus, "BruteForceEngine", FakeEngine)
    monkeypatch.setattr(menus, "HTTPLoginAdapter", FakeAdapter)
    monkeypatch.setattr(menus.state, "config", {"bf_attempts": 10, "bf_attempts_per_user": 5})
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    menus.menu_bruteforce()

    audit = next(call for call in calls if call[0] == "audit")
    assert audit[1:3] == ("http://127.0.0.1:8080/login", "fixture-user")
    assert audit[3]["preflight_confirmed"] is True
    assert audit[3]["wordlist_path"] == str(path)
    assert audit[3]["threads"] == 1
    assert any(call[0] == "engine" and call[2] is manager for call in calls)
    assert "Sem indicador de sucesso" in capsys.readouterr().out


def test_subdomain_bruteforce_uses_selected_wordlist_and_requires_confirmation(monkeypatch, capsys, tmp_path):
    manager = menus.get_wordlist_manager(tmp_path / "wordlists")
    calls = []
    answers = iter(["3", "fixture.test", "D", "SIM", "00"])
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus, "ascii_bruteforce", lambda: None)
    monkeypatch.setattr(menus, "get_wordlist_manager", lambda: manager)
    monkeypatch.setattr(menus, "_load_scanner_scope", lambda: None)
    monkeypatch.setattr(menus, "_confirm_aggressive", lambda target: calls.append(("confirm", target)) or True)
    monkeypatch.setattr(menus, "brute_subdomains", lambda domain, *, wordlist, scope_rules: calls.append(("scan", domain, wordlist, scope_rules)) or [])
    monkeypatch.setattr(menus.state, "config", DEFAULT_CONFIG.copy())
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    menus.menu_bruteforce()

    rendered = capsys.readouterr().out
    scan = next(call for call in calls if call[0] == "scan")
    assert scan[1] == "fixture.test"
    assert scan[2] == manager.read("builtin_subdomains")
    assert scan[3] is None
    assert calls[0] == ("confirm", "fixture.test")
    assert "WORDLISTS: subdomains" in rendered
    assert "Preflight DNS: fixture.test" in rendered


def test_subdomain_bruteforce_honors_scope_filter_and_does_not_scan_without_consent(monkeypatch, tmp_path, capsys):
    source = tmp_path / "fixture-subdomains.txt"
    source.write_text("portal\nadmin\n", encoding="utf-8")
    manager = menus.get_wordlist_manager(tmp_path / "wordlists")
    info = manager.add(source, "subdomains")
    calls = []
    answers = iter(["3", "example.test", "1", "00"])
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus, "ascii_bruteforce", lambda: None)
    monkeypatch.setattr(menus, "get_wordlist_manager", lambda: manager)
    monkeypatch.setattr(menus, "_load_scanner_scope", lambda: {"portal.example.test"})
    monkeypatch.setattr(menus, "_confirm_aggressive", lambda _target: False)
    monkeypatch.setattr(menus, "brute_subdomains", lambda *_args, **_kwargs: calls.append("scan") or [])
    monkeypatch.setattr(menus.state, "config", {**DEFAULT_CONFIG, "subdomain_wordlist_id": "builtin_subdomains"})
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    menus.menu_bruteforce()

    rendered = capsys.readouterr().out
    assert info.id in [item.id for item in manager.list("subdomains")]
    assert calls == []
    assert "1 candidatos; até 2 probes wildcard, candidatos filtrados pelo escopo" in rendered
    assert "Operação cancelada" in rendered


def test_main_menu_uses_00_as_its_only_exit_number(monkeypatch, capsys):
    answers = iter(["00"])
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus, "ascii_raven_eye_logo", lambda: None)
    monkeypatch.setattr(menus, "verify_integrity", lambda: None)
    monkeypatch.setattr(menus, "save_config", lambda _config: None)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    with pytest.raises(SystemExit):
        menus.menu_principal()

    rendered = capsys.readouterr().out
    assert "00. SAIR" in rendered
    assert "99. MANUAL" not in rendered


def test_export_submenu_without_reports_offers_00_back_choice(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "00")

    menus._export_report_submenu()

    rendered = capsys.readouterr().out
    assert "Nenhum arquivo de relatório encontrado." in rendered
    assert "99 - Manual\n  00 - Voltar" in rendered


def test_every_interactive_menu_shows_00_as_its_last_numbered_choice(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus, "save_config", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(menus, "verify_integrity", lambda: None)
    monkeypatch.setattr(menus.state, "config", DEFAULT_CONFIG.copy())
    monkeypatch.setattr("builtins.input", lambda _prompt="": "00")
    for name in (name for name in dir(menus) if name.startswith("ascii_")):
        monkeypatch.setattr(menus, name, lambda: None)

    menu_names = (
        "menu_google_hacking", "menu_logs", "_export_report_submenu", "menu_config",
        "menu_crawler", "menu_ofensivo", "menu_bruteforce", "menu_vulnerability_scanner",
        "menu_nuke", "menu_principal", "_menu_sala_principal", "menu_virustotal",
        "_menu_nmap_standalone",
    )
    option_pattern = re.compile(r"^\s*(?:\d{1,2}|99|00)[.) -]")
    ansi_pattern = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

    for name in menu_names:
        rendered = io.StringIO()
        try:
            with contextlib.redirect_stdout(rendered):
                getattr(menus, name)()
        except SystemExit as exc:
            assert exc.code == 0
        visible = ansi_pattern.sub("", rendered.getvalue())
        numbered_choices = [line.strip() for line in visible.splitlines() if option_pattern.match(line)]
        assert numbered_choices, f"{name} rendered no numbered choices"
        assert numbered_choices[-1].startswith("00"), f"{name} does not put 00 last: {numbered_choices}"
        ordinary_numbers = [
            int(re.match(r"\d+", line).group())
            for line in numbered_choices
            if not line.startswith(("99", "00"))
        ]
        assert ordinary_numbers == sorted(set(ordinary_numbers)), (
            f"{name} has out-of-order or repeated numbered choices: {numbered_choices}"
        )
        if any(line.startswith("99") for line in numbered_choices):
            assert numbered_choices[-2].startswith("99"), (
                f"{name} does not put the manual immediately before 00: {numbered_choices}"
            )
