from raveneye_pkg import menus, state


def test_menu_logs_deletes_unquoted_path_with_spaces(tmp_path, monkeypatch):
    target = tmp_path / "report with spaces.log"
    target.write_text("local fixture\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(menus, "_find_report_files", lambda _pattern: [])
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus, "ascii_book", lambda: None)
    monkeypatch.setattr(menus, "_is_log_subcategory", lambda _path: False)
    monkeypatch.setattr(state, "config", {"log_file": ""})

    answers = iter([f"delete {target}", "SIM", "00"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    menus.menu_logs()

    assert not target.exists()
    moved = list((tmp_path / ".raveneye_trash").glob("*_report with spaces.log"))
    assert len(moved) == 1


def test_menu_log_path_parser_supports_quoted_and_unquoted_paths():
    assert menus._parse_log_path_argument("/tmp/report with spaces.log") == "/tmp/report with spaces.log"
    assert menus._parse_log_path_argument('"/tmp/report with spaces.log"') == "/tmp/report with spaces.log"


def test_menu_logs_lists_per_scan_event_jsonl(tmp_path, monkeypatch, capsys):
    event_log = tmp_path / "reports" / "RavenEye_events.jsonl"
    event_log.parent.mkdir()
    event_log.write_text('{"schema_version":"1.0","event":"scan.summary","target":"example.test","data":{}}\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(menus, "_clear_screen", lambda: None)
    monkeypatch.setattr(menus, "ascii_book", lambda: None)
    monkeypatch.setattr(menus.state, "config", {"log_file": ""})
    monkeypatch.setattr("builtins.input", lambda _prompt="": "00")

    menus.menu_logs()

    rendered = capsys.readouterr().out
    assert "EVENTOS DO SCAN — JSONL" in rendered
    assert str(event_log) in rendered


def test_selected_event_jsonl_is_rendered_as_human_readable_lines(tmp_path, monkeypatch, capsys):
    source = tmp_path / "RavenEye_events.jsonl"
    source.write_text(
        '{"schema_version":"1.0","timestamp":"2026-10-09T12:00:00Z","event":"search.response",'
        '"target":"example.test","data":{"provider":"SearXNG local (Docker)","titulo":"Docker response",'
        '"link":"https://example.test/.env","snippet":"Useful result"}}\n',
        encoding="utf-8",
    )
    answers = iter(["head 1", "00"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    menus._log_file_viewer(str(source))

    rendered = capsys.readouterr().out
    assert "RESPOSTA SearXNG local (Docker)" in rendered
    assert "Docker response" in rendered
