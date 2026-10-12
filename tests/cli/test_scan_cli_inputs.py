from types import SimpleNamespace

from click.testing import CliRunner

from raveneye.cli import main as cli_module


def _install_scan_fakes(monkeypatch, tmp_path):
    cfg = SimpleNamespace(multi_target_enabled=False, max_targets=5, max_pages=10, database_path=str(tmp_path / "db.sqlite"))
    scanned = []
    monkeypatch.setattr(cli_module, "load_config", lambda: cfg)

    class Batch:
        urls = ["https://example.test/"]

    monkeypatch.setattr(cli_module, "normalize_targets", lambda *_args, **_kwargs: Batch())

    async def fake_scan_urls(urls, _cfg):
        scanned.extend(urls)
        return []

    monkeypatch.setattr(cli_module, "scan_urls", fake_scan_urls)
    monkeypatch.setattr(cli_module, "render_txt", lambda target, *_args, **_kwargs: f"target={target}")

    class Repository:
        def __init__(self, _path):
            pass

        def save_scan(self, *_args, **_kwargs):
            pass

    monkeypatch.setattr(cli_module, "ScanRepository", Repository)
    return scanned


def test_scan_uses_normalized_target_in_report_and_repository(monkeypatch, tmp_path):
    _install_scan_fakes(monkeypatch, tmp_path)
    out = tmp_path / "report.txt"
    result = CliRunner().invoke(cli_module.main, ["scan", "https://example.test/", "--output", str(out)], input="y\n")
    assert result.exit_code == 0, result.output
    assert out.read_text(encoding="utf-8") == "target=https://example.test/"


def test_scan_requires_authorization_before_any_request(monkeypatch, tmp_path):
    scanned = _install_scan_fakes(monkeypatch, tmp_path)
    result = CliRunner().invoke(
        cli_module.main,
        ["scan", "https://example.test/", "--output", str(tmp_path / "report.txt")],
        input="n\n",
    )
    assert result.exit_code != 0
    assert "autorização" in result.output.lower()
    assert scanned == []


def test_scan_fails_clearly_for_missing_or_invalid_crawl_jsonl(monkeypatch, tmp_path):
    _install_scan_fakes(monkeypatch, tmp_path)
    runner = CliRunner()
    missing = runner.invoke(cli_module.main, ["scan", "https://example.test/", "--crawl-file", str(tmp_path / "missing.jsonl")], input="y\n")
    assert missing.exit_code != 0
    assert "Arquivo de crawl não encontrado" in missing.output

    bad = tmp_path / "bad.jsonl"
    bad.write_text("not-json\n", encoding="utf-8")
    invalid = runner.invoke(cli_module.main, ["scan", "https://example.test/", "--crawl-file", str(bad)], input="y\n")
    assert invalid.exit_code != 0
    assert f"{bad}:1" in invalid.output


def test_scan_ignores_crawl_urls_outside_explicit_target_scope(monkeypatch, tmp_path):
    scanned = _install_scan_fakes(monkeypatch, tmp_path)
    crawl = tmp_path / "crawl.jsonl"
    crawl.write_text(
        '{"url":"https://api.example.test/v1"}\n'
        '{"url":"http://127.0.0.1:8080/admin"}\n'
        '{"url":"https://example.test.attacker.invalid/leak"}\n',
        encoding="utf-8",
    )
    result = CliRunner().invoke(cli_module.main, [
        "scan", "https://example.test/", "--crawl-file", str(crawl), "--output", str(tmp_path / "r.txt")
    ], input="y\n")
    assert result.exit_code == 0, result.output
    assert scanned == ["https://example.test/", "https://api.example.test/v1"]
    assert "ignoradas: 2" in result.output
