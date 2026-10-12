from click.testing import CliRunner

from raveneye.cli.main import main


def test_click_cli_accepts_short_help_at_root_and_subcommand():
    runner = CliRunner()

    root = runner.invoke(main, ["-h"])
    scan = runner.invoke(main, ["scan", "-h"])

    assert root.exit_code == 0
    assert "Commands:" in root.output
    assert "scan" in root.output
    assert scan.exit_code == 0
    assert "--crawl-file" in scan.output
    assert "--output" in scan.output
