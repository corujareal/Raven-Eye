import pytest
import sys

# The shared test conftest installs a lightweight colorama stub. The CLI's
# bootstrap checks module specs, so use the installed dependency for this test.
if getattr(sys.modules.get("colorama"), "__spec__", None) is None:
    sys.modules.pop("colorama", None)
import RavenEye


def test_crawler_cli_keeps_legacy_default_and_exposes_async():
    parser = RavenEye._build_argparser()
    default_args = parser.parse_args(["crawler", "https://example.test"])
    async_args = parser.parse_args(["crawler", "https://example.test", "--engine", "async"])

    assert default_args.engine == "legacy"
    assert async_args.engine == "async"


def test_crawler_cli_routes_engine_without_removing_legacy(monkeypatch):
    calls = []
    monkeypatch.setattr(
        RavenEye.state, "config", {"max_pages": 100, "max_depth": 3, "delay": 0, "proxy": ""},
        raising=False,
    )
    monkeypatch.setattr(RavenEye, "_run_async_crawler", lambda args: calls.append(("async", args.url)))
    monkeypatch.setattr(RavenEye, "_run_crawler", lambda *args, **kwargs: calls.append(("legacy", args[1])))

    async_args = RavenEye._build_argparser().parse_args(
        ["crawler", "https://example.test", "--engine", "async"]
    )
    legacy_args = RavenEye._build_argparser().parse_args(["crawler", "https://example.test"])

    assert RavenEye._run_command(async_args)
    assert RavenEye._run_command(legacy_args)
    assert calls == [("async", "https://example.test"), ("legacy", "https://example.test")]


def test_async_engine_rejects_legacy_only_features(monkeypatch):
    monkeypatch.setattr(RavenEye.state, "config", {"proxy": ""}, raising=False)
    args = RavenEye._build_argparser().parse_args(
        ["crawler", "https://example.test", "--engine", "async", "--nmap"]
    )

    with pytest.raises(SystemExit, match="use --engine legacy"):
        RavenEye._run_async_crawler(args)
