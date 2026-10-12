import json
from types import SimpleNamespace

import benchmarks.bruteforce_comparison as comparison
from benchmarks.bruteforce_comparison import FixtureState


def test_csrf_fixture_rotates_single_use_tokens_and_counts_rejections():
    state = FixtureState()
    state.reset(csrf_enabled=True)

    assert "raveneye-fixture-csrf-1" in state.csrf_form()
    assert state.check_and_rotate_csrf("wrong-token") is False
    assert "raveneye-fixture-csrf-1" in state.csrf_form()

    assert state.check_and_rotate_csrf("raveneye-fixture-csrf-1") is True
    assert "raveneye-fixture-csrf-2" in state.csrf_form()
    state.record(False, csrf_valid=True)
    state.record(False, csrf_valid=False)

    snapshot = state.snapshot()
    assert snapshot["authentication_posts"] == 2
    assert snapshot["rejected_posts"] == 2
    assert snapshot["csrf_rejected_posts"] == 1


def test_benchmark_main_resets_fixture_for_plain_and_rotating_csrf_cases(monkeypatch, tmp_path, capsys):
    hydra = tmp_path / "hydra"
    hydra.write_text("fixture executable", encoding="utf-8")
    hydra.chmod(0o755)
    report_path = tmp_path / "comparison.json"
    monkeypatch.setattr(comparison.sys, "argv", [
        "bruteforce_comparison.py", "--hydra", str(hydra), "--runs", "1",
        "--output", str(report_path),
    ])
    monkeypatch.setattr(
        comparison.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout="Hydra v-fixture\n", stderr=""),
    )

    class FakeServer:
        server_port = 45678
        fixture_thread = SimpleNamespace(join=lambda **_kwargs: None)

        def shutdown(self):
            pass

        def server_close(self):
            pass

    monkeypatch.setattr(comparison, "make_fixture", lambda _state: FakeServer())
    observed = []

    def fake_run(_base_url, case, _candidates, state, *_args):
        observed.append((case, state.csrf_enabled))
        return {"case": case}

    def fake_hydra(_binary, _version, _base_url, case, _candidates, state, _root, *, profile):
        observed.append((case, state.csrf_enabled))
        return {"case": case, "profile": profile}

    monkeypatch.setattr(comparison, "run_raveneye", fake_run)
    monkeypatch.setattr(comparison, "run_hydra", fake_hydra)
    monkeypatch.setattr(comparison, "aggregate", lambda rows: {"runs": len(rows)})

    comparison.main()

    expected = [
        (case, case.startswith("csrf-"))
        for case in ("positive", "negative", "csrf-positive", "csrf-negative")
        for _ in range(3)
    ]
    assert observed == expected
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["summary"] == {"runs": 12}
    assert report["authentication_policy"]["output_contains_credentials"] is False
    assert "raveneye-fixture-valid-only" not in capsys.readouterr().out
