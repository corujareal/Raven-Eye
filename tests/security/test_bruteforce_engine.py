from __future__ import annotations

import asyncio
import threading

import pytest

from raveneye.bruteforce.engine import (
    BruteForceEngine,
    CredentialAuditPolicy,
)
from raveneye.bruteforce.http_client import LoginResponse
from raveneye.wordlists import WordlistManager
from raveneye_pkg import bruteforce as legacy


def test_engine_requires_preflight_before_importing_or_running_credentials(monkeypatch):
    called = []
    monkeypatch.setattr(legacy, "bruteforce_login", lambda *args, **kwargs: called.append(True))

    with pytest.raises(ValueError, match="confirmation"):
        asyncio.run(BruteForceEngine().run("http://127.0.0.1/login"))

    assert called == []


def test_engine_enforces_policy_and_returns_only_redacted_metrics(monkeypatch):
    secret = "never-return-this-password"
    calls = []

    def fake_audit(*args, **kwargs):
        calls.append((args, kwargs))
        return secret, 3

    monkeypatch.setattr(legacy, "bruteforce_login", fake_audit)
    engine = BruteForceEngine(CredentialAuditPolicy(max_attempts=8, lockout_threshold=2))

    with pytest.raises(ValueError, match="max_attempts"):
        asyncio.run(engine.run(
            "https://fixture.example.test/login?marker=private",
            "fixture-user",
            preflight_confirmed=True,
            max_attempts=9,
        ))
    assert calls == []

    result = asyncio.run(engine.run(
        "https://fixture.example.test/login?marker=private",
        "fixture-user",
        preflight_confirmed=True,
        wordlist_path="/private/passwords.txt",
        max_attempts=4,
        per_user_limit=2,
    ))

    assert result.status == "possible_match"
    assert result.match_confidence == "possible"
    assert result.attempts == 3
    assert result.attempts_per_second > 0
    assert result.target_origin == "https://fixture.example.test:443"
    assert secret not in repr(result)
    assert "private" not in repr(result)
    assert calls[0][0][:2] == ("https://fixture.example.test/login?marker=private", "fixture-user")
    assert calls[0][1]["threads"] == 1
    assert calls[0][1]["stop_on_success"] is True
    assert calls[0][1]["preflight_confirmed"] is True
    assert calls[0][1]["use_extra_passwords"] is False


def test_engine_cancellation_stops_before_next_credential_post(tmp_path, monkeypatch):
    password_file = tmp_path / "passwords.txt"
    password_file.write_text("fixture-password\n", encoding="utf-8")
    manager = WordlistManager(tmp_path / "data" / "wordlists")
    get_started = threading.Event()
    release_get = threading.Event()

    class BlockingFixtureClient:
        posts = 0

        def __init__(self, target, **_kwargs):
            self.target = target

        def request(self, method, _url, *, data=None):
            if method == "GET":
                get_started.set()
                release_get.wait(timeout=3)
                return LoginResponse(200, self.target, "<form></form>", {})
            type(self).posts += 1
            return LoginResponse(200, self.target, "invalid", {})

        def close(self):
            return None

    monkeypatch.setattr(legacy.state, "config", {"bf_attempts": 10, "bf_attempts_per_user": 5})
    monkeypatch.setattr(legacy, "ProtectedLoginClient", BlockingFixtureClient)
    monkeypatch.setattr(legacy, "_sleep", lambda *_args, **_kwargs: None)
    engine = BruteForceEngine(wordlist_manager=manager)

    async def cancel_after_preflight_get():
        task = asyncio.create_task(engine.run(
            "http://127.0.0.1:8080/login",
            "fixture-user",
            preflight_confirmed=True,
            wordlist_path=str(password_file),
        ))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 2
        while not get_started.is_set() and loop.time() < deadline:
            await asyncio.sleep(0.01)
        assert get_started.is_set()
        task.cancel()
        # Let the engine set its cooperative cancellation event before the
        # local fixture releases its in-flight GET response.
        await asyncio.sleep(0)
        release_get.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_after_preflight_get())
    assert BlockingFixtureClient.posts == 0
