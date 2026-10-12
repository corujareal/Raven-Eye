from __future__ import annotations

import json

import pytest

from raveneye.bruteforce.checkpoint import CheckpointError, CheckpointStore
from raveneye.bruteforce.http_client import LoginResponse, ProtectedLoginClient, ProtectedRequestError
from raveneye.wordlists import WordlistManager
from raveneye_pkg import bruteforce


class FakeLoginClient:
    def __init__(self, target: str, *, timeout: float = 8.0, rate_limit: bool = False):
        self.target = target
        self.rate_limit = rate_limit
        self.posts = 0
        self.attempts = []
        self.closed = False

    def request(self, method, _url, *, data=None):
        if method == "GET":
            return LoginResponse(200, self.target, '<form><input name="csrf-token" value="token"></form>', {})
        self.posts += 1
        self.attempts.append((data.get("username"), data.get("password")))
        if self.rate_limit:
            return LoginResponse(429, self.target, "", {"Retry-After": "60"})
        if data.get("password") == "unit-secret":
            return LoginResponse(200, self.target.rsplit("/", 1)[0] + "/dashboard", "SIGNED_IN_OK", {})
        return LoginResponse(200, self.target, "Invalid credentials", {})

    def close(self):
        self.closed = True


class FakeResponse:
    def __init__(self, status: int, body: bytes = b"", headers: dict | None = None):
        self.status_code = status
        self.headers = headers or {}
        self.encoding = "utf-8"
        self.body = body
        self.closed = False

    def iter_content(self, chunk_size=16384):
        if self.body:
            yield self.body

    def close(self):
        self.closed = True


def test_checkpoint_is_authenticated_and_contains_no_credentials(tmp_path):
    store = CheckpointStore(tmp_path / "checkpoints")
    identity = store.identity("http://example.test/login", "private-fingerprint")
    path = store.save(identity, {"state": "interrupted", "next_index": 2})

    assert store.load(identity)["next_index"] == 2
    assert "private-fingerprint" not in path.read_text(encoding="utf-8")
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["record"]["next_index"] = 3
    path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(CheckpointError):
        store.load(identity)


def test_checkpoint_refuses_symlinked_storage_root(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_root = tmp_path / "linked-checkpoints"
    linked_root.symlink_to(outside, target_is_directory=True)
    with pytest.raises(CheckpointError):
        CheckpointStore(linked_root).identity("http://example.test/login", "fingerprint")
    assert list(outside.iterdir()) == []


def test_login_audit_requires_preflight_before_any_request(tmp_path, monkeypatch):
    password_file = tmp_path / "passwords.txt"
    password_file.write_text("unit-secret\n", encoding="utf-8")
    manager = WordlistManager(tmp_path / "user-data" / "wordlists")
    called = []
    monkeypatch.setattr(bruteforce, "ProtectedLoginClient", lambda *args, **kwargs: called.append(args))
    with pytest.raises(bruteforce.CredentialAuditError):
        bruteforce.bruteforce_login(
            "http://127.0.0.1:8080/login", "unit-user", wordlist_path=str(password_file),
            _wordlist_manager=manager,
        )
    assert called == []


def test_login_flow_redacts_secrets_and_uses_no_baseline_post(tmp_path, monkeypatch, capsys):
    password_file = tmp_path / "passwords.txt"
    password_file.write_text("bad-secret\nunit-secret\n", encoding="utf-8")
    manager = WordlistManager(tmp_path / "user-data" / "wordlists")
    monkeypatch.setattr(bruteforce.state, "config", {"bf_attempts": 10, "bf_attempts_per_user": 5})
    monkeypatch.setattr(bruteforce, "_sleep", lambda *_args, **_kwargs: None)
    clients = []

    def make_client(target, **kwargs):
        client = FakeLoginClient(target, **kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr(bruteforce, "ProtectedLoginClient", make_client)
    found, attempts = bruteforce.bruteforce_login(
        "http://127.0.0.1:8080/login", "unit-user", wordlist_path=str(password_file),
        use_extra_passwords=False, success_marker="SIGNED_IN_OK", resumable=True,
        preflight_confirmed=True, _wordlist_manager=manager,
    )

    output = capsys.readouterr().out
    assert found == "unit-secret"  # preserved API result; never emitted in logs
    assert attempts == 2
    assert clients[0].posts == 2
    assert clients[0].closed
    assert "unit-secret" not in output
    assert "bad-secret" not in output
    checkpoint_files = list((tmp_path / "user-data" / "checkpoints").glob("run-*.json"))
    assert len(checkpoint_files) == 1
    checkpoint_text = checkpoint_files[0].read_text(encoding="utf-8")
    assert "unit-secret" not in checkpoint_text
    assert "unit-user" not in checkpoint_text


def test_explicit_success_marker_disables_redirect_heuristic(tmp_path, monkeypatch, capsys):
    password_file = tmp_path / "passwords.txt"
    password_file.write_text("candidate-one\n", encoding="utf-8")
    manager = WordlistManager(tmp_path / "user-data" / "wordlists")
    monkeypatch.setattr(bruteforce.state, "config", {"bf_attempts": 10, "bf_attempts_per_user": 5})
    monkeypatch.setattr(bruteforce, "_sleep", lambda *_args, **_kwargs: None)

    class DashboardRedirectClient:
        def __init__(self, target, **_kwargs):
            self.target = target

        def request(self, method, _url, *, data=None):
            if method == "GET":
                return LoginResponse(200, self.target, "login form", {})
            return LoginResponse(
                200, self.target.rsplit("/", 1)[0] + "/dashboard", "MFA required", {},
            )

        def close(self):
            return None

    monkeypatch.setattr(bruteforce, "ProtectedLoginClient", DashboardRedirectClient)
    found, attempts = bruteforce.bruteforce_login(
        "http://127.0.0.1:8080/login", "fixture-user",
        wordlist_path=str(password_file), use_extra_passwords=False,
        success_marker="EXCLUSIVE_SUCCESS", preflight_confirmed=True,
        _wordlist_manager=manager,
    )

    assert found is None
    assert attempts == 1
    assert "Possivel credencial valida observada" not in capsys.readouterr().out


def test_separate_user_and_password_lists_apply_per_account_cap(tmp_path, monkeypatch):
    user_file = tmp_path / "users.txt"
    user_file.write_text("user-one\nuser-two\n", encoding="utf-8")
    password_file = tmp_path / "passwords.txt"
    password_file.write_text("\n".join(f"candidate-{index}" for index in range(10)), encoding="utf-8")
    manager = WordlistManager(tmp_path / "user-data" / "wordlists")
    monkeypatch.setattr(bruteforce.state, "config", {"bf_attempts": 10, "bf_attempts_per_user": 5})
    monkeypatch.setattr(bruteforce, "_sleep", lambda *_args, **_kwargs: None)
    clients = []

    def make_client(target, **kwargs):
        client = FakeLoginClient(target, **kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr(bruteforce, "ProtectedLoginClient", make_client)
    found, attempts = bruteforce.bruteforce_login(
        "http://127.0.0.1:8080/login", "", wordlist_path=str(password_file),
        userlist_path=str(user_file), use_extra_passwords=False, max_attempts=10,
        preflight_confirmed=True, _wordlist_manager=manager,
    )
    assert found is None
    assert attempts == 10
    assert clients[0].attempts.count(("user-one", "candidate-0")) == 1
    assert sum(1 for user, _password in clients[0].attempts if user == "user-one") == 5
    assert sum(1 for user, _password in clients[0].attempts if user == "user-two") == 5


def test_http_audit_reuses_only_a_csrf_token_refreshed_by_post_response(tmp_path, monkeypatch):
    password_file = tmp_path / "passwords.txt"
    password_file.write_text("candidate-one\ncandidate-two\n", encoding="utf-8")
    manager = WordlistManager(tmp_path / "user-data" / "wordlists")
    monkeypatch.setattr(bruteforce.state, "config", {"bf_attempts": 10, "bf_attempts_per_user": 5})
    monkeypatch.setattr(bruteforce, "_sleep", lambda *_args, **_kwargs: None)

    class RotatingCsrfClient:
        gets = 0
        posts = 0
        used_tokens = []

        def __init__(self, target, **_kwargs):
            self.target = target

        def request(self, method, _url, *, data=None):
            if method == "GET":
                type(self).gets += 1
                token = f"initial-{type(self).gets}"
                return LoginResponse(
                    200, self.target,
                    f'<input type="hidden" name="csrf-token" value="{token}">', {},
                )
            type(self).posts += 1
            type(self).used_tokens.append(data["csrf-token"])
            token = f"refreshed-{type(self).posts}"
            return LoginResponse(
                200, self.target,
                f'<input type="hidden" name="csrf-token" value="{token}">', {},
            )

        def close(self):
            return None

    monkeypatch.setattr(bruteforce, "ProtectedLoginClient", RotatingCsrfClient)

    found, attempts = bruteforce.bruteforce_login(
        "http://127.0.0.1:8080/login", "fixture-user",
        wordlist_path=str(password_file), use_extra_passwords=False,
        max_attempts=2, per_user_limit=2, preflight_confirmed=True,
        _wordlist_manager=manager,
    )

    assert found is None
    assert attempts == 2
    assert RotatingCsrfClient.gets == 1
    assert RotatingCsrfClient.posts == 2
    assert RotatingCsrfClient.used_tokens == ["initial-1", "refreshed-1"]


def test_login_uses_matching_form_action_and_only_its_csrf_fields(tmp_path, monkeypatch):
    password_file = tmp_path / "passwords.txt"
    password_file.write_text("fixture-password\n", encoding="utf-8")
    manager = WordlistManager(tmp_path / "user-data" / "wordlists")
    monkeypatch.setattr(bruteforce.state, "config", {"bf_attempts": 10, "bf_attempts_per_user": 5})
    monkeypatch.setattr(bruteforce, "_sleep", lambda *_args, **_kwargs: None)

    class LoginFormClient:
        def __init__(self, target, **_kwargs):
            self.target = target
            self.posts = []

        def validate_origin(self, url):
            if url.split("/", 3)[:3] != self.target.split("/", 3)[:3]:
                raise ProtectedRequestError("different origin")

        def request(self, method, url, *, data=None):
            if method == "GET":
                return LoginResponse(
                    200,
                    "http://127.0.0.1:8080/auth/login",
                    """
                    <form method="post" action="/search">
                      <input name="search_token" value="unrelated-token">
                    </form>
                    <form method="post" action="../session/start">
                      <input name="username">
                      <input name="password">
                      <input type="hidden" name="csrf_token" value="login-token">
                    </form>
                    """,
                    {},
                )
            self.posts.append((url, dict(data or {})))
            return LoginResponse(200, url, "FIXTURE_LOGIN_OK", {})

        def close(self):
            return None

    clients = []

    def make_client(target, **kwargs):
        client = LoginFormClient(target, **kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr(bruteforce, "ProtectedLoginClient", make_client)
    found, attempts = bruteforce.bruteforce_login(
        "http://127.0.0.1:8080/login", "fixture-user",
        wordlist_path=str(password_file), use_extra_passwords=False,
        success_marker="FIXTURE_LOGIN_OK", preflight_confirmed=True,
        _wordlist_manager=manager,
    )

    assert found == "fixture-password"
    assert attempts == 1
    assert clients[0].posts == [(
        "http://127.0.0.1:8080/session/start",
        {"username": "fixture-user", "password": "fixture-password", "csrf_token": "login-token"},
    )]


@pytest.mark.parametrize(
    ("method", "action", "message"),
    [
        ("get", "/session/start", "nao usa POST"),
        ("post", "https://other.example.test/session/start", "sai da origem confirmada"),
    ],
)
def test_unsafe_login_form_is_blocked_before_credentials_are_posted(
    tmp_path, monkeypatch, method, action, message,
):
    password_file = tmp_path / "passwords.txt"
    password_file.write_text("fixture-password\n", encoding="utf-8")
    manager = WordlistManager(tmp_path / "user-data" / "wordlists")
    monkeypatch.setattr(bruteforce.state, "config", {"bf_attempts": 10, "bf_attempts_per_user": 5})
    posts = []

    class UnsafeFormClient:
        def __init__(self, target, **_kwargs):
            self.target = target

        def validate_origin(self, url):
            if url.split("/", 3)[:3] != self.target.split("/", 3)[:3]:
                raise ProtectedRequestError("different origin")

        def request(self, request_method, url, *, data=None):
            if request_method == "GET":
                return LoginResponse(
                    200, self.target,
                    f'<form method="{method}" action="{action}">'
                    '<input name="username"><input name="password"></form>', {},
                )
            posts.append((url, data))
            return LoginResponse(200, url, "invalid", {})

        def close(self):
            return None

    monkeypatch.setattr(bruteforce, "ProtectedLoginClient", UnsafeFormClient)
    with pytest.raises(bruteforce.CredentialAuditError, match=message):
        bruteforce.bruteforce_login(
            "http://127.0.0.1:8080/login", "fixture-user",
            wordlist_path=str(password_file), use_extra_passwords=False,
            preflight_confirmed=True, _wordlist_manager=manager,
        )
    assert posts == []


def test_http_rate_limit_stops_and_blocked_checkpoint_cannot_resume(tmp_path, monkeypatch):
    password_file = tmp_path / "passwords.txt"
    password_file.write_text("unit-secret\nsecond-secret\n", encoding="utf-8")
    manager = WordlistManager(tmp_path / "user-data" / "wordlists")
    monkeypatch.setattr(bruteforce.state, "config", {"bf_attempts": 10, "bf_attempts_per_user": 5})
    waits = []
    monkeypatch.setattr(bruteforce, "_sleep", lambda seconds: waits.append(seconds))
    clients = []

    def make_client(target, **kwargs):
        client = FakeLoginClient(target, rate_limit=True, **kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr(bruteforce, "ProtectedLoginClient", make_client)
    url = "http://127.0.0.1:8080/login"
    found, attempts = bruteforce.bruteforce_login(
        url, "unit-user", wordlist_path=str(password_file), use_extra_passwords=False,
        success_marker="SIGNED_IN_OK", resumable=True, preflight_confirmed=True,
        _wordlist_manager=manager,
    )
    assert found is None
    assert attempts == 1
    assert clients[0].posts == 1
    assert waits == []
    run_path = next((tmp_path / "user-data" / "checkpoints").glob("run-*.json"))
    identity = run_path.stem.removeprefix("run-")
    store = CheckpointStore(run_path.parent)
    assert store.load(identity)["state"] == "blocked"

    with pytest.raises(bruteforce.CredentialAuditError):
        bruteforce.bruteforce_login(
            url, "unit-user", wordlist_path=str(password_file), use_extra_passwords=False,
            resumable=True, resume=True, preflight_confirmed=True, _wordlist_manager=manager,
        )
    with pytest.raises(bruteforce.CredentialAuditError):
        bruteforce.bruteforce_login(
            url, "unit-user", wordlist_path=str(password_file), use_extra_passwords=False,
            resumable=True, resume=False, preflight_confirmed=True, _wordlist_manager=manager,
        )
    assert len(clients) == 1


def test_authentication_challenge_on_preflight_get_stops_before_post(tmp_path, monkeypatch):
    password_file = tmp_path / "passwords.txt"
    password_file.write_text("candidate-secret\n", encoding="utf-8")
    manager = WordlistManager(tmp_path / "user-data" / "wordlists")
    monkeypatch.setattr(bruteforce.state, "config", {"bf_attempts": 10, "bf_attempts_per_user": 5})
    client = FakeLoginClient("http://127.0.0.1:8080/login")
    client.request = lambda method, _url, *, data=None: LoginResponse(401, client.target, "", {})
    monkeypatch.setattr(bruteforce, "ProtectedLoginClient", lambda *args, **kwargs: client)

    found, attempts = bruteforce.bruteforce_login(
        "http://127.0.0.1:8080/login", "unit-user", wordlist_path=str(password_file),
        use_extra_passwords=False, resumable=True, preflight_confirmed=True,
        _wordlist_manager=manager,
    )

    assert found is None
    assert attempts == 0
    assert client.posts == 0
    checkpoint_path = next((tmp_path / "user-data" / "checkpoints").glob("run-*.json"))
    identity = checkpoint_path.stem.removeprefix("run-")
    assert CheckpointStore(checkpoint_path.parent).load(identity)["state"] == "blocked"


def test_resume_skips_an_uncertain_inflight_credential_instead_of_repeating(tmp_path, monkeypatch):
    password_file = tmp_path / "passwords.txt"
    password_file.write_text("uncertain-secret\nunit-secret\n", encoding="utf-8")
    manager = WordlistManager(tmp_path / "user-data" / "wordlists")
    monkeypatch.setattr(bruteforce.state, "config", {"bf_attempts": 10, "bf_attempts_per_user": 5})
    monkeypatch.setattr(bruteforce, "_sleep", lambda *_args, **_kwargs: None)
    calls = []

    class InterruptedClient(FakeLoginClient):
        def request(self, method, url, *, data=None):
            if method == "POST":
                calls.append(data["password"])
                raise ProtectedRequestError("synthetic network interruption")
            return super().request(method, url, data=data)

    monkeypatch.setattr(bruteforce, "ProtectedLoginClient", InterruptedClient)
    url = "http://127.0.0.1:8080/login"
    found, attempts = bruteforce.bruteforce_login(
        url, "unit-user", wordlist_path=str(password_file), use_extra_passwords=False,
        success_marker="SIGNED_IN_OK", resumable=True, preflight_confirmed=True,
        _wordlist_manager=manager,
    )
    assert found is None and attempts == 0
    assert calls == ["uncertain-secret"]

    class ResumeClient(FakeLoginClient):
        def request(self, method, url, *, data=None):
            if method == "POST":
                calls.append(data["password"])
            return super().request(method, url, data=data)

    monkeypatch.setattr(bruteforce, "ProtectedLoginClient", ResumeClient)
    found, attempts = bruteforce.bruteforce_login(
        url, "unit-user", wordlist_path=str(password_file), use_extra_passwords=False,
        success_marker="SIGNED_IN_OK", resumable=True, resume=True,
        preflight_confirmed=True, _wordlist_manager=manager,
    )
    assert found == "unit-secret"
    assert attempts == 2  # one uncertain item counted, one request executed
    assert calls == ["uncertain-secret", "unit-secret"]


def test_resume_requires_a_checkpoint_bound_to_the_exact_login_form(tmp_path, monkeypatch):
    password_file = tmp_path / "passwords.txt"
    password_file.write_text("candidate-one\n", encoding="utf-8")
    manager = WordlistManager(tmp_path / "user-data" / "wordlists")
    monkeypatch.setattr(bruteforce.state, "config", {"bf_attempts": 10, "bf_attempts_per_user": 5})
    monkeypatch.setattr(bruteforce, "_sleep", lambda *_args, **_kwargs: None)
    clients = []

    def make_client(target, **kwargs):
        client = FakeLoginClient(target, **kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr(bruteforce, "ProtectedLoginClient", make_client)
    common = {
        "username": "fixture-user",
        "wordlist_path": str(password_file),
        "use_extra_passwords": False,
        "resumable": True,
        "preflight_confirmed": True,
        "_wordlist_manager": manager,
    }
    bruteforce.bruteforce_login("http://127.0.0.1:8080/login", **common)
    assert len(clients) == 1

    with pytest.raises(bruteforce.CredentialAuditError, match="Checkpoint compativel nao encontrado"):
        bruteforce.bruteforce_login(
            "http://127.0.0.1:8080/other-login", resume=True, **common,
        )
    assert len(clients) == 1


def test_resume_without_checkpoint_fails_before_creating_login_client(tmp_path, monkeypatch):
    password_file = tmp_path / "passwords.txt"
    password_file.write_text("candidate-one\n", encoding="utf-8")
    manager = WordlistManager(tmp_path / "user-data" / "wordlists")
    clients = []
    monkeypatch.setattr(bruteforce, "ProtectedLoginClient", lambda *args, **kwargs: clients.append(args))

    with pytest.raises(bruteforce.CredentialAuditError, match="Checkpoint compativel nao encontrado"):
        bruteforce.bruteforce_login(
            "http://127.0.0.1:8080/login", "fixture-user",
            wordlist_path=str(password_file), use_extra_passwords=False,
            resumable=True, resume=True, preflight_confirmed=True,
            _wordlist_manager=manager,
        )
    assert clients == []


def test_login_client_blocks_cross_origin_replay_and_oversized_body(monkeypatch):
    client = ProtectedLoginClient("http://127.0.0.1:8080/login")
    assert client.session.trust_env is False
    assert client.session.proxies == {}
    calls = []
    redirect = FakeResponse(302, headers={"Location": "http://127.0.0.1:8081/blocked"})
    monkeypatch.setattr(client.session, "request", lambda *args, **kwargs: calls.append(args) or redirect)
    with pytest.raises(ProtectedRequestError):
        client.request("GET", "http://127.0.0.1:8080/login")
    assert len(calls) == 1
    assert redirect.closed
    client.close()

    client = ProtectedLoginClient("http://127.0.0.1:8080/login", max_bytes=1024)
    large = FakeResponse(200, b"x" * 2048, {"Content-Length": "2048"})
    monkeypatch.setattr(client.session, "request", lambda *args, **kwargs: large)
    with pytest.raises(ProtectedRequestError):
        client.request("GET", "http://127.0.0.1:8080/login")
    assert large.closed
    client.close()
