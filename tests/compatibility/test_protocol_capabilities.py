import asyncio
import importlib
from types import SimpleNamespace
import pytest

from raveneye.bruteforce.protocols.base import UnsupportedProtocolError


@pytest.mark.parametrize("name", [
    "ftp", "ldap", "mongodb", "mysql", "postgres", "rdp",
    "redis", "smb", "smtp", "telnet",
])
def test_unavailable_protocols_fail_explicitly(name):
    module = importlib.import_module(f"raveneye.bruteforce.protocols.{name}")
    with pytest.raises(UnsupportedProtocolError):
        asyncio.run(module.Adapter().connect())


def test_http_adapter_routes_through_guarded_engine():
    from raveneye.bruteforce.protocols.http import Adapter

    class Engine:
        async def run(self, login_url, username, **options):
            return (login_url, username, options["preflight_confirmed"])

    result = asyncio.run(Adapter(Engine()).audit(
        "http://127.0.0.1/login", "fixture-user", preflight_confirmed=True,
    ))
    assert result == ("http://127.0.0.1/login", "fixture-user", True)


def test_http_adapter_does_not_misrepresent_connect_as_supported():
    from raveneye.bruteforce.protocols.http import Adapter

    with pytest.raises(UnsupportedProtocolError, match="Adapter.audit"):
        asyncio.run(Adapter().connect())


def test_ssh_adapter_pins_ip_and_keeps_host_key_validation_enabled(monkeypatch):
    from raveneye.bruteforce.protocols import ssh

    calls = []

    class SSHError(Exception):
        pass

    class PermissionDenied(SSHError):
        pass

    class HostKeyNotVerifiable(SSHError):
        pass

    class Connection:
        closed = False

        def close(self):
            self.closed = True

        async def wait_closed(self):
            return None

    connection = Connection()

    async def connect(host, **kwargs):
        calls.append((host, kwargs))
        return connection

    FakeAsyncSSH = SimpleNamespace(
        Error=SSHError,
        PermissionDenied=PermissionDenied,
        HostKeyNotVerifiable=HostKeyNotVerifiable,
        connect=connect,
    )

    monkeypatch.setattr(ssh, "asyncssh", FakeAsyncSSH)
    monkeypatch.setattr(ssh, "_resolve_and_pin", lambda host, port: "127.0.0.1")
    monkeypatch.setattr(ssh.state, "config", {"scope_file": ""})

    result = asyncio.run(ssh.Adapter().connect(
        "fixture.example.test", "fixture-user", "fixture-password",
        preflight_confirmed=True,
    ))

    assert result is True
    assert calls[0][0] == "127.0.0.1"
    assert calls[0][1]["host_key_alias"] == "fixture.example.test"
    assert "known_hosts" not in calls[0][1]  # AsyncSSH's normal known_hosts validation stays enabled.
    assert calls[0][1]["client_keys"] is None
    assert calls[0][1]["public_key_auth"] is False
    assert calls[0][1]["password_auth"] is True
    assert calls[0][1]["kbdint_auth"] is False
    assert calls[0][1]["host_based_auth"] is False
    assert calls[0][1]["gss_auth"] is False
    assert calls[0][1]["gss_kex"] is False
    assert connection.closed


def test_ssh_adapter_refuses_without_preflight_and_stops_on_scope_errors(monkeypatch, tmp_path):
    from raveneye.bruteforce.protocols import ssh

    with pytest.raises(ssh.SSHConnectionError, match="confirmation"):
        asyncio.run(ssh.Adapter().connect("127.0.0.1", "user", "password"))

    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("allowed.example.test\n", encoding="utf-8")
    monkeypatch.setattr(ssh.state, "config", {"scope_file": str(scope_file)})
    monkeypatch.setattr(
        ssh, "_resolve_and_pin",
        lambda *_args: (_ for _ in ()).throw(AssertionError("scope check must run before DNS")),
    )
    with pytest.raises(ssh.SSHConnectionError, match="outside the configured scope"):
        asyncio.run(ssh.Adapter().connect(
            "blocked.example.test", "user", "password", preflight_confirmed=True,
        ))


def test_ssh_adapter_distinguishes_bad_password_and_untrusted_host_key(monkeypatch):
    from raveneye.bruteforce.protocols import ssh

    class SSHError(Exception):
        pass

    class PermissionDenied(SSHError):
        pass

    class HostKeyNotVerifiable(SSHError):
        pass

    class FakeAsyncSSH:
        failure = PermissionDenied

        @classmethod
        async def connect(cls, *_args, **_kwargs):
            raise cls.failure()

    FakeAsyncSSH.Error = SSHError
    FakeAsyncSSH.PermissionDenied = PermissionDenied
    FakeAsyncSSH.HostKeyNotVerifiable = HostKeyNotVerifiable

    monkeypatch.setattr(ssh, "asyncssh", FakeAsyncSSH)
    monkeypatch.setattr(ssh, "_resolve_and_pin", lambda *_args: "127.0.0.1")
    monkeypatch.setattr(ssh.state, "config", {"scope_file": ""})
    adapter = ssh.Adapter()

    assert asyncio.run(adapter.connect(
        "fixture.example.test", "user", "wrong", preflight_confirmed=True,
    )) is False

    FakeAsyncSSH.failure = HostKeyNotVerifiable
    with pytest.raises(ssh.SSHHostKeyError, match="known_hosts"):
        asyncio.run(adapter.connect(
            "fixture.example.test", "user", "wrong", preflight_confirmed=True,
        ))
