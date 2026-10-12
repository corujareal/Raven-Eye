"""Single-credential SSH verification with pinned routing and host-key checks."""
from __future__ import annotations

import ipaddress
from pathlib import Path

try:
    import asyncssh
except ImportError:  # The installer declares AsyncSSH as a required runtime dep.
    asyncssh = None

from raveneye.bruteforce.http_client import _resolve_and_pin
from raveneye.network.domains import canonical_host, host_matches_rule
from raveneye_pkg import state
from .base import UnsupportedProtocolError


class SSHConnectionError(RuntimeError):
    """A sanitized SSH transport failure."""


class SSHHostKeyError(SSHConnectionError):
    """The target host key could not be verified against known_hosts."""


def _validate_host(host: str) -> str:
    value = str(host or "").strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        parsed_ip = ipaddress.ip_address(value)
        if parsed_ip.is_multicast or parsed_ip.is_reserved or parsed_ip.is_unspecified or parsed_ip.is_link_local:
            raise ValueError
        return str(parsed_ip)
    except ValueError:
        if not value or any(char in value for char in "/\\@?#"):
            raise ValueError("SSH host must be a DNS name or IP address") from None
        try:
            return canonical_host(value)
        except ValueError:
            raise ValueError("SSH host must be a DNS name or IP address") from None


def _check_scope(host: str) -> None:
    scope_file = str(state.config.get("scope_file", "") or "").strip()
    if not scope_file:
        return
    try:
        rules = [
            line.strip()
            for line in Path(scope_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except (OSError, UnicodeError):
        raise SSHConnectionError("Configured scope file is unavailable; SSH audit refused.") from None
    if not rules or not any(host_matches_rule(host, rule) for rule in rules):
        raise SSHConnectionError("SSH target is outside the configured scope.")


class Adapter:
    """Verify one explicit SSH username/password pair; never runs commands."""

    protocol = "ssh"

    async def connect(
        self,
        host: str,
        username: str,
        password: str,
        *,
        port: int = 22,
        timeout: float = 8.0,
        preflight_confirmed: bool = False,
        known_hosts: str | None = None,
    ) -> bool:
        if not preflight_confirmed:
            raise SSHConnectionError("Explicit target confirmation is required before SSH authentication.")
        target_host = _validate_host(host)
        if isinstance(port, bool) or not 1 <= int(port) <= 65535 or int(port) != port:
            raise ValueError("SSH port must be between 1 and 65535")
        try:
            timeout_value = float(timeout)
        except (TypeError, ValueError):
            raise ValueError("SSH timeout must be between 1 and 30 seconds") from None
        if not 1.0 <= timeout_value <= 30.0:
            raise ValueError("SSH timeout must be between 1 and 30 seconds")
        if not isinstance(username, str) or not username or not isinstance(password, str):
            raise ValueError("SSH username and password must be text; username cannot be empty")

        _check_scope(target_host)
        if asyncssh is None:
            raise UnsupportedProtocolError("SSH audit requires the installed AsyncSSH dependency.")
        pinned_ip = _resolve_and_pin(target_host, int(port))
        options = {
            "port": int(port),
            "username": username,
            "password": password,
            # Dial the previously resolved address while validating the host
            # key against the original name and port.
            "host_key_alias": target_host,
            "client_keys": None,
            "public_key_auth": False,
            "password_auth": True,
            "kbdint_auth": False,
            "host_based_auth": False,
            "gss_auth": False,
            "gss_kex": False,
            "connect_timeout": timeout_value,
            "login_timeout": timeout_value,
        }
        if known_hosts:
            options["known_hosts"] = known_hosts

        try:
            connection = await asyncssh.connect(pinned_ip, **options)
        except asyncssh.PermissionDenied:
            return False
        except asyncssh.HostKeyNotVerifiable:
            raise SSHHostKeyError("SSH host key did not match trusted known_hosts data.") from None
        except (asyncssh.Error, OSError, TimeoutError):
            raise SSHConnectionError("SSH connection failed or timed out for the confirmed target.") from None
        try:
            return True
        finally:
            connection.close()
            await connection.wait_closed()
