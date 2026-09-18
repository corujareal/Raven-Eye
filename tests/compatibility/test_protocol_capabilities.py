import asyncio
import importlib
import pytest

from raveneye.bruteforce.protocols.base import UnsupportedProtocolError


@pytest.mark.parametrize("name", [
    "ftp", "http", "ldap", "mongodb", "mysql", "postgres", "rdp",
    "redis", "smb", "smtp", "ssh", "telnet",
])
def test_unavailable_protocols_fail_explicitly(name):
    module = importlib.import_module(f"raveneye.bruteforce.protocols.{name}")
    with pytest.raises(UnsupportedProtocolError):
        asyncio.run(module.Adapter().connect())
