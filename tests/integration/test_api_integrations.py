from __future__ import annotations

import json
import os
import sys
from types import SimpleNamespace

from raveneye_pkg import state
from raveneye_pkg import api_integrations, config_io


class FakeResponse:
    def __init__(self, payload, status_code=200, headers=None):
        self._payload = payload
        self.status_code = status_code
        self.headers = headers or {}

    def json(self):
        return self._payload


def test_asset_integrations_send_provider_auth_and_return_compact_summaries(monkeypatch):
    monkeypatch.setenv("CENSYS_API_KEY", "censys-test-secret")
    monkeypatch.setenv("CENSYS_ORGANIZATION_ID", "org-test")
    monkeypatch.setenv("NETLAS_API_KEY", "netlas-test-secret")
    monkeypatch.setenv("LEAKIX_API_KEY", "leakix-test-secret")
    calls = []
    payloads = {
        "censys.io": {
            "result": {"resource": {
                "ip": "203.0.113.8", "service_count": 1,
                "services": [{"port": 443}],
                "autonomous_system": {"asn": 64500, "name": "Example AS"},
                "dns": {"names": ["www.example.test"]},
                "banner": "private raw banner",
            }}
        },
        "netlas.io": {
            "ip": "203.0.113.8", "ports": [{"port": 8443}],
            "organization": "Example Org", "software": [{"tag": [{
                "azure_cdn": {"version": ""}, "name": "azure_cdn",
                "fullname": "Azure CDN", "category": ["CDN"],
            }]}],
            "raw": "private raw response",
        },
        "leakix.net": {
            "Services": [{"host": "www.example.test", "port": 443,
                          "protocol": "https", "banner": "private leak body"}],
            "Leaks": [{"host": "www.example.test", "event_type": "fixture",
                       "leak": {"type": "config", "severity": "low", "raw": "secret"}}],
        },
    }

    def requester(url, **kwargs):
        calls.append((url, kwargs))
        host = url.split("/")[2]
        provider = next(name for name in payloads if host.endswith(name))
        return FakeResponse(payloads[provider])

    results = api_integrations.collect_asset_intelligence(
        "www.example.test", "203.0.113.8", requester=requester,
    )

    assert set(results) == {"censys", "netlas", "leakix"}
    assert [row[1]["allow_redirects"] for row in calls] == [False, False, False]
    assert all(row[1]["timeout"] == (4, 12) for row in calls)
    censys_headers = calls[0][1]["headers"]
    assert censys_headers["Authorization"] == "Bearer censys-test-secret"
    assert censys_headers["X-Organization-ID"] == "org-test"
    assert censys_headers["Accept"] == api_integrations._CENSYS_ACCEPT
    assert calls[1][1]["headers"]["Authorization"] == "Bearer netlas-test-secret"
    assert calls[2][1]["headers"]["api-key"] == "leakix-test-secret"
    assert results["censys"]["data"]["ports"] == [443]
    assert results["netlas"]["data"]["ports"] == [8443]
    assert results["netlas"]["data"]["software"] == ["Azure CDN", "azure_cdn"]
    assert results["leakix"]["data"]["leaks_count"] == 1
    serialized = json.dumps(results)
    for secret in ("test-secret", "private raw", "private leak body"):
        assert secret not in serialized


def test_censys_organization_id_is_optional_for_host_lookup(monkeypatch):
    monkeypatch.setenv("CENSYS_API_KEY", "censys-test-secret")
    monkeypatch.delenv("CENSYS_ORGANIZATION_ID", raising=False)
    monkeypatch.setattr(state, "config", {})
    monkeypatch.setattr(state, "CENSYS_API_KEY", "")
    calls = []

    def requester(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse({"result": {"resource": {"ip": "203.0.113.8", "services": []}}})

    result = api_integrations.collect_asset_intelligence(
        "example.test", "203.0.113.8", requester=requester,
    )

    assert result["censys"]["status"] == "ok"
    assert len(calls) == 1
    assert calls[0][1]["headers"]["Authorization"] == "Bearer censys-test-secret"
    assert "X-Organization-ID" not in calls[0][1]["headers"]


def test_censys_skips_lookup_when_target_ip_is_unavailable(monkeypatch):
    monkeypatch.setenv("CENSYS_API_KEY", "censys-test-secret")
    monkeypatch.delenv("CENSYS_ORGANIZATION_ID", raising=False)
    monkeypatch.delenv("NETLAS_API_KEY", raising=False)
    monkeypatch.delenv("LEAKIX_API_KEY", raising=False)
    monkeypatch.setattr(state, "config", {})
    monkeypatch.setattr(state, "CENSYS_API_KEY", "")
    calls = []

    result = api_integrations.collect_asset_intelligence(
        "example.test", "", requester=lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    assert result["censys"]["status"] == "target_ip_unavailable"
    assert calls == []


def test_provider_http_errors_distinguish_auth_plan_permission_and_missing_asset():
    expected = {
        400: "invalid_request",
        401: "authentication_failed",
        402: "plan_limit",
        403: "permission_denied",
        404: "asset_not_found",
        422: "invalid_request",
    }
    for http_status, expected_status in expected.items():
        payload, error = api_integrations._fetch(
            "Netlas", "https://fixture.invalid/host/example.test/",
            headers={}, requester=lambda *_args, status=http_status, **_kwargs: FakeResponse({}, status),
        )
        assert payload is None
        assert error["status"] == expected_status
        assert error["http_status"] == http_status


def test_api_timeout_and_server_failures_are_distinguished_without_echoing_body():
    cases = {
        408: "provider_timeout",
        500: "provider_unavailable",
        503: "provider_unavailable",
        504: "provider_unavailable",
    }
    for http_status, expected_status in cases.items():
        _payload, error = api_integrations._fetch(
            "Netlas", "https://fixture.invalid/host/example.test/",
            headers={},
            requester=lambda *_args, status=http_status, **_kwargs: FakeResponse(
                {"error": "sensitive-provider-detail"}, status,
            ),
        )
        assert error["status"] == expected_status
        assert error["http_status"] == http_status
        assert "sensitive-provider-detail" not in json.dumps(error)


def test_http_204_is_reported_as_no_content_without_fabricating_http_200(monkeypatch):
    monkeypatch.setenv("NETLAS_API_KEY", "netlas-test-secret")
    monkeypatch.delenv("CENSYS_API_KEY", raising=False)
    monkeypatch.delenv("LEAKIX_API_KEY", raising=False)
    monkeypatch.setattr(state, "config", {})
    monkeypatch.setattr(state, "NETLAS_API_KEY", "")

    result = api_integrations.collect_asset_intelligence(
        "example.test", "203.0.113.8",
        requester=lambda *_args, **_kwargs: FakeResponse({}, status_code=204),
    )

    assert result["netlas"]["status"] == "no_content"
    assert result["netlas"]["http_status"] == 204
    assert "data" not in result["netlas"]


def test_leakix_rate_limit_delay_hint_is_preserved_without_retry():
    calls = []
    _payload, error = api_integrations._fetch(
        "LeakIX", "https://fixture.invalid/domain/example.test",
        headers={},
        requester=lambda *_args, **_kwargs: calls.append(True) or FakeResponse({}, 429, {"x-limited-for": "344.24ms"}),
    )

    assert error["status"] == "rate_limited"
    assert "X-Limited-For: 344.24ms" in error["message"]
    assert calls == [True]


def test_asset_integrations_skip_unconfigured_providers(monkeypatch):
    monkeypatch.delenv("CENSYS_API_KEY", raising=False)
    monkeypatch.delenv("NETLAS_API_KEY", raising=False)
    monkeypatch.delenv("LEAKIX_API_KEY", raising=False)
    monkeypatch.setattr(state, "config", {})
    monkeypatch.setattr(state, "CENSYS_API_KEY", "")
    monkeypatch.setattr(state, "NETLAS_API_KEY", "")
    monkeypatch.setattr(state, "LEAKIX_API_KEY", "")
    called = []

    assert api_integrations.collect_asset_intelligence(
        "example.test", "203.0.113.8", requester=lambda *a, **k: called.append(a),
    ) == {}
    assert called == []


def test_provider_rate_limit_is_reported_without_retry(monkeypatch):
    monkeypatch.setenv("NETLAS_API_KEY", "netlas-test-secret")
    monkeypatch.delenv("CENSYS_API_KEY", raising=False)
    monkeypatch.delenv("LEAKIX_API_KEY", raising=False)
    monkeypatch.setattr(state, "config", {})
    monkeypatch.setattr(state, "NETLAS_API_KEY", "")
    calls = []

    def requester(url, **kwargs):
        calls.append(url)
        return FakeResponse({}, 429, {"Retry-After": "30"})

    results = api_integrations.collect_asset_intelligence(
        "example.test", "203.0.113.8", requester=requester,
    )

    assert results["netlas"]["status"] == "rate_limited"
    assert "30s" in results["netlas"]["message"]
    assert len(calls) == 1


def test_new_api_keys_persist_obfuscated_and_environment_overrides(monkeypatch, tmp_path):
    path = tmp_path / "config.json"
    monkeypatch.setattr(config_io, "CONFIG_FILE", str(path))
    monkeypatch.delenv("CENSYS_API_KEY", raising=False)
    monkeypatch.setattr(state, "config", config_io.DEFAULT_CONFIG.copy())
    monkeypatch.setattr(state, "CENSYS_API_KEY", "")

    config_io.set_api_key("censys", "censys-test-secret")
    config_io.save_config(state.config)
    saved = path.read_text(encoding="utf-8")
    assert "censys-test-secret" not in saved
    assert config_io.load_config()["_censys_decoded"] == "censys-test-secret"

    monkeypatch.setenv("CENSYS_API_KEY", "environment-secret")
    assert config_io.get_api_key("censys") == "environment-secret"


def test_google_cse_environment_key_and_id_override_stored_values(monkeypatch):
    monkeypatch.setattr(state, "config", {
        "_google_cse_decoded": "stored-key", "google_cse_id": "stored-id",
    })
    monkeypatch.setattr(state, "GOOGLE_CSE_API_KEY", "")
    monkeypatch.setenv("GOOGLE_CSE_API_KEY", "environment-key")
    monkeypatch.setenv("GOOGLE_CSE_ID", "environment-id")

    assert config_io.get_api_key("google_cse") == "environment-key"
    assert config_io.get_google_cse_id() == "environment-id"


def test_dotenv_credentials_are_loaded_without_overriding_exported_environment(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "CENSYS_API_KEY=dotenv-censys\n"
        "CENSYS_ORGANIZATION_ID=dotenv-org\n"
        "GOOGLE_CSE_API_KEY=dotenv-google\n"
        "GOOGLE_CSE_ID=dotenv-id\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(config_io, "_ENVIRONMENT_LOADED", False)
    monkeypatch.setattr(state, "config", {"_censys_decoded": "", "_google_cse_decoded": ""})
    monkeypatch.setattr(state, "CENSYS_API_KEY", "")
    monkeypatch.setattr(state, "GOOGLE_CSE_API_KEY", "")

    def fake_load_dotenv(path, *, override=False):
        for line in path.read_text(encoding="utf-8").splitlines():
            key, value = line.split("=", 1)
            if override or key not in os.environ:
                os.environ[key] = value

    monkeypatch.setitem(sys.modules, "dotenv", SimpleNamespace(load_dotenv=fake_load_dotenv))
    for key in ("CENSYS_API_KEY", "CENSYS_ORGANIZATION_ID", "GOOGLE_CSE_API_KEY", "GOOGLE_CSE_ID"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GOOGLE_CSE_API_KEY", "exported-google")

    assert config_io.get_api_key("censys") == "dotenv-censys"
    assert os.environ["CENSYS_ORGANIZATION_ID"] == "dotenv-org"
    assert config_io.get_api_key("google_cse") == "exported-google"
    assert config_io.get_google_cse_id() == "dotenv-id"
