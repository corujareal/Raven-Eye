from __future__ import annotations

import pytest

from raveneye_pkg import scanners


def test_subdomain_lookup_uses_only_valid_unique_in_scope_candidates(monkeypatch):
    calls = []
    monkeypatch.setattr(
        scanners,
        "_resolve_subdomain_addresses",
        lambda host: calls.append(host) or (["192.0.2.10", "2001:db8::10"], False),
    )

    found = scanners.brute_subdomains(
        "Example.Test.",
        ["portal", "admin", "portal", "bad/name", "-invalid"],
        scope_rules={"portal.example.test"},
    )

    assert calls == ["portal.example.test"]
    assert found == [{
        "subdomain": "portal.example.test",
        "ip": "192.0.2.10",
        "ips": ["192.0.2.10", "2001:db8::10"],
        "confidence": "unverified",
    }]


def test_empty_explicit_subdomain_wordlist_does_not_fall_back_to_bundled_list(monkeypatch):
    calls = []
    monkeypatch.setattr(scanners, "_resolve_subdomain_addresses", lambda host: calls.append(host) or (["192.0.2.10"], False))

    assert scanners.brute_subdomains("example.test", []) == []
    assert calls == []


def test_subdomain_domain_validation_blocks_malformed_names_before_dns(monkeypatch):
    calls = []
    monkeypatch.setattr(scanners, "_resolve_subdomain_addresses", lambda host: calls.append(host) or ([], False))

    with pytest.raises(ValueError, match="Domínio DNS inválido"):
        scanners.brute_subdomains("bad_domain.test", ["portal"])
    with pytest.raises(ValueError, match="Domínio DNS inválido"):
        scanners.brute_subdomains("192.0.2.1", ["portal"])
    assert calls == []


def test_dns_resolution_exceptions_are_reported_as_inconclusive(monkeypatch, capsys):
    calls = []

    def resolve(host):
        calls.append(host)
        if host.startswith("timeout."):
            return [], True
        return [], False

    monkeypatch.setattr(scanners, "_resolve_subdomain_addresses", resolve)
    monkeypatch.setattr(scanners.time, "sleep", lambda _seconds: None)

    assert scanners.brute_subdomains("example.test", ["timeout", "missing"]) == []
    assert calls.count("timeout.example.test") == 2
    assert "1 resoluções falharam; esses itens são inconclusivos" in capsys.readouterr().out


def test_system_resolver_keeps_ipv4_and_ipv6_answers(monkeypatch):
    records = [
        (scanners.socket.AF_INET, scanners.socket.SOCK_STREAM, 6, "", ("192.0.2.4", 0)),
        (scanners.socket.AF_INET6, scanners.socket.SOCK_STREAM, 6, "", ("2001:db8::4", 0, 0, 0)),
        (scanners.socket.AF_INET, scanners.socket.SOCK_STREAM, 6, "", ("192.0.2.4", 0)),
    ]
    monkeypatch.setattr(scanners.socket, "getaddrinfo", lambda *_args: records)

    assert scanners._resolve_subdomain_addresses("portal.example.test") == (
        ["192.0.2.4", "2001:db8::4"],
        False,
    )


def test_system_resolver_distinguishes_nxdomain_from_temporary_failure(monkeypatch):
    def fail_with(code):
        def _raise(*_args):
            raise scanners.socket.gaierror(code, "fixture resolver response")
        return _raise

    monkeypatch.setattr(scanners.socket, "getaddrinfo", fail_with(scanners.socket.EAI_NONAME))
    assert scanners._resolve_subdomain_addresses("missing.example.test") == ([], False)

    monkeypatch.setattr(scanners.socket, "getaddrinfo", fail_with(scanners.socket.EAI_AGAIN))
    assert scanners._resolve_subdomain_addresses("slow.example.test") == ([], True)


def test_unicode_domain_normalizes_to_idna_without_network_access():
    assert scanners.normalize_dns_domain("München.example.") == "xn--mnchen-3ya.example"


def test_wildcard_dns_answers_are_retained_as_ambiguous_not_false_confirmations(monkeypatch, capsys):
    def resolve(host):
        if host.startswith("raveneye-check-") or host.startswith("wildcard."):
            return ["192.0.2.25"], False
        return ["192.0.2.50"], False

    monkeypatch.setattr(scanners, "_resolve_subdomain_addresses", resolve)

    found = scanners.brute_subdomains("example.test", ["wildcard", "portal"])

    by_host = {item["subdomain"]: item for item in found}
    assert by_host["wildcard.example.test"]["confidence"] == "wildcard_ambiguous"
    assert by_host["portal.example.test"]["confidence"] == "confirmed"
    assert "DNS wildcard respondeu aos probes" in capsys.readouterr().out
