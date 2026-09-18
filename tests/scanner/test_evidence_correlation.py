from raveneye.scanner.cve_correlator import correlate_technologies, records_from_nvd_json
from raveneye.scanner.passive_checks import check_extended_response

def test_cve_correlation_requires_identified_exact_version():
    tech = [{"name": "nginx", "version": "1.24.0", "confidence": "HIGH", "source": "header:server"}]
    records = [{"product": "nginx", "version": "1.24.0", "cve": "CVE-2024-0001", "severity": "HIGH"}]
    found = correlate_technologies(tech, records, url="https://example.test/")
    assert found[0]["cve"] == "CVE-2024-0001"
    assert correlate_technologies([{**tech[0], "version": "1.24.1"}], records, url="https://example.test/") == []

def test_extended_checks_require_context_for_sensitive_cache():
    found = check_extended_response("https://example.test/account", 200, {"Cache-Control": "public, max-age=60"}, "")
    assert any(x.id == "sensitive-response-public-cache" for x in found)
    ordinary = check_extended_response("https://example.test/assets/app.js", 200, {"Cache-Control": "public"}, "")
    assert not any(x.id == "sensitive-response-public-cache" for x in ordinary)

def test_nvd_cwe_is_preserved():
    data = {"vulnerabilities": [{"cve": {"id": "CVE-2024-1", "descriptions": [], "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}], "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"}]}]}]}}]}
    assert records_from_nvd_json(data)[0]["cwe"] == "CWE-79"
