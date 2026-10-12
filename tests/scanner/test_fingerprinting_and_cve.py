from raveneye.scanner.fingerprint import fingerprint
from raveneye.scanner.cve_correlator import correlate_exact, records_from_nvd_json
from raveneye.reports.html import render

def test_fingerprint_extracts_server_version_and_openapi():
    fs=fingerprint({"Server":"nginx/1.24.0"}, "<html>swagger-ui openapi</html>")
    by={x["name"]:x for x in fs}
    assert by["nginx"]["version"]=="1.24.0"
    assert "Swagger/OpenAPI" in by

def test_cve_nvd_normalization_requires_exact_version():
    data={"vulnerabilities":[{"cve":{"id":"CVE-1","descriptions":[{"lang":"en","value":"summary"}],
      "configurations":[{"nodes":[{"cpeMatch":[{"criteria":"cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"}]}]}]}}]}
    rows=records_from_nvd_json(data)
    assert [x.cve for x in correlate_exact("nginx","1.24.0",rows)]==["CVE-1"]
    assert correlate_exact("nginx","1.24.1",rows)==[]

def test_html_is_self_contained():
    out=render("https://e.test",[{"severity":"INFO","name":"x","url":"u","confidence":"LOW"}])
    assert "self-contained report" in out
    assert "RavenEye v6.6.6" in out
