from raveneye.scanner.passive_checks import check_extended_response
from raveneye.scanner.api_security import inspect_operations


def test_extended_headers_and_disclosure_checks():
    f = check_extended_response(
        'https://example.test/', 200,
        {'Content-Type':'text/html', 'Content-Security-Policy':"default-src 'self' 'unsafe-inline'"},
        '<html><script>//# sourceMappingURL=app.js.map</script></html>'
    )
    ids = {x.id for x in f}
    assert 'csp-unsafe-inline' in ids
    assert 'permissions-policy-missing' in ids
    assert 'source-map-reference' in ids


def test_secret_evidence_is_redacted():
    f = check_extended_response('https://example.test/', 200, {}, "api_key='super-secret-value-123'")
    finding = next(x for x in f if x.id == 'potential-secret-disclosure')
    assert 'super-secret' not in finding.evidence
    assert 'redacted' in finding.evidence.lower()


def test_openapi_operation_security_review():
    spec = {'openapi':'3.0.0','paths':{'/users/{id}':{'get':{'parameters':[{'name':'id','in':'path'}]}}}}
    f = inspect_operations(spec, 'https://example.test')
    assert any(x['id'] == 'api-object-reference-review' for x in f)
