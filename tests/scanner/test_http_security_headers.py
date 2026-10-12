from raveneye.scanner.passive_checks import scan_headers


def test_https_hsts_and_cookie_flags_are_checked():
    findings = scan_headers('https://example.test/', {'content-type':'text/html','set-cookie':'sid=abc'}, '<html></html>')
    ids = {f.id for f in findings}
    assert 'tls.hsts' in ids
    assert 'cookie-secure' in ids
    assert 'cookie-httponly' in ids
    assert 'cookie-samesite' in ids


def test_http_does_not_report_hsts_missing():
    findings = scan_headers('http://example.test/', {}, '')
    assert 'tls.hsts' not in {f.id for f in findings}


def test_secret_evidence_is_redacted():
    findings = scan_headers('https://example.test/', {}, 'api_key=SUPERSECRET123')
    f = next(x for x in findings if x.id == 'possible-secret-disclosure')
    assert 'SUPERSECRET123' not in f.evidence
    assert '<redacted>' in f.evidence


def test_debug_and_private_address_disclosure_are_detected():
    body = 'Traceback (most recent call last) ... internal service 10.0.0.5'
    ids = {f.id for f in scan_headers('https://example.test/', {}, body)}
    assert 'debug-information-disclosure' in ids
    assert 'private-address-disclosure' in ids
