from raveneye.scanner.passive_checks import scan_headers


class MultiHeaders(dict):
    def getall(self, name, default=None):
        if name.lower() == 'set-cookie':
            return ['sid=one; Secure; HttpOnly; SameSite=Lax', 'prefs=two']
        return default or []


def test_multiple_set_cookie_headers_are_checked_individually():
    findings = scan_headers('https://example.test/', MultiHeaders({'Set-Cookie': 'sid=one'}), '')
    secure = [f for f in findings if f.id == 'cookie-secure']
    httponly = [f for f in findings if f.id == 'cookie-httponly']
    samesite = [f for f in findings if f.id == 'cookie-samesite']
    assert len(secure) == len(httponly) == len(samesite) == 1
    assert '#2' in secure[0].evidence


def test_cookie_flags_are_parsed_as_attributes_and_generic_cookies_stay_low_confidence():
    class Headers(dict):
        def getall(self, name, default=None):
            if name.lower() == 'set-cookie':
                return [
                    'analytics=secure-httponly-samesite; Securely; X-HttpOnly; SameSite-Mode=Lax',
                    'sessionid=fixture-secret',
                    'prefs=ok; Secure; HttpOnly; SameSite=Lax',
                ]
            return default or []

    findings = scan_headers(
        'https://fixture.test/', Headers({'Set-Cookie': 'multiple'}), '',
    )
    cookie_findings = [finding for finding in findings if finding.id.startswith('cookie-')]
    generic = [finding for finding in cookie_findings if '#1' in finding.evidence]
    session = [finding for finding in cookie_findings if '#2' in finding.evidence]
    correctly_flagged = [finding for finding in cookie_findings if '#3' in finding.evidence]

    assert {finding.id for finding in generic} == {'cookie-secure', 'cookie-httponly', 'cookie-samesite'}
    assert all(finding.severity == 'INFO' and finding.confidence == 'LOW' for finding in generic)
    assert {finding.id for finding in session} == {'cookie-secure', 'cookie-httponly', 'cookie-samesite'}
    assert all(finding.severity == 'LOW' and finding.confidence == 'MEDIUM' for finding in session)
    assert correctly_flagged == []
    assert 'fixture-secret' not in repr(cookie_findings)


def test_cookie_prefix_constraints_and_samesite_none_are_checked_without_values():
    class Headers(dict):
        def getall(self, name, default=None):
            if name.lower() == 'set-cookie':
                return [
                    '__Secure-session=secret-one; HttpOnly',
                    '__Host-session=secret-two; Secure; Domain=example.test; Path=/',
                    'cross-site=secret-three; SameSite=None',
                    '__Host-valid=secret-four; Secure; HttpOnly; Path=/; SameSite=Lax',
                    '__Secure-valid=secret-five; Secure; HttpOnly',
                    'cross-site-valid=secret-six; SameSite=None; Secure',
                ]
            return default or []

    findings = scan_headers('https://fixture.test/', Headers({'Set-Cookie': 'hidden'}), '')
    by_id = {}
    for finding in findings:
        by_id.setdefault(finding.id, []).append(finding)

    assert len(by_id['cookie.prefix-secure']) == 1
    assert len(by_id['cookie.prefix-host']) == 1
    assert len(by_id['cookie.samesite-none-secure']) == 1
    assert by_id['cookie.prefix-secure'][0].stage == 'CONFIRMED'
    assert by_id['cookie.prefix-host'][0].stage == 'CONFIRMED'
    assert by_id['cookie.samesite-none-secure'][0].stage == 'CONFIRMED'
    serialized = repr(findings)
    for value in ('secret-one', 'secret-two', 'secret-three', 'secret-four', 'secret-five', 'secret-six'):
        assert value not in serialized

    insecure = scan_headers('http://fixture.test/', {
        'Set-Cookie': '__Secure-http=hidden; Secure',
    })
    assert any(item.id == 'cookie.prefix-secure' for item in insecure)

    loopback = scan_headers('http://localhost/', {
        'Set-Cookie': '__Host-local=hidden; Secure; Path=/',
    })
    assert not any(item.id == 'cookie.prefix-host' for item in loopback)
