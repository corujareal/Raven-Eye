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
