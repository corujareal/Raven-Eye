import json
import pytest
from raveneye.network.ssrf_guard import validate_url, SSRFBlocked
from raveneye.scanner.api_security import analyze_openapi


def test_openapi_security_disabled_is_reported():
    spec={'openapi':'3.0.0','paths':{'/users/{id}':{'get':{'security':[],'parameters':[{'name':'id','in':'path'}],'responses':{'200':{}}}}}}
    fs=analyze_openapi(spec, base_url='https://example.com/api')
    assert any('disables declared security' in f['name'] for f in fs)
    assert any('object-reference' in f['name'] for f in fs)


def test_ssrf_rejects_literal_private_ip():
    with pytest.raises(SSRFBlocked):
        validate_url('http://127.0.0.1/')


def test_ssrf_rejects_private_dns_resolution(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [(2,1,6,'',('10.0.0.5',80))]
    monkeypatch.setattr('socket.getaddrinfo', fake_getaddrinfo)
    with pytest.raises(SSRFBlocked):
        validate_url('https://example.invalid/')
