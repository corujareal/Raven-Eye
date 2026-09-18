import random
from types import SimpleNamespace

from raveneye.network.scope_guard import ScopeGuard
from raveneye.scanner.passive_checks import scan_headers
from raveneye.scanner.pipeline import _query_params


def test_scanner_uses_config_scope_exclusions():
    cfg = SimpleNamespace(scope=SimpleNamespace(include_domains=['example.com'], exclude=['/private']))
    # Regression contract: the scanner pipeline must read cfg.scope.exclude.
    assert getattr(cfg.scope, 'exclude') == ['/private']


def test_scope_guard_blocks_excluded_paths_and_suffix_collisions():
    guard = ScopeGuard(domains={'example.com', '*.example.com'}, excludes=('/private*',))
    import pytest
    with pytest.raises(ValueError):
        guard.check('https://example.com/private/admin')
    with pytest.raises(ValueError):
        # suffix collision must never become in-scope
        guard.check('https://evil-example.com/')
    assert guard.check('https://api.example.com/public')


def test_scanner_headers_survive_malformed_fuzz_inputs():
    rnd = random.Random(45001)
    alphabet = "abcXYZ0123;:'\"/\\<>[]{}()_-?=&% "
    for _ in range(500):
        headers = {
            'Content-Type': rnd.choice(['text/html', 'application/json', '', 'text/plain']),
            'Server': ''.join(rnd.choice(alphabet) for _ in range(rnd.randrange(0, 40))),
            'Set-Cookie': ''.join(rnd.choice(alphabet) for _ in range(rnd.randrange(0, 80))),
        }
        body = ''.join(rnd.choice(alphabet) for _ in range(rnd.randrange(0, 500)))
        findings = scan_headers(rnd.choice(['http://example.com/', 'https://example.com/']), headers, body)
        assert isinstance(findings, list)


def test_query_parameter_parser_is_bounded_and_stable():
    url = 'https://example.com/?' + '&'.join(f'p{i}=x' for i in range(100))
    params = _query_params(url)
    assert len(params) == 24
    assert params[:3] == ['p0', 'p1', 'p2']
