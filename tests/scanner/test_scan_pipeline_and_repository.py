import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from raveneye.scanner.pipeline import _dedupe_findings, _safe_active_findings, scan_urls
import raveneye.scanner.pipeline as pipeline
from raveneye.database.repository import ScanRepository

async def test_scan_urls_returns_per_url_results(monkeypatch):
    async def fake_scan(url, cfg, scope=None, **_kwargs):
        return {'url': url, 'status': 200, 'findings': [], 'technologies': []}
    monkeypatch.setattr('raveneye.scanner.pipeline.scan_url', fake_scan)
    class C: concurrency=2
    rows = await scan_urls(['https://a.test', 'https://b.test'], C())
    assert [r['url'] for r in rows] == ['https://a.test', 'https://b.test']


async def test_reflection_canary_is_used_but_never_serialized_in_finding():
    requests = []

    async def fixture_request(url):
        requests.append(url)
        value = parse_qs(urlsplit(url).query, keep_blank_values=True)['page'][0]
        return {'body': f'<p>{value}</p>', 'status': 200, 'headers': {'Content-Type': 'text/html'}}

    findings = await _safe_active_findings(
        'https://fixture.test/item?page=original',
        '<p>baseline</p>',
        SimpleNamespace(status=200, headers={'Content-Type': 'text/html'}),
        fixture_request,
    )

    assert any('RAVENEYE_' in url for url in requests)
    assert findings
    assert 'RAVENEYE_' not in repr(findings)
    assert '[redacted]' in findings[0]['url'] or '%5Bredacted%5D' in findings[0]['url']


async def test_scan_without_configured_scope_accepts_seed_host_fixture(monkeypatch):
    captured = {}

    class FixtureContent:
        async def read(self, _limit):
            return b'<html><title>fixture</title></html>'

    class FixtureResponse:
        status = 200
        headers = {'Content-Type': 'text/html'}
        charset = 'utf-8'
        content = FixtureContent()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

    class FixtureSession:
        def __init__(self, **kwargs):
            captured.update(kwargs)
            self.guard = kwargs['scope_guard']

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def request(self, _method, url, **_kwargs):
            self.guard.check(url)
            captured.setdefault('requested_urls', []).append(url)
            return FixtureResponse()

    monkeypatch.setattr(pipeline, 'AsyncSession', FixtureSession)
    cfg = SimpleNamespace(
        scope=SimpleNamespace(include_domains=[], exclude=[]),
        user_agent='fixture', timeout_seconds=2, verify_tls=True,
        requests_per_second=100, max_response_bytes=4096,
        cve_records_path=None,
    )

    result = await pipeline.scan_url(
        'https://fixture.test/item?page=RAVENEYE_page_probe', cfg, active_safe=True,
    )

    assert result['status'] == 200
    assert captured['allowed_domains'] == {'fixture.test'}
    assert captured['requested_urls'][0] == 'https://fixture.test/item?page=RAVENEYE_page_probe'
    assert all('fixture.test' in url for url in captured['requested_urls'])
    assert 'RAVENEYE_' not in repr(result)
    assert '[redacted]' in result['url'] or '%5Bredacted%5D' in result['url']


def test_same_response_secret_and_header_findings_are_not_duplicated():
    url = 'https://fixture.test/'
    response_hash = 'same-response-hash'
    findings = [
        {
            'id': 'possible-secret-disclosure', 'url': url, 'severity': 'MEDIUM',
            'evidence_metadata': {'response': {'sha256': response_hash}},
        },
        {
            'id': 'potential-secret-disclosure', 'url': url, 'severity': 'HIGH',
            'evidence_metadata': {'response': {'sha256': response_hash}},
        },
        {
            'id': 'headers.csp', 'url': url,
            'evidence_metadata': {'response': {'sha256': response_hash}},
        },
        {
            'id': 'csp-missing', 'url': url,
            'evidence_metadata': {'response': {'sha256': response_hash}},
        },
    ]

    deduped = _dedupe_findings(findings)

    assert [finding['id'] for finding in deduped] == [
        'possible-secret-disclosure', 'headers.csp',
    ]
    # Keep the earlier, lower-severity duplicate as the conservative record.
    assert deduped[0]['severity'] == 'MEDIUM'


def test_xcto_aliases_from_passive_checks_collapse_for_same_response():
    response_hash = 'same-xcto-response'
    deduped = _dedupe_findings([
        {
            'id': 'headers.xcto', 'url': 'https://fixture.test/',
            'evidence_metadata': {'response': {'sha256': response_hash}},
        },
        {
            'id': 'headers-security.xcto', 'url': 'https://fixture.test/',
            'evidence_metadata': {'response': {'sha256': response_hash}},
        },
    ])
    assert [item['id'] for item in deduped] == ['headers.xcto']


def test_repository_persists_findings(tmp_path):
    p=tmp_path/'scan.db'; repo=ScanRepository(p)
    sid=repo.save_scan('https://example.test',[{'name':'CSP missing','severity':'MEDIUM','confidence':'HIGH','url':'https://example.test','evidence':'x'*700,'remediation':'Set CSP'}],4.0)
    import sqlite3
    with sqlite3.connect(p) as db:
        row=db.execute('select scan_id,name,evidence from findings where scan_id=?',(sid,)).fetchone()
    assert row[0]==sid and row[1]=='CSP missing' and len(row[2])==500
