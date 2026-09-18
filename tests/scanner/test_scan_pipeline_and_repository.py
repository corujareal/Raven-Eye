import json
from pathlib import Path
from raveneye.scanner.pipeline import scan_urls
from raveneye.database.repository import ScanRepository

async def test_scan_urls_returns_per_url_results(monkeypatch):
    async def fake_scan(url, cfg, scope=None):
        return {'url': url, 'status': 200, 'findings': [], 'technologies': []}
    monkeypatch.setattr('raveneye.scanner.pipeline.scan_url', fake_scan)
    class C: concurrency=2
    rows = await scan_urls(['https://a.test', 'https://b.test'], C())
    assert [r['url'] for r in rows] == ['https://a.test', 'https://b.test']


def test_repository_persists_findings(tmp_path):
    p=tmp_path/'scan.db'; repo=ScanRepository(p)
    sid=repo.save_scan('https://example.test',[{'name':'CSP missing','severity':'MEDIUM','confidence':'HIGH','url':'https://example.test','evidence':'x'*700,'remediation':'Set CSP'}],4.0)
    import sqlite3
    with sqlite3.connect(p) as db:
        row=db.execute('select scan_id,name,evidence from findings where scan_id=?',(sid,)).fetchone()
    assert row[0]==sid and row[1]=='CSP missing' and len(row[2])==500
