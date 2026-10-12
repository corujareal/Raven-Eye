import json
import sqlite3
import pytest
from raveneye.database.async_repository import AsyncScanRepository
from raveneye.core.orchestrator import _risk_score

@pytest.mark.asyncio
async def test_async_repository_roundtrip(tmp_path):
    repo=AsyncScanRepository(tmp_path/'x.db')
    evidence = {
        'schema_version': '1.0', 'observed_at': '2026-10-07T00:00:00+00:00',
        'source': 'fixture', 'request': {'sha256': 'a' * 64},
        'response': {'sha256': 'b' * 64}, 'baseline': {'sha256': 'c' * 64},
    }
    finding = {
        'name':'x','severity':'HIGH','confidence':'HIGH','url':'https://example.test',
        'stage':'PROBABLE','confidence_score':80,'observed_at':evidence['observed_at'],
        'evidence_metadata':evidence,'cve_source':'NVD','cve_schema_version':'NVD-2.0',
        'cve_retrieved_at':'2026-10-01T00:00:00Z','cve_dataset_sha256':'d' * 64,
    }
    sid=await repo.save_scan('https://example.test',[finding],7.0)
    rows=await repo.recent_scans()
    assert sid == 1 and rows[0]['risk_score'] == 7.0
    with sqlite3.connect(repo.path) as db:
        row = db.execute(
            'SELECT stage,confidence_score,request_sha256,response_sha256,baseline_sha256,evidence_metadata,cve_source,cve_schema_version,cve_retrieved_at,cve_dataset_sha256 FROM findings'
        ).fetchone()
    assert row[:5] == ('PROBABLE', 80, 'a' * 64, 'b' * 64, 'c' * 64)
    assert json.loads(row[5]) == evidence
    assert row[6:] == ('NVD','NVD-2.0','2026-10-01T00:00:00Z','d' * 64)


@pytest.mark.asyncio
async def test_async_repository_migrates_existing_findings_table(tmp_path):
    path = tmp_path/'old.db'
    with sqlite3.connect(path) as db:
        db.executescript('''
        CREATE TABLE scans(id INTEGER PRIMARY KEY,target TEXT NOT NULL,created_at TEXT NOT NULL,mode TEXT,risk_score REAL);
        CREATE TABLE findings(id INTEGER PRIMARY KEY,scan_id INTEGER,name TEXT,severity TEXT,confidence TEXT,url TEXT,evidence TEXT,remediation TEXT,cwe TEXT,cve TEXT);
        ''')
    repo = AsyncScanRepository(path)

    await repo.init()

    with sqlite3.connect(path) as db:
        columns = {row[1] for row in db.execute('PRAGMA table_info(findings)')}
    assert {'stage','confidence_score','evidence_metadata','cve_dataset_sha256'} <= columns

def test_risk_score_not_diluted_by_info():
    assert _risk_score([{'severity':'CRITICAL'}]+[{'severity':'INFO'}]*100) == 5.0
