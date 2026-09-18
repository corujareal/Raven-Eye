import pytest
from raveneye.database.async_repository import AsyncScanRepository
from raveneye.core.orchestrator import _risk_score

@pytest.mark.asyncio
async def test_async_repository_roundtrip(tmp_path):
    repo = AsyncScanRepository(tmp_path / 'raveneye.db')
    sid = await repo.save_scan('example.test', [{
        'name': 'x', 'severity': 'HIGH', 'confidence': 'HIGH', 'url': 'https://example.test/',
        'evidence': 'safe', 'remediation': 'fix', 'cwe': 'CWE-79', 'cve': ''
    }], 7.0)
    assert sid == 1
    rows = await repo.recent_scans()
    assert rows[0]['target'] == 'example.test'
    assert rows[0]['risk_score'] == 7.0

def test_risk_score_is_bounded():
    assert _risk_score([]) == 0.0
    assert _risk_score([{'severity': 'CRITICAL'}, {'severity': 'HIGH'}]) == 8.5
