import asyncio
import pytest
from raveneye.database.async_repository import AsyncScanRepository
from raveneye.core.orchestrator import _risk_score

@pytest.mark.asyncio
async def test_async_repository_roundtrip(tmp_path):
    repo=AsyncScanRepository(tmp_path/'x.db')
    sid=await repo.save_scan('https://example.test',[{'name':'x','severity':'HIGH','confidence':'HIGH','url':'https://example.test'}],7.0)
    rows=await repo.recent_scans()
    assert sid == 1 and rows[0]['risk_score'] == 7.0

def test_risk_score_not_diluted_by_info():
    assert _risk_score([{'severity':'CRITICAL'}]+[{'severity':'INFO'}]*100) == 5.0
