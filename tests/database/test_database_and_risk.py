import pytest
from raveneye.database.db import init_db, create_scan, add_finding
from raveneye.reports.base import risk_score
from raveneye.scanner.passive_checks import check_response

@pytest.mark.asyncio
async def test_database_scan_and_finding(tmp_path):
    db=await init_db(tmp_path/'r.db'); sid=await create_scan(db,'https://example.test')
    await add_finding(db,sid,'https://example.test',{'severity':'HIGH','name':'x','url':'https://example.test'})
    cur=await db.execute('select count(*) from findings'); assert (await cur.fetchone())[0]==1
    await db.close()

def test_risk_score_is_bounded():
    assert 0 <= risk_score([{'severity':'CRITICAL'}]*20) <= 10

def test_cookie_checks():
    fs=check_response('https://example.test',200,{'Set-Cookie':'sid=abc'},'')
    assert any('Cookie Missing Secure'==f.name for f in fs)
