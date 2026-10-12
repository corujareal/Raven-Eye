import pytest
from raveneye.core.config import RavenConfig
from raveneye.core.logger import redact
from raveneye.network.session import AsyncSession
from raveneye.scanner.pipeline import scan_url

@pytest.mark.asyncio
async def test_async_session_is_lazy_and_closes_cleanly():
    session = AsyncSession(user_agent='RavenEye/6.6.6', timeout=5, requests_per_second=100)
    assert session.session is None
    async with session as entered:
        assert entered.session is not None
        assert not entered.session.closed
    assert entered.session.closed

@pytest.mark.asyncio
async def test_scope_and_ssrf_reject_private_destination():
    cfg = RavenConfig(timeout_seconds=5)
    with pytest.raises(Exception):
        await scan_url('http://127.0.0.1:9/', cfg, scope={'127.0.0.1'})

@pytest.mark.asyncio
async def test_secret_redaction_is_stable():
    assert redact('Authorization: Bearer supersecret') == 'Authorization=<redacted>'
    assert redact('token=abcdef') == 'token=<redacted>'
