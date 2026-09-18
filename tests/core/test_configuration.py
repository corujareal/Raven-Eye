from raveneye.core.config import RavenConfig
from raveneye.crawler.filters import Scope
from raveneye.reports.base import risk_score

def test_version(): assert RavenConfig().version == '6.6.6'
def test_scope():
    s=Scope(domains=['example.com'],exclude=['/logout'])
    assert s.allows('https://example.com/a')
    assert not s.allows('https://evil.com/a')
    assert not s.allows('https://example.com/logout')
def test_risk(): assert risk_score([{'severity':'CRITICAL'}]) == 10
