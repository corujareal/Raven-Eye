from raveneye.core.config import RavenConfig
from raveneye.crawler.filters import Scope
from raveneye.reports.base import risk_score

def test_version(): assert RavenConfig().version == '6.6.6'
def test_crawler_per_host_rate_limit_is_configurable():
    config = RavenConfig(per_host_requests_per_second=2.5)
    assert config.per_host_requests_per_second == 2.5
def test_scope():
    s=Scope(domains=['example.com'],exclude=['/logout'])
    assert s.allows('https://example.com/a')
    assert not s.allows('https://evil.com/a')
    assert not s.allows('https://example.com/logout')
def test_risk(): assert risk_score([{'severity':'CRITICAL'}]) == 10
