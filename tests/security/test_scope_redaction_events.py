import asyncio
from raveneye.crawler.filters import Scope
from raveneye.core.logger import redact
from raveneye.network.scope_guard import ScopeGuard
from raveneye.scanner.cve_correlator import correlate_exact

def test_scope_dsl():
    s=Scope(domains={'*.example.com'},paths=['/api'],regex=['https://'],excludes={'admin.example.com'})
    assert s.allows('https://api.example.com/api/v1')
    assert not s.allows('https://api.example.com/home')
    assert not s.allows('https://admin.example.com/api')

def test_scope_guard_matches_scope_rules():
    g=ScopeGuard(domains={'example.com'},paths=('/api',),excludes=('*/private*',))
    assert g.check('https://example.com/api/x')
    try: g.check('https://example.com/private/api')
    except ValueError: return
    assert False

def test_redaction():
    out=redact('Authorization: Bearer abc123 token=secret')
    assert 'abc123' not in out and 'secret' not in out

def test_exact_cve_correlation():
    rows=[{'product':'nginx','version':'1.2.3','cve':'CVE-X'},{'product':'nginx','version':'1.2.4','cve':'CVE-Y'}]
    assert [x.cve for x in correlate_exact('nginx','1.2.3',rows)]==['CVE-X']

def test_event_bus_priority_order():
    from raveneye.core.events import Event, EventBus
    async def run():
        bus=EventBus(); await bus.publish(Event('low'),50); await bus.publish(Event('high'),1)
        assert (await bus.next()).topic=='high'
    asyncio.run(run())
