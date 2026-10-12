import os
from raveneye.core.config import load_config
from raveneye.core.events import Event, EventBus
from raveneye.network.ssrf_guard import SSRFBlocked, validate_url

def test_version_is_pinned():
    cfg=load_config()
    assert cfg.version=='6.6.6'
    assert cfg.user_agent.endswith('6.6.6')

def test_toml_config(tmp_path):
    p=tmp_path/'raveneye.toml'; p.write_text('concurrency=9\n[scope]\ninclude_domains=["example.test"]\n',encoding='utf-8')
    cfg=load_config(p)
    assert cfg.scope.include_domains==['example.test']
    assert cfg.concurrency==9

def test_ssrf_blocks_private_literal():
    try: validate_url('http://127.0.0.1/')
    except SSRFBlocked: return
    assert False

async def test_eventbus_dispatch():
    bus=EventBus(); seen=[]
    bus.subscribe('x', lambda e: seen.append(e.data['n']))
    await bus.publish(Event('x',{'n':1}), priority=1)
    await bus.dispatch_one()
    assert seen==[1]
