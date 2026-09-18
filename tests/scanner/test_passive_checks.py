from pathlib import Path
from raveneye.scanner.passive_checks import scan_headers
from raveneye.scanner.active_safe import validate_https, validate_cookie_flags
from raveneye.crawler.jsonl import write_jsonl
import asyncio

def test_passive_checks_redact_secret():
    fs=scan_headers('https://example.test', {'server':'demo/1.2','set-cookie':'sid=abc'}, 'api_key="supersecretvalue"')
    assert any(f.template_id == 'possible-secret-disclosure' for f in fs)
    assert all('supersecretvalue' not in f.evidence for f in fs)

def test_safe_validation_helpers():
    assert validate_https('https://example.test').passed
    assert not validate_https('http://example.test').passed
    results=validate_cookie_flags(['sid=x; Secure; HttpOnly'])
    assert all(x.passed for x in results)

def test_stream_jsonl(tmp_path: Path):
    async def rows():
        for i in range(3):
            yield {'i': i}
    path=tmp_path/'out.jsonl'
    assert asyncio.run(write_jsonl(rows(), path)) == 3
    assert path.read_text().count('\n') == 3
