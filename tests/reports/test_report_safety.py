import asyncio
import json
from pathlib import Path

import pytest

from raveneye.database.async_repository import AsyncScanRepository
from raveneye.reports.html import render as html_render
from raveneye.reports.txt import render as txt_render
from raveneye.scanner.pipeline import _safe_active_findings


def test_report_does_not_contain_implementation_prompt_language():
    findings=[{'id':'xss.reflection','name':'User Input Reflected','severity':'INFO','confidence':'HIGH','url':'https://example.test/?q=x','evidence':'marker','remediation':'Encode output.'}]
    out=txt_render('https://example.test',findings)
    assert 'def ' not in out
    assert 'import ' not in out
    assert 'Implementation Notes' not in out
    assert 'RAVENEYE v6.6.6' in out


def test_html_report_has_no_external_dependency_and_has_clean_sections():
    out=html_render('https://example.test',[{'severity':'HIGH','name':'Test','url':'https://example.test/x','confidence':'HIGH'}])
    assert 'self-contained report' in out
    assert '<script src=' not in out
    assert 'RavenEye v6.6.6' in out
    assert '<th>Severity</th>' in out

@pytest.mark.asyncio
async def test_safe_active_checks_report_reflection_without_claiming_xss():
    async def fake_request(url):
        from urllib.parse import parse_qs, urlsplit
        value=parse_qs(urlsplit(url).query).get('q',[''])[0]
        if value == "'":
            return 'SQL syntax error near q'
        return f'<html>{value}</html>'
    findings=await _safe_active_findings('https://example.test/?q=hello','<html>hello</html>',None,fake_request)
    ids={f['id'] for f in findings}
    assert 'xss.reflection' in ids
    assert 'sqli.error-differential' in ids
    assert not any(f['name'].lower().startswith('confirmed xss') for f in findings)

@pytest.mark.asyncio
async def test_finding_history_persists_across_scans(tmp_path):
    repo=AsyncScanRepository(tmp_path/'raven.db')
    finding={'id':'demo','name':'Demo Finding','severity':'MEDIUM','confidence':'HIGH','url':'https://example.test/x'}
    await repo.save_scan('https://example.test',[finding],4.0)
    await repo.save_scan('https://example.test',[finding],4.0)
    history=await repo.finding_history('https://example.test')
    assert len(history)==1
    assert history[0]['occurrences']==2
