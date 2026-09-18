from raveneye.scanner.template_engine import TemplateEngine
from raveneye.scanner.passive_checks import check_response
from raveneye.scanner.api_security import analyze_graphql

def test_template_engine_and_condition_and_extract():
    t={'id':'x','info':{'name':'X','severity':'medium','remediation':'fix'},'matchers-condition':'and',
       'matchers':[{'type':'word','words':['hello']},{'type':'regex','regex':['version=(\\d+)']}],
       'extractors':[{'type':'regex','regex':['version=(\\d+)']}]}
    r=TemplateEngine().match(t,'hello version=42',{},'https://example.test',200)
    assert r and '42' in r[0].evidence

def test_passive_safe_checks():
    fs=check_response('https://example.test',200,{'content-type':'text/html'},'<html><script src="http://x"></script></html>')
    ids={f.template_id for f in fs}
    assert 'headers.csp' in ids and 'mixed-content-reference' in ids

def test_graphql_introspection_is_passive():
    fs=analyze_graphql('https://example.test/graphql','{"data":{"__schema":{}}}','application/json')
    assert fs and fs[0]['severity']=='MEDIUM'
