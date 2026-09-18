from raveneye.crawler.extractors import extract_html
from raveneye.crawler.api_discovery import parse_openapi, graphql_indicators
from raveneye.crawler.sitemaps import parse_robots, parse_sitemap
from raveneye.reports.html import render

def test_extracts_js_endpoints_and_websockets():
    x=extract_html('https://example.test/a', '<script>fetch("/api/users");</script><a href="/x">x</a><script>wss://socket.example/ws</script>')
    assert 'https://example.test/api/users' in x['js_endpoints']
    assert 'wss://socket.example/ws' in x['websockets']

def test_parse_openapi_methods():
    d=parse_openapi('{"openapi":"3.0.0","paths":{"/users":{"get":{"operationId":"list"},"post":{}}}}')
    assert {e['method'] for e in d['endpoints']} == {'GET','POST'}

def test_graphql_indicator():
    assert graphql_indicators('{"data":{"__schema":{}}}')['introspection_enabled_indicator']

def test_robots_and_sitemap():
    r=parse_robots('User-agent: *\nDisallow: /private\nAllow: /public\nSitemap: /sitemap.xml','https://e.test/')
    assert r['sitemaps']==['https://e.test/sitemap.xml']
    assert parse_sitemap('<urlset><url><loc>/a</loc></url></urlset>','https://e.test/')==['https://e.test/a']

def test_html_report_has_expected_columns():
    out=render('https://e.test',[{'severity':'HIGH','name':'Test','url':'https://e.test/x','confidence':'HIGH'}])
    assert '<th>Severity</th>' in out and '<th>Finding</th>' in out and '<th>URL</th>' in out
