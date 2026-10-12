from raveneye.crawler.extractors import extract_html
from raveneye.crawler.api_discovery import discover_api_urls, parse_openapi, graphql_indicators
from raveneye.crawler.sitemaps import parse_robots, parse_sitemap
from raveneye_pkg.network import get_js_urls_from_soup
from bs4 import BeautifulSoup
from raveneye.reports.html import render

def test_extracts_js_endpoints_and_websockets():
    x=extract_html('https://example.test/a', '<script>fetch("/api/users");</script><a href="/x">x</a><script>wss://socket.example/ws</script>')
    assert 'https://example.test/api/users' in x['js_endpoints']
    assert 'wss://socket.example/ws' in x['websockets']


def test_inline_javascript_uses_code_aware_extraction_and_reports_templates():
    html = '''
      <script>
        const documentation = "Example: fetch('/api/not-live')";
        fetch(`/api/users/${userId}`);
      </script>
      <script type="application/json">fetch('/api/not-executable')</script>
      <template><script>fetch('/api/not-active')</script></template>
    '''

    found = extract_html('https://example.test/app', html)

    assert found['js_endpoints'] == []
    assert found['urls'] == []
    assert found['route_templates'] == ['https://example.test/api/users/{param}']


def test_external_javascript_detection_handles_cache_query_and_module_type():
    soup = BeautifulSoup(
        '<script src="/assets/app.js?v=123#top"></script>'
        '<script type="module" src="/assets/entry?v=3"></script>'
        '<script type="application/json" src="/data.json"></script>',
        "html.parser",
    )

    assert get_js_urls_from_soup(soup, "https://example.test/page") == [
        "https://example.test/assets/app.js?v=123",
        "https://example.test/assets/entry?v=3",
    ]

def test_parse_openapi_methods():
    d=parse_openapi('{"openapi":"3.0.0","paths":{"/users":{"get":{"operationId":"list"},"post":{}}}}')
    assert {e['method'] for e in d['endpoints']} == {'GET','POST'}

def test_graphql_indicator():
    assert graphql_indicators('{"data":{"__schema":{}}}')['introspection_enabled_indicator']

def test_common_api_hints_can_be_emitted_once_without_losing_page_evidence():
    base = 'https://example.test/page'
    body = '<script>fetch("/api/accounts")</script>'
    first = discover_api_urls(base, body)
    later = discover_api_urls(base, body, include_common_hints=False)

    assert 'https://example.test/openapi.json' in first
    assert 'https://example.test/api/accounts' in later
    assert 'https://example.test/openapi.json' not in later

def test_robots_and_sitemap():
    r=parse_robots('User-agent: *\nDisallow: /private\nAllow: /public\nSitemap: /sitemap.xml','https://e.test/')
    assert r['sitemaps']==['https://e.test/sitemap.xml']
    assert parse_sitemap('<urlset><url><loc>/a</loc></url></urlset>','https://e.test/')==['https://e.test/a']

def test_html_report_has_expected_columns():
    out=render('https://e.test',[{'severity':'HIGH','name':'Test','url':'https://e.test/x','confidence':'HIGH'}])
    assert '<th>Severity</th>' in out and '<th>Finding</th>' in out and '<th>URL</th>' in out
