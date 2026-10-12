from raveneye.crawler.sitemaps import parse_sitemap
from raveneye.scanner.api_security import analyze_openapi, inspect_operations

def test_sitemap_index_locations_are_discovered():
    text='<sitemapindex><sitemap><loc>/a.xml</loc></sitemap><sitemap><loc>https://x.test/b.xml</loc></sitemap></sitemapindex>'
    assert parse_sitemap(text, 'https://x.test/') == ['https://x.test/a.xml','https://x.test/b.xml']

def test_openapi_security_and_id_parameter_checks():
    spec={'openapi':'3.0.0','paths':{'/users/{id}':{'get':{'parameters':[{'name':'id','in':'path'}],'security':[]}}}}
    names={f['name'] for f in analyze_openapi(spec,base_url='https://x.test/openapi.json')}
    assert 'API endpoint explicitly disables declared security' in names
    assert 'Potential object-reference parameter requires authorization review' in names

def test_openapi_operation_inspection_is_advisory():
    spec={'openapi':'3.0.0','paths':{'/users/{id}':{'get':{'parameters':[{'name':'id','in':'path'}]}}}}
    findings=inspect_operations(spec,'https://x.test')
    assert any('authorization' in str(f).lower() for f in findings)
