from raveneye.scanner.api_security import analyze_openapi
from raveneye.reports.html import render

def test_openapi_security_and_https_findings():
    spec={'openapi':'3.0.0','servers':[{'url':'http://api.test'}],'paths':{'/users/{id}':{'get':{'security':[],'parameters':[{'name':'id','in':'query'}]}}}}
    f=analyze_openapi(spec,base_url='https://api.test')
    names={x['name'] for x in f}
    assert 'API endpoint explicitly disables declared security' in names
    assert 'OpenAPI server uses HTTP' in names

def test_html_report_donut_and_rows():
    out=render('https://e.test',[{'severity':'HIGH','name':'Test','url':'https://e.test/x','confidence':'HIGH'}])
    assert 'conic-gradient' in out and '<td>HIGH</td>' in out
