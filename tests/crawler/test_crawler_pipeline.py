from raveneye.crawler.classifier import classify
from raveneye.core.rate_limit import TokenBucket
from raveneye.scanner.passive_checks import check_response


def test_classifier():
    assert classify('https://x.test/app.js','application/javascript',200)=='static_asset'
    assert classify('https://x.test/api/users','application/json',200)=='api_endpoint'
    assert classify('https://x.test/nope','text/html',404)=='error'


def test_passive_checks():
    findings=check_response('https://x.test',200,{'content-type':'text/html'},'hello')
    ids={x.id for x in findings}
    assert 'headers.csp' in ids and 'headers.xcto' in ids and 'tls.hsts' in ids
