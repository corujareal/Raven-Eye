from raveneye.crawler.discovery import well_known_urls, discover_from_robots
from raveneye.crawler.jsonl import write_jsonl, iter_jsonl


def test_well_known_urls():
    urls = well_known_urls('https://example.com/start')
    assert 'https://example.com/.well-known/security.txt' in urls


def test_robots_discovery():
    text='''User-agent: *\nAllow: /public\nDisallow: /private\nSitemap: https://example.com/sitemap.xml\n'''
    found=discover_from_robots(text,'https://example.com/robots.txt')
    assert 'https://example.com/public' in found
    assert 'https://example.com/private' in found
    assert 'https://example.com/sitemap.xml' in found


def test_jsonl_roundtrip(tmp_path):
    p=tmp_path/'rows.jsonl'
    write_jsonl(p,[{'url':'https://example.com','status':200},{'url':'https://example.com/a'}])
    assert list(iter_jsonl(p))[1]['url'].endswith('/a')
