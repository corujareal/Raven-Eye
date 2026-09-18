from __future__ import annotations
import re
from urllib.parse import urljoin

_LOC_RE = re.compile(r'<loc>\s*(.*?)\s*</loc>', re.I | re.S)

def parse_robots(text: str, base_url: str):
    allowed, disallowed, sitemaps = [], [], []
    applies=False
    for raw in text.splitlines():
        line=raw.split('#',1)[0].strip()
        if not line or ':' not in line: continue
        k,v=(x.strip() for x in line.split(':',1)); kl=k.lower()
        if kl=='user-agent': applies = v=='*'
        elif applies and kl=='allow': allowed.append(urljoin(base_url,v))
        elif applies and kl=='disallow' and v: disallowed.append(urljoin(base_url,v))
        elif kl=='sitemap': sitemaps.append(urljoin(base_url,v))
    return {'allow':allowed,'disallow':disallowed,'sitemaps':sitemaps}

def parse_sitemap(text: str, base_url: str):
    """Return URLs from both urlset and sitemapindex documents."""
    return list(dict.fromkeys(urljoin(base_url, x.strip()) for x in _LOC_RE.findall(text) if x.strip()))
