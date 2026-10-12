from __future__ import annotations
from urllib.parse import urlparse
from .sitemaps import parse_robots, parse_sitemap
from .extractors import extract_openapi


def well_known_urls(base_url: str) -> list[str]:
    p = urlparse(base_url)
    if not p.scheme or not p.netloc:
        return []
    root = f"{p.scheme}://{p.netloc}"
    return [root + "/.well-known/security.txt", root + "/.well-known/assetlinks.json"]


def discover_from_robots(text: str, base_url: str) -> list[str]:
    data = parse_robots(text, base_url)
    return list(dict.fromkeys(data["allow"] + data["disallow"] + data["sitemaps"]))


def discover_openapi(text: str) -> list[str]:
    return extract_openapi(text)
