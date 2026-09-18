from __future__ import annotations
from urllib.parse import urlsplit

STATIC_EXT = {'.js','.mjs','.css','.png','.jpg','.jpeg','.gif','.svg','.webp','.ico','.woff','.woff2','.ttf','.map','.pdf','.zip'}

def classify(url: str, content_type: str = '', status: int | None = None) -> str:
    path = urlsplit(url).path.lower()
    ct = (content_type or '').lower()
    if status is not None and 300 <= status < 400:
        return 'redirect'
    if status is not None and status >= 400:
        return 'error'
    if any(path.endswith(x) for x in STATIC_EXT) or any(x in ct for x in ('javascript','css','image/','font/')):
        return 'static_asset'
    if 'json' in ct or path.endswith(('.json','.graphql','.gql')) or '/api/' in path:
        return 'api_endpoint'
    return 'page'
