from __future__ import annotations

import re
from urllib.parse import urlsplit


STATIC_EXT = {'.js', '.mjs', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico', '.woff', '.woff2', '.ttf', '.map', '.pdf', '.zip'}
_LISTING = re.compile(r"index of /|directory listing|parent directory", re.I)
_ERROR = re.compile(r"stack trace|traceback \(most recent call last\)|internal server error|fatal error", re.I)
_LOGIN = re.compile(r"\b(sign in|log in|login|authenticate|password|senha)\b", re.I)


def classify(url: str, content_type: str = '', status: int | None = None,
             body: str = '', forms: list[dict] | None = None) -> str:
    """Classify page intent with explicit signals; never treats it as a finding."""
    path = urlsplit(url).path.lower()
    ct = (content_type or '').lower()
    title_match = re.search(r"<title[^>]*>(.*?)</title\s*>", body[:200_000], re.I | re.S)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
    if status is not None and 300 <= status < 400:
        return 'redirect'
    if status is not None and status >= 400:
        return 'error'
    if any(path.endswith(x) for x in STATIC_EXT) or any(x in ct for x in ('javascript', 'css', 'image/', 'font/')):
        return 'static_asset'
    if _LISTING.search(title) or (_LISTING.search(body[:100_000]) and 'href="../"' in body[:100_000].lower()):
        return 'listing'
    if _ERROR.search(title) or _ERROR.search(body[:100_000]):
        return 'error'
    password_form = any(
        isinstance(form, dict) and any(str(field.get('type', '')).lower() == 'password' for field in form.get('fields', []) if isinstance(field, dict))
        for form in (forms or [])
    )
    if password_form or _LOGIN.search(title) or re.search(r"/(?:login|signin|sign-in|auth)(?:/|$)", path):
        return 'login'
    if forms:
        return 'form'
    if 'json' in ct or path.endswith(('.json', '.graphql', '.gql')) or '/api/' in path:
        return 'api_endpoint'
    return 'page'
