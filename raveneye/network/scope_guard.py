from __future__ import annotations
from dataclasses import dataclass, field
from urllib.parse import urlsplit
import fnmatch, re
from .domains import host_matches_rule

def path_matches_scope_prefix(path: str, prefix: str) -> bool:
    """Match a path prefix on URL segment boundaries.

    A configured ``/api`` scope includes ``/api`` and ``/api/v1`` but excludes
    sibling names such as ``/apiary``. This keeps the crawler, browser, and
    request guard aligned on the URL path's slash-delimited segments.
    """
    candidate = path or "/"
    configured = str(prefix or "/")
    if not configured.startswith("/"):
        configured = "/" + configured
    if configured == "/":
        return candidate.startswith("/")
    base = configured.rstrip("/") or "/"
    return candidate == base or candidate.startswith(base + "/")

@dataclass(slots=True)
class ScopeGuard:
    domains: set[str] = field(default_factory=set)
    exact_hosts: set[str] = field(default_factory=set)
    paths: tuple[str, ...] = ()
    regex: tuple[str, ...] = ()
    excludes: tuple[str, ...] = ()

    def check(self, url: str) -> str:
        p = urlsplit(url)
        host = (p.hostname or '').lower().rstrip('.')
        path = p.path or '/'
        if p.scheme not in {'http', 'https'} or not host or p.username is not None or p.password is not None:
            raise ValueError('URL fora do escopo: esquema/host inválido')
        if (self.domains or self.exact_hosts) and host not in self.exact_hosts and not any(host_matches_rule(host, d) for d in self.domains):
            raise ValueError('URL fora do escopo: domínio')
        if self.paths and not any(path_matches_scope_prefix(path, prefix) for prefix in self.paths):
            raise ValueError('URL fora do escopo: caminho')
        if self.regex and not any(re.search(pattern, url) for pattern in self.regex):
            raise ValueError('URL fora do escopo: regex')
        for pattern in self.excludes:
            normalized = str(pattern)
            if (
                fnmatch.fnmatch(host, normalized.lower())
                or fnmatch.fnmatch(url, normalized)
                or (normalized.startswith('/') and fnmatch.fnmatch(path, normalized))
                or (not normalized.startswith(('/', 'http://', 'https://')) and normalized in path)
            ):
                raise ValueError('URL excluída pelo escopo')
        return url
