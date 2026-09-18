from __future__ import annotations
from dataclasses import dataclass, field
from urllib.parse import urlsplit
import fnmatch, re

@dataclass(slots=True)
class ScopeGuard:
    domains: set[str] = field(default_factory=set)
    paths: tuple[str, ...] = ()
    regex: tuple[str, ...] = ()
    excludes: tuple[str, ...] = ()

    def check(self, url: str) -> str:
        p = urlsplit(url)
        host = (p.hostname or '').lower().rstrip('.')
        path = p.path or '/'
        if p.scheme not in {'http', 'https'} or not host:
            raise ValueError('URL fora do escopo: esquema/host inválido')
        if self.domains and not any(fnmatch.fnmatch(host, d.lower().rstrip('.')) or host == d.lower().rstrip('.') for d in self.domains):
            raise ValueError('URL fora do escopo: domínio')
        if self.paths and not any(path.startswith(prefix) for prefix in self.paths):
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
