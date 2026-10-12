from __future__ import annotations
from dataclasses import dataclass, field
from urllib.parse import urlsplit
import fnmatch, re
from ..network.domains import host_matches_rule
from ..network.scope_guard import path_matches_scope_prefix

@dataclass(slots=True)
class Scope:
    domains: set[str] | None = None
    exact_hosts: set[str] = field(default_factory=set)
    excludes: set[str] = field(default_factory=set)
    exclude: set[str] | None = None
    regex: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    def allows(self,url:str)->bool:
        p=urlsplit(url); host=(p.hostname or '').lower().rstrip('.'); path=p.path or '/'
        if p.scheme not in {'http','https'} or not host or p.username is not None or p.password is not None: return False
        if (self.domains or self.exact_hosts) and host not in self.exact_hosts and not any(host_matches_rule(host, domain) for domain in self.domains or set()): return False
        if self.paths and not any(path_matches_scope_prefix(path, x) for x in self.paths): return False
        try:
            if self.regex and not any(re.search(x,url) for x in self.regex): return False
        except re.error: return False
        blocked=set(self.excludes)|set(self.exclude or ())
        return not any(
            fnmatch.fnmatch(host, pattern.lower())
            or fnmatch.fnmatch(url, pattern)
            or (pattern.startswith("/") and fnmatch.fnmatch(path, pattern))
            or (not pattern.startswith(("/", "http://", "https://")) and pattern in path)
            for pattern in blocked
        )
