from __future__ import annotations
from dataclasses import dataclass, field
from urllib.parse import urlsplit
import fnmatch, re

@dataclass(slots=True)
class Scope:
    domains: set[str] | None = None
    excludes: set[str] = field(default_factory=set)
    exclude: set[str] | None = None
    regex: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    def allows(self,url:str)->bool:
        p=urlsplit(url); host=(p.hostname or '').lower().rstrip('.'); path=p.path or '/'
        if p.scheme not in {'http','https'} or not host: return False
        if self.domains and not any(fnmatch.fnmatch(host,d.lower().rstrip('.')) or host==d.lower().rstrip('.') for d in self.domains): return False
        if self.paths and not any(path.startswith(x) for x in self.paths): return False
        try:
            if self.regex and not any(re.search(x,url) for x in self.regex): return False
        except re.error: return False
        blocked=set(self.excludes)|set(self.exclude or ())
        return not any(fnmatch.fnmatch(host,d.lower()) or fnmatch.fnmatch(url,d) or d in path for d in blocked)
