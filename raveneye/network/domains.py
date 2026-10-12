"""Shared domain and wildcard matching used by scope and SSRF checks."""
from __future__ import annotations

import ipaddress


def canonical_host(value: str) -> str:
    host = str(value or "").strip().rstrip(".").lower()
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        return host.encode("idna").decode("ascii").lower()


def host_matches_rule(host: str, rule: str) -> bool:
    """Plain domain includes subdomains; *.domain includes subdomains only."""
    try:
        candidate = canonical_host(host)
        pattern = str(rule or "").strip().lower().rstrip(".")
        if pattern.startswith("*."):
            root = canonical_host(pattern[2:])
            return candidate.endswith("." + root) and candidate != root
        if "*" in pattern or "?" in pattern:
            import fnmatch
            return fnmatch.fnmatchcase(candidate, canonical_host(pattern))
        normalized = canonical_host(pattern)
        try:
            ipaddress.ip_address(normalized)
            return candidate == normalized
        except ValueError:
            return candidate == normalized or candidate.endswith("." + normalized)
    except (UnicodeError, ValueError):
        return False
