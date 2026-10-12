from __future__ import annotations

"""Target batch normalization and multi-target policy."""

from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

@dataclass(frozen=True, slots=True)
class TargetBatch:
    urls: tuple[str, ...]
    enabled: bool

    @property
    def is_multi(self) -> bool:
        return len(self.urls) > 1

def normalize_target(raw: str) -> str:
    raw = str(raw or "").strip()
    if not raw:
        return ""
    scheme_hint = raw.split("://", 1)[0].lower() if "://" in raw else ""
    if "://" in raw and scheme_hint not in {"http", "https"}:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    elif scheme_hint != raw.split("://", 1)[0]:
        raw = scheme_hint + "://" + raw.split("://", 1)[1]
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    # Canonicalize target identity so equivalent inputs do not create duplicate
    # scans or separate history entries. Preserve the explicit HTTP/HTTPS scheme,
    # host, non-default port and path, but remove fragments and a trailing slash.
    host = parsed.hostname.lower()
    try:
        port = parsed.port
    except ValueError:
        return ""
    if port is not None and ((parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80)):
        port = None
    netloc = host if port is None else f"{host}:{port}"
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"
    normalized = urlunparse((parsed.scheme.lower(), netloc, path, "", parsed.query, ""))
    # Keep the historical canonical form for bare origins while preserving a
    # slash when a path/query is actually present.
    if path == "/" and not parsed.query:
        return f"{parsed.scheme.lower()}://{netloc}"
    return normalized

def normalize_targets(values, *, enabled: bool, max_targets: int = 50) -> TargetBatch:
    seen: set[str] = set()
    out: list[str] = []
    for value in values or []:
        target = normalize_target(value)
        if not target or target in seen:
            continue
        seen.add(target)
        out.append(target)
        if len(out) >= max_targets:
            break
    if not enabled and len(out) > 1:
        out = out[:1]
    return TargetBatch(tuple(out), enabled)
