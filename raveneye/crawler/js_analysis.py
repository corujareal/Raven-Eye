"""Static JavaScript endpoint discovery without executing untrusted scripts."""
from __future__ import annotations
import re
from urllib.parse import urljoin

_CALL = re.compile(r"(?:fetch|axios\.(?:get|post|put|patch|delete)|\.open)\s*\(\s*['\"]([^'\"]+)", re.I)
_WS = re.compile(r"(?:new\s+WebSocket\s*\(\s*|['\"])(wss?://[^'\"\s<>]+)", re.I)
_SOURCE_MAP = re.compile(r"(?://#|/\*)\s*sourceMappingURL=([^\s*]+)")

def analyze_javascript(base_url: str, source: str) -> dict[str, list[str]]:
    endpoints = {urljoin(base_url, p) for p in _CALL.findall(source) if p.startswith(("/", "./", "../", "http://", "https://"))}
    websockets = set(_WS.findall(source))
    maps = {urljoin(base_url, p.strip()) for p in _SOURCE_MAP.findall(source)}
    return {"urls": sorted(endpoints), "websockets": sorted(websockets), "source_maps": sorted(maps)}
