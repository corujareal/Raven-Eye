from __future__ import annotations
import re
from dataclasses import dataclass

_VERSION_PATTERNS = {
    "nginx": re.compile(r"nginx[/ ](?P<v>[0-9]+(?:\.[0-9]+){1,3})", re.I),
    "apache": re.compile(r"(?:apache[/ ]httpd[/ ]|apache[/ ])(?P<v>[0-9]+(?:\.[0-9]+){1,3})", re.I),
    "php": re.compile(r"php[/ ](?P<v>[0-9]+(?:\.[0-9]+){1,3})", re.I),
    "express": re.compile(r"express(?:[/ ]| v)(?P<v>[0-9]+(?:\.[0-9]+){1,3})", re.I),
    "wordpress": re.compile(r"wordpress[/ ](?P<v>[0-9]+(?:\.[0-9]+){1,3})", re.I),
    "django": re.compile(r"django[/ ](?P<v>[0-9]+(?:\.[0-9]+){1,3})", re.I),
    "ruby on rails": re.compile(r"rails[/ ](?P<v>[0-9]+(?:\.[0-9]+){1,3})", re.I),
    "asp.net": re.compile(r"asp\.net[/ ](?P<v>[0-9]+(?:\.[0-9]+){1,3})", re.I),
}

@dataclass(frozen=True, slots=True)
class Technology:
    name: str
    version: str | None = None
    source: str = "heuristic"
    confidence: str = "MEDIUM"

def _version(name: str, value: str) -> str | None:
    m = _VERSION_PATTERNS.get(name.lower())
    if not m:
        return None
    hit = m.search(value or "")
    return hit.group("v") if hit else None

def fingerprint(headers, body=""):
    h = {str(k).lower(): str(v) for k, v in headers.items()}
    b = str(body or "")
    low = b.lower()
    found: dict[tuple[str, str | None], Technology] = {}

    def add(name, version=None, source="heuristic", confidence="MEDIUM"):
        key = (name.lower(), version)
        if key not in found:
            found[key] = Technology(name, version, source, confidence)

    server = h.get("server")
    if server:
        # Preserve the server family while extracting a version where possible.
        family = server.split("/", 1)[0].strip()
        v = _version(family, server)
        add(family, v, "header:server", "HIGH" if v else "MEDIUM")

    powered = h.get("x-powered-by")
    if powered:
        family = powered.split("/", 1)[0].strip()
        add(family, _version(family, powered), "header:x-powered-by", "HIGH")

    if "wp-content/" in low or "wp-includes/" in low:
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*wordpress[/ ]([0-9.]+)', b, re.I)
        add("WordPress", m.group(1) if m else None, "html", "HIGH" if m else "MEDIUM")
    if re.search(r"__next_data__|/_next/static/", low):
        add("Next.js", None, "html", "MEDIUM")
    if "graphql" in low:
        add("GraphQL", None, "html", "LOW")
    if "swagger-ui" in low or "swagger" in low and "openapi" in low:
        add("Swagger/OpenAPI", None, "html", "MEDIUM")
    if "react" in low and re.search(r"react(?:\.|/| )", low):
        add("React", None, "html", "LOW")
    if "laravel_session" in h.get("set-cookie", "").lower() or "laravel" in low:
        add("Laravel", None, "header/html", "MEDIUM")
    if "django" in h.get("x-powered-by", "").lower() or "csrfmiddlewaretoken" in low:
        add("Django", None, "header/html", "MEDIUM")
    if "__vite" in low or "/@vite/client" in low:
        add("Vite", None, "html", "MEDIUM")
    if "cloudflare" in h.get("server", "").lower() or "cf-ray" in h:
        add("Cloudflare", None, "header", "HIGH")

    return [dict(name=x.name, version=x.version, source=x.source, confidence=x.confidence)
            for x in found.values()]
