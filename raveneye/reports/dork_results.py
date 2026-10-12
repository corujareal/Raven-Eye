"""Small, dependency-free sanitizer for automated-search response exports."""
from __future__ import annotations

import html
import ipaddress
import re
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit, urlunsplit

_SECRET_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:ghp|github_pat|glpat)-[A-Za-z0-9_-]{16,}\b", re.I),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|authorization)\b\s*[:=]\s*['\"]?[^\s'\",;<>]{4,}"),
)
_SENSITIVE_PARAMETER = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|access[_-]?token|auth|authorization|code|credential|jwt|password|passwd|secret|session|signature|token)(?:$|[_-])",
    re.I,
)
_SAFE_PROVIDERS = {"SearXNG local (Docker)", "Google CSE"}
_SAFE_MOTIVES = {
    "arquivo potencialmente sensível", "possível segredo exposto",
    "listagem de diretório", "documentação ou endpoint de API",
    "superfície de diagnóstico", "possível divulgação de erro",
    "superfície administrativa", "resultado em escopo para revisão",
}
_SAFE_EVIDENCE = {
    "extensão ou caminho sensível na URL",
    "padrão de credencial ou chave privada no resultado",
    "URL ou título indica listagem de diretório",
    "caminho de API reconhecível", "caminho de diagnóstico reconhecível",
    "título ou trecho contém marcador de erro",
    "caminho de autenticação ou administração",
    "sem marcador específico; mantido para reduzir falsos negativos",
}


def _safe_response_text(value: object, limit: int = 500) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]", " ", str(value or ""))
    text = html.unescape(unquote_plus(text))
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _omit_queries(value: object, queries: list[str], limit: int) -> str:
    text = _safe_response_text(value, max(limit, 4096))
    for raw_query in queries:
        query = _safe_response_text(raw_query, 4096)
        if len(query) < 8:
            continue
        while True:
            index = text.casefold().find(query.casefold())
            if index < 0:
                break
            text = text[:index] + "[CONSULTA OMITIDA]" + text[index + len(query):]
    return text[:limit]


def _contains_query(value: object, queries: list[str]) -> bool:
    decoded = unquote_plus(str(value or "")).casefold()
    return any(
        len(query := _safe_response_text(raw, 4096)) >= 8 and query.casefold() in decoded
        for raw in queries
    )


def _in_scope_url(raw_url: object, domain: str) -> str | None:
    if not isinstance(raw_url, str) or len(raw_url) > 4096 or any(ord(char) < 32 for char in raw_url):
        return None
    try:
        parsed = urlsplit(raw_url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return None
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        target = domain.strip().rstrip(".")
        if "://" in target:
            target = urlsplit(target).hostname or ""
        target = target.encode("idna").decode("ascii").lower()
        try:
            if ipaddress.ip_address(host) != ipaddress.ip_address(target):
                return None
        except ValueError:
            if host != target and not host.endswith("." + target):
                return None
        port = parsed.port
        authority_host = f"[{host}]" if ":" in host else host
        netloc = authority_host if port is None or (parsed.scheme.lower(), port) in {("http", 80), ("https", 443)} else f"{authority_host}:{port}"
        query = urlencode([
            (key, "[REDACTED]" if _SENSITIVE_PARAMETER.search(key) else value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        ], doseq=True)
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", query, ""))
    except (UnicodeError, ValueError):
        return None


def sanitize_dork_results(report: dict) -> dict | None:
    """Whitelist in-scope result response fields and never assert confirmation."""
    source = report.get("google_dorks_results")
    if not isinstance(source, dict):
        return None
    target = report.get("target", {})
    domain = str(target.get("domain", "")) if isinstance(target, dict) else str(target or "")
    raw_provider = source.get("provider")
    provider = raw_provider if isinstance(raw_provider, str) and raw_provider in _SAFE_PROVIDERS else "desconhecido"
    raw_queries = report.get("google_dorks", [])
    queries = [str(value) for value in raw_queries if isinstance(value, str)] if isinstance(raw_queries, list) else []

    def count(key: str) -> int:
        try:
            return max(0, min(10_000_000, int(source.get(key, 0) or 0)))
        except (TypeError, ValueError, OverflowError):
            return 0

    rows = []
    raw_rows = source.get("interessantes", [])
    if not isinstance(raw_rows, list):
        raw_rows = []
    for item in raw_rows:
        if not isinstance(item, dict):
            continue
        link = _in_scope_url(item.get("link", ""), domain) if domain else None
        if not link or _contains_query(link, queries):
            continue
        confidence = item.get("confidence")
        if not isinstance(confidence, str) or confidence not in {"alta", "média", "baixa"}:
            confidence = "baixa"
        try:
            score = max(0, min(10, int(item.get("score", 0) or 0)))
        except (TypeError, ValueError, OverflowError):
            score = 0
        evidence = item.get("evidencias", [])
        safe_evidence = [value for value in evidence if isinstance(value, str) and value in _SAFE_EVIDENCE] if isinstance(evidence, list) else []
        row_provider = item.get("provider")
        if not isinstance(row_provider, str) or row_provider not in _SAFE_PROVIDERS:
            row_provider = provider
        motive = item.get("motivo")
        if not isinstance(motive, str) or motive not in _SAFE_MOTIVES:
            motive = "resultado em escopo para revisão"
        row = {
            "titulo": _omit_queries(item.get("titulo", ""), queries, 240),
            "link": link,
            "snippet": _omit_queries(item.get("snippet", ""), queries, 500),
            "provider": row_provider,
            "motivo": motive,
            "confidence": confidence,
            "score": score,
            "evidencias": safe_evidence,
            # A search result is never proof that a vulnerability exists.
            "confirmed": False,
        }
        if row_provider == "SearXNG local (Docker)" and isinstance(item.get("engines"), str):
            row["engines"] = _omit_queries(item["engines"], queries, 160)
        rows.append(row)

    confidence_counts = {level: sum(row["confidence"] == level for row in rows) for level in ("alta", "média", "baixa")}
    errors = source.get("erros", [])
    return {
        "provider": provider,
        "dorks_executados": count("dorks_executados"),
        "total_bruto": count("total_bruto"),
        "total_interessantes": len(rows),
        "total_em_escopo": count("total_em_escopo"),
        "total_fora_de_escopo": count("total_fora_de_escopo"),
        "total_duplicados": count("total_duplicados"),
        "total_payload_echoes_omitidos": count("total_payload_echoes_omitidos"),
        "confidence_counts": confidence_counts,
        "interessantes": rows,
        "erros": [f"{min(len(errors), 1000)} aviso(s); detalhes omitidos"] if isinstance(errors, list) and errors else [],
    }
