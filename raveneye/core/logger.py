from __future__ import annotations
import json, logging, re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SECRET = re.compile(r'(?i)(authorization|cookie|set-cookie|api[-_]?key|token|password|secret)\s*[:=]\s*[^,;\s]+(?:\s+[^,;\s]+)?')
_URL = re.compile(r'https?://[^\s<>\"\']+', re.IGNORECASE)
_QUERY_LABEL = re.compile(r'(?i)\b(dorks?|search[ _-]?queries|queries|query|consultas?)\s*[:=]\s*(?:\"[^\"]*\"|\'[^\']*\'|[^,;\n]+)')
_OMIT_KEYS = {"dork", "dorks", "google_dorks", "custom_dorks", "search_query", "search_queries", "query", "queries"}
_SECRET_KEYS = {
    "api_key", "apikey", "access_key", "access_token", "auth_token", "authorization",
    "client_secret", "cookie", "credentials", "password", "passwd", "secret", "session",
    "set_cookie", "token",
}


def _sensitive_key(key: Any) -> bool:
    normalized = str(key).strip().casefold().replace("-", "_")
    return normalized in _SECRET_KEYS or normalized.endswith(("_api_key", "_access_token", "_auth_token", "_client_secret", "_password", "_passwd", "_secret", "_session", "_token"))


def _redact_url(match: re.Match[str]) -> str:
    raw = match.group(0)
    suffix = ""
    while raw and raw[-1] in ".,;:!?)]}":
        suffix = raw[-1] + suffix
        raw = raw[:-1]
    try:
        parsed = urlsplit(raw)
        if not parsed.query:
            return match.group(0)
        if "=" not in parsed.query:
            return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "query=%5BREDACTED%5D", "")) + suffix
        fields = parse_qsl(parsed.query, keep_blank_values=True)
        query_fields = []
        for key, _value in fields:
            safe_key = key if re.fullmatch(r"[A-Za-z0-9_.~-]{1,64}", key) else "query"
            query_fields.append((safe_key, "[REDACTED]"))
        query = urlencode(query_fields, doseq=True)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, "")) + suffix
    except ValueError:
        return "[URL OMITTED]" + suffix


def redact_text(value: Any) -> str:
    text = str(value)
    text = _QUERY_LABEL.sub(lambda m: f"{m.group(1)}=[QUERY OMITTED]", text)
    text = _URL.sub(_redact_url, text)
    return _SECRET.sub(lambda m: f'{m.group(1)}=<redacted>', text)


def redact_data(value: Any) -> Any:
    """Sanitize log-shaped data while retaining result/response fields."""
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            if str(key).lower() in _OMIT_KEYS:
                clean[key] = "[QUERY OMITTED]"
            elif _sensitive_key(key):
                clean[key] = "[REDACTED]"
            else:
                clean[key] = redact_data(item)
        return clean
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, tuple):
        return [redact_data(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value

def redact(value: Any) -> str:
    text = redact_text(value)
    try:
        structured = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return text
    if isinstance(structured, (dict, list)):
        return json.dumps(redact_data(structured), ensure_ascii=False)
    return text

class JsonlHandler(logging.Handler):
    def __init__(self, path: str | Path):
        super().__init__(); self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True)
    def emit(self, record: logging.LogRecord) -> None:
        payload={'ts':record.created,'level':record.levelname,'logger':record.name,'message':redact(record.getMessage())}
        with self.path.open('a',encoding='utf-8') as f: f.write(json.dumps(payload,ensure_ascii=False)+'\n')

def get_logger(path: str='output/raveneye.jsonl') -> logging.Logger:
    log=logging.getLogger('raveneye')
    log.setLevel(logging.INFO)
    marker=str(Path(path).resolve())
    if not any(getattr(h,'raveneye_path',None)==marker for h in log.handlers):
        h=JsonlHandler(path); h.raveneye_path=marker; log.addHandler(h)
    return log


class RedactionFilter(logging.Filter):
    """Scrub formatted messages before handlers persist them."""
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = ()
        return True
