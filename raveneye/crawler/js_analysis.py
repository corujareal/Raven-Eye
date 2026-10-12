"""Bounded, static JavaScript endpoint discovery; scripts are never executed."""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlsplit, urlunsplit

_ROUTE_VALUE = re.compile(
    r"^/(?:api|graphql|gql|auth|oauth|login|logout|session|ws|websocket|v[0-9]+)(?:/|\b)",
    re.IGNORECASE,
)
_SOURCE_MAP = re.compile(r"^\s*[#@]?\s*sourceMappingURL=([^\s*]+)")
_ESCAPED_SLASH = re.compile(r"\\/")
_INTERPOLATION = re.compile(r"\$\{[^}]*\}")
_JS_IDENTIFIER_START = re.compile(r"[A-Za-z_$]")
_JS_IDENTIFIER_CONTINUE = re.compile(r"[A-Za-z0-9_$]")
_JS_STATEMENT_START = {"class", "const", "export", "function", "if", "import", "let", "return", "throw", "var"}


def _literal(value: str) -> str:
    """Decode only common URL-literal escapes without interpreting JS syntax."""
    return _ESCAPED_SLASH.sub("/", value).replace("\\\\", "\\")


def _javascript_tokens(source: str) -> list[tuple[str, str, int]]:
    """Tokenize only enough JavaScript syntax to identify literal imports.

    This is intentionally not a JavaScript parser: it ignores comments and
    quoted code examples, and never evaluates expressions. Tokens retain line
    numbers so semicolon-free module declarations stop before the next statement.
    """
    tokens: list[tuple[str, str, int]] = []
    regex_prefix_words = {
        "await", "case", "delete", "do", "else", "in", "instanceof",
        "new", "of", "return", "throw", "typeof", "void", "yield",
    }
    i = 0
    line = 1
    size = len(source)
    while i < size:
        char = source[i]
        if char in "\r\n":
            if char == "\n" or (char == "\r" and (i + 1 >= size or source[i + 1] != "\n")):
                line += 1
            i += 1
            continue
        if char.isspace():
            i += 1
            continue
        if source.startswith("//", i):
            end = i + 2
            while end < size and source[end] not in "\r\n":
                end += 1
            i = end
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            end = size if end < 0 else end + 2
            line += source[i:end].count("\n")
            i = end
            continue
        if char == "/":
            previous = tokens[-1] if tokens else None
            regex_can_start = previous is None
            if previous:
                previous_kind, previous_value, _ = previous
                regex_can_start = (
                    previous_kind == "identifier" and previous_value in regex_prefix_words
                ) or (
                    previous_kind == "punctuation"
                    and previous_value in {
                        "(", "[", "{", ",", ";", ":", "=", "!", "?", "+",
                        "-", "*", "%", "&", "|", "^", "~", "<", ">",
                    }
                )
            if regex_can_start:
                end = i + 1
                escaped = False
                in_character_class = False
                regex_closed = False
                while end < size and source[end] not in "\r\n":
                    current = source[end]
                    if escaped:
                        escaped = False
                    elif current == "\\":
                        escaped = True
                    elif current == "[":
                        in_character_class = True
                    elif current == "]":
                        in_character_class = False
                    elif current == "/" and not in_character_class:
                        end += 1
                        while end < size and source[end].isalpha():
                            end += 1
                        tokens.append(("regex", source[i + 1:end], line))
                        i = end
                        regex_closed = True
                        break
                    end += 1
                if regex_closed:
                    continue
        if char in {"'", '"', "`"}:
            quote = char
            token_line = line
            start = i + 1
            i += 1
            escaped = False
            dynamic_template = False
            while i < size:
                current = source[i]
                if current == "\n":
                    line += 1
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif quote == "`" and source.startswith("${", i):
                    dynamic_template = True
                elif current == quote:
                    break
                i += 1
            value = source[start:i]
            if i < size:
                i += 1
            tokens.append(("dynamic" if dynamic_template else "literal", value, token_line))
            continue
        if _JS_IDENTIFIER_START.fullmatch(char):
            token_line = line
            end = i + 1
            while end < size and _JS_IDENTIFIER_CONTINUE.fullmatch(source[end]):
                end += 1
            tokens.append(("identifier", source[i:end], token_line))
            i = end
            continue
        tokens.append(("punctuation", char, line))
        i += 1
    return tokens


def _http_route_template(base_url: str, value: str) -> str | None:
    """Return a path-only API template for a dynamic request literal.

    Templates are report evidence, never fetch targets. Dropping query strings
    avoids exposing embedded values and avoids pretending to know runtime data.
    """
    if not _INTERPOLATION.search(value):
        return None
    raw = _literal(value).strip()
    if not raw or any(char.isspace() for char in raw):
        return None
    if not raw.startswith(("/", "./", "../", "http://", "https://")):
        return None
    try:
        raw_parts = urlsplit(raw)
        if raw_parts.scheme and _INTERPOLATION.search(raw_parts.netloc):
            return None
        candidate = _INTERPOLATION.sub("{param}", raw)
        parsed = urlsplit(urljoin(base_url, candidate))
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None):
            return None
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    except ValueError:
        return None


def _endpoint_literals(base_url: str, source: str, *, max_results: int) -> tuple[set[str], set[str], set[str]]:
    """Extract endpoints from top-level JS string tokens and known call sites.

    Regexes over raw source also inspect strings that contain documentation or
    examples (for example ``"fetch('/api/example')"``). Tokenizing first keeps
    those nested examples inert while preserving actual URL strings in calls,
    client configuration, route declarations, and WebSocket constructors.
    """
    tokens = _javascript_tokens(source)
    endpoints: set[str] = set()
    websockets: set[str] = set()
    route_templates: set[str] = set()
    request_methods = {"get", "post", "put", "patch", "delete", "head", "options"}
    url_config_keys = {"baseurl", "url", "endpoint", "uri"}

    def string_value(token: tuple[str, str, int] | None) -> str | None:
        if token is None or token[0] not in {"literal", "dynamic"}:
            return None
        return _literal(token[1]).strip()

    def add_http(token: tuple[str, str, int] | None, *, keep_template: bool = False) -> None:
        candidate = string_value(token)
        if candidate and not any(char.isspace() for char in candidate):
            endpoint = _http_endpoint(base_url, candidate)
            if endpoint:
                endpoints.add(endpoint)
            elif keep_template and token and token[0] == "dynamic":
                template = _http_route_template(base_url, candidate)
                if template:
                    route_templates.add(template)

    def add_websocket(token: tuple[str, str, int] | None) -> None:
        candidate = string_value(token)
        if candidate and not any(char.isspace() for char in candidate):
            endpoint = _websocket_endpoint(base_url, candidate)
            if endpoint:
                websockets.add(endpoint)

    for index, token in enumerate(tokens):
        kind, value, _line = token
        normalized = value.casefold()

        # fetch('/api/...') and axios.get('/api/...')
        if kind == "identifier" and normalized == "fetch":
            if index + 2 < len(tokens) and tokens[index + 1][1] == "(":
                add_http(tokens[index + 2], keep_template=True)
        elif kind == "identifier" and normalized == "axios":
            if (index + 4 < len(tokens) and tokens[index + 1][1] == "."
                    and tokens[index + 2][1].casefold() in request_methods
                    and tokens[index + 3][1] == "("):
                add_http(tokens[index + 4], keep_template=True)

        # xhr.open('POST', '/api/...')
        if kind == "identifier" and normalized == "open" and index + 4 < len(tokens):
            method = string_value(tokens[index + 2]) if tokens[index + 1][1] == "(" else None
            if (method and method.casefold() in request_methods
                    and tokens[index + 3][1] == ","):
                add_http(tokens[index + 4], keep_template=True)

        # baseURL: '/v1', "endpoint": '/api/...'
        key = value.casefold() if kind in {"identifier", "literal"} else ""
        if key in url_config_keys and index + 2 < len(tokens) and tokens[index + 1][1] == ":":
            add_http(tokens[index + 2], keep_template=True)

        if kind not in {"literal", "dynamic"}:
            continue
        candidate = _literal(value).strip()
        if _ROUTE_VALUE.match(candidate) or candidate.startswith(("http://", "https://")):
            add_http(token)
        if candidate.startswith(("ws://", "wss://")):
            add_websocket(token)

        # new WebSocket('/socket') also accepts relative paths that do not
        # start with one of the usual API route prefixes.
        if index >= 3 and tokens[index - 3][1] == "new" and tokens[index - 2][1] == "WebSocket":
            if index >= 1 and tokens[index - 1][1] == "(":
                add_websocket(token)

        if (len(endpoints) >= max_results and len(websockets) >= max_results
                and len(route_templates) >= max_results):
            break

    return endpoints, websockets, route_templates


def _import_specifiers(source: str, *, max_results: int) -> list[str]:
    """Return bounded literal module/worker URLs, excluding comments and strings."""
    tokens = _javascript_tokens(source)
    found: set[str] = set()

    def accept(token: tuple[str, str, int] | None) -> None:
        if token and token[0] == "literal" and token[1] and not _INTERPOLATION.search(token[1]):
            candidate = _literal(token[1]).strip()
            if candidate.startswith(("/", "./", "../", "http://", "https://")):
                found.add(candidate)

    def declaration_specifier(start: int) -> None:
        if start + 1 >= len(tokens):
            return
        nxt = tokens[start + 1]
        if nxt[0] == "literal":  # import "./side-effect.js"
            accept(nxt)
            return
        if nxt[1] == "(" and start + 2 < len(tokens):  # import("./lazy.js")
            accept(tokens[start + 2])
            return
        if nxt[1] == ".":  # import.meta is not a module request
            return

        depth = 0
        start_line = tokens[start][2]
        for pos in range(start + 1, min(len(tokens), start + 513)):
            kind, value, token_line = tokens[pos]
            if value in {"(", "{", "["}:
                depth += 1
            elif value in {")", "}", "]"}:
                depth = max(0, depth - 1)
            elif value == ";" and depth == 0:
                return
            elif depth == 0 and value == "from" and pos + 1 < len(tokens):
                accept(tokens[pos + 1])
                return
            elif (depth == 0 and token_line > start_line and kind == "identifier"
                  and value in _JS_STATEMENT_START):
                return

    for index, token in enumerate(tokens):
        kind, value, _line = token
        if kind != "identifier":
            continue
        previous = tokens[index - 1][1] if index else ""
        if value in {"import", "export"} and previous not in {".", "?"}:
            declaration_specifier(index)
            continue
        if value == "importScripts" and index + 1 < len(tokens) and tokens[index + 1][1] == "(":
            pos = index + 2
            while pos < len(tokens) and tokens[pos][1] != ")":
                accept(tokens[pos])
                # Only a literal argument at an argument boundary is trusted.
                if tokens[pos][0] == "literal" and pos + 1 < len(tokens) and tokens[pos + 1][1] == ",":
                    pos += 2
                else:
                    break
            continue
        if value in {"Worker", "SharedWorker"} and index > 0 and previous == "new":
            if index + 2 < len(tokens) and tokens[index + 1][1] == "(":
                first = tokens[index + 2]
                if first[0] == "literal":
                    accept(first)
                elif (first[1] == "new" and index + 5 < len(tokens)
                      and tokens[index + 3][1] == "URL" and tokens[index + 4][1] == "("
                      and tokens[index + 5][0] == "literal"):
                    accept(tokens[index + 5])

    return sorted(found)[:max_results]


def _source_map_references(source: str) -> list[str]:
    """Read source-map directives from actual comments, never from strings."""
    references: list[str] = []
    i = 0
    size = len(source)
    quote = ""
    escaped = False
    while i < size:
        char = source[i]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            i += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            i += 1
            continue
        if source.startswith("//", i):
            end = i + 2
            while end < size and source[end] not in "\r\n":
                end += 1
            match = _SOURCE_MAP.search(source[i + 2:end])
            if match:
                references.append(match.group(1))
            i = end
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            end = size if end < 0 else end
            match = _SOURCE_MAP.search(source[i + 2:end])
            if match:
                references.append(match.group(1))
            i = size if end == size else end + 2
            continue
        i += 1
    return references


def _script_endpoint(base_url: str, value: str) -> str | None:
    endpoint = _http_endpoint(base_url, value)
    if not endpoint:
        return None
    parsed = urlsplit(endpoint)
    # Module URLs may be extensionless; the syntactic import/worker context
    # already establishes that this is a script resource.
    return endpoint if parsed.scheme in {"http", "https"} else None


def _http_endpoint(base_url: str, value: str) -> str | None:
    value = _literal(value).strip()
    if not value or _INTERPOLATION.search(value):
        # A partially interpolated route is not a fetchable URL; avoid sending
        # requests to a guessed placeholder path.
        return None
    if not value.startswith(("/", "./", "../", "http://", "https://")):
        return None
    try:
        parsed = urlsplit(urljoin(base_url, value))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    except ValueError:
        return None


def _websocket_endpoint(base_url: str, value: str) -> str | None:
    value = _literal(value).strip()
    if not value or _INTERPOLATION.search(value):
        return None
    try:
        if value.startswith(("ws://", "wss://")):
            parsed = urlsplit(value)
        elif value.startswith(("/", "./", "../")):
            resolved = urlsplit(urljoin(base_url, value))
            scheme = "wss" if resolved.scheme == "https" else "ws" if resolved.scheme == "http" else ""
            if not scheme:
                return None
            parsed = resolved._replace(scheme=scheme)
        else:
            return None
        if parsed.scheme not in {"ws", "wss"} or not parsed.hostname:
            return None
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
    except ValueError:
        return None


def analyze_javascript(base_url: str, source: str, *, max_results: int = 1000) -> dict[str, list[str]]:
    """Extract request-like URLs from bounded script text without execution.

    The parser recognizes common fetch/axios calls, XHR ``open(method, url)``,
    URL fields in client configuration, route-like literals, WebSockets,
    source-map references, and literal ECMAScript module/worker imports.
    Dynamic template expressions are deliberately not converted into guessed
    request paths. Static extraction never executes script content.
    """
    if not isinstance(source, str) or not source:
        return {"urls": [], "websockets": [], "source_maps": [], "scripts": [], "route_templates": []}
    cap = max(1, min(10000, int(max_results)))
    endpoints, websockets, route_templates = _endpoint_literals(base_url, source, max_results=cap)

    maps: set[str] = set()
    # Source-map declarations are comments by definition, so inspect actual
    # comment spans while endpoint parsing uses the comment-masked copy.
    for reference in _source_map_references(source):
        try:
            parsed = urlsplit(urljoin(base_url, _literal(reference.strip())))
            if parsed.scheme in {"http", "https"} and parsed.hostname:
                maps.add(urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, "")))
                if len(maps) >= cap:
                    break
        except ValueError:
            continue
    scripts = {
        resolved for raw in _import_specifiers(source, max_results=cap)
        if (resolved := _script_endpoint(base_url, raw))
    }
    return {
        "urls": sorted(endpoints)[:cap],
        "websockets": sorted(websockets)[:cap],
        "source_maps": sorted(maps)[:cap],
        "scripts": sorted(scripts)[:cap],
        "route_templates": sorted(route_templates)[:cap],
    }


def analyze_source_map(base_url: str, content: str, *, max_sources: int = 500,
                       max_source_bytes: int = 1_000_000, max_results: int = 1000) -> dict:
    """Inspect bounded source-map embedded sources without executing JavaScript."""
    try:
        document = json.loads(content)
    except (TypeError, ValueError):
        return {"urls": [], "websockets": [], "scripts": [], "route_templates": [], "sources_analyzed": 0}
    if not isinstance(document, dict) or not isinstance(document.get("sourcesContent"), list):
        return {"urls": [], "websockets": [], "scripts": [], "route_templates": [], "sources_analyzed": 0}
    source_cap = max(0, min(2000, int(max_sources)))
    byte_cap = max(1024, min(10_000_000, int(max_source_bytes)))
    result_cap = max(1, min(10000, int(max_results)))
    urls: set[str] = set()
    sockets: set[str] = set()
    scripts: set[str] = set()
    route_templates: set[str] = set()
    count = 0
    for source in document["sourcesContent"][:source_cap]:
        if not isinstance(source, str) or len(source.encode("utf-8", errors="ignore")) > byte_cap:
            continue
        found = analyze_javascript(base_url, source, max_results=result_cap)
        urls.update(found["urls"])
        sockets.update(found["websockets"])
        scripts.update(found["scripts"])
        route_templates.update(found["route_templates"])
        count += 1
        if (len(urls) >= result_cap and len(sockets) >= result_cap
                and len(scripts) >= result_cap and len(route_templates) >= result_cap):
            break
    return {"urls": sorted(urls)[:result_cap], "websockets": sorted(sockets)[:result_cap],
            "scripts": sorted(scripts)[:result_cap], "route_templates": sorted(route_templates)[:result_cap],
            "sources_analyzed": count}
