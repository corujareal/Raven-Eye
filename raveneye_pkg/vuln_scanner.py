from __future__ import annotations

"""Scanner defensivo modular da RavenEye 6.6.6.

As verificações ativas são não destrutivas e limitadas por escopo, timeout,
concorrência e rate limit. A existência de um indício nunca é tratada como
prova de exploração bem-sucedida.
"""

import concurrent.futures
import hashlib
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from raveneye.core.targets import normalize_target
from raveneye.network.domains import canonical_host
from raveneye.network.scope_guard import ScopeGuard

from bs4 import BeautifulSoup

from raveneye_pkg import state
from raveneye_pkg.database import get_cve, get_scan, put_cve, put_scan, save_scan_with_findings
from raveneye_pkg.network import _pin_dns_to, _resolve_safe_ip, get_proxies, get_random_headers
from raveneye.scanner.evidence import (
    make_evidence, request_sha256, sanitize_url, score_finding, stage_for_finding,
)
from raveneye.scanner.cve_correlator import correlate_technologies, load_local_snapshot
from raveneye_pkg.scanners import (
    check_cors,
    check_directory_listing,
    check_error_disclosure,
    check_http_request_smuggling,
    check_jwt_weaknesses,
    check_open_redirect,
    check_security_headers,
    check_ssl_cert,
    get_exploitdb_search,
    get_nmap,
    get_tech,
)


@dataclass
class Finding:
    category: str
    name: str
    severity: str
    confidence: str
    target: str
    url: str = ""
    method: str = "GET"
    parameter: str = ""
    evidence: str = ""
    description: str = ""
    impact: str = ""
    recommendation: str = ""
    cwe: str = ""
    cve: str = ""
    exploitdb: list[dict[str, Any]] | None = None
    scanner: str = "RavenVulnScanner"
    timestamp: float = 0.0
    stage: str = "POSSIBLE"
    confidence_score: int = 0
    score_factors: dict[str, int] | None = None
    evidence_metadata: dict[str, Any] | None = None
    observed_at: str = ""
    cve_source: str = ""
    cve_schema_version: str = ""
    cve_retrieved_at: str = ""
    cve_dataset_sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["exploitdb"] = data["exploitdb"] or []
        data["timestamp"] = self.timestamp or time.time()
        if data.get("url"):
            data["url"] = sanitize_url(data["url"])
        if data.get("target"):
            data["target"] = sanitize_url(data["target"]) or data["target"]
        return data


class _RateLimiter:
    def __init__(self, rate: float) -> None:
        self.rate = max(0.1, float(rate))
        self._next = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        if now < self._next:
            time.sleep(self._next - now)
        self._next = max(now, self._next) + (1.0 / self.rate)


class RavenVulnScanner:
    """Engine de detecção com baseline, evidência e confidence score."""

    REQUIRED = {
        "sql_injection", "command_injection", "directory_traversal", "xxe",
        "xss", "ssl_tls", "open_ports", "ldap_injection", "csrf",
        "headers_security", "information_disclosure",
    }

    EXTRA = {
        "ssrf", "ssti", "nosql_injection", "xpath_injection", "crlf_injection",
        "host_header_injection", "http_request_smuggling", "http_parameter_pollution",
        "open_redirect", "cors", "cookie_security", "authentication",
        "authorization", "idor_bola", "directory_listing", "sensitive_files",
        "debug_disclosure", "http_methods", "api_security", "graphql",
        "websocket", "jwt", "dns_misconfiguration", "subdomain_takeover",
        "exposed_services", "vulnerable_components", "outdated_components",
        "secret_exposure", "technology_disclosure",
    }

    SQL_ERRORS = re.compile(
        r"(sql syntax|mysql_fetch|mysqli_|pdoexception|pg::syntax|"
        r"postgres(?:ql)?\s+(?:error|syntax error)|ora-\d{4,5}|sqlite error|"
        r"unclosed quotation mark|odbc sql)",
        re.I,
    )
    CMD_ERRORS = re.compile(
        r"((?:sh|bash):\s*[^\r\n]{1,120}:\s*(?:command )?not found|"
        r"cmd\.exe is not recognized as an internal or external command|"
        r"cannot execute (?:binary file|command)|syntax error near unexpected token)",
        re.I,
    )
    SHELLISH_PARAMS = {"cmd", "command", "exec", "execute", "query", "shell", "ping"}
    SSRF_PARAMS = {"url", "uri", "dest", "destination", "redirect", "next", "target", "callback", "webhook"}
    TEMPLATE_PARAMS = {"template", "view", "name", "content", "message", "subject"}
    LDAP_PARAMS = {"username", "user", "uid", "cn", "dn", "filter", "search"}
    NOSQL_PARAMS = {"query", "filter", "where", "search", "username", "id"}
    SESSION_COOKIE_NAME = re.compile(
        r"(?i)(?:^|[._-])(?:session|sessionid|sess|sessid|auth|token|jwt|sid)(?:$|[._-])"
    )
    KNOWN_SESSION_COOKIE_NAMES = {
        "phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid",
    }

    def __init__(
        self,
        target: str,
        root_mode: bool = False,
        urls: list[str] | None = None,
        max_workers: int | None = None,
        rate_limit: float | None = None,
        active: bool = True,
        timeout: int = 8,
        enable_smuggling: bool = False,
        scope_domains: set[str] | list[str] | None = None,
        scope_excludes: set[str] | list[str] | None = None,
    ) -> None:
        normalized_target = normalize_target(target)
        if not normalized_target:
            raise ValueError("Alvo inválido: informe um domínio ou URL HTTP(S).")
        self.target = normalized_target
        self.root_mode = bool(root_mode)
        normalized_urls = [normalize_target(value) for value in (urls or [normalized_target])]
        self.urls = list(dict.fromkeys(value for value in normalized_urls if value)) or [normalized_target]
        self._scope_explicit = bool(scope_domains)
        self.scope_domains = {str(value).strip() for value in (scope_domains or []) if str(value).strip()}
        self.scope_excludes = {str(value).strip() for value in (scope_excludes or []) if str(value).strip()}
        self.max_workers = max(1, min(20, int(max_workers or state.config.get("scanner_max_workers", 6))))
        self.rate = _RateLimiter(rate_limit or state.config.get("scanner_rate_limit", 8.0))
        self.active = active
        self.enable_smuggling = bool(enable_smuggling)
        self.timeout = max(2, int(timeout))
        self.findings: list[Finding] = []
        self._cancel = False
        self._response_evidence: dict[str, dict[str, Any]] = {}
        self._blocked_network_events: set[str] = set()

        parsed = urlparse(self.target)
        self.domain = parsed.hostname or ""
        self._scope_host = canonical_host(self.domain)
        self._scope_default_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not self.scope_domains:
            self.scope_domains = {self._scope_host}
        if self._scope_explicit:
            self._scope_guard = ScopeGuard(
                domains=self.scope_domains,
                excludes=tuple(self.scope_excludes),
            )
        else:
            # With no configured scope, bind to the exact host the user gave.
            # Domain rules otherwise include all subdomains by design.
            self._scope_guard = ScopeGuard(
                exact_hosts={self._scope_host},
                excludes=tuple(self.scope_excludes),
            )

    def cancel(self) -> None:
        self._cancel = True

    def _in_scope(self, url: str) -> bool:
        try:
            p = urlparse(url)
            if p.scheme not in {"http", "https"} or not p.hostname or p.username is not None or p.password is not None:
                return False
            host = canonical_host(p.hostname)
            self._scope_guard.check(url)
            if not self._scope_explicit and host == self._scope_host:
                port = p.port or (443 if p.scheme == "https" else 80)
                # An implicit HTTP↔HTTPS upgrade on the same host remains in
                # scope. Custom target ports stay pinned to that exact port.
                if self._scope_default_port in {80, 443} and port in {80, 443}:
                    return True
                return port == self._scope_default_port
            return True
        except (TypeError, ValueError, UnicodeError):
            return False

    def _request(self, url: str, **kwargs: Any):
        if self._cancel:
            return None
        configured_proxy = get_proxies()
        if configured_proxy and not state.config.get("scanner_allow_proxy", False):
            self._blocked_network_events.add("scanner_proxy_disabled_by_default")
            return None

        headers = kwargs.pop("headers", get_random_headers())
        timeout = kwargs.pop("timeout", self.timeout)
        follow_redirects = bool(kwargs.pop("allow_redirects", True))
        # Requests helpers may set these; redirects are processed manually and
        # every response body has a fixed memory cap.
        kwargs.pop("proxies", None)
        kwargs.pop("stream", None)
        current = url
        try:
            for _hop in range(6):
                if not self._in_scope(current):
                    self._blocked_network_events.add("redirect_out_of_scope")
                    return None
                ip, safe = _resolve_safe_ip(current)
                if not safe or not ip:
                    self._blocked_network_events.add("destination_blocked_by_ssrf_guard")
                    return None
                self.rate.wait()
                request_args = dict(
                    timeout=timeout,
                    allow_redirects=False,
                    headers=headers,
                    proxies=configured_proxy,
                    stream=True,
                    **kwargs,
                )
                # When explicitly enabled, a proxy resolves destinations on
                # its own; pinning the origin locally would pin the proxy.
                with _pin_dns_to(None if configured_proxy else ip):
                    response = state._SESSION.get(current, **request_args)
                if (
                    follow_redirects
                    and response.status_code in {301, 302, 303, 307, 308}
                    and response.headers.get("Location")
                ):
                    current = urljoin(current, response.headers["Location"])
                    close = getattr(response, "close", None)
                    if callable(close):
                        close()
                    continue

                max_bytes = max(1024, int(state.config.get("scanner_max_response_bytes", 2_000_000)))
                body = bytearray()
                truncated = False
                iterator = getattr(response, "iter_content", None)
                if callable(iterator):
                    for chunk in iterator(chunk_size=65536):
                        if not chunk:
                            continue
                        remaining = max_bytes + 1 - len(body)
                        body.extend(chunk[:remaining])
                        if len(body) > max_bytes:
                            break
                    truncated = len(body) > max_bytes
                    body = body[:max_bytes]
                    response._content = bytes(body)
                    response._content_consumed = True
                else:
                    body_text = str(getattr(response, "text", ""))
                    encoded = body_text.encode("utf-8", "replace")
                    truncated = len(encoded) > max_bytes
                    response._content = encoded[:max_bytes]
                    response._content_consumed = True
                observed = make_evidence(
                    method="GET", url=current, status=response.status_code,
                    headers=dict(response.headers), body=str(response.text),
                    source="legacy-http-response", stage="POSSIBLE",
                    factors={"direct_observation": True}, truncated=truncated,
                )
                self._response_evidence[url] = observed
                self._response_evidence[current] = observed
                close = getattr(response, "close", None)
                if callable(close):
                    close()
                return response
            self._blocked_network_events.add("redirect_limit_reached")
            return None
        except Exception as exc:
            state.vprint(2, f"[WARN] scanner request failed (URL redacted): {type(exc).__name__}")
            return None

    def _add(self, **kwargs: Any) -> None:
        evidence_url = str(kwargs.pop("_evidence_url", kwargs.get("url", "")))
        evidence_request_sha256 = str(kwargs.pop("_evidence_request_sha256", ""))
        baseline = kwargs.pop("_baseline_observation", None)
        additional_factors = kwargs.pop("_score_factors", {})
        kwargs.setdefault("target", self.target)
        kwargs.setdefault("timestamp", time.time())
        observation = self._response_evidence.get(evidence_url)
        if not observation and evidence_request_sha256:
            observation = next((
                record for record in self._response_evidence.values()
                if record.get("request", {}).get("sha256") == evidence_request_sha256
            ), None)
        stage = str(kwargs.get("stage") or stage_for_finding(str(kwargs.get("category", ""))))
        if stage not in {"POSSIBLE", "PROBABLE", "CONFIRMED"}:
            stage = "POSSIBLE"
        kwargs["stage"] = stage
        if observation:
            metadata = dict(observation)
            metadata["stage"] = stage
            score_factors = {"direct_observation": True, **dict(additional_factors or {})}
            if baseline:
                baseline_record = {
                    "status": baseline.get("status"),
                    "body_sha256": baseline.get("body_sha256", ""),
                    "response_sha256": baseline.get("response_sha256", ""),
                    "body_length": baseline.get("body_length", 0),
                }
                response_record = metadata.get("response", {})
                metadata["baseline"] = baseline_record
                metadata["delta"] = {
                    "compared": True,
                    "status_changed": baseline_record["status"] != response_record.get("status"),
                    "body_hash_changed": baseline_record["body_sha256"] != response_record.get("body_sha256"),
                    "body_length_delta": response_record.get("body_length", 0) - baseline_record["body_length"],
                }
                score_factors["baseline_compared"] = True
            score, factors = score_finding(stage, score_factors)
            metadata["confidence_score"] = score
            metadata["score_factors"] = factors
            kwargs.setdefault("evidence_metadata", metadata)
            kwargs.setdefault("observed_at", metadata.get("observed_at", ""))
            kwargs.setdefault("confidence_score", score)
            kwargs.setdefault("score_factors", factors)
        else:
            score, factors = score_finding(stage, {"heuristic_only": True})
            kwargs.setdefault("confidence_score", score)
            kwargs.setdefault("score_factors", factors)
            observed_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
            kwargs.setdefault("evidence_metadata", {
                "schema_version": "1.0", "source": "legacy-input-heuristic",
                "observed_at": observed_at,
                "request": {"method": str(kwargs.get("method", "GET")).upper(),
                            "sha256": request_sha256(str(kwargs.get("method", "GET")), evidence_url or self.target)},
                "stage": stage, "confidence_score": score, "score_factors": factors,
                "response": {"observed": False, "sha256": "", "body_sha256": "",
                             "status": None, "body_length": 0, "truncated": False},
                "baseline": {"observed": False, "sha256": "", "body_sha256": "",
                             "response_sha256": "", "status": None, "body_length": 0},
                "delta": {"compared": False},
            })
            kwargs.setdefault("observed_at", observed_at)
        self.findings.append(Finding(**kwargs))

    def _baseline_signature(self, response, request_url: str = "") -> dict[str, Any]:
        body = str(response.text)[:200000] if response is not None else ""
        observation = self._response_evidence.get(request_url) or self._response_evidence.get(
            str(getattr(response, "url", ""))
        )
        if observation:
            response_record = observation.get("response", {})
            body_sha = response_record.get("body_sha256", "")
            response_sha = response_record.get("sha256", "")
            body_length = response_record.get("body_length", len(body.encode("utf-8", "replace")))
        else:
            body_sha = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()
            response_sha = ""
            body_length = len(body.encode("utf-8", "replace"))
        return {
            "status": response.status_code if response is not None else 0,
            "body_length": body_length,
            "body_sha256": body_sha,
            "response_sha256": response_sha,
            "content_type": response.headers.get("Content-Type", "") if response is not None else "",
        }

    @staticmethod
    def _has_response_delta(response, baseline: dict[str, Any]) -> bool:
        if response is None:
            return False
        body_length = len(str(response.text).encode("utf-8", "replace"))
        return (
            response.status_code != baseline.get("status")
            or abs(body_length - int(baseline.get("body_length", 0)))
            > max(100, int(int(baseline.get("body_length", 0)) * 0.20))
        )

    @staticmethod
    def _stable_probe_pair(first, second, first_signature: str, second_signature: str) -> bool:
        if not first or not second or not first_signature or not second_signature:
            return False
        if first.status_code != second.status_code or first_signature.casefold() != second_signature.casefold():
            return False
        first_length = len(str(first.text).encode("utf-8", "replace"))
        second_length = len(str(second.text).encode("utf-8", "replace"))
        return abs(first_length - second_length) <= max(64, int(max(first_length, second_length) * 0.10))

    @staticmethod
    def _replace_query(url: str, param: str, value: str) -> str:
        p = urlparse(url)
        pairs = parse_qsl(p.query, keep_blank_values=True)
        replaced = False
        out = []
        for k, v in pairs:
            if k == param and not replaced:
                out.append((k, value))
                replaced = True
            else:
                out.append((k, v))
        return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(out), p.fragment))

    def _urls_with_params(self) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for url in self.urls:
            try:
                for key, _ in parse_qsl(urlparse(url).query, keep_blank_values=True):
                    if key and self._in_scope(url):
                        out.append((url, key))
            except Exception:
                continue
        return list(dict.fromkeys(out))

    def _check_headers(self) -> None:
        for item in check_security_headers(self.target, requester=self._request):
            sev = str(item.get("severity", "BAIXO")).upper()
            # Header ausente é postura/configuração, não prova de exploit.
            self._add(
                category="headers_security",
                name=f"Security header ausente: {item.get('header', '')}",
                severity=sev,
                confidence="HIGH",
                url=self.target,
                evidence=item.get("desc", ""),
                description="Header de segurança esperado não foi observado na resposta.",
                impact="Pode reduzir proteções do navegador dependendo do contexto.",
                recommendation=f"Configurar {item.get('header', '')} de forma adequada ao aplicativo.",
            )

    def _check_cookies(self) -> None:
        r = self._request(self.target)
        if not r:
            return
        for cookie in r.cookies:
            rest = getattr(cookie, "_rest", {}) or {}
            cookie_name = str(getattr(cookie, "name", ""))
            likely_session = (
                cookie_name.strip().lower() in self.KNOWN_SESSION_COOKIE_NAMES
                or bool(self.SESSION_COOKIE_NAME.search(cookie_name))
            )
            secure = bool(getattr(cookie, "secure", False))
            httponly = any(str(k).lower() == "httponly" for k in rest)
            samesite = next((v for k, v in rest.items() if str(k).lower() == "samesite"), None)
            if not secure and urlparse(self.target).scheme == "https":
                self._add(
                    category="cookie_security", name=f"Cookie sem Secure: {cookie_name}",
                    severity="BAIXO" if likely_session else "INFO",
                    confidence="MEDIUM" if likely_session else "LOW", url=self.target,
                    evidence=(f"Set-Cookie {cookie_name} não possui Secure; "
                              f"nome com indício de sessão: {'sim' if likely_session else 'não'}"),
                    description=("Cookie com nome compatível com sessão em HTTPS pode ser enviado em canal não protegido."
                                 if likely_session else "Cookie sem Secure observado; o nome não indica que armazene sessão."),
                    recommendation="Use Secure em cookies de sessão ou outros cookies sensíveis.",
                    stage="POSSIBLE",
                    _score_factors={"heuristic_only": not likely_session},
                )
            if not httponly:
                self._add(
                    category="cookie_security", name=f"Cookie sem HttpOnly: {cookie_name}",
                    severity="BAIXO" if likely_session else "INFO",
                    confidence="MEDIUM" if likely_session else "LOW", url=self.target,
                    evidence=(f"Set-Cookie {cookie_name} não possui HttpOnly; "
                              f"nome com indício de sessão: {'sim' if likely_session else 'não'}"),
                    description=("JavaScript do navegador pode acessar um cookie com nome compatível com sessão."
                                 if likely_session else "Cookie legível por JavaScript observado; pode ser intencional para preferências ou estado público."),
                    recommendation="Use HttpOnly em cookies de sessão que não precisam ser lidos pelo JavaScript.",
                    stage="POSSIBLE",
                    _score_factors={"heuristic_only": not likely_session},
                )
            if samesite is None:
                self._add(
                    category="cookie_security", name=f"Cookie sem SameSite: {cookie_name}",
                    severity="BAIXO" if likely_session else "INFO",
                    confidence="MEDIUM" if likely_session else "LOW", url=self.target,
                    evidence=(f"Set-Cookie {cookie_name} não declara SameSite; "
                              f"nome com indício de sessão: {'sim' if likely_session else 'não'}"),
                    recommendation="Defina SameSite para cookies de sessão conforme o fluxo legítimo da aplicação.",
                    stage="POSSIBLE",
                    _score_factors={"heuristic_only": not likely_session},
                )

    def _check_xss_and_sql(self) -> None:
        for url, param in self._urls_with_params()[:80]:
            if self._cancel:
                return
            baseline = self._request(url)
            if not baseline:
                continue
            base = self._baseline_signature(baseline, url)
            baseline_body = str(baseline.text)[:200000]

            marker = f"RAVENEYE_{hashlib.sha1(f'{url}|{param}'.encode()).hexdigest()[:10]}"
            marker_url = self._replace_query(url, param, marker)
            probe = self._request(marker_url)
            if probe:
                body = str(probe.text)[:200000]
                if marker in body and marker not in baseline_body:
                    self._add(
                        category="xss", name="Reflexão de parâmetro detectada",
                        severity="INFO", confidence="LOW", url=url, parameter=param,
                        stage="POSSIBLE",
                        evidence="Marcador benigno único retornou no corpo; contexto de saída não foi validado.",
                        description="O valor controlado pelo parâmetro foi refletido; isso é evidência de reflexão, não prova isolada de XSS executável.",
                        impact="Reflexões não escapadas podem permitir XSS dependendo do contexto de saída.",
                        recommendation="Aplicar escaping contextual e validação de entrada.",
                        cwe="CWE-79",
                        _evidence_url=marker_url,
                        _baseline_observation=base,
                        _score_factors={"unique_marker": True, "differential_signal": True},
                    )

            quote_url = self._replace_query(url, param, "'")
            sql_probe = self._request(quote_url)
            sql_repeat = self._request(quote_url)
            base_sql_error = self.SQL_ERRORS.search(baseline_body)
            sql_match = self.SQL_ERRORS.search(str(sql_probe.text)[:200000]) if sql_probe else None
            sql_repeat_match = self.SQL_ERRORS.search(str(sql_repeat.text)[:200000]) if sql_repeat else None
            if sql_probe and sql_repeat and sql_match and sql_repeat_match:
                stable = self._stable_probe_pair(sql_probe, sql_repeat, sql_match.group(0), sql_repeat_match.group(0))
                changed = self._has_response_delta(sql_probe, base) and self._has_response_delta(sql_repeat, base)
                if not base_sql_error and stable and changed:
                    self._add(
                        category="sql_injection", name="Indício diferencial repetível de erro SQL",
                        severity="MEDIO", confidence="MEDIUM", url=url, parameter=param,
                        stage="PROBABLE",
                        evidence="Assinatura SQL ausente no baseline e reproduzida em dois probes benignos com resposta alterada; assinatura bruta omitida.",
                        description="Uma alteração sintática simples produziu erro de banco acompanhado de mudança de resposta.",
                        impact="Pode permitir manipulação de consultas se a entrada não estiver parametrizada.",
                        recommendation="Use consultas parametrizadas/prepared statements e valide a entrada.",
                        cwe="CWE-89",
                        _evidence_url=quote_url,
                        _baseline_observation=base,
                        _score_factors={"differential_signal": True, "repeatable": True},
                    )

            if param.lower() in self.SHELLISH_PARAMS:
                shell_url = self._replace_query(url, param, "\"")
                shell_probe = self._request(shell_url)
                shell_repeat = self._request(shell_url)
                shell_match = self.CMD_ERRORS.search(str(shell_probe.text)[:200000]) if shell_probe else None
                shell_repeat_match = self.CMD_ERRORS.search(str(shell_repeat.text)[:200000]) if shell_repeat else None
                if (
                    shell_probe and shell_repeat and not self.CMD_ERRORS.search(baseline_body)
                    and self._stable_probe_pair(
                        shell_probe, shell_repeat,
                        shell_match.group(0) if shell_match else "",
                        shell_repeat_match.group(0) if shell_repeat_match else "",
                    )
                    and self._has_response_delta(shell_probe, base)
                    and self._has_response_delta(shell_repeat, base)
                ):
                    self._add(
                        category="command_injection", name="Indício diferencial repetível de erro de shell",
                        severity="MEDIO", confidence="MEDIUM", url=url, parameter=param,
                        stage="PROBABLE",
                        evidence="Assinatura de erro de shell ausente no baseline e reproduzida após entrada benigna; texto bruto omitido.",
                        description="A entrada controlada coincidiu com uma mensagem típica de shell.",
                        impact="Pode permitir execução de comandos no servidor se confirmado.",
                        recommendation="Não concatene entrada em comandos; use APIs sem shell e allowlists.",
                        cwe="CWE-78",
                        _evidence_url=shell_url,
                        _baseline_observation=base,
                        _score_factors={"differential_signal": True, "repeatable": True},
                    )

    def _check_csrf(self) -> None:
        for url in self.urls[:60]:
            if self._cancel:
                return
            r = self._request(url)
            if not r or "text/html" not in r.headers.get("Content-Type", "").lower():
                continue
            soup = BeautifulSoup(r.text[:500000], "html.parser")
            for form in soup.find_all("form"):
                method = str(form.get("method", "get")).lower()
                if method != "post":
                    continue
                inputs = [
                    re.sub(r"[^a-z0-9]", "", str(x.get("name", "")).casefold())
                    for x in form.find_all("input")
                ]
                has_input_token = any(
                    any(marker in name for marker in (
                        "csrf", "xsrf", "authenticity", "requestverification",
                        "antiforgery", "nonce",
                    )) or name in {"token", "formtoken"}
                    for name in inputs if name
                )
                # Frameworks such as Rails and Django commonly place a
                # request token in a meta tag for JavaScript to copy into the
                # POST header instead of rendering it as a form input.
                has_meta_token = any(
                    re.sub(r"[^a-z0-9]", "", str(meta.get("name", "")).casefold())
                    in {"csrf", "csrftoken", "xsrf", "xsrftoken", "authenticitytoken", "requestverificationtoken"}
                    and str(meta.get("content", "")).strip()
                    for meta in soup.find_all("meta")
                )
                has_token = has_input_token or has_meta_token
                if not has_token:
                    self._add(
                        category="csrf", name="Form POST sem token CSRF aparente",
                        severity="BAIXO", confidence="LOW", url=url, stage="POSSIBLE",
                        evidence=f"Form POST para {form.get('action', '') or url} sem campo de token reconhecível.",
                        description="Ausência de token não prova CSRF; aplicações podem usar SameSite, cabeçalhos ou outros controles.",
                        impact="Operações autenticadas podem ficar expostas a requisições cross-site em determinadas condições.",
                        recommendation="Use proteção CSRF apropriada ao framework e valide Origin/Referer quando adequado.",
                        cwe="CWE-352",
                    )

    def _check_traversal_xxe_and_injection_candidates(self) -> None:
        for url, param in self._urls_with_params()[:100]:
            p = param.lower()
            if p in self.LDAP_PARAMS:
                self._add(
                    category="ldap_injection", name="Parâmetro compatível com entrada LDAP",
                    severity="INFO", confidence="LOW", url=url, parameter=param,
                    evidence=f"Nome do parâmetro '{param}' é compatível com filtros/identificadores LDAP.",
                    description="Candidato para revisão manual; nenhuma exploração foi executada.",
                    recommendation="Use filtros parametrizados e escape de caracteres LDAP.",
                    cwe="CWE-90",
                )
            if p in self.NOSQL_PARAMS:
                self._add(
                    category="nosql_injection", name="Parâmetro compatível com consulta NoSQL",
                    severity="INFO", confidence="LOW", url=url, parameter=param,
                    evidence=f"Parâmetro '{param}' pode alimentar filtros de consulta.",
                    description="Candidato heurístico; requer validação controlada no ambiente autorizado.",
                    recommendation="Valide tipos e construa consultas com APIs seguras.",
                )
            if p in self.TEMPLATE_PARAMS:
                self._add(
                    category="ssti", name="Parâmetro potencialmente relacionado a template",
                    severity="INFO", confidence="LOW", url=url, parameter=param,
                    evidence=f"Parâmetro '{param}' tem semântica de template/conteúdo.",
                    description="Candidato heurístico; nenhum template foi executado.",
                    recommendation="Não interprete entrada do usuário como template.",
                    cwe="CWE-1336",
                )
            if p in self.SSRF_PARAMS:
                self._add(
                    category="ssrf", name="Parâmetro potencialmente controlando URL",
                    severity="INFO", confidence="LOW", url=url, parameter=param,
                    evidence=f"Parâmetro '{param}' tem semântica de URL/destino.",
                    description="Candidato heurístico; nenhum endpoint interno foi acessado.",
                    recommendation="Use allowlist de destinos e bloqueio de redes internas.",
                    cwe="CWE-918",
                )
            if "../" in url or "%2e%2e" in url.lower():
                self._add(
                    category="directory_traversal", name="Sequência de traversal observada",
                    severity="LOW", confidence="LOW", url=url, parameter=param,
                    evidence="A URL contém uma sequência de subida de diretório.",
                    description="A presença da sequência não prova acesso a arquivos.",
                    recommendation="Canonicalize caminhos e restrinja a raiz permitida.",
                    cwe="CWE-22",
                )

        # XXE: sem enviar entidade externa. Apenas verifica endpoints XML já
        # identificados e resposta/Content-Type, evitando leitura de recursos locais.
        xml_candidates = [u for u in self.urls if any(x in u.lower() for x in ("/xml", "soap", "wsdl"))]
        for u in xml_candidates[:20]:
            self._add(
                category="xxe", name="Endpoint XML candidato a revisão XXE",
                severity="INFO", confidence="LOW", url=u,
                evidence="Endpoint/rota indica processamento XML.",
                description="Candidato passivo; nenhum recurso externo foi referenciado.",
                recommendation="Desative entidades externas e DTD quando não forem necessários.",
                cwe="CWE-611",
            )

    def _check_host_header_and_crlf(self) -> None:
        for url, param in self._urls_with_params()[:40]:
            probe = self._request(
                self._replace_query(url, param, "RAVENEYE%0d%0aX-RavenEye:1"),
                allow_redirects=False,
            )
            if probe and "X-RavenEye" in probe.headers:
                self._add(
                    category="crlf_injection", name="Header adicional refletido",
                    severity="ALTO", confidence="HIGH", url=url, parameter=param,
                    evidence="A resposta apresentou X-RavenEye após entrada controlada.",
                    recommendation="Normalize/encode entradas antes de construir headers.",
                    cwe="CWE-113",
                )

        if not self._in_scope(self.target):
            return
        canary = "raveneye-invalid.example"
        if not self.active:
            return
        r = self._request(self.target, headers={**get_random_headers(), "Host": canary})
        if r and (canary in r.text[:100000] or canary in r.headers.get("Location", "")):
            self._add(
                category="host_header_injection", name="Host controlado refletido",
                severity="ALTO", confidence="MEDIUM", url=self.target,
                evidence="Host canário refletido em Location ou no corpo; impacto ainda não confirmado.",
                recommendation="Valide o Host contra uma allowlist no proxy/aplicação.",
                cwe="CWE-644",
            )

    def _check_open_ports(self) -> None:
        if not self.active:
            return
        ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 5432, 6379, 8080, 8443, 9200]
        host = self.domain
        if not host:
            return
        ip, safe = _resolve_safe_ip(self.target)
        if not safe or not ip:
            self._blocked_network_events.add("port_scan_blocked_by_ssrf_guard")
            return
        open_ports: list[int] = []
        for port in ports:
            if self._cancel:
                return
            try:
                self.rate.wait()
                sock = socket.create_connection((ip, port), timeout=1.5)
                sock.close()
                open_ports.append(port)
            except Exception:
                continue
        for port in open_ports:
            self._add(
                category="open_ports", name=f"Porta TCP aberta: {port}",
                severity="INFO", confidence="HIGH", target=self.target,
                evidence=f"Conexão TCP concluída para {host}:{port}.",
                description="Porta acessível externamente; exposição não é por si só uma vulnerabilidade.",
                recommendation="Restrinja serviços que não precisam ser públicos.",
            )

    def _check_technology(self) -> dict[str, Any]:
        tech = get_tech(self.target, requester=self._request)
        server = tech.get("servidor", "")
        if server and server != "Desconhecido":
            self._add(
                category="technology_disclosure", name="Banner de servidor exposto",
                severity="INFO", confidence="HIGH", url=self.target,
                evidence=server,
                description="O servidor informa sua tecnologia no cabeçalho HTTP.",
                recommendation="Reduza banners quando isso for compatível com a operação.",
            )
        return tech

    def _existing_checks(self) -> None:
        try:
            for item in check_cors(self.urls, limit=min(30, len(self.urls)), requester=self._request):
                self._add(
                    category="cors", name="CORS permissivo",
                    severity=str(item.get("severity", "MEDIO")).upper(),
                    confidence="HIGH" if item.get("credentials") == "true" and item.get("acao") != "*" else "MEDIUM",
                    url=item.get("url", ""), evidence=f"Origin={item.get('origin_testada')} ACAO={item.get('acao')}",
                    description="A origem fornecida foi aceita pela aplicação.",
                    recommendation="Use allowlist explícita de origens.",
                    cwe="CWE-942",
                )
        except Exception as exc:
            state.vprint(2, f"[WARN] scanner CORS: {exc}")

        try:
            for item in check_open_redirect(self.urls, requester=self._request):
                self._add(
                    category="open_redirect", name="Open Redirect",
                    severity=str(item.get("severity", "MEDIO")).upper(),
                    confidence="HIGH", url=item.get("url", ""), parameter=item.get("param", ""),
                    evidence="Location confirmou o canário HTTPS externo; valor bruto omitido.",
                    recommendation="Permita somente destinos internos/allowlisted.",
                    cwe="CWE-601",
                    _evidence_request_sha256=item.get("request_sha256", ""),
                )
        except Exception as exc:
            state.vprint(2, f"[WARN] scanner redirect: {exc}")

        try:
            for url in check_directory_listing(self.urls[:50], requester=self._request):
                self._add(
                    category="directory_listing", name="Directory listing",
                    severity="MEDIO", confidence="HIGH", url=url,
                    evidence="Resposta 200 contém indicadores de índice de diretório.",
                    recommendation="Desabilite autoindex/listing em diretórios públicos.",
                    cwe="CWE-548",
                )
        except Exception as exc:
            state.vprint(2, f"[WARN] scanner directory listing: {exc}")

        try:
            for item in check_error_disclosure(self.urls[:30], requester=self._request):
                self._add(
                    category="information_disclosure", name="Mensagem de erro detalhada",
                    severity=str(item.get("severity", "MEDIO")).upper(),
                    confidence="HIGH", url=item.get("url", ""),
                    evidence=f"{item.get('tipo')}: {item.get('snippet', '')}",
                    description="A resposta revelou informação interna de implementação.",
                    recommendation="Desabilite stack traces em produção e use páginas de erro genéricas.",
                    cwe="CWE-209",
                )
        except Exception as exc:
            state.vprint(2, f"[WARN] scanner disclosure: {exc}")

        try:
            for item in check_jwt_weaknesses(self.target, requester=self._request):
                self._add(
                    category="jwt", name=item.get("tipo", "Fraqueza JWT"),
                    severity=str(item.get("severity", "MEDIO")).upper(),
                    confidence="MEDIUM", url=self.target,
                    evidence=item.get("desc", str(item)),
                    recommendation="Use algoritmos/segredos fortes e valide claims corretamente.",
                )
        except Exception as exc:
            state.vprint(2, f"[WARN] scanner JWT: {exc}")

        if not self.enable_smuggling:
            self._blocked_network_events.add("request_smuggling_not_run_by_default")
            return
        try:
            smuggle = check_http_request_smuggling(self.target, timeout=self.timeout)
            if smuggle:
                self._add(
                    category="http_request_smuggling", name="Indício de request smuggling",
                    severity="ALTO", confidence="MEDIUM", url=self.target,
                    evidence=str(smuggle),
                    description="Heurística de discrepância no tratamento de requests.",
                    recommendation="Padronize parsing HTTP entre proxy e servidor.",
                    cwe="CWE-444",
                )
        except Exception as exc:
            state.vprint(2, f"[WARN] scanner smuggling: {exc}")

    def _cve_enrichment(self, tech: dict[str, Any]) -> None:
        """Correlate offline advisory snapshots; remote search requires explicit opt-in."""
        products: list[dict[str, Any]] = []
        server = str(tech.get("servidor", "") or "")
        m = re.search(r"([A-Za-z][A-Za-z0-9._-]{1,40})[/ ](v?\d+(?:\.\d+){1,3})", server)
        if m:
            products.append({
                "name": m.group(1), "version": m.group(2).lstrip("vV"),
                "confidence": "MEDIUM", "source": "header:server",
            })
        for product in [tech.get("cms"), *tech.get("frameworks", [])]:
            if product:
                products.append({
                    "name": str(product), "version": None,
                    "confidence": "LOW", "source": "legacy-html-fingerprint",
                })

        snapshot_path = (
            state.config.get("cve_records_path")
            or os.environ.get("RAVENEYE_CVE_RECORDS_PATH")
        )
        if snapshot_path:
            try:
                records, metadata = load_local_snapshot(snapshot_path)
                for item in correlate_technologies(
                    products, records, url=self.target, source_metadata=metadata
                ):
                    self._add(
                        category="vulnerable_components",
                        name=item["name"],
                        severity=item["severity"],
                        confidence=item["confidence"],
                        url=self.target,
                        evidence=item["evidence"],
                        recommendation=item["remediation"],
                        cwe=item.get("cwe", ""),
                        cve=item.get("cve", ""),
                        stage="POSSIBLE",
                        cve_source=item.get("cve_source", ""),
                        cve_schema_version=item.get("cve_schema_version", ""),
                        cve_retrieved_at=item.get("cve_retrieved_at", ""),
                        cve_dataset_sha256=item.get("cve_dataset_sha256", ""),
                    )
                return
            except (OSError, ValueError, TypeError) as exc:
                state.vprint(1, f"[WARN] local CVE snapshot unavailable: {type(exc).__name__}")

        # Keep the old online enrichment available to operators who explicitly
        # enable it. It is off by default because it sends product/version
        # fingerprints to an external search service and its records lack the
        # complete provenance/range semantics of an NVD 2.0 local snapshot.
        if not state.config.get("scanner_online_cve_enrichment", False):
            return
        for product in products:
            version = product.get("version")
            if not version:
                continue
            key = f"{product['name'].lower()}|{version}"
            cached = get_cve(key)
            if cached is None:
                try:
                    cached = get_exploitdb_search(f"{product['name']} {version}")
                    put_cve(key, cached or [], product=product["name"], version=version)
                except Exception:
                    cached = []
            matched = [
                item for item in (cached or [])
                if str(item.get("id", "")).startswith("CVE-")
                and product["name"].lower() in f"{item.get('titulo', '')} {item.get('id', '')}".lower()
                and version.lower() in f"{item.get('titulo', '')} {item.get('id', '')}".lower()
            ]
            if not matched:
                continue
            cve_id = str(matched[0].get("id", ""))
            self._add(
                category="vulnerable_components",
                name=f"Componente com CVE potencialmente aplicável: {product['name']}",
                severity="INFO",
                confidence="LOW",
                url=self.target,
                evidence="Busca externa retornou advisory lexicalmente relacionado; applicability não foi validada.",
                description="Fingerprint de banner e busca textual não provam que a instância esteja vulnerável.",
                recommendation="Verifique inventário, faixa de versões, backports e condições do advisory.",
                cve=cve_id,
                exploitdb=[x for x in matched if "exploit-db.com" in str(x.get("url", ""))][:5],
                stage="POSSIBLE",
                cve_source="legacy-online-search",
            )

    def run(self) -> dict[str, Any]:
        started = time.time()
        cache_key = hashlib.sha256(
            f"{self.target}|{self.root_mode}|{','.join(sorted(self.urls))}".encode()
        ).hexdigest()
        if not self.active:
            cached = get_scan(cache_key)
            if cached:
                return cached

        self._check_headers()
        self._check_cookies()
        self._existing_checks()
        self._check_csrf()
        self._check_traversal_xxe_and_injection_candidates()
        if self.active:
            self._check_xss_and_sql()
            self._check_host_header_and_crlf()
        self._check_open_ports()
        tech = self._check_technology()
        self._cve_enrichment(tech)

        # Deduplicação por categoria/URL/parâmetro/evidência.
        unique: dict[tuple[str, str, str, str], Finding] = {}
        for f in self.findings:
            key = (f.category, f.url, f.parameter, f.evidence[:160])
            unique.setdefault(key, f)
        self.findings = list(unique.values())

        summary = self._summary()
        weights = {"CRITICO": 10, "ALTO": 7, "MEDIO": 4, "BAIXO": 1, "INFO": 0}
        weighted = sum(weights.get(k, 0) * v for k, v in summary.items())
        risk_score = round(min(10.0, weighted / max(1, len([f for f in self.findings if f.severity.upper() != "INFO"]))) if self.findings else 0.0, 1)
        result = {
            "scanner": "RavenVulnScanner",
            "mode": "root" if self.root_mode else "solo",
            "target": sanitize_url(self.target) or self.target,
            "started_at": started,
            "elapsed": time.time() - started,
            "categories": sorted(self.REQUIRED | self.EXTRA),
            "findings": [f.to_dict() for f in self.findings],
            "summary": summary,
            "risk_score": risk_score,
            "network_safety_events": sorted(self._blocked_network_events),
            "limitations": [
                "Correlações CVE usam snapshot local por padrão e permanecem POSSIBLE; banner e advisory não provam patch instalado.",
                "Request smuggling raw-socket fica fora do scan padrão; ativa-se em scanner_enable_smuggling após autorização e validação do impacto.",
                "Proxy do scanner fica desativado por padrão porque um proxy remoto resolve destinos fora do controle de DNS local; scanner_allow_proxy permite opt-in.",
                "scanner_online_cve_enrichment consulta serviço externo e fica desativado por padrão.",
                "Heurísticas de baixo confidence exigem validação manual.",
                "Não são executadas ações destrutivas nem exploração de shell.",
            ],
        }
        try:
            save_scan_with_findings(result)
        except Exception as exc:
            state.vprint(2, f"[WARN] persistência de findings: {exc}")
        if not self.active:
            put_scan(cache_key, result, ttl=int(state.config.get("scan_cache_ttl", 3600)))
        return result

    def _summary(self) -> dict[str, int]:
        summary = {"CRITICO": 0, "ALTO": 0, "MEDIO": 0, "BAIXO": 0, "INFO": 0}
        for f in self.findings:
            sev = f.severity.upper()
            summary[sev] = summary.get(sev, 0) + 1
        return summary
