from __future__ import annotations

"""Scanner defensivo modular da RavenEye 6.6.6.

As verificações ativas são não destrutivas e limitadas por escopo, timeout,
concorrência e rate limit. A existência de um indício nunca é tratada como
prova de exploração bem-sucedida.
"""

import concurrent.futures
import hashlib
import re
import socket
import ssl
import time
from dataclasses import dataclass, asdict
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from bs4 import BeautifulSoup

from raveneye_pkg import state
from raveneye_pkg.database import get_cve, get_scan, put_cve, put_scan, save_scan_with_findings
from raveneye_pkg.network import get_proxies, get_random_headers, is_safe_url, request_url
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

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["exploitdb"] = data["exploitdb"] or []
        data["timestamp"] = self.timestamp or time.time()
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
        r"(sql syntax|mysql_fetch|mysqli_|pdoexception|postgresql|pg::syntax|"
        r"ora-\d{4,5}|sqlite error|unclosed quotation mark|odbc sql)",
        re.I,
    )
    CMD_ERRORS = re.compile(
        r"(sh: .*not found|bash: .*command|cmd\.exe|powershell|"
        r"cannot execute|syntax error near unexpected token)",
        re.I,
    )
    SHELLISH_PARAMS = {"cmd", "command", "exec", "execute", "query", "shell", "ping"}
    SSRF_PARAMS = {"url", "uri", "dest", "destination", "redirect", "next", "target", "callback", "webhook"}
    TEMPLATE_PARAMS = {"template", "view", "name", "content", "message", "subject"}
    LDAP_PARAMS = {"username", "user", "uid", "cn", "dn", "filter", "search"}
    NOSQL_PARAMS = {"query", "filter", "where", "search", "username", "id"}

    def __init__(
        self,
        target: str,
        root_mode: bool = False,
        urls: list[str] | None = None,
        max_workers: int | None = None,
        rate_limit: float | None = None,
        active: bool = True,
        timeout: int = 8,
    ) -> None:
        self.target = target
        self.root_mode = bool(root_mode)
        self.urls = list(dict.fromkeys(urls or [target]))
        self.max_workers = max(1, min(20, int(max_workers or state.config.get("scanner_max_workers", 6))))
        self.rate = _RateLimiter(rate_limit or state.config.get("scanner_rate_limit", 8.0))
        self.active = active
        self.timeout = max(2, int(timeout))
        self.findings: list[Finding] = []
        self._cancel = False

        parsed = urlparse(target)
        self.domain = parsed.hostname or ""
        self.scope_netloc = parsed.netloc.lower()

    def cancel(self) -> None:
        self._cancel = True

    def _in_scope(self, url: str) -> bool:
        try:
            p = urlparse(url)
            if p.scheme not in {"http", "https"} or not p.hostname:
                return False
            return p.netloc.lower() == self.scope_netloc
        except Exception:
            return False

    def _request(self, url: str, **kwargs: Any):
        if self._cancel or not self._in_scope(url) or not is_safe_url(url):
            return None
        self.rate.wait()
        try:
            return state._SESSION.get(
                url,
                timeout=kwargs.pop("timeout", self.timeout),
                allow_redirects=kwargs.pop("allow_redirects", True),
                headers=kwargs.pop("headers", get_random_headers()),
                proxies=get_proxies(),
                **kwargs,
            )
        except Exception as exc:
            state.vprint(2, f"[WARN] scanner request {url}: {exc}")
            return None

    def _add(self, **kwargs: Any) -> None:
        kwargs.setdefault("target", self.target)
        kwargs.setdefault("timestamp", time.time())
        self.findings.append(Finding(**kwargs))

    @staticmethod
    def _baseline_signature(response) -> dict[str, Any]:
        body = response.text if response is not None else ""
        return {
            "status": response.status_code if response is not None else 0,
            "length": len(body),
            "hash": hashlib.sha256(body[:200000].encode("utf-8", "ignore")).hexdigest(),
            "url": response.url if response is not None else "",
            "content_type": response.headers.get("Content-Type", "") if response is not None else "",
        }

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
        for item in check_security_headers(self.target):
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
            secure = bool(getattr(cookie, "secure", False))
            httponly = any(str(k).lower() == "httponly" for k in rest)
            samesite = next((v for k, v in rest.items() if str(k).lower() == "samesite"), None)
            if not secure and urlparse(self.target).scheme == "https":
                self._add(
                    category="cookie_security", name=f"Cookie sem Secure: {cookie.name}",
                    severity="MEDIO", confidence="HIGH", url=self.target,
                    evidence=f"Set-Cookie {cookie.name} não possui Secure.",
                    description="Cookie de sessão em HTTPS pode ser enviado em canal não protegido.",
                    recommendation="Use Secure para cookies sensíveis.",
                )
            if not httponly:
                self._add(
                    category="cookie_security", name=f"Cookie sem HttpOnly: {cookie.name}",
                    severity="BAIXO", confidence="HIGH", url=self.target,
                    evidence=f"Set-Cookie {cookie.name} não possui HttpOnly.",
                    description="JavaScript do navegador pode acessar o cookie.",
                    recommendation="Use HttpOnly para cookies que não precisam ser lidos pelo JavaScript.",
                )
            if samesite is None:
                self._add(
                    category="cookie_security", name=f"Cookie sem SameSite: {cookie.name}",
                    severity="BAIXO", confidence="MEDIUM", url=self.target,
                    evidence=f"Set-Cookie {cookie.name} não declara SameSite.",
                    recommendation="Defina SameSite conforme o fluxo legítimo da aplicação.",
                )

    def _check_xss_and_sql(self) -> None:
        for url, param in self._urls_with_params()[:80]:
            if self._cancel:
                return
            baseline = self._request(url)
            if not baseline:
                continue
            base = self._baseline_signature(baseline)

            marker = f"RAVENEYE_{hashlib.sha1(f'{url}|{param}'.encode()).hexdigest()[:10]}"
            probe = self._request(self._replace_query(url, param, marker))
            if probe:
                body = probe.text[:200000]
                if marker in body:
                    self._add(
                        category="xss", name="Reflexão de parâmetro detectada",
                        severity="MEDIO", confidence="MEDIUM", url=url, parameter=param,
                        evidence=f"Marcador único {marker} retornou no corpo da resposta.",
                        description="O valor controlado pelo parâmetro foi refletido; isso é evidência de reflexão, não prova isolada de XSS executável.",
                        impact="Reflexões não escapadas podem permitir XSS dependendo do contexto de saída.",
                        recommendation="Aplicar escaping contextual e validação de entrada.",
                        cwe="CWE-79",
                    )

            sql_probe = self._request(self._replace_query(url, param, "'"))
            if sql_probe:
                changed = (
                    sql_probe.status_code != base["status"]
                    or abs(len(sql_probe.text) - base["length"]) > max(100, int(base["length"] * 0.20))
                )
                if changed and self.SQL_ERRORS.search(sql_probe.text[:200000]):
                    self._add(
                        category="sql_injection", name="Indício forte de erro SQL controlável",
                        severity="ALTO", confidence="HIGH", url=url, parameter=param,
                        evidence=self.SQL_ERRORS.search(sql_probe.text[:200000]).group(0)[:120],
                        description="Uma alteração sintática simples produziu erro de banco acompanhado de mudança de resposta.",
                        impact="Pode permitir manipulação de consultas se a entrada não estiver parametrizada.",
                        recommendation="Use consultas parametrizadas/prepared statements e valide a entrada.",
                        cwe="CWE-89",
                    )

            if param.lower() in self.SHELLISH_PARAMS:
                shell_probe = self._request(self._replace_query(url, param, "\""))
                if shell_probe and self.CMD_ERRORS.search(shell_probe.text[:200000]):
                    self._add(
                        category="command_injection", name="Indício de interpretação por shell",
                        severity="CRITICO", confidence="MEDIUM", url=url, parameter=param,
                        evidence=self.CMD_ERRORS.search(shell_probe.text[:200000]).group(0)[:120],
                        description="A entrada controlada coincidiu com uma mensagem típica de shell.",
                        impact="Pode permitir execução de comandos no servidor se confirmado.",
                        recommendation="Não concatene entrada em comandos; use APIs sem shell e allowlists.",
                        cwe="CWE-78",
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
                inputs = [str(x.get("name", "")).lower() for x in form.find_all("input")]
                has_token = any(
                    ("csrf" in x or "xsrf" in x or "authenticity" in x or "nonce" in x)
                    for x in inputs
                )
                if not has_token:
                    self._add(
                        category="csrf", name="Form POST sem token CSRF aparente",
                        severity="MEDIO", confidence="MEDIUM", url=url,
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
        p = urlparse(self.target)
        canary = "raveneye-invalid.example"
        try:
            self.rate.wait()
            r = state._SESSION.get(
                self.target, headers={**get_random_headers(), "Host": canary},
                timeout=self.timeout, allow_redirects=False, proxies=get_proxies(),
            )
            if r and (canary in r.text[:100000] or canary in r.headers.get("Location", "")):
                self._add(
                    category="host_header_injection", name="Host controlado refletido",
                    severity="ALTO", confidence="HIGH", url=self.target,
                    evidence=f"Host canário '{canary}' apareceu na resposta.",
                    recommendation="Valide o Host contra uma allowlist no proxy/aplicação.",
                    cwe="CWE-644",
                )
        except Exception:
            pass

    def _check_open_ports(self) -> None:
        ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 5432, 6379, 8080, 8443, 9200]
        host = self.domain
        if not host:
            return
        open_ports: list[int] = []
        for port in ports:
            if self._cancel:
                return
            try:
                ip = socket.gethostbyname(host)
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
        tech = get_tech(self.target)
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
            for item in check_cors(self.urls, limit=min(30, len(self.urls))):
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
            for item in check_open_redirect(self.urls):
                self._add(
                    category="open_redirect", name="Open Redirect",
                    severity=str(item.get("severity", "MEDIO")).upper(),
                    confidence="HIGH", url=item.get("url", ""), parameter=item.get("param", ""),
                    evidence=f"Location={item.get('location', '')}",
                    recommendation="Permita somente destinos internos/allowlisted.",
                    cwe="CWE-601",
                )
        except Exception as exc:
            state.vprint(2, f"[WARN] scanner redirect: {exc}")

        try:
            for url in check_directory_listing(self.urls[:50]):
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
            for item in check_error_disclosure(self.urls[:30]):
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
            for item in check_jwt_weaknesses(self.target):
                self._add(
                    category="jwt", name=item.get("tipo", "Fraqueza JWT"),
                    severity=str(item.get("severity", "MEDIO")).upper(),
                    confidence="MEDIUM", url=self.target,
                    evidence=item.get("desc", str(item)),
                    recommendation="Use algoritmos/segredos fortes e valide claims corretamente.",
                )
        except Exception as exc:
            state.vprint(2, f"[WARN] scanner JWT: {exc}")

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
        """Correlaciona CVEs somente quando produto/versão aparecem de forma coerente."""
        products: list[tuple[str, str]] = []
        server = str(tech.get("servidor", "") or "")
        m = re.search(r"([A-Za-z][A-Za-z0-9._-]{1,40})[/ ](v?\d+(?:\.\d+){1,3})", server)
        if m:
            products.append((m.group(1), m.group(2)))
        for product in [tech.get("cms"), *tech.get("frameworks", [])]:
            if product:
                products.append((str(product), ""))

        for product, version in products:
            # Correlação CVE exige produto + versão observável. Sem versão, não
            # transformamos um resultado de busca genérico em finding de CVE.
            if not version:
                continue
            key = f"{product.lower()}|{version}"
            cached = get_cve(key)
            if cached is None:
                try:
                    query = f"{product} {version}".strip()
                    cached = get_exploitdb_search(query)
                    put_cve(key, cached or [], product=product, version=version or None)
                except Exception:
                    cached = []
            if not cached:
                continue

            matched = []
            for item in cached:
                cve = str(item.get("id", ""))
                title = str(item.get("titulo", ""))
                haystack = f"{title} {cve}".lower()
                product_ok = product.lower() in haystack
                version_ok = (not version) or (version.lower().lstrip("v") in haystack)
                if cve.startswith("CVE-") and product_ok and version_ok:
                    matched.append(item)
            if not matched:
                continue

            # Criamos um finding de "componente potencialmente afetado", nunca
            # um finding confirmado. Backports e configurações podem invalidar
            # a correlação e por isso confidence permanece MEDIUM.
            cve_id = str(matched[0].get("id", ""))
            self._add(
                category="vulnerable_components",
                name=f"Componente com CVE potencialmente aplicável: {product}",
                severity="MEDIO",
                confidence="MEDIUM",
                url=self.target,
                evidence=f"Fingerprint detectado: {server or product} {version}".strip(),
                description="A versão/fingerprint observada coincide com uma referência CVE; isso não prova que a instância esteja vulnerável.",
                impact="Pode haver exposição caso a versão afetada não tenha sido corrigida por atualização/backport.",
                recommendation="Confirme a versão instalada, patches/backports e condições de exploração antes de classificar como vulnerável.",
                cve=cve_id,
                exploitdb=[x for x in matched if "exploit-db.com" in str(x.get("url", ""))][:5],
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
            "target": self.target,
            "started_at": started,
            "elapsed": time.time() - started,
            "categories": sorted(self.REQUIRED | self.EXTRA),
            "findings": [f.to_dict() for f in self.findings],
            "summary": summary,
            "risk_score": risk_score,
            "limitations": [
                "CVE/ExploitDB são enriquecimento; CVE não prova que o alvo é vulnerável.",
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
