from __future__ import annotations

"""Camada de rede: headers, protecao SSRF com IP pinning contra DNS
rebinding, request_url com retry/backoff, resolucao DNS e utilitarios
de URL."""


import ipaddress
import random
import re
import socket
import subprocess
import threading
from contextlib import suppress, contextmanager
from functools import lru_cache
from urllib.parse import urljoin, urlparse, urldefrag
import requests
from bs4 import BeautifulSoup
from raveneye_pkg.terminal import Fore, Style
from raveneye_pkg import state
from raveneye_pkg.state import vprint, _sleep
from raveneye_pkg.constants import USER_AGENTS, _SSRF_BLOCKED_HOSTS


# ==================================================================
# FUNÇÕES — headers e proxy
# ==================================================================
def get_random_headers() -> dict[str, str]:
    """Retorna headers HTTP realistas com User-Agent rotacionado.

    Se 'stealth_mode' estiver ativo na config, delega para get_stealth_headers()
    (headers mais variados/menos previsiveis, uteis para reduzir fingerprinting
    por WAFs baseados em padrao fixo de headers)."""
    if state.config.get("stealth_mode"):
        return get_stealth_headers()
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    }


def get_stealth_headers() -> dict[str, str]:
    """Headers com maior variacao entre requests, para reduzir a chance de
    um WAF identificar um padrao fixo de fingerprint entre requisicoes.

    Nao faz spoofing de IP/host (X-Forwarded-For/-Host) por padrao — isso
    e feito de forma isolada e opcional em check_web_cache_poisoning(),
    onde o objetivo e testar reflexao, nao evasao geral.
    """
    accept_langs = [
        "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
        "en-US,en;q=0.9",
        "en-GB,en;q=0.9,en-US;q=0.8",
        "es-ES,es;q=0.9,en;q=0.7",
    ]
    sec_fetch_sites = ["none", "same-origin", "cross-site"]
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(accept_langs),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": random.choice(sec_fetch_sites),
        "Cache-Control": random.choice(["max-age=0", "no-cache"]),
    }
    if random.random() < 0.5:
        headers["Sec-Fetch-User"] = "?1"
    if random.random() < 0.3:
        headers["DNT"] = "1"
    return headers


def get_proxies() -> dict[str, str] | None:
    """Retorna dict de proxies se configurado."""
    proxy = state.config.get("proxy", "")
    if proxy:
        return {"http": proxy, "https": proxy}
    return None


# ------------------------------------------------------------------
# Mitigacao de DNS rebinding: pino o IP ja validado para a conexao real,
# em vez de deixar o urllib3 resolver o DNS de novo no momento do connect()
# (janela onde o registro DNS poderia ter mudado desde a checagem SSRF).
# ------------------------------------------------------------------
_dns_pin_local = threading.local()


_orig_getaddrinfo = socket.getaddrinfo


def _pinned_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    pinned = getattr(_dns_pin_local, "ip", None)
    if pinned:
        if ":" in pinned:
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (pinned, port, 0, 0))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (pinned, port))]
    return _orig_getaddrinfo(host, port, family, type, proto, flags)


@contextmanager
def _pin_dns_to(ip: str | None):
    """Durante o bloco 'with', qualquer resolucao DNS feita pela thread atual
    (incluindo a interna do urllib3/requests) retorna apenas o IP ja validado
    como seguro, fechando a janela de DNS rebinding entre checagem e conexao."""
    prev = getattr(_dns_pin_local, "ip", None)
    _dns_pin_local.ip = ip
    try:
        yield
    finally:
        _dns_pin_local.ip = prev


def _resolve_safe_ip(url: str) -> tuple[str | None, bool]:
    """Resolve o host da URL e valida se o IP e seguro (nao interno/privado).

    Retorna (ip_ou_None, seguro). Se o host ja for um IP literal, retorna-o
    diretamente. Se a resolucao falhar, retorna (None, True) — deixa o erro
    de DNS acontecer naturalmente no request em vez de mascarar como SSRF.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return None, False
        if host.lower() in _SSRF_BLOCKED_HOSTS:
            return None, False
        try:
            ip_obj = ipaddress.ip_address(host)
            resolved_ip = host
        except ValueError:
            resolved = resolve_host(host)
            if not resolved:
                return None, False
            ip_obj = ipaddress.ip_address(resolved)
            resolved_ip = resolved
        safe = not (
            ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
            or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified
        )
        return (resolved_ip if safe else None), safe
    except Exception as e:
        vprint(2, f"[WARN] _resolve_safe_ip: {e}")
        return None, False  # falha fechada: erro de validacao nunca libera um destino desconhecido


def is_safe_url(url: str) -> bool:
    """Bloqueia URLs que resolvem para IPs internos/privados (protecao SSRF).

    Usado no request_url() para validar tanto a URL inicial quanto
    cada hop de redirect, evitando que uma pagina maliciosa ou um
    Location header redirecione o RavenEye para endpoints internos
    (ex: AWS/GCP metadata service, localhost, rede privada/RFC1918).
    """
    _, safe = _resolve_safe_ip(url)
    return safe


# ==================================================================
# FUNÇÕES — request e network
# ==================================================================
def request_url(url: str, timeout: int = 15, max_retries: int = 3,
                 backoff_cap: int = 30) -> tuple[str | None, str | None]:
    """GET com retry, backoff exponencial, rate limit e protecao SSRF em
    redirects — com IP pinning para mitigar DNS rebinding entre a checagem
    e a conexao real (ver _pin_dns_to).

    timeout/max_retries sao configuraveis para permitir chamadas mais rapidas
    e tolerantes a falha (ex: probing de parametros, onde um candidato lento
    ou travado nao deve segurar a fila inteira por ~50s no pior caso)."""
    ip, safe = _resolve_safe_ip(url)
    if not safe:
        vprint(1, f"[SSRF] Bloqueado: {url} aponta para IP interno/privado")
        return None, "URL bloqueada (SSRF: IP interno/privado)"

    last_err = "Unknown error"
    for attempt in range(max_retries):
        try:
            current_url = url
            current_ip = ip
            r = None
            for _hop in range(5):  # segue ate 5 redirects, validando e re-pinando cada hop
                with _pin_dns_to(current_ip):
                    r = state._SESSION.get(
                        current_url, headers=get_random_headers(), timeout=timeout,
                        allow_redirects=False, proxies=get_proxies()
                    )
                if r.status_code in (301, 302, 303, 307, 308) and "Location" in r.headers:
                    next_url = urljoin(current_url, r.headers["Location"])
                    next_ip, next_safe = _resolve_safe_ip(next_url)
                    if not next_safe:
                        vprint(1, f"[SSRF] Redirect bloqueado: {current_url} -> {next_url}")
                        return None, "Redirect bloqueado (SSRF: IP interno/privado)"
                    current_url, current_ip = next_url, next_ip
                    continue
                break

            if r.status_code == 429:
                wait = min(2 ** attempt, backoff_cap)
                vprint(1, f"[RATE LIMIT] {url} — aguardando {wait}s")
                _sleep(wait)
                continue
            if r.status_code == 200 and "text/html" in r.headers.get("Content-Type", ""):
                return r.text, None
            elif r.status_code == 200:
                return r.text, None
            else:
                last_err = f"HTTP {r.status_code}"
                break
        except requests.exceptions.Timeout:
            last_err = "Timeout"
            if attempt < max_retries - 1:
                _sleep(min(2 ** attempt, backoff_cap))
        except requests.exceptions.ConnectionError as e:
            last_err = f"ConnectionError: {str(e)[:50]}"
            if attempt < max_retries - 1:
                _sleep(min(2 ** attempt, backoff_cap))
        except Exception as e:
            last_err = str(e)[:60]
            break
    vprint(2, f"[WARN] request_url: {url} — {last_err}")
    return None, last_err


@lru_cache(maxsize=1024)
def resolve_host(domain: str) -> str | None:
    """Resolve DNS com cache para evitar lookups repetidos."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as e:
        vprint(2, f"[WARN] DNS resolve {domain}: {e}")
        return None


def normalize_url(url: str) -> str:
    """Normaliza URL para deduplicação por path."""
    try:
        parsed = urlparse(url)
        path = parsed.path.rstrip("/").lower() or "/"
        params = sorted(parsed.query.split("&")) if parsed.query else []
        query = "&".join(p for p in params if p)
        return f"{parsed.scheme}://{parsed.netloc.lower()}{path}{'?' + query if query else ''}"
    except Exception as e:
        vprint(2, f"[WARN] normalize_url: {e}")
        return url


# ==================================================================
# FUNÇÕES — extração de dados
# ==================================================================
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_URL_IN_TEXT_RE = re.compile(r"""https?://[a-zA-Z0-9\-._~%!$&'()*+,;=:@/?]+""")
_PATH_IN_JS_RE = re.compile(r"""["'](/[a-zA-Z0-9_\-./]{2,}?)["']""")
# extensoes que claramente nao sao endpoints de app (ruido de asset estatico)
_ASSET_EXT = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2",
              ".ttf", ".eot", ".ico", ".map")


def get_links_from_soup(soup: BeautifulSoup, base_url: str, target_domain: str) -> list[str]:
    """Extrai links do HTML — nao so <a href>, mas tambem forms, <link>,
    meta refresh/og:url, comentarios HTML e paths/URLs dentro de scripts
    inline. Isso e o que faz o crawler achar 'links escondidos' de verdade,
    em vez de depender so de âncoras visiveis na pagina."""
    links: set[str] = set()

    def _consider(raw: str) -> None:
        raw = raw.strip()
        if not raw:
            return
        try:
            abs_url = urljoin(base_url, raw)
            abs_url, _ = urldefrag(abs_url)
        except ValueError:
            return
        if not abs_url.startswith(("http://", "https://")):
            return
        domain = urlparse(abs_url).netloc.split(":")[0]
        if domain == target_domain or domain.endswith(f".{target_domain}"):
            links.add(abs_url)

    try:
        for a in soup.find_all("a", href=True):
            _consider(a["href"])

        for form in soup.find_all("form", action=True):
            _consider(form["action"])

        for link_tag in soup.find_all("link", href=True):
            _consider(link_tag["href"])

        for meta in soup.find_all("meta"):
            content = meta.get("content", "")
            if not content:
                continue
            http_equiv = (meta.get("http-equiv") or "").lower()
            prop = (meta.get("property") or meta.get("name") or "").lower()
            if http_equiv == "refresh" and "url=" in content.lower():
                _consider(content.split("url=", 1)[-1].strip("'\" "))
            elif prop in ("og:url", "twitter:url"):
                _consider(content)

        # Comentarios HTML — as vezes escondem links de debug/paginas antigas
        for comment_text in _HTML_COMMENT_RE.findall(str(soup)):
            for m in _URL_IN_TEXT_RE.findall(comment_text):
                _consider(m)
            for m in re.findall(r'href=["\']([^"\']+)["\']', comment_text):
                _consider(m)

        # Scripts inline (sem src): paths/URLs referenciados no codigo JS da propria pagina
        for script in soup.find_all("script", src=False):
            text = script.string or ""
            if not text:
                continue
            for m in _URL_IN_TEXT_RE.findall(text):
                _consider(m)
            for m in _PATH_IN_JS_RE.findall(text):
                if not m.lower().endswith(_ASSET_EXT):
                    _consider(m)
    except Exception as e:
        vprint(2, f"[WARN] get_links_from_soup: {e}")
    return list(links)


def extract_links_from_js_content(js_text: str, base_url: str, target_domain: str) -> list[str]:
    """Minera paths/endpoints de dentro do CONTEUDO de um arquivo JS ja
    baixado (nao so a URL do arquivo). Bundles de JS frequentemente contem
    a lista completa de rotas/endpoints de uma API ou SPA, referenciada como
    strings literais no codigo — uma das fontes mais ricas de 'links
    escondidos' que uma pagina nao mostra diretamente."""
    links: set[str] = set()
    if not js_text:
        return []
    try:
        for m in _URL_IN_TEXT_RE.findall(js_text):
            try:
                abs_url, _ = urldefrag(m)
            except ValueError:
                continue
            domain = urlparse(abs_url).netloc.split(":")[0]
            if domain == target_domain or domain.endswith(f".{target_domain}"):
                links.add(abs_url)
        for m in _PATH_IN_JS_RE.findall(js_text):
            if m.lower().endswith(_ASSET_EXT):
                continue
            try:
                abs_url = urljoin(base_url, m)
            except ValueError:
                continue
            domain = urlparse(abs_url).netloc.split(":")[0]
            if domain == target_domain or domain.endswith(f".{target_domain}"):
                links.add(abs_url)
    except Exception as e:
        vprint(2, f"[WARN] extract_links_from_js_content: {e}")
    return list(links)[:300]  # limite de seguranca — bundles grandes podem ter milhares de strings


def get_js_urls_from_soup(soup: BeautifulSoup, base_url: str) -> list[str]:
    """Extrai URLs de scripts JavaScript do BeautifulSoup."""
    js_urls: list[str] = []
    try:
        for tag in soup.find_all("script", src=True):
            src = tag["src"].strip()
            abs_url = urljoin(base_url, src)
            if abs_url.startswith(("http://", "https://")) and abs_url.endswith((".js", ".mjs")):
                js_urls.append(abs_url)
    except Exception as e:
        vprint(2, f"[WARN] get_js_urls_from_soup: {e}")
    return js_urls


def extract_endpoints(url: str) -> str | None:
    """Extrai o caminho (endpoint) de uma URL."""
    try:
        path = urlparse(url).path
        if not path or path == "/":
            return None
        return path.rstrip("/")
    except Exception as e:
        vprint(2, f"[WARN] extract_endpoints: {e}")
        return None


def extract_parameters(urls: list[str]) -> dict[str, list[str]]:
    """Extrai e agrupa parâmetros de query string de todas as URLs."""
    params: dict[str, list[str]] = {}
    for url in urls:
        try:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            for pair in parsed.query.split("&"):
                if "=" in pair:
                    key = pair.split("=", 1)[0].strip()
                    if key:
                        params.setdefault(key, [])
                        if url not in params[key]:
                            params[key].append(url)
        except Exception as e:
            vprint(2, f"[WARN] extract_parameters: {e}")
    return dict(sorted(params.items(), key=lambda x: len(x[1]), reverse=True))


def classify_link(url: str) -> str:
    """Classifica uma URL por categoria de interesse."""
    u = url.lower()
    if any(p in u for p in ("/admin", "/administrator", "/login", "/signin", "/dashboard", "/cpanel", "/wp-admin")):
        return "[Admin/Login]"
    if any(p in u for p in ("/api", "/swagger", "/v1", "/v2", "/v3", "/graphql", "/api-docs")):
        return "[API]"
    if "?" in u and "=" in u:
        return "[Parametros]"
    if any(p in u for p in ("/backup", "/dump", "/sql", "/database", "/config", "/settings", "/.env", "/.git")):
        return "[Config/Backup]"
    if any(p in u for p in ("/debug", "/test", "/dev", "/stage", "/staging", "/beta")):
        return "[Teste/Dev]"
    if u.endswith((".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".rar", ".sql", ".bak", ".log")):
        return "[Arquivo]"
    return "[Comum]"


# ==================================================================
# FUNÇÕES — ping e WHOIS
# ==================================================================
def _is_valid_host(host: str) -> bool:
    """Valida que host/IP eh seguro para passar a subprocess (ping, nmap).

    Bloqueia strings que comecem com '-' (flag injection). Valida IPs de
    verdade via ipaddress (IPv4/IPv6, com ou sem colchetes); para hostnames,
    exige labels RFC-1123 validos (alfanumerico + hifen, sem iniciar/terminar
    com hifen) em vez de uma regex frouxa que aceitava quase qualquer coisa
    no formato geral de host/IP.
    """
    if not host or host.startswith("-"):
        return False
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        pass
    if len(host) > 253 or host.startswith(".") or host.endswith(".") or ".." in host:
        return False
    label_re = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
    return all(label_re.match(label) for label in host.split("."))


def ping_host(url: str) -> str:
    """Executa ping no host da URL."""
    host = urlparse(url).netloc or urlparse(url).path
    host = host.split(":")[0]
    if not _is_valid_host(host):
        return "ERRO: host invalido"
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            result = subprocess.run(
                ["ping", "-c", "1", host],
                capture_output=True, text=True, timeout=5
            )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "time=" in line:
                    time_ms = line.split("time=")[1].split()[0]
                    return f"OK {time_ms} ms"
            return "OK"
        return f"FALHOU: {result.stderr.strip()[:40]}"
    except Exception as e:
        return f"ERRO: {str(e)[:30]}"



socket.getaddrinfo = _pinned_getaddrinfo

