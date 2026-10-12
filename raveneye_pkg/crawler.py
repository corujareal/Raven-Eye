from __future__ import annotations

"""RavenCrawler: crawler multi-threaded com Playwright instalado no runtime,
orquestra todos os scanners para produzir o relatorio final de um alvo."""


import concurrent.futures
import fnmatch
import hashlib
import random
import re
import threading
import time
from collections import deque
from pathlib import Path
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from raveneye_pkg.terminal import Fore, Style
from raveneye_pkg import state
from raveneye_pkg.state import vprint, _sleep
from raveneye_pkg.network import (
    request_url, resolve_host, normalize_url, get_links_from_soup,
    get_js_urls_from_soup, extract_endpoints, extract_parameters,
    classify_link, ping_host, get_random_headers, get_proxies,
    extract_links_from_js_content,
)
from raveneye_pkg.constants import COMMON_PARAM_NAMES
from raveneye.network.domains import host_matches_rule
from raveneye.core.browser import launch_chromium_sync
from raveneye.network.browser_proxy import SafeSocksProxy
from raveneye.crawler.js_analysis import analyze_javascript, analyze_source_map
from raveneye_pkg.scanners import (
    get_tech, check_security_headers, check_ssl_cert, check_outdated_versions,
    get_subdomains_crtsh, check_subdomain_takeover, get_whois, get_archive_snapshot,
    get_shodan_info, get_exploitdb_search, get_nmap, check_email_security,
    check_zone_transfer, vulnerability_scan, check_cors, check_open_redirect,
    check_directory_listing, check_error_disclosure, probe_http_methods,
    google_dork_search, run_google_dorks_search, run_searxng_dorks_search,
    scan_js_for_secrets,
    check_web_cache_poisoning, check_http_request_smuggling, check_jwt_weaknesses,
    check_virustotal, path_guessing, fetch_robots_and_sitemap, get_wayback_urls,
    find_real_ip,
)



from raveneye_pkg.state import DNSPYTHON_AVAILABLE, PLAYWRIGHT_AVAILABLE
if PLAYWRIGHT_AVAILABLE:
    from playwright.sync_api import sync_playwright


# ==================================================================
# CLASSE — RavenCrawler
# ==================================================================
class RavenCrawler:
    """Crawler multithread com renderização Playwright configurável para SPAs."""

    def __init__(
        self, start_url: str, max_pages: int, max_depth: int, delay: float,
        use_payload: bool = False, use_google: bool = False, use_wayback: bool = False,
        include_shodan: bool = False, include_whois: bool = False,
        include_archive: bool = False, include_exploitdb: bool = False,
        include_nmap: bool = False, include_bruteforce: bool = False,
        include_cache_poisoning: bool = False, include_smuggling: bool = False,
        include_jwt: bool = False, include_virustotal: bool = False,
        include_vuln_scanner: bool = False,
        scanner_authorized: bool = False,
        shodan_key: str | None = None, bf_attempts: int = 500,
        root_mode: bool = False, large_bf: bool = False,
        scope_domains: list[str] | None = None,
        scope_excludes: set[str] | list[str] | None = None,
    ) -> None:
        if include_vuln_scanner and not scanner_authorized:
            raise PermissionError("RavenVulnScanner exige autorização explícita antes de iniciar.")
        self.start_url = start_url
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.delay = delay
        self.use_payload = use_payload
        self.use_google = use_google
        self.use_wayback = use_wayback
        self.include_shodan = include_shodan
        self.include_whois = include_whois
        self.include_archive = include_archive
        self.include_exploitdb = include_exploitdb
        self.include_nmap = include_nmap
        self.include_bruteforce = include_bruteforce
        self.include_cache_poisoning = include_cache_poisoning
        self.include_smuggling = include_smuggling
        self.include_jwt = include_jwt
        self.include_virustotal = include_virustotal
        self.include_vuln_scanner = include_vuln_scanner
        self.shodan_key = shodan_key
        self.bf_attempts = bf_attempts
        self.root_mode = root_mode
        self.large_bf = large_bf
        parsed = urlparse(start_url)
        self.target_domain = parsed.hostname or ""
        self._explicit_scope = bool(scope_domains)
        self.scope_domains = list(scope_domains or [])
        self.scope_exact_hosts = set() if self._explicit_scope else ({self.target_domain} if self.target_domain else set())
        self.scope_excludes = set(scope_excludes or ())
        self.max_workers = min(state.config.get("max_workers", 5), 20)
        self.use_js_render = state.config.get("use_js_render", False) and PLAYWRIGHT_AVAILABLE

        self._lock = threading.Lock()
        self.cancel_event = threading.Event()
        self.started_at = 0.0
        self.request_count = 0
        self.error_count = 0
        self.to_crawl: deque = deque()
        self.to_crawl_set: set[str] = set()
        self.crawled: set[str] = set()
        self.visited: list[dict] = []
        self.endpoints: set[str] = set()
        self.all_urls: set[str] = set()
        self.file_urls: list[str] = []
        self.js_urls: list[str] = []
        self._js_url_set: set[str] = set()
        self.js_route_templates: list[str] = []
        self._js_route_template_set: set[str] = set()
        self.fetched_js: set[str] = set()

        # Deteccao de baseline/soft-404: evita contar "o site manda tudo pra
        # home" como se fossem paginas/achados reais distintos
        self.baseline_404: dict | None = None
        self.content_hashes: dict[str, str] = {}  # hash -> primeira URL que teve esse conteudo
        self.duplicate_urls: list[dict] = []       # URLs cujo conteudo bate com outra ja vista
        self.soft_fail_filtered: int = 0            # candidatos descartados por baterem no baseline
        self.interesting_params: list[dict] = []    # parametros que realmente mudam a resposta

    def cancel(self) -> None:
        """Solicita cancelamento cooperativo do crawl."""
        self.cancel_event.set()

    def _is_in_scope(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ""
            _ = parsed.port
        except (TypeError, ValueError):
            return False
        if (parsed.scheme.lower() not in {"http", "https"} or not domain
                or parsed.username is not None or parsed.password is not None):
            return False
        path = parsed.path or "/"
        if domain not in self.scope_exact_hosts and not any(host_matches_rule(domain, rule) for rule in self.scope_domains):
            return False
        return not any(
            fnmatch.fnmatch(domain.lower().rstrip("."), pattern.lower())
            or fnmatch.fnmatch(url, pattern)
            or (pattern.startswith("/") and fnmatch.fnmatch(path, pattern))
            or (not pattern.startswith(("/", "http://", "https://")) and pattern in path)
            for pattern in self.scope_excludes
        )

    def _record_js_route_templates(self, candidates) -> None:
        """Retain bounded, in-scope route templates without scheduling them."""
        with self._lock:
            for candidate in candidates:
                value = str(candidate or "")
                if (len(self.js_route_templates) >= 5000
                        or value in self._js_route_template_set
                        or not self._is_in_scope(value)):
                    continue
                self._js_route_template_set.add(value)
                self.js_route_templates.append(value)

    def _add_to_queue(self, url: str, depth: int, guessed: bool = False) -> None:
        norm = normalize_url(url)
        with self._lock:
            if norm not in self.crawled and norm not in self.to_crawl_set:
                if self._is_in_scope(url):
                    self.to_crawl.append((url, depth, guessed))
                    self.to_crawl_set.add(norm)
                else:
                    vprint(1, f"  [SCOPE] Bloqueado: {url}")

    def _add_priority(self, urls: list[str], source: str, guessed: bool = True) -> None:
        """Adiciona URLs com prioridade (na frente da fila). 'guessed=True' marca
        a URL como advinhada (path guessing, wayback) — sera filtrada contra o
        baseline de soft-404 antes de contar como achado real. 'guessed=False'
        e para fontes que o proprio site declarou (sitemap.xml, robots.txt),
        que sao mais confiaveis que um chute puro."""
        count = 0
        for u in urls:
            norm = normalize_url(u)
            with self._lock:
                if norm not in self.crawled and norm not in self.to_crawl_set and self._is_in_scope(u):
                    self.to_crawl.appendleft((u, 0, guessed))
                    self.to_crawl_set.add(norm)
                    count += 1
        vprint(1, f"  + {count} URLs de {source}")

    def _establish_baseline(self) -> None:
        """Pede um path aleatorio que quase certamente nao existe, e guarda o
        tamanho/hash da resposta. Usado para filtrar 'soft-404' — paginas que
        retornam HTTP 200 mas na verdade so mandam de volta a home/erro
        generico, que sem isso seriam contadas como paginas/achados reais."""
        token = f"raveneye-nonexistent-{random.randint(10**9, 10**10 - 1)}"
        probe_url = f"{self.start_url.rstrip('/')}/{token}"
        if not self._is_in_scope(probe_url):
            self.baseline_404 = None
            vprint(1, "  [SCOPE] Baseline ignorado: alvo fora do escopo")
            return
        html, err = request_url(
            probe_url, timeout=10, max_retries=2,
            allowed_domains=set(self.scope_domains),
            exclude_patterns=self.scope_excludes,
            exact_hosts=self.scope_exact_hosts,
        )
        if html:
            self.baseline_404 = {
                "length": len(html),
                "hash": hashlib.sha256(html.encode("utf-8", errors="ignore")).hexdigest(),
            }
            vprint(1, f"  [*] Baseline soft-404 estabelecido ({self.baseline_404['length']} bytes)")
        else:
            self.baseline_404 = None

    def _is_soft_fail(self, html: str) -> bool:
        """Compara uma resposta contra o baseline de soft-404. Match exato de
        hash, ou tamanho muito proximo (±3%), indica que o servidor devolveu
        a mesma pagina de sempre (home/erro generico) em vez de conteudo real."""
        if not self.baseline_404 or not html:
            return False
        content_hash = hashlib.sha256(html.encode("utf-8", errors="ignore")).hexdigest()
        if content_hash == self.baseline_404["hash"]:
            return True
        base_len = self.baseline_404["length"]
        if base_len > 0 and abs(len(html) - base_len) / base_len <= 0.03:
            return True
        return False

    def _probe_parameters(self) -> None:
        """Testa nomes de parametro comuns (COMMON_PARAM_NAMES) contra o alvo
        EM PARALELO (threads), comparando a resposta com o baseline. So
        registra como 'parametro interessante' quando a resposta realmente
        muda (marcador refletido no corpo, tamanho/status diferente do
        baseline) — em vez de jogar centenas de URLs ?param=PAYLOAD na fila
        de crawl (que antes usava a wordlist de SENHAS como se fossem nomes
        de parametro, gerando so ruido).

        Usa timeout curto e poucas tentativas por candidato (nao e um
        recurso critico — se um candidato falhar, so seguimos para o
        proximo) para nao travar o scan inteiro num alvo lento/instavel.
        """
        if not self.baseline_404:
            self._establish_baseline()
        if not self._is_in_scope(self.start_url):
            vprint(1, "  [SCOPE] Probe de parâmetros ignorado: alvo fora do escopo")
            return
        marker = f"rvn{random.randint(100000, 999999)}"
        # limite proprio, independente do bf_attempts (que e do bruteforce de
        # login) — testar todos os ~147 nomes raramente vale o tempo extra
        limit = min(state.config.get("param_probe_limit", 80), len(COMMON_PARAM_NAMES))
        params_to_test = COMMON_PARAM_NAMES[:limit]
        tested = 0
        found = 0
        vprint(1, f"  [*] Testando {limit} nomes de parametro contra {self.start_url} (paralelo)...")

        def _probe_one(param: str) -> dict | None:
            test_url = f"{self.start_url}?{param}={marker}"
            if not self._is_in_scope(test_url):
                return None
            html, err = request_url(
                test_url, timeout=8, max_retries=1,
                allowed_domains=set(self.scope_domains),
                exclude_patterns=self.scope_excludes,
                exact_hosts=self.scope_exact_hosts,
            )
            if not html:
                return None
            reflected = marker in html
            soft = self._is_soft_fail(html)
            if reflected or not soft:
                if reflected or (self.baseline_404 and abs(
                        len(html) - self.baseline_404["length"]
                ) / max(self.baseline_404["length"], 1) > 0.03):
                    return {"param": param, "url": test_url, "refletido": reflected}
            return None

        probe_workers = min(self.max_workers * 2, 20)
        with concurrent.futures.ThreadPoolExecutor(max_workers=probe_workers) as executor:
            futures = {executor.submit(_probe_one, p): p for p in params_to_test}
            for fut in concurrent.futures.as_completed(futures):
                tested += 1
                if not state.QUIET_MODE:
                    print(f"\r  [*] Probing de parametros: {tested}/{limit} testados, "
                          f"{found} interessantes", end="", flush=True)
                try:
                    result = fut.result()
                except Exception as e:
                    vprint(2, f"[WARN] _probe_parameters {futures[fut]}: {e}")
                    continue
                if result:
                    with self._lock:
                        self.interesting_params.append(result)
                        self.all_urls.add(result["url"])
                    found += 1
        if not state.QUIET_MODE:
            print()
        vprint(1, f"  [*] Probing de parametros concluido: {found}/{tested} interessantes")

    def _is_file_url(self, url: str) -> bool:
        exts = (
            ".pdf", ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".exe", ".msi",
            ".iso", ".img", ".sql", ".db", ".bak", ".old", ".log", ".csv",
        )
        return urlparse(url).path.lower().endswith(exts)

    def _is_spa(self, html: str) -> bool:
        indicators = [
            '<div id="root">', '<app-root>', 'ng-version',
            'data-reactroot', '__NEXT_DATA__', 'data-v-'
        ]
        return any(ind in html for ind in indicators)

    def _fetch_with_playwright(self, url: str) -> str | None:
        if not PLAYWRIGHT_AVAILABLE:
            return None
        if state.config.get("proxy"):
            vprint(1, "[JS] Render Playwright indisponível com proxy externo configurado; egress não pode ser validado com segurança")
            return None
        proxy = SafeSocksProxy(set(self.scope_domains), exact_hosts=self.scope_exact_hosts).start()
        browser = None
        try:
            with sync_playwright() as p:
                browser = launch_chromium_sync(
                    p.chromium,
                    headless=True,
                    proxy={"server": proxy.url, "bypass": ""},
                    chromium_sandbox=True,
                    args=[
                        "--proxy-bypass-list=<-loopback>",
                        "--disable-background-networking", "--disable-component-update",
                        "--disable-sync", "--no-first-run",
                    ],
                )
                context = browser.new_context()
                page = context.new_page()

                def scope_route(route) -> None:
                    if not proxy.allows_url(route.request.url):
                        route.abort()
                        return
                    route.continue_()

                page.route("**/*", scope_route)
                page.goto(url, timeout=20000)
                page.wait_for_timeout(2000)
                return page.content()
        except Exception as e:
            vprint(2, f"[WARN] _fetch_with_playwright bloqueado/indisponível ({type(e).__name__})")
            return None
        finally:
            if browser is not None:
                try:
                    browser.close()
                except Exception:
                    pass
            proxy.close()

    @staticmethod
    def _looks_like_xml(url: str, content: str) -> bool:
        """Detect XML documents before invoking BeautifulSoup."""
        path = urlparse(url).path.lower()
        if path.endswith((".xml", ".rss", ".atom")):
            return True
        sample = (content or "")[:2000].lstrip("\ufeff \t\r\n")
        if sample.startswith("<?xml"):
            return True
        return bool(re.match(r"<(?:(?:urlset|sitemapindex|rss|feed)\b)", sample, re.I))

    def _crawl_single(self, url: str, depth: int, guessed: bool = False) -> None:
        if self.cancel_event.is_set():
            return
        norm = normalize_url(url)
        with self._lock:
            if norm in self.crawled or depth > self.max_depth:
                return
            self.crawled.add(norm)

        if self._is_file_url(url):
            with self._lock:
                self.file_urls.append(url)
            vprint(1, f"  [ARQUIVO] {url}")
            return

        with self._lock:
            self.request_count += 1
        html, err = request_url(
            url, allowed_domains=set(self.scope_domains), exclude_patterns=self.scope_excludes,
            exact_hosts=self.scope_exact_hosts,
        )
        if not html:
            with self._lock:
                self.error_count += 1

        if html and self.use_js_render and self._is_spa(html):
            vprint(1, f"  [SPA detectada] Usando Playwright para {url}")
            rendered = self._fetch_with_playwright(url)
            if rendered:
                html = rendered

        if not html:
            vprint(1, f"  [ERRO] {url}: {err}")
            _sleep(self.delay + random.uniform(0, self.delay * 0.5))
            return

        parsed_resource = urlparse(url)
        with self._lock:
            is_js_resource = norm in self._js_url_set
        if parsed_resource.path.lower().endswith(".map"):
            mapped = analyze_source_map(url, html)
            discovered = set(mapped["urls"] + mapped["scripts"])
            self._record_js_route_templates(mapped["route_templates"])
            module_urls = [item for item in mapped["scripts"] if self._is_in_scope(item)]
            with self._lock:
                for module_url in module_urls:
                    module_key = normalize_url(module_url)
                    if module_key not in self._js_url_set:
                        self._js_url_set.add(module_key)
                        self.js_urls.append(module_url)
                self.visited.append({
                    "url": url, "title": "JavaScript source map", "depth": depth,
                    "class": "static_asset", "duplicado": False,
                    "source_map_sources_analyzed": mapped["sources_analyzed"],
                })
                self.all_urls.add(url)
            for candidate in discovered:
                self._add_to_queue(candidate, depth + 1, guessed=False)
            vprint(1, f"  [SOURCE MAP] {len(mapped['urls'])} endpoints, {len(module_urls)} módulos em {url[:60]}")
            _sleep(self.delay + random.uniform(0, self.delay * 0.5))
            return

        if parsed_resource.path.lower().endswith((".js", ".mjs")) or is_js_resource:
            analysis = analyze_javascript(url, html)
            discovered = set(analysis["urls"] + analysis["scripts"] + analysis["source_maps"])
            discovered.update(extract_links_from_js_content(html, url, self.target_domain))
            self._record_js_route_templates(analysis["route_templates"])
            module_urls = [item for item in analysis["scripts"] if self._is_in_scope(item)]
            with self._lock:
                for module_url in module_urls:
                    module_key = normalize_url(module_url)
                    if module_key not in self._js_url_set:
                        self._js_url_set.add(module_key)
                        self.js_urls.append(module_url)
                self.visited.append({
                    "url": url, "title": "JavaScript resource", "depth": depth,
                    "class": "static_asset", "duplicado": False,
                })
                self.all_urls.add(url)
                endpoint = extract_endpoints(url)
                if endpoint:
                    self.endpoints.add(endpoint)
            for candidate in discovered:
                self._add_to_queue(candidate, depth + 1, guessed=False)
            vprint(1, f"  [JS] {len(analysis['urls'])} endpoints, {len(module_urls)} módulos em {url[:60]}")
            _sleep(self.delay + random.uniform(0, self.delay * 0.5))
            return

        # Filtro de soft-404: URLs advinhadas (path guessing/wayback) cuja
        # resposta bate com o baseline de "nao existe" sao descartadas aqui
        # em vez de contadas como pagina/achado real — e a causa principal de
        # "o site manda tudo pra aba inicial" aparecer como dezenas de falsos
        # positivos no relatorio.
        if guessed and self._is_soft_fail(html):
            with self._lock:
                self.soft_fail_filtered += 1
            vprint(2, f"  [SOFT-404] Descartado (bate com baseline): {url}")
            _sleep(self.delay + random.uniform(0, self.delay * 0.5))
            return

        content_hash = hashlib.sha256(html.encode("utf-8", errors="ignore")).hexdigest()
        is_duplicate = False
        with self._lock:
            if content_hash in self.content_hashes:
                is_duplicate = True
                self.duplicate_urls.append({
                    "url": url, "duplicado_de": self.content_hashes[content_hash]
                })
            else:
                self.content_hashes[content_hash] = url

        parser = "xml" if self._looks_like_xml(url, html) else "html.parser"
        soup = BeautifulSoup(html, parser)
        title = ""
        if parser == "xml":
            # XML resources such as sitemaps are not HTML pages. Extract <loc>
            # entries and enqueue them, avoiding the misleading HTML-parser warning.
            xml_locs = []
            try:
                for loc in soup.find_all("loc"):
                    value = loc.get_text("", strip=True)
                    if value:
                        xml_locs.append(value)
            except Exception as exc:
                vprint(2, f"  [WARN] XML loc extraction: {exc}")
            for link in xml_locs[:1000]:
                self._add_to_queue(link, depth + 1, guessed=False)
            title = "XML document"
        try:
            title_tag = soup.find("title")
            title = title_tag.get_text().strip() if title_tag else "Sem titulo"
        except Exception:
            title = "Erro titulo"

        links = get_links_from_soup(soup, url, self.target_domain)
        js = get_js_urls_from_soup(soup, url)
        inline_module_urls: set[str] = set()
        inline_endpoints: set[str] = set()
        inline_route_templates: set[str] = set()
        for script in soup.find_all("script", src=False):
            script_type = (script.get("type") or "").split(";", 1)[0].strip().lower()
            if (script_type not in {"", "module", "application/javascript", "text/javascript", "application/ecmascript", "text/ecmascript"}
                    or script.find_parent("template")):
                continue
            source = script.string or script.get_text()
            if not source or len(source) > 1_000_000:
                continue
            inline_analysis = analyze_javascript(url, source)
            inline_module_urls.update(inline_analysis["scripts"])
            inline_endpoints.update(inline_analysis["urls"])
            inline_route_templates.update(inline_analysis["route_templates"])
        self._record_js_route_templates(inline_route_templates)
        links.extend(sorted(inline_endpoints))
        js.extend(sorted(inline_module_urls))

        with self._lock:
            self.visited.append({
                "url": url, "title": title, "depth": depth,
                "class": classify_link(url),
                "duplicado": is_duplicate,
            })
            self.all_urls.add(url)
            ep = extract_endpoints(url)
            if ep:
                self.endpoints.add(ep)
            new_js = [
                ju for ju in js
                if self._is_in_scope(ju) and normalize_url(ju) not in self._js_url_set
            ]
            self.js_urls.extend(new_js)
            self._js_url_set.update(normalize_url(ju) for ju in new_js)

        for link in links:
            self._add_to_queue(link, depth + 1, guessed=False)

        # Minera links de dentro do CONTEUDO real dos arquivos JS descobertos
        # (nao so a URL do arquivo .js) — bundles de SPA/API frequentemente
        # tem a lista inteira de rotas embutida como strings no codigo.
        # Timeout curto/1 tentativa: e descoberta supletiva, nao deve travar
        # a thread por ~50s se um arquivo JS estiver lento (era esse o timeout
        # padrao antes, multiplicado por pagina x arquivos JS = lentidao real
        # em sites com muitos bundles).
        for ju in new_js:
            with self._lock:
                if ju in self.fetched_js:
                    continue
                self.fetched_js.add(ju)
            js_content, _ = request_url(
                ju, timeout=8, max_retries=1,
                allowed_domains=set(self.scope_domains),
                exclude_patterns=self.scope_excludes,
                exact_hosts=self.scope_exact_hosts,
            )
            if js_content and len(js_content) <= 2_000_000:  # pula bundles gigantes
                analysis = analyze_javascript(ju, js_content)
                self._record_js_route_templates(analysis["route_templates"])
                js_links = set(extract_links_from_js_content(js_content, ju, self.target_domain))
                js_links.update(analysis["urls"])
                js_links.update(analysis["source_maps"])
                module_urls = [item for item in analysis["scripts"] if self._is_in_scope(item)]
                with self._lock:
                    new_modules = [item for item in module_urls if normalize_url(item) not in self._js_url_set]
                    self._js_url_set.update(normalize_url(item) for item in new_modules)
                    self.js_urls.extend(new_modules)
                for jl in js_links:
                    self._add_to_queue(jl, depth + 1, guessed=False)
                for module_url in new_modules:
                    self._add_to_queue(module_url, depth + 1, guessed=False)
                if js_links:
                    vprint(1, f"  [JS] {len(js_links)} links minerados de {ju[:60]}")

        if not is_duplicate:
            vprint(1, f"  [OK] {url[:80]} ({len(links)} links, {len(js)} JS)")
        else:
            vprint(1, f"  [DUPLICADO] {url[:80]} (mesmo conteudo de {self.content_hashes[content_hash][:60]})")

        _sleep(self.delay + random.uniform(0, self.delay * 0.5))

    def _result_snapshot(self, robots: dict) -> dict:
        return {
            "pages": len(self.crawled),
            "unique": len(self.visited),
            "list": self.visited,
            "endpoints": list(self.endpoints),
            "all_urls": list(self.all_urls),
            "file_urls": self.file_urls,
            "js_urls": self.js_urls,
            "js_route_templates": self.js_route_templates[:5000],
            "robots": robots,
            "duplicate_urls": self.duplicate_urls,
            "soft_fail_filtered": self.soft_fail_filtered,
            "interesting_params": self.interesting_params,
            "metrics": {
                "requests": self.request_count,
                "errors": self.error_count,
                "elapsed": time.time() - self.started_at if self.started_at else 0,
                "cancelled": self.cancel_event.is_set(),
            },
        }

    def crawl(self) -> dict:
        """Executa o crawl multi-threaded."""
        self.started_at = time.time()
        if not self._is_in_scope(self.start_url):
            self.error_count += 1
            vprint(1, f"[SCOPE] Crawler cancelado: alvo fora do escopo ({self.start_url})")
            return self._result_snapshot({
                "robots_disallowed": [], "robots_allowed": [],
                "sitemap_urls": [], "raw_robots": "",
            })
        self._establish_baseline()
        self._add_to_queue(self.start_url, 0, guessed=False)

        robots = fetch_robots_and_sitemap(
            self.start_url,
            allowed_domains=set(self.scope_domains),
            exclude_patterns=self.scope_excludes,
            exact_hosts=self.scope_exact_hosts,
        )
        if robots["robots_disallowed"]:
            # o proprio site declarou esses paths (Disallow) — mais confiavel
            # que um chute puro, mas ainda vale filtrar por baseline ja que
            # muitos so existem "no papel" e nunca foram implementados
            self._add_priority(robots["robots_disallowed"], "robots.txt (Disallow)", guessed=True)
        if robots["sitemap_urls"]:
            # BUG FIX: sitemap.xml era buscado e descartado, nunca entrava no
            # crawl — e uma das fontes mais ricas de 'links escondidos' que
            # existem (o site literalmente declara todas as paginas)
            sitemap_page_urls = [u for u in robots["sitemap_urls"] if u.startswith(("http://", "https://"))]
            self._add_priority(sitemap_page_urls, "Sitemap.xml", guessed=False)

        if self.use_payload:
            self._probe_parameters()
        if self.use_google:
            paths = path_guessing(self.target_domain, limit=50)
            self._add_priority(paths, "Path Guessing", guessed=True)
        if self.use_wayback:
            from_year = state.config.get("wayback_from_year", 2020)
            wb_urls = get_wayback_urls(self.target_domain, limit=self.max_pages, from_year=from_year)
            if wb_urls:
                self._add_priority(wb_urls, "Wayback Machine", guessed=True)

        done = 0
        crawl_start = time.time()
        max_runtime = state.config.get("max_runtime_seconds", 900)
        print(f"\nCrawler iniciado em {self.start_url} (max {self.max_pages} pags, prof. {self.max_depth}, "
              f"threads: {self.max_workers}, limite de tempo: {max_runtime}s)")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures: dict = {}
            timed_out = False
            while True:
                if self.cancel_event.is_set():
                    break
                with self._lock:
                    queue_empty = len(self.to_crawl) == 0
                    done = len(self.crawled)

                elapsed = time.time() - crawl_start
                if not state.QUIET_MODE:
                    print(f"\r  [{done}/{self.max_pages}] Crawlando... ({len(self.visited)} pags OK, fila: {len(self.to_crawl)}, "
                          f"filtrados: {self.soft_fail_filtered}, {int(elapsed)}s)", end="", flush=True)

                if done >= self.max_pages:
                    break

                if max_runtime and elapsed > max_runtime:
                    timed_out = True
                    vprint(1, f"\n  [!] Limite de tempo do crawler atingido ({max_runtime}s) — "
                              f"encerrando com o que foi coletado ate agora.")
                    break

                with self._lock:
                    while self.to_crawl and len(futures) < self.max_workers * 2:
                        url, depth, guessed = self.to_crawl.popleft()
                        norm = normalize_url(url)
                        self.to_crawl_set.discard(norm)
                        if norm not in self.crawled and depth <= self.max_depth:
                            f = executor.submit(self._crawl_single, url, depth, guessed)
                            futures[f] = url

                if not futures and queue_empty:
                    break

                done_futures = [f for f in list(futures.keys()) if f.done()]
                for f in done_futures:
                    try:
                        f.result()
                    except Exception as e:
                        vprint(2, f"[WARN] crawl future: {e}")
                    del futures[f]

                if not done_futures and not self.to_crawl:
                    _sleep(0.2)

            if timed_out and futures:
                # nao espera os workers em voo indefinidamente — da uma
                # janela curta para desligarem, depois segue com o que tiver
                concurrent.futures.wait(list(futures.keys()), timeout=10)

        print()
        if self.soft_fail_filtered:
            vprint(1, f"  [*] {self.soft_fail_filtered} URLs advinhadas descartadas por soft-404 "
                       f"(bateram no baseline — provavelmente so redirecionam pra home/erro generico)")
        return self._result_snapshot(robots)

    def run(self) -> dict:
        """Executa o crawler completo e retorna relatório."""
        start_time = time.time()
        if not state.QUIET_MODE:
            print(f"\n{Fore.YELLOW}[*] Raven Eye em acao{Style.RESET_ALL}")

        crawl_res = self.crawl()
        result: dict = {"crawler": crawl_res, "start_time": start_time}

        domain = self.target_domain
        ip = resolve_host(domain) or "Unknown"
        result["target"] = {"domain": domain, "ip": ip}
        result["ping"] = ping_host(self.start_url)

        # Passive asset enrichment is activated provider-by-provider only when
        # a key is configured. The integration stores a compact summary and
        # never includes provider banners or raw leak content in the report.
        try:
            from raveneye_pkg.api_integrations import collect_asset_intelligence
            enrichment = collect_asset_intelligence(domain, ip)
            if enrichment:
                result["asset_intelligence"] = enrichment
                for provider, item in enrichment.items():
                    vprint(1, f"[*] {provider}: {item.get('status', 'unknown')}")
        except Exception as exc:
            vprint(1, f"[!] Enriquecimento de APIs indisponível ({type(exc).__name__}).")

        vprint(1, "[*] Consultando crt.sh...")
        subdomains = get_subdomains_crtsh(domain)
        result["subdomains"] = subdomains
        if subdomains:
            result["subdomain_takeover"] = check_subdomain_takeover(subdomains)

        # Descoberta de IP real por tras de CDN/WAF (Cloudflare) — passiva,
        # via DNS de subdominios ja conhecidos + registro SPF. Se achar
        # candidato, faz um PING ADICIONAL direto nele: pingar so o dominio
        # quando ha CDN na frente so mede a latencia ate o proxy do
        # Cloudflare, nao diz nada sobre o servidor de origem de verdade.
        vprint(1, "[*] Verificando se o dominio esta atras de CDN/WAF...")
        real_ip_info = find_real_ip(domain, subdomains)
        result["real_ip"] = real_ip_info
        if real_ip_info["candidatos"]:
            top_candidate = real_ip_info["candidatos"][0]
            result["ping_ip_real"] = {
                "ip": top_candidate["ip"],
                "origem": top_candidate["subdominio"],
                "resultado": ping_host(top_candidate["ip"]),
            }
            print(Fore.GREEN + f"  [+] {len(real_ip_info['candidatos'])} candidato(s) a IP real "
                                f"encontrado(s) (dominio esta atras de {real_ip_info['cdn_detectado']})" + Style.RESET_ALL)

        print(Fore.CYAN + "\n[*] Coletando informacoes do alvo..." + Style.RESET_ALL)
        result["tech"] = get_tech(self.start_url)
        result["security_headers"] = check_security_headers(self.start_url)
        result["ssl"] = check_ssl_cert(domain)

        # BUG FIX: check_outdated_versions existia mas nunca era chamada em lugar nenhum
        try:
            r_hdr = state._SESSION.get(self.start_url, headers=get_random_headers(), timeout=10,
                                  allow_redirects=True, proxies=get_proxies())
            result["outdated_versions"] = check_outdated_versions(r_hdr.headers)
        except Exception as e:
            vprint(2, f"[WARN] outdated_versions check: {e}")
            result["outdated_versions"] = []

        if self.include_whois:
            vprint(1, "[*] Consultando WHOIS...")
            result["whois"] = get_whois(domain)
        if self.include_archive:
            vprint(1, "[*] Consultando Wayback Machine...")
            result["archive"] = get_archive_snapshot(self.start_url)
        if self.include_shodan and ip != "Unknown":
            vprint(1, "[*] Consultando Shodan...")
            result["shodan"] = get_shodan_info(ip, self.shodan_key or "")
        if self.include_exploitdb:
            vprint(1, "[*] Consultando exploits...")
            result["exploitdb"] = get_exploitdb_search(domain)

        # NMAP — BUG FIX: sempre registra resultado no report
        if self.include_nmap:
            if ip != "Unknown":
                vprint(1, "[*] Executando Nmap...")
                result["nmap"] = get_nmap(ip, root_mode=self.root_mode)
            else:
                result["nmap"] = {
                    "portas": [], "vulns": [], "os": "", "raw": "",
                    "status": "ERRO", "erro": f"IP nao resolvido para {domain}"
                }

        if DNSPYTHON_AVAILABLE:
            vprint(1, "[*] Verificando SPF/DMARC/DKIM...")
            result["email_security"] = check_email_security(domain)
            result["zone_transfer"] = check_zone_transfer(domain)

        all_urls_list = list(crawl_res["all_urls"])
        endpoints_list = crawl_res["endpoints"]

        result["vulnerabilities"] = vulnerability_scan(all_urls_list, domain)
        result["cors"] = check_cors(all_urls_list)
        result["open_redirect"] = check_open_redirect(all_urls_list)
        result["directory_listing"] = check_directory_listing(all_urls_list[:50])
        result["error_disclosure"] = check_error_disclosure(all_urls_list[:30])
        result["http_methods"] = probe_http_methods(all_urls_list)
        result["parameters"] = extract_parameters(all_urls_list)
        result["google_dorks"] = google_dork_search(domain)

        provider = state.config.get("dork_search_provider", "none")
        if provider == "searxng":
            vprint(1, "[*] Consultando resultados de dorks no SearXNG local...")
            result["google_dorks_results"] = run_searxng_dorks_search(
                result["google_dorks"], domain,
                state.config.get("searxng_url", "http://127.0.0.1:8080"),
            )
        elif provider == "google_cse":
            from raveneye_pkg.config_io import get_api_key, get_google_cse_id
            cse_key = get_api_key("google_cse")
            cse_id = get_google_cse_id()
            if cse_key and cse_id:
                vprint(1, "[*] Consultando resultados de dorks no Google CSE...")
                result["google_dorks_results"] = run_google_dorks_search(
                    result["google_dorks"], domain, cse_key, cse_id
                )
            else:
                result["google_dorks_results"] = {
                    "provider": "Google CSE", "dorks_executados": 0,
                    "total_bruto": 0, "total_interessantes": 0,
                    "interessantes": [], "erros": ["Google CSE não configurado"],
                }

        if self.include_cache_poisoning:
            vprint(1, "[*] Testando Web Cache Poisoning...")
            result["cache_poisoning"] = check_web_cache_poisoning(all_urls_list)
        if self.include_smuggling:
            vprint(1, "[*] Testando HTTP Request Smuggling (heuristico)...")
            result["http_smuggling"] = check_http_request_smuggling(self.start_url)
        if self.include_jwt:
            vprint(1, "[*] Verificando fraquezas em JWT...")
            result["jwt_weaknesses"] = check_jwt_weaknesses(self.start_url)
        if self.include_virustotal:
            vprint(1, "[*] Consultando VirusTotal...")
            from raveneye_pkg.config_io import get_api_key
            vt_key = get_api_key("virustotal")
            result["virustotal"] = check_virustotal(self.start_url, vt_key)

        if crawl_res.get("js_urls"):
            vprint(1, f"[*] Escaneando {len(crawl_res['js_urls'])} arquivos JS...")
            result["secrets_js"] = scan_js_for_secrets(crawl_res["js_urls"])

        if self.include_vuln_scanner:
            try:
                from raveneye_pkg.vuln_scanner import RavenVulnScanner
                vprint(1, f"[*] RavenVulnScanner ({'com root' if self.root_mode else 'solo'})...")
                scanner = RavenVulnScanner(
                    target=self.start_url,
                    root_mode=self.root_mode,
                    urls=all_urls_list,
                    max_workers=state.config.get("scanner_max_workers", 6),
                    rate_limit=state.config.get("scanner_rate_limit", 8.0),
                    active=True,
                )
                result["vulnerability_scan"] = scanner.run()
                if self.root_mode and ip != "Unknown":
                    try:
                        result["vulnerability_scan"]["nmap_enrichment"] = get_nmap(ip, root_mode=True)
                    except Exception as exc:
                        vprint(2, f"[WARN] scanner Nmap root: {exc}")
            except Exception as exc:
                vprint(2, f"[WARN] RavenVulnScanner: {exc}")
                result["vulnerability_scan"] = {
                    "scanner": "RavenVulnScanner",
                    "mode": "root" if self.root_mode else "solo",
                    "findings": [],
                    "summary": {},
                    "error": str(exc),
                }

        result["elapsed"] = time.time() - start_time
        return result
