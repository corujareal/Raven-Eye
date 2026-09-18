from __future__ import annotations

"""Todas as funcoes de deteccao/recon: tecnologia, headers de seguranca,
CORS, redirects, cache poisoning, HTTP smuggling, JWT, secrets em JS,
subdominios/DNS, Nmap, Google Dorks (local + Custom Search API), WHOIS,
Wayback, ExploitDB, Shodan e VirusTotal."""


import base64
import concurrent.futures
import datetime
import ipaddress
import json
import os
import re
import xml.etree.ElementTree as ET
import shutil
import socket
import ssl
import subprocess
import threading
import time
from contextlib import suppress
from pathlib import Path
from urllib.parse import urlparse
import requests
from raveneye_pkg.terminal import Fore, Style
from raveneye_pkg import state
from raveneye_pkg.state import vprint
from raveneye_pkg.network import _is_valid_host, get_proxies, get_random_headers, resolve_host
from raveneye_pkg.constants import (
    TAKEOVER_FINGERPRINTS, SECRET_PATTERNS, SECURITY_HEADERS,
    OUTDATED_VERSIONS, REDIRECT_PARAMS, ERROR_PATTERNS,
    SUBDOMAIN_WORDLIST, _JWT_COMMON_SECRETS, _DORK_INTERESTING_KEYWORDS,
    CLOUDFLARE_IPV4_RANGES, CLOUDFLARE_IPV6_RANGES,
)


from raveneye_pkg.state import (
    SHODAN_AVAILABLE, WHOIS_AVAILABLE, DNSPYTHON_AVAILABLE,
    JSBEAUTIFIER_AVAILABLE, PYJWT_AVAILABLE,
)
if SHODAN_AVAILABLE:
    import shodan
if WHOIS_AVAILABLE:
    import whois
if DNSPYTHON_AVAILABLE:
    import dns.resolver
    import dns.zone
    import dns.query
if JSBEAUTIFIER_AVAILABLE:
    import jsbeautifier
if PYJWT_AVAILABLE:
    import jwt as _pyjwt


def get_whois(domain: str) -> dict:
    """Consulta WHOIS do domínio. Sempre retorna dict (chave 'erro' vazia em caso de sucesso)."""
    if not WHOIS_AVAILABLE:
        return {"erro": "whois nao instalado (pip install python-whois)"}
    try:
        w = whois.whois(domain)
        email = getattr(w, "emails", None)
        if isinstance(email, list):
            email = ", ".join(email)
        return {
            "dominio": w.domain_name if w.domain_name else domain,
            "registrador": w.registrar or "N/A",
            "criacao": str(w.creation_date) if w.creation_date else "N/A",
            "expiracao": str(w.expiration_date) if w.expiration_date else "N/A",
            "name_servers": w.name_servers if w.name_servers else "N/A",
            "email_contato": email or "N/A",
            "erro": "",
        }
    except Exception as e:
        vprint(2, f"[WARN] get_whois: {e}")
        return {"erro": str(e)}


# ==================================================================
# FUNÇÕES — Wayback Machine
# ==================================================================
def get_archive_snapshot(url: str) -> dict:
    """Obtém snapshot do Wayback Machine via HTTP."""
    try:
        r = state._SESSION.get(
            f"http://archive.org/wayback/available?url={url}",
            timeout=15, headers=get_random_headers(), proxies=get_proxies()
        )
        if r.status_code == 200:
            data = r.json()
            snap = data.get("archived_snapshots", {}).get("closest")
            if snap:
                return {"url": snap["url"], "timestamp": snap["timestamp"], "status": "ok"}
    except Exception as e:
        vprint(2, f"[WARN] get_archive_snapshot: {e}")
    return {"status": "nenhum"}


def get_wayback_urls(domain: str, limit: int = 500, from_year: int = 2020) -> list[str]:
    """Obtém URLs históricas do Wayback CDX API com streaming."""
    urls: list[str] = []
    try:
        api_url = (
            f"http://web.archive.org/cdx/search/cdx?url={domain}/*"
            f"&output=text&collapse=urlkey&fl=original"
            f"&from={from_year}0101&limit={limit}"
        )
        r = state._SESSION.get(api_url, timeout=30, stream=True,
                         headers=get_random_headers(), proxies=get_proxies())
        if r.status_code == 200:
            for line in r.iter_lines(decode_unicode=True):
                line = line.strip()
                if line and line.startswith(("http://", "https://")):
                    urls.append(line)
                if len(urls) >= limit:
                    break
    except Exception as e:
        vprint(2, f"[WARN] get_wayback_urls: {e}")
    return urls


# ==================================================================
# FUNÇÕES — ExploitDB / NVD
# ==================================================================
def get_exploitdb_search(query: str) -> list[dict]:
    """Busca exploits via searchsploit ou NVD API."""
    if shutil.which("searchsploit"):
        try:
            result = subprocess.run(
                ["searchsploit", "--json", query],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                exploits = data.get("RESULTS_EXPLOIT", [])
                return [
                    {"id": e.get("EDB-ID", "N/A"), "titulo": e.get("Title", "N/A"),
                     "data": e.get("Date", "N/A"), "tipo": e.get("Type", "N/A"),
                     "url": f"https://www.exploit-db.com/exploits/{e.get('EDB-ID')}"}
                    for e in exploits[:10]
                ]
        except Exception as e:
            vprint(2, f"[WARN] searchsploit: {e}")
    try:
        r = state._SESSION.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=10",
            timeout=20, headers=get_random_headers(), proxies=get_proxies()
        )
        if r.status_code == 200:
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            results = []
            for v in vulns[:10]:
                cve = v.get("cve", {})
                cve_id = cve.get("id", "N/A")
                desc = cve.get("descriptions", [{}])[0].get("value", "N/A")[:100]
                score = "N/A"
                try:
                    score = str(cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"])
                except Exception:
                    pass
                results.append({
                    "id": cve_id, "titulo": desc, "data": cve.get("published", "N/A"),
                    "tipo": f"CVSS: {score}",
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })
            return results
    except Exception as e:
        vprint(2, f"[WARN] get_exploitdb_search NVD: {e}")
    return [{
        "id": "N/A", "titulo": "Busca automatica indisponivel — pesquise manualmente",
        "data": "N/A", "tipo": "ERRO",
        "url": f"https://www.exploit-db.com/search?q={query}",
    }]


# ==================================================================
# FUNÇÕES — Shodan
# ==================================================================
def get_shodan_info(ip: str, api_key: str) -> dict:
    """Consulta informações do IP no Shodan. Sempre retorna dict (chave 'erro' vazia em caso de sucesso)."""
    if not SHODAN_AVAILABLE or not api_key:
        return {"erro": "Shodan indisponivel (sem chave ou modulo)"}
    try:
        api = shodan.Shodan(api_key)
        host = api.host(ip)
        vulns = (
            list(host.get("vulns", {}).keys())
            if isinstance(host.get("vulns"), dict)
            else host.get("vulns", [])
        )
        return {
            "ip": host["ip_str"],
            "org": host.get("org", "N/A"),
            "os": host.get("os", "N/A"),
            "hostnames": host.get("hostnames", []),
            "portas": sorted(host.get("ports", [])),
            "vulns": vulns[:20],
            "erro": "",
        }
    except Exception as e:
        vprint(2, f"[WARN] get_shodan_info: {e}")
        return {"erro": str(e)}


# ==================================================================
# FUNÇÕES — Nmap (BUG FIX: resultado sempre registrado)
# ==================================================================
def _find_nmap() -> str | None:
    """Encontra o executável do Nmap."""
    for cmd in ("nmap", "/data/data/com.termux/files/usr/bin/nmap"):
        try:
            subprocess.run([cmd, "--version"], capture_output=True, check=True, timeout=5)
            return cmd
        except Exception:
            continue
    return None


def _parse_nmap_xml(xml_text: str) -> dict | None:
    """Faz parsing estruturado da saida XML do Nmap (-oX -), muito mais
    confiavel do que aplicar regex em cima do texto formatado para humanos
    (que muda de layout entre versoes do nmap e scripts NSE). Retorna None
    se o XML nao puder ser interpretado, para o chamador cair no fallback
    por regex em cima do texto bruto.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        vprint(2, f"[WARN] _parse_nmap_xml: XML invalido ({e})")
        return None

    services: list[str] = []
    cves: set[str] = set()
    os_info = ""

    for host in root.findall("host"):
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = port.get("portid", "?")
                protocol = port.get("protocol", "tcp")
                svc_el = port.find("service")
                name = svc_el.get("name", "") if svc_el is not None else ""
                product = svc_el.get("product", "") if svc_el is not None else ""
                version = svc_el.get("version", "") if svc_el is not None else ""
                extra = " ".join(p for p in (product, version) if p)
                svc = f"{portid}/{protocol} - {name}"
                if extra:
                    svc += f" ({extra})"
                services.append(svc)
                print(Fore.WHITE + f"      {svc}" + Style.RESET_ALL)

                for script in port.findall("script"):
                    output = script.get("output", "")
                    cves.update(re.findall(r"(?i)(CVE-\d{4}-\d+)", output))

        for script in host.findall("hostscript/script"):
            output = script.get("output", "")
            cves.update(re.findall(r"(?i)(CVE-\d{4}-\d+)", output))

        os_el = host.find("os")
        if os_el is not None:
            osmatch = os_el.find("osmatch")
            if osmatch is not None:
                os_info = osmatch.get("name", "")

    return {
        "portas": services,
        "vulns": sorted(cves)[:20],
        "os": os_info,
    }


def get_nmap(target_ip: str, root_mode: bool = False) -> dict:
    """Executa varredura Nmap com -D RND:5 para evasão.

    Usa saida XML estruturada (-oX -) e faz parsing via xml.etree, com
    fallback para o parsing por regex em texto bruto caso o XML venha
    malformado por algum motivo (ex: nmap interrompido no meio da escrita).
    """
    nmap_cmd = _find_nmap()
    if not nmap_cmd:
        return {"portas": [], "vulns": [], "os": "", "erro": "Nmap nao encontrado no sistema",
                "raw": "", "status": "ERRO"}
    if not _is_valid_host(target_ip):
        return {"portas": [], "vulns": [], "os": "", "erro": "IP/host invalido",
                "raw": "", "status": "ERRO"}
    if root_mode and os.geteuid() != 0:
        return {"portas": [], "vulns": [], "os": "", "erro": "Modo root requer sudo",
                "raw": "", "status": "ERRO"}
    try:
        if root_mode:
            cmd = [
                nmap_cmd, "-sS", "-O", "-A", "-p-", "-T4", "--open",
                "--min-rate", "500", "--host-timeout", "70s", "-D", "RND:5",
                "-oX", "-", target_ip
            ]
        else:
            cmd = [
                nmap_cmd, "-sT", "-sV", "-sC", "-T4", "--open",
                "--min-rate", "300", "--host-timeout", "45s", "-D", "RND:5",
                "-oX", "-", target_ip
            ]
        print(Fore.YELLOW + f"  [+] Nmap em {target_ip}: {' '.join(cmd)}" + Style.RESET_ALL)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            stdout, stderr = proc.communicate(timeout=150 if root_mode else 75)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            return {"portas": [], "vulns": [], "os": "", "erro": "Timeout no Nmap",
                    "raw": stdout or "", "status": "TIMEOUT"}

        # Aceita output mesmo com returncode != 0 (nmap pode retornar 1 em alguns casos normais)
        if proc.returncode != 0 and not stdout.strip():
            return {"portas": [], "vulns": [], "os": "", "erro": f"Erro Nmap: {stderr.strip()[:200]}",
                    "raw": stderr, "status": "ERRO"}

        output = stdout
        parsed = _parse_nmap_xml(output)
        if parsed is None:
            # Fallback: parsing por regex no texto bruto (formato antigo)
            vprint(1, "[!] XML do Nmap invalido, usando fallback por regex")
            services: list[str] = []
            for line in output.splitlines():
                m = re.match(r"^(\d+/(?:tcp|udp))\s+open\s+(\S+)\s*(.*)$", line)
                if m:
                    svc = f"{m.group(1)} - {m.group(2)}"
                    if m.group(3):
                        svc += f" ({m.group(3).strip()})"
                    services.append(svc)
                    print(Fore.WHITE + f"      {svc}" + Style.RESET_ALL)
            cves = list(set(re.findall(r"\|_?([Cc][Vv][Ee]-\d{4}-\d+)", output)))
            os_info = ""
            if root_mode:
                os_m = re.search(r"OS details: (.+)", output)
                if os_m:
                    os_info = os_m.group(1)
            parsed = {"portas": services, "vulns": cves[:20], "os": os_info}

        print(Fore.GREEN + f"  [+] Nmap concluido. {len(parsed['portas'])} portas abertas, "
                            f"{len(parsed['vulns'])} CVEs." + Style.RESET_ALL)
        return {
            "portas": parsed["portas"],
            "vulns": parsed["vulns"],
            "os": parsed["os"],
            "raw": output[:5000],   # raw para debug no log
            "status": "OK",
            "erro": ""
        }
    except Exception as e:
        vprint(2, f"[WARN] get_nmap: {e}")
        return {"portas": [], "vulns": [], "os": "", "erro": str(e),
                "raw": "", "status": "ERRO"}


# ==================================================================
# FUNÇÕES — Detecção de tecnologia
# ==================================================================
def get_tech(url: str) -> dict:
    """Detecta tecnologias em 3 camadas: headers, HTML, cookies."""
    result: dict = {
        "servidor": "Desconhecido", "linguagens": [],
        "cms": None, "frameworks": [], "waf": None, "cdn": None
    }
    try:
        r = state._SESSION.get(url, headers=get_random_headers(), timeout=10,
                         allow_redirects=True, proxies=get_proxies())
        headers = r.headers
        body = r.text[:50000]

        server = headers.get("Server", "")
        if server:
            result["servidor"] = server
        xp = headers.get("X-Powered-By", "")
        if "PHP" in xp:
            result["linguagens"].append("PHP")
        if "ASP.NET" in headers.get("X-AspNet-Version", "") or "ASP.NET" in xp:
            result["linguagens"].append("ASP.NET")
        if "Python" in xp or "Django" in xp or "Flask" in xp:
            result["linguagens"].append("Python")
        if "Node" in xp or "Express" in xp:
            result["linguagens"].append("Node.js")
        if "Ruby" in xp:
            result["linguagens"].append("Ruby")
        if "Java" in xp or "Tomcat" in server:
            result["linguagens"].append("Java")
        if "CF-Ray" in headers:
            result["waf"] = "Cloudflare"
            result["cdn"] = "Cloudflare"
        elif "X-Sucuri-ID" in headers:
            result["waf"] = "Sucuri"
        elif any(h.startswith("X-Akamai") for h in headers):
            result["cdn"] = "Akamai"
        elif "X-Cache" in headers:
            result["cdn"] = "CDN generico"
        if "X-Varnish" in headers:
            result["cdn"] = "Varnish"

        if "wp-content/" in body or "wp-includes/" in body or "wp-json/" in body:
            result["cms"] = "WordPress"
        elif "Drupal.settings" in body or "/sites/default/files/" in body:
            result["cms"] = "Drupal"
        elif "/components/com_" in body and "Joomla" in body:
            result["cms"] = "Joomla"
        elif "Mage.Cookies" in body or "/skin/frontend/" in body:
            result["cms"] = "Magento"
        elif "prestashop" in body.lower():
            result["cms"] = "PrestaShop"
        elif "catalog/view/theme" in body:
            result["cms"] = "OpenCart"
        if "_next/" in body or "__NEXT_DATA__" in body:
            result["frameworks"].append("Next.js")
        elif "data-reactroot" in body or "__REACT_DEVTOOLS_GLOBAL_HOOK__" in body:
            result["frameworks"].append("React")
        if "__vue__" in body or "data-v-" in body:
            result["frameworks"].append("Vue.js")
        if "ng-version" in body or "_nghost-" in body:
            result["frameworks"].append("Angular")
        if "csrf-param" in body and "authenticity_token" in body:
            result["frameworks"].append("Ruby on Rails")
        if "csrfmiddlewaretoken" in body and "django" in body.lower():
            result["frameworks"].append("Django")
        if "laravel_session" in str(r.cookies):
            result["frameworks"].append("Laravel")

        if not result["linguagens"]:
            result["linguagens"].append("Nao detectado")
    except Exception as e:
        vprint(2, f"[WARN] get_tech: {e}")
    return result


# ==================================================================
# FUNÇÕES — Google Dorks (EXPANDIDO ~85 dorks)
# ==================================================================
def load_custom_dorks() -> list[str]:
    """Carrega dorks customizados de um arquivo texto (um por linha), se configurado
    em 'Configuracoes' > 'Arquivo de dorks customizados'. Placeholders {domain} no
    arquivo sao substituidos pelo dominio alvo no momento do uso."""
    path = state.config.get("custom_dorks_file", "")
    if not path:
        return []
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]
    except Exception as e:
        vprint(2, f"[WARN] load_custom_dorks: {e}")
        return []


def google_dork_search(domain: str) -> list[str]:
    """Gera lista expandida de Google Dorks (built-in + customizados via config)."""
    custom = [d.replace("{domain}", domain) if "{domain}" in d else f"site:{domain} {d}"
              for d in load_custom_dorks()]
    return custom + [
        # ── Arquivos sensíveis ──────────────────────────────────────
        f"site:{domain} filetype:pdf",
        f"site:{domain} filetype:xls OR filetype:xlsx OR filetype:csv",
        f"site:{domain} filetype:doc OR filetype:docx",
        f"site:{domain} ext:env OR ext:sql OR ext:bak OR ext:old OR ext:backup",
        f"site:{domain} ext:log OR ext:conf OR ext:cfg OR ext:ini OR ext:yaml OR ext:yml",
        f"site:{domain} ext:xml OR ext:json OR ext:txt inurl:password OR inurl:secret",
        f"site:{domain} filetype:php inurl:config OR inurl:setup OR inurl:install",
        f"site:{domain} filetype:asp OR filetype:aspx inurl:admin",
        f"site:{domain} filetype:sh OR filetype:bash OR filetype:py",
        f'site:{domain} ext:pem OR ext:key OR ext:crt OR ext:p12 OR ext:pfx',
        f'site:{domain} filetype:sql "INSERT INTO" OR "CREATE TABLE"',
        f'site:{domain} filetype:txt inurl:robots OR inurl:security OR inurl:sitemap',
        # ── Admin / Painel ──────────────────────────────────────────
        f"site:{domain} inurl:admin OR inurl:administrator OR inurl:dashboard",
        f"site:{domain} inurl:login OR inurl:signin OR inurl:auth OR inurl:sso",
        f"site:{domain} inurl:wp-content OR inurl:wp-admin OR inurl:wp-login",
        f'site:{domain} intitle:"phpMyAdmin" OR inurl:phpmyadmin',
        f"site:{domain} inurl:cpanel OR inurl:webmail OR inurl:plesk OR inurl:whm",
        f"site:{domain} inurl:panel OR inurl:controlpanel OR inurl:manage",
        f'site:{domain} intitle:"Admin" OR intitle:"Login" OR intitle:"Dashboard"',
        f"site:{domain} inurl:adminer OR inurl:dbadmin OR inurl:database",
        f'site:{domain} inurl:admin inurl:login',
        f'site:{domain} intitle:"control panel" OR intitle:"admin panel"',
        # ── API / GraphQL / Swagger ─────────────────────────────────
        f"site:{domain} inurl:api OR inurl:v1 OR inurl:v2 OR inurl:v3",
        f"site:{domain} inurl:swagger OR inurl:graphql OR inurl:api-docs",
        f"site:{domain} inurl:openapi OR inurl:redoc OR inurl:api/swagger.json",
        f'site:{domain} inurl:rest OR inurl:restapi OR inurl:jsonapi',
        f'site:{domain} inurl:api/users OR inurl:api/admin OR inurl:api/token',
        f'site:{domain} inurl:.json OR inurl:.xml inurl:api',
        f'site:{domain} inurl:graphql/console OR inurl:graphiql',
        # ── Debug / Dev / Staging ───────────────────────────────────
        f"site:{domain} inurl:debug OR inurl:test OR inurl:dev OR inurl:staging",
        f"site:{domain} inurl:beta OR inurl:uat OR inurl:qa OR inurl:preprod",
        f'site:{domain} intitle:"test" OR intitle:"debug" OR intitle:"development"',
        f'site:{domain} inurl:phpinfo OR inurl:info.php OR inurl:php-info',
        f'site:{domain} "phpinfo()" OR "php info" OR "PHP Version"',
        f'site:{domain} inurl:server-status OR inurl:server-info',
        # ── Credenciais / Secrets ───────────────────────────────────
        f'site:{domain} "DB_PASSWORD" OR "DB_USER" OR "API_KEY" OR "SECRET_KEY"',
        f'site:{domain} "password" filetype:txt OR filetype:log',
        f'site:{domain} "username" OR "password" filetype:env',
        f'site:{domain} "access_token" OR "refresh_token" OR "client_secret"',
        f'site:{domain} "aws_access_key_id" OR "aws_secret_access_key"',
        f'site:{domain} "-----BEGIN RSA PRIVATE KEY-----"',
        f'site:{domain} "Authorization: Bearer" OR "token:" filetype:log',
        f'site:{domain} inurl:config filetype:yml OR filetype:yaml',
        f'site:{domain} "mysql_connect" OR "mysqli_connect" filetype:php',
        # ── Git / Exposição de código ───────────────────────────────
        f"site:{domain} inurl:.git OR inurl:.svn OR inurl:.env",
        f'site:{domain} inurl:.git/config OR inurl:.git/HEAD',
        f'site:{domain} inurl:.DS_Store OR inurl:Thumbs.db',
        f'site:{domain} inurl:composer.json OR inurl:package.json OR inurl:Gemfile',
        f'site:{domain} inurl:.htaccess OR inurl:.htpasswd OR inurl:web.config',
        # ── Erros / Information Disclosure ──────────────────────────
        f'site:{domain} "Internal Server Error" OR "stack trace" OR "exception"',
        f'site:{domain} "Warning: mysql_" OR "Fatal error:" OR "Parse error:"',
        f'site:{domain} "ORA-" OR "MySQL server version" OR "SQLSTATE"',
        f'site:{domain} "Traceback (most recent call last)" OR "Django" intitle:"Debug"',
        f'site:{domain} intitle:"Index of" OR intitle:"Index of /"',
        f'site:{domain} intitle:"Index of" "parent directory"',
        f'site:{domain} intitle:"Apache Status" OR intitle:"Apache Server Status"',
        f'site:{domain} "Directory Listing For" OR "[To Parent Directory]"',
        # ── Backup / Upload ─────────────────────────────────────────
        f'site:{domain} inurl:backup OR inurl:bkp OR inurl:bak OR inurl:old',
        f'site:{domain} inurl:upload OR inurl:uploads OR inurl:uploaded',
        f'site:{domain} inurl:backup filetype:zip OR filetype:tar OR filetype:gz',
        # ── CMS específico ──────────────────────────────────────────
        f'site:{domain} inurl:wp-json/wp/v2/users',
        f'site:{domain} inurl:xmlrpc.php',
        f'site:{domain} inurl:joomla OR inurl:com_content OR inurl:com_users',
        f'site:{domain} inurl:drupal OR inurl:sites/default/files',
        f'site:{domain} inurl:magento OR inurl:downloader OR inurl:mage',
        # ── Redirects / SSRF ────────────────────────────────────────
        f"site:{domain} inurl:redirect OR inurl:url= OR inurl:next= OR inurl:return=",
        f'site:{domain} inurl:proxy OR inurl:forward OR inurl:wpad',
        # ── Cloud / S3 ──────────────────────────────────────────────
        f'site:{domain} "s3.amazonaws.com" OR "storage.googleapis.com" OR "blob.core.windows.net"',
        f'site:{domain} inurl:s3 OR inurl:storage OR inurl:cdn filetype:txt',
        # ── OAuth / JWT / Auth ──────────────────────────────────────
        f'site:{domain} inurl:oauth OR inurl:oauth2 OR inurl:authorize',
        f'site:{domain} inurl:saml OR inurl:sso OR inurl:oidc OR inurl:openid',
        f'site:{domain} "eyJ" inurl:token OR inurl:jwt',
        # ── Mobile / App ────────────────────────────────────────────
        f'site:{domain} inurl:app OR inurl:mobile OR inurl:android OR inurl:ios',
        f'site:{domain} filetype:apk OR filetype:ipa',
        # ── WordPress específico ────────────────────────────────────
        f'site:{domain} inurl:wp-config.php OR inurl:wp-settings.php',
        f'site:{domain} inurl:wp-json/oembed OR inurl:wp-json/wp/v2',
        # ── Câmeras / IoT ───────────────────────────────────────────
        f'site:{domain} inurl:ViewerFrame?Mode= OR inurl:MultiCameraFrame',
        f'site:{domain} intitle:"Webcam" OR intitle:"Network Camera" OR intitle:"Live View"',
        # ── Senhas default ──────────────────────────────────────────
        f'site:{domain} "admin" "password" filetype:log',
        f'site:{domain} intitle:"router" OR intitle:"modem" inurl:login',
        # ── Exposição de dados ──────────────────────────────────────
        f'site:{domain} "email" OR "senha" OR "cpf" filetype:csv',
        f'site:{domain} "username" "password" filetype:xls OR filetype:xlsx',
        f'site:{domain} ext:sql "CREATE TABLE users" OR "INSERT INTO users"',
        # ── Bug Bounty relevante ────────────────────────────────────
        f'site:{domain} inurl:callback OR inurl:webhook OR inurl:hook',
        f'site:{domain} inurl:cgi-bin OR inurl:cgi OR inurl:cmd.exe',
        f'site:{domain} inurl:shell OR inurl:cmd OR inurl:exec OR inurl:system',
        f'site:{domain} inurl:include OR inurl:require OR inurl:file= OR inurl:path=',
        f'site:{domain} "X-Forwarded-For" OR "X-Real-IP" filetype:log',
    ]


def _classify_interesting_dork_result(item: dict) -> str | None:
    """Retorna o motivo pelo qual um resultado do SERP e considerado interessante,
    ou None se parecer apenas uma pagina comum (homepage, blog, etc)."""
    haystack = f"{item.get('title', '')} {item.get('link', '')} {item.get('snippet', '')}".lower()
    for motivo, keywords in _DORK_INTERESTING_KEYWORDS.items():
        if any(kw in haystack for kw in keywords):
            return motivo
    return None


def run_google_dorks_search(dorks: list[str], domain: str, api_key: str, cse_id: str,
                             max_queries: int = 90) -> dict:
    """Executa os dorks de fato via Google Custom Search JSON API (oficial) e
    filtra apenas os resultados que parecem interessantes (arquivos sensiveis,
    paineis admin, APIs expostas, etc), em vez de devolver o SERP bruto.

    Requer 'Chave Google CSE' e 'Google CSE ID' configurados (gratuitos, cota de
    100 consultas/dia). Nao faz scraping do google.com — usa a API oficial,
    unica forma sustentavel e dentro dos Termos de Servico do Google de
    automatizar buscas.
    """
    result: dict = {
        "dorks_executados": 0, "total_bruto": 0, "total_interessantes": 0,
        "interessantes": [], "erros": [],
    }
    seen_links: set[str] = set()
    dorks_to_run = dorks[:max_queries]

    for dork in dorks_to_run:
        try:
            r = state._SESSION.get(
                "https://www.googleapis.com/customsearch/v1",
                params={"key": api_key, "cx": cse_id, "q": dork, "num": 10},
                timeout=15, proxies=get_proxies()
            )
            result["dorks_executados"] += 1
            if r.status_code == 429 or (r.status_code == 403 and "quota" in r.text.lower()):
                result["erros"].append("Cota diaria da Google Custom Search API excedida — parando.")
                break
            if r.status_code != 200:
                result["erros"].append(f"HTTP {r.status_code} para dork: {dork[:50]}")
                continue
            items = r.json().get("items", [])
            result["total_bruto"] += len(items)
            for raw in items:
                item = {
                    "titulo": raw.get("title", ""), "link": raw.get("link", ""),
                    "snippet": raw.get("snippet", ""),
                }
                if item["link"] in seen_links:
                    continue
                motivo = _classify_interesting_dork_result(item)
                if motivo:
                    seen_links.add(item["link"])
                    item["motivo"] = motivo
                    item["dork"] = dork
                    result["interessantes"].append(item)
        except Exception as e:
            result["erros"].append(f"{str(e)[:80]} (dork: {dork[:50]})")
            vprint(2, f"[WARN] run_google_dorks_search: {e}")

    result["total_interessantes"] = len(result["interessantes"])
    return result


def path_guessing(domain: str, limit: int = 50) -> list[str]:
    """Gera URLs de paths comuns para crawl."""
    paths = [
        "admin", "login", "signin", "administrator", "dashboard", "wp-admin",
        "cpanel", "webmail", "phpmyadmin", "mysql", "backup", "config", "settings",
        "api", "swagger", "docs", "database", "sql", "dump", "log", "logs",
        "error_log", "debug", "test", "beta", "dev", "staging", "backoffice",
        ".env", ".git", ".git/config", "phpinfo.php", "info.php",
        "server-status", "server-info", "sitemap.xml", "robots.txt",
        "api/v1", "api/v2", "graphql", "api-docs", "openapi.json",
        "swagger.json", "swagger-ui", "redoc", "xmlrpc.php", "wp-login.php",
        "upload", "uploads", "files", "images", "static", "assets",
        "console", "shell", "terminal", "exec", "cmd",
        "composer.json", "package.json", "Dockerfile", ".dockerenv",
    ]
    base = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"
    return [f"{base.rstrip('/')}/{p}" for p in paths][:limit]


# ==================================================================
# FUNÇÕES — Subdomínios e DNS
# ==================================================================
def get_subdomains_crtsh(domain: str) -> list[str]:
    """Enumeração passiva de subdomínios via Certificate Transparency (crt.sh)."""
    try:
        r = state._SESSION.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=20, headers={"Accept": "application/json"}, proxies=get_proxies()
        )
        if r.status_code == 200:
            subs: set[str] = set()
            for entry in r.json():
                for sub in entry.get("name_value", "").splitlines():
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(f".{domain}") or sub == domain:
                        subs.add(sub.lower())
            return sorted(subs)
    except Exception as e:
        vprint(2, f"[WARN] get_subdomains_crtsh: {e}")
    return []


class _RateLimiter:
    """Limitador de taxa simples (token bucket de 1 slot) para uso entre threads.
    Garante que chamadas concorrentes a wait() nao excedam 'rate_per_sec' no agregado."""

    def __init__(self, rate_per_sec: float) -> None:
        self.min_interval = 1.0 / rate_per_sec if rate_per_sec > 0 else 0.0
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.time()
            remaining = self._last + self.min_interval - now
            if remaining > 0:
                time.sleep(remaining)
            self._last = time.time()


def brute_subdomains(domain: str, wordlist: list[str] | None = None, max_workers: int = 20) -> list[dict]:
    """Enumeração ATIVA de subdomínios via resolução DNS com wordlist embutida.

    Diferente do bruteforce de login: nao tenta autenticar em nada, apenas
    resolve hostnames candidatos (ex: admin.dominio.com) para ver se existem
    — a mesma natureza de get_subdomains_crtsh(), so que ativa em vez de
    passiva (util para achar subdominios que nunca tiveram certificado TLS
    emitido e por isso nao aparecem no Certificate Transparency/crt.sh).
    Multi-threaded, com rate limiting configuravel (config['dns_rate_limit'],
    consultas/segundo) para nao sobrecarregar o resolver DNS local/externo
    nem gerar falsos negativos por timeout sob rajada de requisicoes.
    """
    wl = wordlist or SUBDOMAIN_WORDLIST
    found: list[dict] = []
    lock = threading.Lock()
    total = len(wl)
    done = 0
    limiter = _RateLimiter(state.config.get("dns_rate_limit", 30))

    def _check(sub: str) -> None:
        nonlocal done
        limiter.wait()
        candidate = f"{sub}.{domain}"
        ip = resolve_host(candidate)
        with lock:
            done += 1
            if ip:
                found.append({"subdomain": candidate, "ip": ip})
            print(f"\r  [{done}/{total}] testados | {len(found)} encontrados", end="", flush=True)

    print(Fore.CYAN + f"[*] Bruteforce de subdominios em {domain} "
                       f"({total} candidatos embutidos, {max_workers} threads, "
                       f"{state.config.get('dns_rate_limit', 30)} req/s max)" + Style.RESET_ALL)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_check, sub) for sub in wl]
        concurrent.futures.wait(futures)
    print()
    found.sort(key=lambda x: x["subdomain"])
    print(Fore.GREEN + f"[+] {len(found)} subdominios encontrados." + Style.RESET_ALL)
    return found


def check_zone_transfer(domain: str) -> dict:
    """Tenta AXFR em todos os nameservers."""
    if not DNSPYTHON_AVAILABLE:
        return {"error": "dnspython nao instalado (pip install dnspython)"}
    try:
        results: dict = {}
        for ns in dns.resolver.resolve(domain, "NS"):
            ns_host = str(ns.target).rstrip(".")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=10))
                results[ns_host] = {
                    "status": "VULNERAVEL — AXFR permitido",
                    "records": len(zone.keys()),
                    "severity": "CRITICO",
                }
            except Exception:
                results[ns_host] = {"status": "seguro"}
        return results
    except Exception as e:
        vprint(2, f"[WARN] check_zone_transfer: {e}")
        return {"error": str(e)}


def check_email_security(domain: str) -> dict:
    """Verifica SPF, DMARC e DKIM do domínio."""
    if not DNSPYTHON_AVAILABLE:
        return {"error": "dnspython nao instalado"}
    results: dict = {"spf": None, "dmarc": None, "dkim_selector": None, "findings": []}
    try:
        try:
            for r in dns.resolver.resolve(domain, "TXT"):
                txt = str(r)
                if "v=spf1" in txt:
                    results["spf"] = txt
                    if "~all" in txt:
                        results["findings"].append({"issue": "SPF usa ~all (softfail)", "severity": "BAIXO"})
                    break
            # BUG FIX: TXT existe mas nenhum registro e SPF -> tambem conta como ausente
            if not results["spf"]:
                results["findings"].append({"issue": "SPF ausente — vulneravel a email spoofing", "severity": "MEDIO"})
        except Exception:
            results["findings"].append({"issue": "SPF ausente — vulneravel a email spoofing", "severity": "MEDIO"})
        try:
            for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"):
                txt = str(r)
                if "v=DMARC1" in txt:
                    results["dmarc"] = txt
                    if "p=none" in txt:
                        results["findings"].append({"issue": "DMARC com p=none (sem enforcement)", "severity": "MEDIO"})
                    break
            # BUG FIX: TXT existe em _dmarc mas nenhum registro e DMARC -> tambem conta como ausente
            if not results["dmarc"]:
                results["findings"].append({"issue": "DMARC ausente — sem protecao contra spoofing", "severity": "MEDIO"})
        except Exception:
            results["findings"].append({"issue": "DMARC ausente — sem protecao contra spoofing", "severity": "MEDIO"})
        for sel in ["default", "google", "mail", "dkim", "k1", "s1", "s2", "selector1", "selector2"]:
            try:
                dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
                results["dkim_selector"] = sel
                break
            except Exception:
                continue
        if not results["dkim_selector"]:
            results["findings"].append({"issue": "Nenhum seletor DKIM encontrado", "severity": "INFO"})
    except Exception as e:
        vprint(2, f"[WARN] check_email_security: {e}")
    return results


# ==================================================================
# FUNÇÕES — Descoberta de IP real por tras de CDN/WAF
# ==================================================================
def is_cloudflare_ip(ip: str, ranges: dict[str, list] | None = None) -> bool:
    """Verifica se um IP esta dentro dos ranges publicos do Cloudflare."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    ranges = ranges or {"v4": CLOUDFLARE_IPV4_RANGES, "v6": CLOUDFLARE_IPV6_RANGES}
    cidrs = ranges["v4"] if ip_obj.version == 4 else ranges["v6"]
    for cidr in cidrs:
        try:
            if ip_obj in ipaddress.ip_network(cidr):
                return True
        except ValueError:
            continue
    return False


def get_cloudflare_ranges() -> dict[str, list[str]]:
    """Busca a lista atualizada de ranges do Cloudflare via API oficial
    (cloudflare.com/ips-v4 e ips-v6); cai para a lista embutida se nao
    houver rede ou o formato mudar. Os ranges podem ficar desatualizados
    com o tempo, entao prefere sempre a versao ao vivo quando possivel."""
    ranges = {"v4": list(CLOUDFLARE_IPV4_RANGES), "v6": list(CLOUDFLARE_IPV6_RANGES)}
    try:
        r4 = state._SESSION.get("https://www.cloudflare.com/ips-v4", timeout=8)
        if r4.status_code == 200:
            live_v4 = [l.strip() for l in r4.text.splitlines() if l.strip() and "/" in l]
            if live_v4:
                ranges["v4"] = live_v4
        r6 = state._SESSION.get("https://www.cloudflare.com/ips-v6", timeout=8)
        if r6.status_code == 200:
            live_v6 = [l.strip() for l in r6.text.splitlines() if l.strip() and "/" in l]
            if live_v6:
                ranges["v6"] = live_v6
    except Exception as e:
        vprint(2, f"[WARN] get_cloudflare_ranges: {e} — usando lista embutida")
    return ranges


def find_real_ip(domain: str, subdomains: list[str] | None = None) -> dict:
    """Tenta descobrir o IP de origem REAL por tras de um CDN/WAF (Cloudflare
    e o mais comum), usando so tecnicas passivas de DNS/enumeracao:

      1. Resolve o dominio principal e verifica se o IP esta nos ranges do CF.
      2. Resolve cada subdominio ja conhecido (de crt.sh/bruteforce DNS) — um
         subdominio esquecido (mail, dev, staging antigo, cpanel, ftp...)
         frequentemente NAO passa pelo proxy do CDN e aponta direto pro
         servidor de origem.
      3. Extrai IPs declarados no registro SPF (mecanismo ip4:/ip6:) — o
         servidor de email quase nunca fica atras do proxy HTTP do CDN.

    Isso e reconhecimento passivo (so consultas DNS/HTTP normais), nao um
    ataque — nao tenta conectar nem validar o IP candidato contra o site,
    so aponta os candidatos pra confirmacao manual do pentester.
    """
    result: dict = {
        "dominio_atras_de_cdn": False, "cdn_detectado": None,
        "ip_principal": None, "candidatos": [], "fonte_ranges": "embutida",
    }
    ranges = get_cloudflare_ranges()
    if ranges["v4"] != CLOUDFLARE_IPV4_RANGES:
        result["fonte_ranges"] = "API oficial (atualizada)"

    main_ip = resolve_host(domain)
    result["ip_principal"] = main_ip
    if main_ip and is_cloudflare_ip(main_ip, ranges):
        result["dominio_atras_de_cdn"] = True
        result["cdn_detectado"] = "Cloudflare"

    seen_ips: set[str] = {main_ip} if main_ip else set()
    for sub in (subdomains or []):
        ip = resolve_host(sub)
        if not ip or ip in seen_ips:
            continue
        seen_ips.add(ip)
        if not is_cloudflare_ip(ip, ranges):
            result["candidatos"].append({
                "subdominio": sub, "ip": ip,
                "motivo": "subdominio nao esta atras do Cloudflare (possivel origem real)",
            })

    try:
        email_sec = check_email_security(domain)
        spf = email_sec.get("spf") or ""
        for m in re.findall(r"ip4:(\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?)", spf):
            result["candidatos"].append({
                "subdominio": f"(SPF de {domain})", "ip": m,
                "motivo": "declarado no registro SPF — servidor de email raramente fica atras do CDN",
            })
        for m in re.findall(r"ip6:([0-9a-fA-F:]+(?:/\d+)?)", spf):
            result["candidatos"].append({
                "subdominio": f"(SPF de {domain})", "ip": m,
                "motivo": "declarado no registro SPF (IPv6)",
            })
    except Exception as e:
        vprint(2, f"[WARN] find_real_ip SPF: {e}")

    return result


# ==================================================================
# FUNÇÕES — Subdomain Takeover
# ==================================================================
def check_subdomain_takeover(subdomains: list[str]) -> list[dict]:
    """Verifica fingerprints de takeover em cada subdomínio."""
    findings: list[dict] = []
    for sub in subdomains:
        for scheme in ("https", "http"):
            try:
                r = state._SESSION.get(
                    f"{scheme}://{sub}", timeout=10,
                    headers=get_random_headers(), allow_redirects=True,
                    proxies=get_proxies()
                )
                for service, fp in TAKEOVER_FINGERPRINTS.items():
                    if fp.lower() in r.text.lower():
                        findings.append({
                            "subdomain": sub, "service": service,
                            "status": "VULNERAVEL", "severity": "ALTO"
                        })
                        break
                break
            except Exception as e:
                vprint(2, f"[WARN] takeover {sub}: {e}")
    return findings


# ==================================================================
# FUNÇÕES — Secrets em JavaScript
# ==================================================================
def _shannon_entropy(s: str) -> float:
    """Calcula a entropia de Shannon (bits por caractere) de uma string.
    Segredos de verdade (chaves, tokens) tendem a ter entropia alta (valores
    quase aleatorios); placeholders e texto comum ('changeme', 'sua_senha')
    tem entropia baixa. Usado para filtrar falso positivo nos patterns
    genericos de secret."""
    if not s:
        return 0.0
    from collections import Counter
    import math
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


_PLACEHOLDER_MARKERS = (
    "xxx", "example", "changeme", "change_me", "your_", "your-", "placeholder",
    "dummy", "sample", "todo", "fixme", "insert", "replace", "enter_", "enter-",
    "senha_aqui", "sua_senha", "sua-senha", "test123", "123456", "password123",
    "secret_here", "api_key_here", "apikey_here", "0000000000", "1111111111",
    "abcdefgh", "qwerty", "asdfgh", "null", "undefined", "none", "n/a",
)


def _looks_like_placeholder(value: str) -> bool:
    """Verifica se um valor capturado parece placeholder/exemplo em vez de
    segredo real — reduz falso positivo dos patterns genericos."""
    low = value.lower()
    if any(marker in low for marker in _PLACEHOLDER_MARKERS):
        return True
    if len(set(low)) <= 2:  # ex: "aaaaaaaa" ou "ababababab"
        return True
    return False


def scan_js_for_secrets(js_urls: list[str]) -> list[dict]:
    """Escaneia arquivos JS em busca de secrets e credenciais.

    Se jsbeautifier estiver disponivel, desofusca/formata o JS minificado
    antes de rodar os patterns — codigo minificado em uma linha as vezes
    esconde secrets que regex multiline padrao perderia.

    Os patterns genericos (que capturam qualquer 'api_key: "..."' ou
    'password: "..."') passam por um filtro de entropia + placeholder antes
    de virar achado — sem isso, texto de exemplo/config publica gera muito
    falso positivo.
    """
    findings: list[dict] = []
    extra_patterns = {
        "JSON Secret Inline": r'["\'](?:api[_-]?key|secret|password|token|auth)["\']\s*:\s*["\']([A-Za-z0-9_\-]{16,})["\']',
    }
    generic_patterns = {"API Key generica", "Password hardcoded", "JSON Secret Inline"}
    seen_overall: set[tuple[str, str]] = set()

    for url in js_urls:
        try:
            r = state._SESSION.get(url, timeout=10, headers=get_random_headers(),
                             proxies=get_proxies())
            if r.status_code != 200:
                continue
            content = r.text
            if JSBEAUTIFIER_AVAILABLE and len(content) < 500_000:
                try:
                    content = jsbeautifier.beautify(content)
                except Exception:
                    pass
            for secret_type, pattern in {**SECRET_PATTERNS, **extra_patterns}.items():
                matches = re.findall(pattern, content)
                for match in matches[:5]:
                    val = match if isinstance(match, str) else (match[-1] if match else "")
                    if not val:
                        continue
                    if secret_type in generic_patterns:
                        if _looks_like_placeholder(val) or _shannon_entropy(val) < 3.0:
                            continue
                    dedup_key = (secret_type, val)
                    if dedup_key in seen_overall:
                        continue
                    seen_overall.add(dedup_key)
                    findings.append({
                        "url": url, "tipo": secret_type,
                        "valor": val[:80] + "..." if len(val) > 80 else val,
                        "severity": "ALTO"
                    })
        except Exception as e:
            vprint(2, f"[WARN] scan_js_for_secrets {url}: {e}")
    return findings


# ==================================================================
# FUNÇÕES — CORS
# ==================================================================
def check_cors(urls: list[str], limit: int = 30) -> list[dict]:
    """Detecta CORS misconfigurations."""
    findings: list[dict] = []
    tested_bases: set[str] = set()
    for url in urls[:limit]:
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            if base in tested_bases:
                continue
            tested_bases.add(base)
            for origin in ["https://evil.com", "null", f"https://evil.{parsed.netloc}"]:
                try:
                    r = state._SESSION.get(
                        url, timeout=10,
                        headers={**get_random_headers(), "Origin": origin},
                        proxies=get_proxies()
                    )
                    acao = r.headers.get("Access-Control-Allow-Origin", "")
                    acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
                    if acao in (origin, "*"):
                        severity = "CRITICO" if (acac == "true" and acao != "*") else "MEDIO"
                        findings.append({
                            "url": url, "origin_testada": origin, "acao": acao,
                            "credentials": acac, "severity": severity
                        })
                        break
                except Exception as e:
                    vprint(2, f"[WARN] check_cors {url}: {e}")
        except Exception as e:
            vprint(2, f"[WARN] check_cors outer: {e}")
    return findings


# ==================================================================
# FUNÇÕES — Security Headers
# ==================================================================
def check_security_headers(url: str) -> list[dict]:
    """Verifica presença de security headers no alvo."""
    findings: list[dict] = []
    try:
        r = state._SESSION.get(url, headers=get_random_headers(), timeout=10,
                         allow_redirects=True, proxies=get_proxies())
        for header, info in SECURITY_HEADERS.items():
            if header not in r.headers:
                findings.append({
                    "header": header, "status": "AUSENTE",
                    "severity": info["severity"], "desc": info["desc"]
                })
    except Exception as e:
        vprint(2, f"[WARN] check_security_headers: {e}")
    return findings


# ==================================================================
# FUNÇÕES — HTTP Methods
# ==================================================================
def probe_http_methods(urls: list[str], limit: int = 20) -> list[dict]:
    """Sonda métodos HTTP perigosos habilitados."""
    findings: list[dict] = []
    for url in urls[:limit]:
        try:
            r = state._SESSION.options(
                url, timeout=8, headers=get_random_headers(), proxies=get_proxies()
            )
            allow = r.headers.get("Allow", "")
            dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow.upper()]
            if dangerous:
                findings.append({
                    "url": url, "methods_allowed": allow,
                    "dangerous": dangerous, "severity": "MEDIO"
                })
        except Exception as e:
            vprint(2, f"[WARN] probe_http_methods {url}: {e}")
    return findings


# ==================================================================
# FUNÇÕES — Robots.txt e Sitemap
# ==================================================================
def fetch_robots_and_sitemap(base_url: str) -> dict:
    """Coleta paths de robots.txt e URLs de sitemap.xml."""
    result: dict = {
        "robots_disallowed": [], "robots_allowed": [],
        "sitemap_urls": [], "raw_robots": ""
    }
    domain = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
    try:
        r = state._SESSION.get(f"{domain}/robots.txt", timeout=10,
                         headers=get_random_headers(), proxies=get_proxies())
        if r.status_code == 200 and "text" in r.headers.get("Content-Type", ""):
            result["raw_robots"] = r.text
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        result["robots_disallowed"].append(f"{domain}{path}")
                elif line.lower().startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        result["robots_allowed"].append(f"{domain}{path}")
                elif line.lower().startswith("sitemap:"):
                    result["sitemap_urls"].append(line.split(":", 1)[1].strip())
    except Exception as e:
        vprint(2, f"[WARN] fetch_robots_and_sitemap robots: {e}")

    if not result["sitemap_urls"]:
        for sitemap_path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"]:
            try:
                r = state._SESSION.get(f"{domain}{sitemap_path}", timeout=10,
                                 headers=get_random_headers(), proxies=get_proxies())
                if r.status_code == 200:
                    result["sitemap_urls"].append(f"{domain}{sitemap_path}")
                    locs = re.findall(r"<loc>(.*?)</loc>", r.text)
                    result["sitemap_urls"].extend(locs[:200])
                    break
            except Exception as e:
                vprint(2, f"[WARN] fetch_robots_and_sitemap sitemap: {e}")
    return result


# ==================================================================
# FUNÇÕES — Open Redirect
# ==================================================================
def check_open_redirect(urls: list[str]) -> list[dict]:
    """Testa parâmetros de redirect com payload evil.com."""
    findings: list[dict] = []
    test_url = "https://evil.com/raveneye-openredirect"
    for url in urls:
        try:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            params = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)
            for param in REDIRECT_PARAMS:
                if param in params:
                    crafted = (
                        f"{parsed.scheme}://{parsed.netloc}{parsed.path}?"
                        + "&".join(
                            f"{k}={test_url if k == param else v}"
                            for k, v in params.items()
                        )
                    )
                    try:
                        r = state._SESSION.get(
                            crafted, timeout=8, allow_redirects=False,
                            headers=get_random_headers(), proxies=get_proxies()
                        )
                        loc = r.headers.get("Location", "")
                        if "evil.com" in loc:
                            findings.append({
                                "url": url, "param": param,
                                "payload": crafted, "location": loc,
                                "severity": "MEDIO"
                            })
                            break
                    except Exception as e:
                        vprint(2, f"[WARN] open_redirect req {url}: {e}")
        except Exception as e:
            vprint(2, f"[WARN] check_open_redirect: {e}")
    return findings


# ==================================================================
# FUNÇÕES — Directory Listing
# ==================================================================
def check_directory_listing(urls: list[str]) -> list[str]:
    """Detecta directory listing habilitado."""
    indicators = [
        "Index of /", "Directory listing for", "Parent Directory",
        "[PARENTDIR]", "<title>Index of", "Last modified</a>"
    ]
    findings: list[str] = []
    for url in urls:
        check_url = url if url.endswith("/") else url + "/"
        try:
            r = state._SESSION.get(check_url, timeout=8, headers=get_random_headers(),
                             proxies=get_proxies())
            if r.status_code == 200 and any(i in r.text for i in indicators):
                findings.append(check_url)
        except Exception as e:
            vprint(2, f"[WARN] check_directory_listing {url}: {e}")
    return findings


# ==================================================================
# FUNÇÕES — Error Disclosure
# ==================================================================
def check_error_disclosure(urls: list[str]) -> list[dict]:
    """Detecta stack traces e mensagens de erro em respostas HTTP."""
    findings: list[dict] = []
    for url in urls:
        try:
            r = state._SESSION.get(url, timeout=8, headers=get_random_headers(),
                             proxies=get_proxies())
            for error_type, pattern in ERROR_PATTERNS.items():
                m = re.search(pattern, r.text)
                if m:
                    findings.append({
                        "url": url, "tipo": error_type,
                        "snippet": m.group(0)[:100], "severity": "MEDIO"
                    })
                    break
        except Exception as e:
            vprint(2, f"[WARN] check_error_disclosure {url}: {e}")
    return findings


# ==================================================================
# FUNÇÕES — SSL/TLS
# ==================================================================
def check_ssl_cert(domain: str) -> dict:
    """Verifica validade e informações do certificado SSL."""
    result: dict = {
        "valid": False, "expiry": None, "issuer": None,
        "subject": None, "san": [], "findings": []
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            result["valid"] = True
            result["subject"] = dict(x[0] for x in cert.get("subject", []))
            result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
            san_list = [v for _, v in cert.get("subjectAltName", [])]
            result["san"] = san_list
            expiry = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            result["expiry"] = expiry.isoformat()
            days_left = (expiry - datetime.datetime.utcnow()).days
            if days_left < 0:
                result["findings"].append({"issue": "Certificado EXPIRADO", "severity": "ALTO"})
            elif days_left < 30:
                result["findings"].append({"issue": f"Certificado expira em {days_left} dias", "severity": "MEDIO"})
    except ssl.SSLCertVerificationError as e:
        result["findings"].append({"issue": f"Certificado invalido: {e}", "severity": "ALTO"})
    except Exception as e:
        vprint(2, f"[WARN] check_ssl_cert {domain}: {e}")
    return result


# ==================================================================
# FUNÇÕES — Outdated versions
# ==================================================================
def check_outdated_versions(headers: dict) -> list[dict]:
    """Detecta versões desatualizadas de software nos headers HTTP."""
    findings: list[dict] = []
    all_headers = " ".join(str(v) for v in headers.values())
    for pattern, info in OUTDATED_VERSIONS.items():
        m = re.search(pattern, all_headers)
        if m:
            findings.append({
                "software": info["name"],
                "version_detected": m.group(1),
                "safe_from": info["safe_from"],
                "severity": "MEDIO",
                "note": f"Verificar CVEs para {info['name']} {m.group(1)}"
            })
    return findings


# ==================================================================
# FUNÇÕES — Web Cache Poisoning
# ==================================================================
def check_web_cache_poisoning(urls: list[str], limit: int = 15) -> list[dict]:
    """Testa reflexao de headers incomuns (candidatos a chave de cache) no corpo
    da resposta — indicativo de possivel Web Cache Poisoning se a resposta
    envenenada puder ser servida a outros usuarios via cache/CDN."""
    findings: list[dict] = []
    probes = [
        ("X-Forwarded-Host", "raveneye-cachetest.invalid"),
        ("X-Forwarded-Scheme", "raveneye-cachetest"),
        ("X-Original-URL", "/raveneye-cachetest"),
    ]
    tested: set[str] = set()
    for url in urls[:limit]:
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        if base in tested:
            continue
        tested.add(base)
        for header, marker in probes:
            try:
                r = state._SESSION.get(
                    url, timeout=10, headers={**get_random_headers(), header: marker},
                    proxies=get_proxies()
                )
                if marker in r.text:
                    findings.append({
                        "url": url, "header": header, "marker": marker,
                        "severity": "ALTO",
                        "note": f"Header {header} refletido no corpo — possivel cache poisoning "
                                f"se esta resposta puder ser cacheada e servida a outros usuarios",
                    })
            except Exception as e:
                vprint(2, f"[WARN] check_web_cache_poisoning {url}: {e}")
    return findings


# ==================================================================
# FUNÇÕES — HTTP Request Smuggling (heuristico)
# ==================================================================
def check_http_request_smuggling(url: str, timeout: int = 8) -> list[dict]:
    """Testa (heuristicamente) sinais de HTTP Request Smuggling (CL.TE / TE.CL).

    Usa socket raw em vez de 'requests' porque bibliotecas HTTP de alto nivel
    recalculam Content-Length automaticamente e nao permitem enviar combinacoes
    conflitantes de framing. Deteccao heuristica por timing: se o backend fica
    esperando bytes extras do corpo, a resposta atrasa de forma anormal.
    Resultado NAO e confirmacao definitiva — recomenda-se validar manualmente.
    """
    findings: list[dict] = []
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return findings
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"

    probes = [
        ("CL.TE", (
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n\r\n0\r\n\r\nX"
        )),
        ("TE.CL", (
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n\r\n5c\r\nGET /raveneye404 HTTP/1.1\r\nHost: x\r\n\r\n0\r\n\r\n"
        )),
    ]

    for technique, payload in probes:
        sock = None
        try:
            start = time.time()
            raw = socket.create_connection((host, port), timeout=timeout)
            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(raw, server_hostname=host)
            else:
                sock = raw
            sock.settimeout(timeout)
            sock.sendall(payload.encode())
            try:
                sock.recv(4096)
            except socket.timeout:
                pass
            elapsed = time.time() - start
            if elapsed >= timeout * 0.9:
                findings.append({
                    "url": url, "technique": technique, "severity": "ALTO",
                    "note": f"Resposta atrasou ~{elapsed:.1f}s — possivel {technique} smuggling "
                            f"(heuristico via timing, confirmar manualmente antes de reportar)",
                })
        except Exception as e:
            vprint(2, f"[WARN] check_http_request_smuggling {technique}: {e}")
        finally:
            if sock:
                with suppress(Exception):
                    sock.close()
    return findings


def _extract_jwt_from_response(r: requests.Response) -> list[str]:
    """Extrai possiveis tokens JWT de cookies e do header Authorization."""
    tokens: list[str] = []
    for cookie in r.cookies:
        if cookie.value.count(".") == 2:
            tokens.append(cookie.value)
    auth = r.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and auth[7:].count(".") == 2:
        tokens.append(auth[7:])
    return tokens


def check_jwt_weaknesses(url: str) -> list[dict]:
    """Verifica tokens JWT encontrados na resposta por fraquezas comuns:
    'alg: none' aceito e secrets HMAC fracos/default (lista curta e conhecida,
    equivalente ao que ferramentas como jwt_tool usam para checagem rapida
    de misconfig — nao e um bruteforce de proposito geral). Requer PyJWT.
    """
    findings: list[dict] = []
    if not PYJWT_AVAILABLE:
        return findings
    try:
        r = state._SESSION.get(url, timeout=10, headers=get_random_headers(), proxies=get_proxies())
    except Exception as e:
        vprint(2, f"[WARN] check_jwt_weaknesses request: {e}")
        return findings

    for token in _extract_jwt_from_response(r):
        try:
            pad = "=" * (-len(token.split(".")[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + pad))
        except Exception:
            continue
        alg = str(header.get("alg", ""))
        if alg.lower() == "none":
            findings.append({
                "url": url, "issue": "alg: none aceito", "severity": "CRITICO",
                "token_preview": token[:20] + "...",
                "note": "Token pode ser forjado sem assinatura valida se o backend aceitar alg=none",
            })
            continue
        if alg.upper().startswith("HS"):
            for secret in _JWT_COMMON_SECRETS:
                try:
                    _pyjwt.decode(token, secret, algorithms=[alg])
                    findings.append({
                        "url": url, "issue": "Secret HMAC fraco/default", "severity": "ALTO",
                        "token_preview": token[:20] + "...",
                        "note": f"Token assinado com secret comum: '{secret}'",
                    })
                    break
                except Exception:
                    continue
    return findings


# ==================================================================
# FUNÇÕES — VirusTotal
# ==================================================================
def check_virustotal(url_or_domain: str, api_key: str) -> dict:
    """Consulta VirusTotal API v3 para uma URL/dominio. Requer API key
    (gratuita em virustotal.com, configuravel no menu Configuracoes)."""
    if not api_key:
        return {"error": "VirusTotal API key nao configurada"}
    try:
        url_id = base64.urlsafe_b64encode(url_or_domain.encode()).decode().rstrip("=")
        r = state._SESSION.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key}, timeout=20, proxies=get_proxies()
        )
        if r.status_code == 404:
            r2 = state._SESSION.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": api_key},
                data={"url": url_or_domain}, timeout=20, proxies=get_proxies()
            )
            if r2.status_code in (200, 201):
                return {"status": "submetido", "nota": "Analise em andamento, consulte novamente em instantes"}
            return {"error": f"HTTP {r2.status_code} ao submeter para analise"}
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "maliciosos": stats.get("malicious", 0),
                "suspeitos": stats.get("suspicious", 0),
                "inofensivos": stats.get("harmless", 0),
                "nao_detectados": stats.get("undetected", 0),
                "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
            }
        return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        vprint(2, f"[WARN] check_virustotal: {e}")
        return {"error": str(e)}


def check_virustotal_domain(domain: str, api_key: str) -> dict:
    """Consulta VirusTotal API v3 para reputacao de um dominio (endpoint
    /domains/, diferente do endpoint de URL — traz dados de DNS, categorias
    e reputacao historica do dominio como um todo)."""
    if not api_key:
        return {"error": "VirusTotal API key nao configurada"}
    try:
        r = state._SESSION.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": api_key}, timeout=20, proxies=get_proxies()
        )
        if r.status_code == 200:
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "maliciosos": stats.get("malicious", 0),
                "suspeitos": stats.get("suspicious", 0),
                "inofensivos": stats.get("harmless", 0),
                "nao_detectados": stats.get("undetected", 0),
                "reputacao": attrs.get("reputation", "N/A"),
                "categorias": list(attrs.get("categories", {}).values()),
                "permalink": f"https://www.virustotal.com/gui/domain/{domain}",
            }
        if r.status_code == 404:
            return {"error": "Dominio nao encontrado na base do VirusTotal"}
        return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        vprint(2, f"[WARN] check_virustotal_domain: {e}")
        return {"error": str(e)}


def check_virustotal_ip(ip: str, api_key: str) -> dict:
    """Consulta VirusTotal API v3 para reputacao de um IP (endpoint
    /ip_addresses/ — traz ASN, pais, provedor e reputacao historica do IP)."""
    if not api_key:
        return {"error": "VirusTotal API key nao configurada"}
    try:
        r = state._SESSION.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key}, timeout=20, proxies=get_proxies()
        )
        if r.status_code == 200:
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "maliciosos": stats.get("malicious", 0),
                "suspeitos": stats.get("suspicious", 0),
                "inofensivos": stats.get("harmless", 0),
                "nao_detectados": stats.get("undetected", 0),
                "asn": attrs.get("asn", "N/A"),
                "as_owner": attrs.get("as_owner", "N/A"),
                "pais": attrs.get("country", "N/A"),
                "reputacao": attrs.get("reputation", "N/A"),
                "permalink": f"https://www.virustotal.com/gui/ip-address/{ip}",
            }
        if r.status_code == 404:
            return {"error": "IP nao encontrado na base do VirusTotal"}
        return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        vprint(2, f"[WARN] check_virustotal_ip: {e}")
        return {"error": str(e)}


# ==================================================================
# FUNÇÕES — vulnerability scan
# ==================================================================
def vulnerability_scan(urls: list[str], domain: str) -> dict:
    """Classifica URLs por categoria de vulnerabilidade."""
    patterns: dict[str, list[str]] = {
        "exposed_admin": [r"/admin", r"/administrator", r"/login", r"/wp-admin", r"/cpanel"],
        "backup_files": [r"\.bak$", r"\.old$", r"\.sql$", r"\.dump$", r"backup", r"\.env$", r"\.git/"],
        "debug_panels": [r"/debug", r"/test", r"/dev", r"/staging", r"/beta", r"/phpinfo"],
        "sensitive_endpoints": [r"/api/v[0-9]", r"/graphql", r"/swagger", r"/config", r"/settings"],
        "info_disclosure": [r"/server-status", r"/phpmyadmin", r"/mysql", r"/database", r"/logs?$"],
    }
    findings: dict[str, list[str]] = {k: [] for k in patterns}
    for url in urls:
        u = url.lower()
        for cat, regexes in patterns.items():
            for regex in regexes:
                if re.search(regex, u):
                    findings[cat].append(url)
                    break
    return {k: list(set(v)) for k, v in findings.items()}
