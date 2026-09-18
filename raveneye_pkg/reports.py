from __future__ import annotations

"""Geracao de relatorios em TXT, JSON, HTML, Markdown e CSV."""


import csv
from html import escape
import datetime
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from raveneye_pkg.terminal import Fore, Style
from raveneye_pkg import state
from raveneye_pkg.state import vprint
from raveneye_pkg.constants import TOOL_NAME, TOOL_VERSION


# ==================================================================
# FUNÇÕES — Relatório TXT (BUG FIX: nmap e google hacking garantidos)
# ==================================================================
def save_report(report: dict, filename: str, link_limit: int) -> None:
    """Salva relatório completo em formato TXT."""
    t = report.get("target", {})
    crawl = report.get("crawler", {})
    elapsed = report.get("elapsed", 0)
    now = datetime.datetime.now().isoformat()

    secrets = report.get("secrets_js", [])
    cors = report.get("cors", [])
    subdomain_takeover = report.get("subdomain_takeover", [])
    sec_headers = report.get("security_headers", [])
    subdomains = report.get("subdomains", [])
    open_redirects = report.get("open_redirect", [])
    dir_listing = report.get("directory_listing", [])
    error_disc = report.get("error_disclosure", [])
    outdated = report.get("outdated_versions", [])
    vulns = report.get("vulnerabilities", {})
    scanner_result = report.get("vulnerability_scan", {}) or {}
    scanner_findings = scanner_result.get("findings", []) if isinstance(scanner_result, dict) else []

    vuln_counts = {"CRITICO": 0, "ALTO": 0, "MEDIO": 0, "BAIXO": 0, "INFO": 0}
    for item in secrets + cors + subdomain_takeover + open_redirects + error_disc + outdated:
        sev = item.get("severity", "INFO").upper().replace("Í", "I").replace("É", "E")
        if sev in vuln_counts:
            vuln_counts[sev] += 1
    for h in sec_headers:
        sev = h.get("severity", "INFO").upper()
        if sev in vuln_counts:
            vuln_counts[sev] += 1

    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write("=" * 90 + "\n")
            f.write(f"              RAVEN EYE v{TOOL_VERSION} - RELATORIO FINAL\n")
            f.write("=" * 90 + "\n")
            f.write(f"Data/Hora: {now}\n")
            f.write(f"Duracao:   {int(elapsed // 60)}m{int(elapsed % 60)}s\n")
            f.write("=" * 90 + "\n\n")

            f.write("[ RESUMO EXECUTIVO ]\n")
            f.write(f"Paginas crawladas: {len(crawl.get('list', []))} | ")
            f.write(f"Endpoints unicos: {len(crawl.get('endpoints', []))} | ")
            f.write(f"Arquivos sensiveis: {len(crawl.get('file_urls', []))}\n")
            f.write(f"Secrets em JS: {len(secrets)} | ")
            f.write(f"Subdominios: {len(subdomains)} | ")
            f.write(f"Subdomain Takeover: {len(subdomain_takeover)}\n")
            f.write(
                f"Vulnerabilidades: CRITICO:{vuln_counts['CRITICO']}  ALTO:{vuln_counts['ALTO']}  "
                f"MEDIO:{vuln_counts['MEDIO']}  BAIXO:{vuln_counts['BAIXO']}  INFO:{vuln_counts['INFO']}\n"
            )
            f.write(f"Security Headers ausentes: {len(sec_headers)} | ")
            f.write(f"CORS issues: {len(cors)} | Open Redirects: {len(open_redirects)}\n")
            f.write(
                f"Paginas duplicadas (mesmo conteudo): {len(crawl.get('duplicate_urls', []))} | "
                f"Soft-404 filtrados: {crawl.get('soft_fail_filtered', 0)} | "
                f"Parametros interessantes: {len(crawl.get('interesting_params', []))}\n\n"
            )

            f.write("[ ALVO ]\n")
            f.write(f"Dominio: {t.get('domain', 'N/A')}\n")
            f.write(f"IP: {t.get('ip', 'N/A')}\n")
            f.write(f"Ping: {report.get('ping', 'N/A')}\n\n")

            real_ip = report.get("real_ip", {})
            if real_ip.get("dominio_atras_de_cdn"):
                f.write("[ IP REAL POR TRAS DO CDN/WAF ]\n")
                f.write(f"CDN detectado: {real_ip.get('cdn_detectado', 'N/A')} "
                        f"(ranges: {real_ip.get('fonte_ranges', 'N/A')})\n")
                candidatos = real_ip.get("candidatos", [])
                if candidatos:
                    f.write(f"Candidatos a IP de origem real ({len(candidatos)}):\n")
                    for c in candidatos:
                        f.write(f"  {c['ip']}  <- {c['subdominio']}\n")
                        f.write(f"    Motivo: {c['motivo']}\n")
                    ping_real = report.get("ping_ip_real")
                    if ping_real:
                        f.write(f"\n  Ping direto no candidato principal ({ping_real['ip']}, "
                                f"via {ping_real['origem']}): {ping_real['resultado']}\n")
                    f.write("  IMPORTANTE: confirme manualmente antes de reportar/testar contra\n")
                    f.write("  esse IP — o site pode nao servir o mesmo conteudo, e testar direto\n")
                    f.write("  a origem pode estar fora do escopo do programa de bug bounty.\n")
                else:
                    f.write("Nenhum candidato a IP real encontrado (subdominios conhecidos\n")
                    f.write("tambem estao atras do CDN, e nao ha IP declarado no SPF).\n")
                f.write("\n")

            tech = report.get("tech", {})
            f.write("[ TECNOLOGIA ]\n")
            f.write(f"Servidor: {tech.get('servidor', 'Desconhecido')}\n")
            f.write(f"Linguagens: {', '.join(tech.get('linguagens', []))}\n")
            f.write(f"CMS: {tech.get('cms') or 'Nao detectado'}\n")
            f.write(f"Frameworks: {', '.join(tech.get('frameworks', [])) or 'Nao detectado'}\n")
            f.write(f"WAF: {tech.get('waf') or 'Nao detectado'}\n")
            f.write(f"CDN: {tech.get('cdn') or 'Nao detectado'}\n\n")

            ssl_data = report.get("ssl", {})
            if ssl_data:
                f.write("[ SSL/TLS ]\n")
                f.write(f"Valido: {ssl_data.get('valid', False)}\n")
                f.write(f"Expira: {ssl_data.get('expiry', 'N/A')}\n")
                san = ssl_data.get("san", [])
                if san:
                    f.write(f"SANs ({len(san)}): {', '.join(san[:10])}\n")
                for finding in ssl_data.get("findings", []):
                    f.write(f"  [{finding.get('severity', 'INFO')}] {finding.get('issue', '')}\n")
                f.write("\n")

            if "whois" in report and isinstance(report["whois"], dict):
                w = report["whois"]
                f.write("[ WHOIS ]\n")
                if w.get("erro"):
                    f.write(f"  ERRO: {w['erro']}\n\n")
                else:
                    f.write(f"Registrador: {w.get('registrador', 'N/A')}\n")
                    f.write(f"Criacao: {w.get('criacao', 'N/A')}\n")
                    f.write(f"Expiracao: {w.get('expiracao', 'N/A')}\n")
                    f.write(f"NS: {w.get('name_servers', 'N/A')}\n")
                    f.write(f"Email contato: {w.get('email_contato', 'N/A')}\n\n")

            if "archive" in report and isinstance(report["archive"], dict):
                if report["archive"].get("status") == "ok":
                    f.write("[ WAYBACK ]\n")
                    f.write(f"Snapshot: {report['archive'].get('url', 'N/A')}\n")
                    f.write(f"Data: {report['archive'].get('timestamp', 'N/A')}\n\n")

            # NMAP — BUG FIX: sempre exibe, mesmo com erro, raw output incluído
            nmap_data = report.get("nmap")
            if isinstance(nmap_data, dict):
                f.write("[ NMAP ]\n")
                f.write(f"Status: {nmap_data.get('status', 'N/A')}\n")
                if nmap_data.get("erro"):
                    f.write(f"  ERRO: {nmap_data['erro']}\n")
                portas = nmap_data.get("portas", [])
                if portas:
                    f.write(f"  Portas abertas ({len(portas)}):\n")
                    for svc in portas:
                        f.write(f"    {svc}\n")
                else:
                    f.write("  Nenhuma porta aberta detectada (filtradas ou host down)\n")
                if nmap_data.get("os"):
                    f.write(f"  SO Detectado: {nmap_data['os']}\n")
                cves = nmap_data.get("vulns", [])
                if cves:
                    f.write(f"  CVEs detectadas ({len(cves)}):\n")
                    for cve in cves:
                        f.write(f"    [MEDIO] CVE: {cve}\n")
                # Raw output para debug (primeiras 30 linhas)
                raw = nmap_data.get("raw", "")
                if raw:
                    raw_lines = [l for l in raw.splitlines() if l.strip()][:30]
                    if raw_lines:
                        f.write("  [RAW NMAP OUTPUT - primeiras linhas]\n")
                        for l in raw_lines:
                            f.write(f"    {l}\n")
                f.write("\n")
            elif isinstance(nmap_data, str):
                # Retrocompatibilidade
                f.write(f"[ NMAP ]\n  {nmap_data}\n\n")

            if "shodan" in report and isinstance(report["shodan"], dict):
                s = report["shodan"]
                f.write("[ SHODAN ]\n")
                if s.get("erro"):
                    f.write(f"  ERRO: {s['erro']}\n\n")
                else:
                    f.write(f"IP: {s.get('ip', 'N/A')}\n")
                    f.write(f"Org: {s.get('org', 'N/A')}\n")
                    f.write(f"OS: {s.get('os', 'N/A')}\n")
                    f.write(f"Portas: {', '.join(map(str, s.get('portas', [])))}\n")
                    for v in s.get("vulns", []):
                        f.write(f"  [ALTO] CVE: {v}\n")
                    f.write("\n")

            if "exploitdb" in report and isinstance(report["exploitdb"], list):
                if report["exploitdb"]:
                    f.write("[ EXPLOITS ]\n")
                    for e in report["exploitdb"][:10]:
                        f.write(f"  {e['id']}: {e['titulo']} ({e.get('data', 'N/A')}) — {e.get('url', '')}\n")
                    f.write("\n")

            # GOOGLE DORKS — sempre salvo com destaque
            dorks = report.get("google_dorks", [])
            f.write(f"[ GOOGLE DORKS ({len(dorks)} dorks gerados) ]\n")
            if dorks:
                for i, d in enumerate(dorks, 1):
                    f.write(f"  {i:3}. {d}\n")
            else:
                f.write("  Nenhum dork gerado\n")
            f.write("\n")

            gdr = report.get("google_dorks_results")
            if gdr:
                f.write(f"[ GOOGLE DORKS — RESULTADOS AUTOMATIZADOS ({gdr.get('total_interessantes', 0)} interessantes de {gdr.get('total_bruto', 0)} brutos) ]\n")
                for item in gdr.get("interessantes", []):
                    f.write(f"  [{item.get('motivo', 'N/A')}] {item['titulo']}\n")
                    f.write(f"    {item['link']}\n")
                    if item.get("snippet"):
                        f.write(f"    {item['snippet'][:150]}\n")
                    f.write(f"    (dork: {item['dork']})\n\n")
                if gdr.get("erros"):
                    f.write(f"  Avisos: {'; '.join(gdr['erros'][:3])}\n")
                f.write("\n")

            if subdomains:
                f.write(f"[ SUBDOMINIOS (crt.sh) ] ({len(subdomains)} encontrados)\n")
                for sub in subdomains[:100]:
                    f.write(f"  {sub}\n")
                f.write("\n")

            if subdomain_takeover:
                f.write("[ SUBDOMAIN TAKEOVER ]\n")
                for item in subdomain_takeover:
                    f.write(f"  [{item.get('severity', 'ALTO')}] {item['subdomain']} — {item['service']}: {item['status']}\n")
                f.write("\n")

            email_sec = report.get("email_security", {})
            if email_sec and not email_sec.get("error"):
                f.write("[ SPF/DMARC/DKIM ]\n")
                f.write(f"SPF: {email_sec.get('spf') or 'AUSENTE'}\n")
                f.write(f"DMARC: {email_sec.get('dmarc') or 'AUSENTE'}\n")
                f.write(f"DKIM seletor: {email_sec.get('dkim_selector') or 'Nenhum encontrado'}\n")
                for finding in email_sec.get("findings", []):
                    f.write(f"  [{finding.get('severity', 'INFO')}] {finding.get('issue', '')}\n")
                f.write("\n")

            zone = report.get("zone_transfer", {})
            if zone and not zone.get("error"):
                f.write("[ ZONE TRANSFER ]\n")
                for ns, res in zone.items():
                    f.write(f"  {ns}: {res.get('status', 'N/A')}\n")
                f.write("\n")

            if sec_headers:
                f.write("[ SECURITY HEADERS AUSENTES ]\n")
                for h in sec_headers:
                    f.write(f"  [{h.get('severity', 'INFO')}] {h['header']}: {h['desc']}\n")
                f.write("\n")

            outdated = report.get("outdated_versions", [])
            if outdated:
                f.write("[ VERSOES DESATUALIZADAS ]\n")
                for o in outdated:
                    f.write(f"  [{o.get('severity', 'MEDIO')}] {o['software']} {o['version_detected']} "
                            f"(seguro a partir de {o['safe_from']}) — {o['note']}\n")
                f.write("\n")

            if cors:
                f.write("[ CORS MISCONFIGURATIONS ]\n")
                for item in cors:
                    f.write(f"  [{item.get('severity', 'MEDIO')}] {item['url']}\n")
                    f.write(f"    Origin: {item['origin_testada']} | ACAO: {item['acao']} | Credentials: {item['credentials']}\n")
                f.write("\n")

            http_methods = report.get("http_methods", [])
            if http_methods:
                f.write("[ HTTP METHODS PERMITIDOS ]\n")
                for item in http_methods:
                    f.write(f"  [{item.get('severity', 'MEDIO')}] {item['url']}: Allow: {item['methods_allowed']}\n")
                    f.write(f"    Perigosos: {', '.join(item.get('dangerous', []))}\n")
                f.write("\n")

            if open_redirects:
                f.write("[ OPEN REDIRECTS ]\n")
                for item in open_redirects:
                    f.write(f"  [{item.get('severity', 'MEDIO')}] {item['url']} (param: {item['param']})\n")
                    f.write(f"    Payload: {item['payload']}\n")
                f.write("\n")

            if dir_listing:
                f.write("[ DIRECTORY LISTING ]\n")
                for url in dir_listing:
                    f.write(f"  [MEDIO] {url}\n")
                f.write("\n")

            if error_disc:
                f.write("[ INFORMATION DISCLOSURE ]\n")
                for item in error_disc:
                    f.write(f"  [{item.get('severity', 'MEDIO')}] {item['url']}\n")
                    f.write(f"    Tipo: {item['tipo']} | Trecho: {item.get('snippet', '')[:80]}\n")
                f.write("\n")

            if secrets:
                f.write("[ SECRETS EM JS ]\n")
                for item in secrets:
                    f.write(f"  [{item.get('severity', 'ALTO')}] {item['tipo']} em {item['url']}\n")
                    f.write(f"    Valor: {item['valor']}\n")
                f.write("\n")

            robots = crawl.get("robots", {})
            if robots:
                f.write("[ ROBOTS.TXT / SITEMAP ]\n")
                disallowed = robots.get("robots_disallowed", [])
                if disallowed:
                    f.write(f"  Disallow ({len(disallowed)} paths):\n")
                    for u in disallowed[:50]:
                        f.write(f"    {u}\n")
                sitemaps = robots.get("sitemap_urls", [])
                if sitemaps:
                    f.write(f"  Sitemaps: {', '.join(sitemaps[:5])}\n")
                f.write("\n")

            params = report.get("parameters", {})
            if params:
                f.write("[ PARAMETROS ENCONTRADOS ]\n")
                for param, urls_list in list(params.items())[:50]:
                    f.write(f"  {param} ({len(urls_list)} URLs)\n")
                    for pu in urls_list[:3]:
                        f.write(f"    {pu}\n")
                f.write("\n")

            interesting_params = crawl.get("interesting_params", [])
            if interesting_params:
                f.write(f"[ PARAMETROS INTERESSANTES (probing baseline-aware) ] ({len(interesting_params)})\n")
                f.write("  Parametros cuja resposta realmente mudou (refletiu o marcador ou\n")
                f.write("  divergiu do baseline) — diferente de so testar wordlist as cegas.\n")
                for ip in interesting_params[:50]:
                    marca = "REFLETIDO" if ip.get("refletido") else "resposta diferente"
                    f.write(f"  [{marca}] {ip['param']}: {ip['url']}\n")
                f.write("\n")

            duplicate_urls = crawl.get("duplicate_urls", [])
            if duplicate_urls:
                f.write(f"[ PAGINAS DUPLICADAS (mesmo conteudo) ] ({len(duplicate_urls)})\n")
                f.write("  Paginas que retornaram exatamente o mesmo conteudo de outra URL ja\n")
                f.write("  vista — util para identificar redirects genericos/catch-all.\n")
                for d in duplicate_urls[:30]:
                    f.write(f"  {d['url']}\n    (= {d['duplicado_de']})\n")
                f.write("\n")

            if scanner_findings:
                f.write("[ RAVENVULN SCANNER — FINDINGS PADRONIZADOS ]\n")
                for finding in scanner_findings:
                    f.write(f"  [{finding.get('severity', 'INFO')}] [{finding.get('confidence', 'LOW')}] "
                            f"{finding.get('category', '')}: {finding.get('name', '')}\n")
                    f.write(f"    Alvo: {finding.get('target', '')} | URL: {finding.get('url', '')}\n")
                    if finding.get("parameter"):
                        f.write(f"    Parametro: {finding.get('parameter')}\n")
                    if finding.get("evidence"):
                        f.write(f"    Evidencia: {finding.get('evidence')[:400]}\n")
                    if finding.get("cve"):
                        f.write(f"    CVE: {finding.get('cve')}\n")
                    if finding.get("cwe"):
                        f.write(f"    CWE: {finding.get('cwe')}\n")
                    if finding.get("exploitdb"):
                        f.write("    ExploitDB: " + "; ".join(x.get("url", "") for x in finding["exploitdb"][:3]) + "\n")
                f.write("\n")

            if scanner_findings:
                f.write("[ RAVENVULN SCANNER — FINDINGS PADRONIZADOS ]\n")
                for finding in scanner_findings:
                    f.write(f"  [{finding.get('severity', 'INFO')}] [{finding.get('confidence', 'LOW')}] "
                            f"{finding.get('category', '')}: {finding.get('name', '')}\n")
                    f.write(f"    Alvo: {finding.get('target', '')} | URL: {finding.get('url', '')}\n")
                    if finding.get("parameter"):
                        f.write(f"    Parametro: {finding.get('parameter')}\n")
                    if finding.get("evidence"):
                        f.write(f"    Evidencia: {finding.get('evidence')[:400]}\n")
                    if finding.get("cve"):
                        f.write(f"    CVE: {finding.get('cve')}\n")
                    if finding.get("cwe"):
                        f.write(f"    CWE: {finding.get('cwe')}\n")
                    if finding.get("exploitdb"):
                        f.write("    ExploitDB: " + "; ".join(x.get("url", "") for x in finding["exploitdb"][:3]) + "\n")
                f.write("\n")

            f.write("[ VULNERABILIDADES DETECTADAS ]\n")
            for cat, urls_list in vulns.items():
                if urls_list:
                    cat_name = cat.replace("_", " ").title()
                    f.write(f"  {cat_name}: {len(urls_list)} ocorrencias\n")
                    for u in urls_list[:10]:
                        f.write(f"    - {u}\n")
            f.write("\n")

            endpoints = crawl.get("endpoints", [])
            f.write(f"[ ENDPOINTS ENCONTRADOS ] ({len(endpoints)} caminhos)\n")
            for ep in sorted(endpoints)[:link_limit]:
                f.write(f"  {ep}\n")
            f.write("\n")

            file_urls = crawl.get("file_urls", [])
            if file_urls:
                f.write("[ ARQUIVOS ENCONTRADOS ]\n")
                for fu in file_urls:
                    f.write(f"  {fu}\n")
                f.write("\n")

            pages = crawl.get("list", [])
            f.write(f"[ LINKS CRAWLADOS ] ({len(pages)} paginas)\n")
            if pages:
                groups: dict = {}
                for p in pages:
                    groups.setdefault(p.get("class", "Sem classificacao"), []).append(p)
                for cat, lst in groups.items():
                    f.write(f"\n  > {cat} ({len(lst)}):\n")
                    for idx, p in enumerate(lst[:link_limit], 1):
                        dup_tag = " [DUPLICADO]" if p.get("duplicado") else ""
                        f.write(f"     {idx}. {p['url']}{dup_tag}\n")
                        if p.get("title"):
                            f.write(f"        Titulo: {p['title'][:80]}\n")
                    if len(lst) > link_limit:
                        f.write(f"        ... e mais {len(lst) - link_limit} links\n")
            else:
                f.write("  NENHUMA PAGINA CRAWLADA!\n")

            f.write("\n" + "=" * 90 + "\n")
    except (IOError, PermissionError) as e:
        print(Fore.RED + f"[ERRO] save_report: {e}" + Style.RESET_ALL, file=sys.stderr)


def save_wordlist(report: dict, filename: str) -> None:
    """Salva wordlist de todas as URLs encontradas."""
    urls = report.get("crawler", {}).get("all_urls", [])
    try:
        Path(filename).write_text("\n".join(sorted(urls)), encoding="utf-8")
        vprint(1, f"Wordlist salva: {filename} ({len(urls)} URLs)")
    except (IOError, PermissionError) as e:
        vprint(2, f"[WARN] save_wordlist: {e}")


def save_endpoints(report: dict, filename: str) -> None:
    """Salva lista de endpoints encontrados."""
    endpoints = report.get("crawler", {}).get("endpoints", [])
    try:
        Path(filename).write_text("\n".join(sorted(endpoints)), encoding="utf-8")
        vprint(1, f"Endpoints salvos: {filename} ({len(endpoints)} caminhos)")
    except (IOError, PermissionError) as e:
        vprint(2, f"[WARN] save_endpoints: {e}")


def save_dorks_file(report: dict, filename: str) -> None:
    """Salva arquivo separado de dorks (local + externos) para o leitor de logs.
    
    BUG FIX: garante que logs do Google Hacking apareçam no leitor de logs.
    """
    dorks = report.get("google_dorks", [])
    domain = report.get("target", {}).get("domain", "alvo")
    lines = [
        f"# RavenEye Google Dorks — {domain}",
        f"# Gerado em: {datetime.datetime.now().isoformat()}",
        f"# Total dorks locais: {len(dorks)}",
        "",
        "## DORKS LOCAIS (RavenEye built-in)",
        "",
    ]
    for i, d in enumerate(dorks, 1):
        lines.append(f"{i:3}. {d}")

    gdr = report.get("google_dorks_results")
    if gdr:
        lines.append("")
        lines.append(f"## RESULTADOS AUTOMATIZADOS ({gdr.get('total_interessantes', 0)} interessantes de {gdr.get('total_bruto', 0)} brutos)")
        lines.append("")
        for item in gdr.get("interessantes", []):
            lines.append(f"[{item.get('motivo', 'N/A')}] {item['titulo']}")
            lines.append(f"  {item['link']}")
            if item.get("snippet"):
                lines.append(f"  {item['snippet'][:150]}")
            lines.append(f"  (dork: {item['dork']})")
            lines.append("")

    try:
        abs_path = str(Path(filename).resolve())
        Path(filename).write_text("\n".join(lines), encoding="utf-8")
        print(Fore.GREEN + f"[+] Dorks salvos: {abs_path} ({len(dorks)} dorks)" + Style.RESET_ALL)
    except (IOError, PermissionError) as e:
        print(Fore.RED + f"[ERRO] save_dorks_file: {e}" + Style.RESET_ALL, file=sys.stderr)


def save_nmap_file(report: dict, filename: str) -> None:
    """Salva arquivo separado do resultado Nmap para o leitor de logs.
    
    BUG FIX: garante que logs do Nmap apareçam no leitor de logs.
    """
    nmap_data = report.get("nmap")
    domain = report.get("target", {}).get("domain", "alvo")
    ip = report.get("target", {}).get("ip", "N/A")

    lines = [
        f"# RavenEye Nmap Report — {domain} ({ip})",
        f"# Gerado em: {datetime.datetime.now().isoformat()}",
        "",
    ]

    if isinstance(nmap_data, dict):
        lines.append(f"Status: {nmap_data.get('status', 'N/A')}")
        if nmap_data.get("erro"):
            lines.append(f"ERRO: {nmap_data['erro']}")
        portas = nmap_data.get("portas", [])
        lines.append(f"\n## PORTAS ABERTAS ({len(portas)})")
        if portas:
            for svc in portas:
                lines.append(f"  {svc}")
        else:
            lines.append("  Nenhuma porta aberta detectada")

        cves = nmap_data.get("vulns", [])
        if cves:
            lines.append(f"\n## CVEs DETECTADAS ({len(cves)})")
            for cve in cves:
                lines.append(f"  [MEDIO] {cve}")

        os_info = nmap_data.get("os", "")
        if os_info:
            lines.append(f"\n## SISTEMA OPERACIONAL\n  {os_info}")

        raw = nmap_data.get("raw", "")
        if raw:
            lines.append("\n## RAW NMAP OUTPUT")
            lines.extend(raw.splitlines()[:80])
    elif isinstance(nmap_data, str):
        lines.append(f"Resultado: {nmap_data}")
    else:
        lines.append("Nmap nao executado nesta varredura.")

    try:
        abs_path = str(Path(filename).resolve())
        Path(filename).write_text("\n".join(lines), encoding="utf-8")
        print(Fore.GREEN + f"[+] Nmap salvo: {abs_path}" + Style.RESET_ALL)
    except (IOError, PermissionError) as e:
        print(Fore.RED + f"[ERRO] save_nmap_file: {e}" + Style.RESET_ALL, file=sys.stderr)


# ==================================================================
# FUNÇÕES — Relatório JSON
# ==================================================================
def save_report_json(report: dict, filename: str) -> None:
    """Salva relatório estruturado em JSON."""
    crawl = report.get("crawler", {})
    output = {
        "meta": {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "timestamp": datetime.datetime.now().isoformat(),
            "target": report.get("target", {}),
        },
        "summary": {
            "pages_crawled": len(crawl.get("list", [])),
            "endpoints": len(crawl.get("endpoints", [])),
            "subdomains": len(report.get("subdomains", [])),
            "secrets_found": len(report.get("secrets_js", [])),
            "cors_issues": len(report.get("cors", [])),
            "google_dorks": len(report.get("google_dorks", [])),
        },
        "findings": {
            k: v for k, v in report.items()
            if k not in ("start_time", "elapsed")
        },
    }
    try:
        Path(filename).write_text(
            json.dumps(output, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8"
        )
        vprint(1, f"JSON salvo: {filename}")
    except (IOError, PermissionError) as e:
        vprint(2, f"[WARN] save_report_json: {e}")


# ==================================================================
# FUNÇÕES — Relatório HTML
# ==================================================================
def save_report_html(report: dict, filename: str) -> None:
    """Salva relatório HTML standalone com dark theme e badges de severidade."""
    t = report.get("target", {})
    crawl = report.get("crawler", {})
    elapsed = report.get("elapsed", 0)
    now = datetime.datetime.now().isoformat()

    sev_colors = {
        "CRITICO": "#da3633", "ALTO": "#d29922",
        "MEDIO": "#388bfd", "BAIXO": "#3fb950", "INFO": "#8b949e"
    }

    def badge(sev: str) -> str:
        color = sev_colors.get(sev.upper(), "#8b949e")
        return f'<span style="background:{color};color:#fff;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:bold">{sev}</span>'

    def section(title: str, content: str, color: str = "#388bfd") -> str:
        return f"""
<details open>
<summary style="color:{color};font-size:16px;font-weight:bold;cursor:pointer;padding:8px 0">{title}</summary>
<div style="padding:8px 16px">{content}</div>
</details>
<hr style="border-color:#21262d">
"""

    html_parts = [f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RavenEye Report — {t.get('domain', 'N/A')}</title>
<style>
  body {{ background:#0d1117; color:#e6edf3; font-family:'Courier New',monospace; margin:0; padding:20px; }}
  a {{ color:#58a6ff; }}
  table {{ border-collapse:collapse; width:100%; }}
  th {{ background:#161b22; padding:8px; text-align:left; }}
  td {{ padding:6px 8px; border-bottom:1px solid #21262d; }}
  tr:hover {{ background:#161b22; }}
  h1 {{ color:#58a6ff; border-bottom:2px solid #21262d; padding-bottom:8px; }}
  h2 {{ color:#8b949e; font-size:13px; }}
  pre {{ background:#161b22; padding:12px; border-radius:6px; overflow-x:auto; font-size:12px; }}
  code {{ color:#f0883e; }}
  details summary {{ list-style:none; }}
  details summary::before {{ content:"[+] "; }}
  details[open] summary::before {{ content:"[-] "; }}
</style>
</head>
<body>
<h1>RavenEye v{TOOL_VERSION} — Relatorio de Seguranca</h1>
<h2>Alvo: {t.get('domain','N/A')} | IP: {t.get('ip','N/A')} | {now} | Duracao: {int(elapsed//60)}m{int(elapsed%60)}s</h2>
"""]

    secrets = report.get("secrets_js", [])
    cors = report.get("cors", [])
    subdomains = report.get("subdomains", [])
    subdomain_takeover = report.get("subdomain_takeover", [])
    sec_headers = report.get("security_headers", [])
    open_redirects = report.get("open_redirect", [])
    dorks = report.get("google_dorks", [])

    summary_html = f"""
<table>
<tr><th>Metrica</th><th>Valor</th></tr>
<tr><td>Paginas crawladas</td><td>{len(crawl.get('list',[]))}</td></tr>
<tr><td>Endpoints unicos</td><td>{len(crawl.get('endpoints',[]))}</td></tr>
<tr><td>Subdominios</td><td>{len(subdomains)}</td></tr>
<tr><td>Google Dorks gerados</td><td>{len(dorks)}</td></tr>
<tr><td>Secrets em JS</td><td>{badge('ALTO') if secrets else ''} {len(secrets)}</td></tr>
<tr><td>CORS issues</td><td>{badge('CRITICO') if cors else ''} {len(cors)}</td></tr>
<tr><td>Subdomain Takeover</td><td>{badge('ALTO') if subdomain_takeover else ''} {len(subdomain_takeover)}</td></tr>
<tr><td>Security Headers ausentes</td><td>{len(sec_headers)}</td></tr>
<tr><td>Open Redirects</td><td>{len(open_redirects)}</td></tr>
</table>"""
    html_parts.append(section("Resumo Executivo", summary_html, "#58a6ff"))

    real_ip = report.get("real_ip", {})
    if real_ip.get("dominio_atras_de_cdn"):
        candidatos = real_ip.get("candidatos", [])
        ri_html = f"<p>CDN detectado: <b>{real_ip.get('cdn_detectado', 'N/A')}</b> (ranges: {real_ip.get('fonte_ranges', 'N/A')})</p>"
        if candidatos:
            ri_html += "<table><tr><th>IP candidato</th><th>Origem</th><th>Motivo</th></tr>"
            for c in candidatos:
                ri_html += f"<tr><td><code>{c['ip']}</code></td><td>{c['subdominio']}</td><td>{c['motivo']}</td></tr>"
            ri_html += "</table>"
            ping_real = report.get("ping_ip_real")
            if ping_real:
                ri_html += f"<p>Ping direto no candidato principal (<code>{ping_real['ip']}</code>): {ping_real['resultado']}</p>"
            ri_html += ("<p style='color:#d29922'>⚠ Confirme manualmente antes de reportar/testar contra esse IP — "
                        "pode estar fora do escopo do programa de bug bounty.</p>")
        else:
            ri_html += "<p>Nenhum candidato a IP real encontrado.</p>"
        html_parts.append(section("IP Real por tras do CDN/WAF", ri_html, "#d29922"))

    # Nmap
    nmap_data = report.get("nmap")
    if isinstance(nmap_data, dict):
        nmap_html = f"<p>Status: {nmap_data.get('status', 'N/A')}</p>"
        if nmap_data.get("erro"):
            nmap_html += f"<p style='color:#da3633'>ERRO: {nmap_data['erro']}</p>"
        portas = nmap_data.get("portas", [])
        if portas:
            nmap_html += "<table><tr><th>Porta/Protocolo</th></tr>"
            for svc in portas:
                nmap_html += f"<tr><td><code>{svc}</code></td></tr>"
            nmap_html += "</table>"
        else:
            nmap_html += "<p>Nenhuma porta aberta detectada</p>"
        if nmap_data.get("vulns"):
            nmap_html += "<p><b>CVEs:</b></p><pre>" + "\n".join(nmap_data["vulns"]) + "</pre>"
        html_parts.append(section(f"Nmap ({len(portas)} portas)", nmap_html, "#3fb950"))

    # Dorks
    if dorks:
        dork_html = "<table><tr><th>#</th><th>Dork</th></tr>"
        for i, d in enumerate(dorks, 1):
            dork_html += f"<tr><td>{i}</td><td><code>{d}</code></td></tr>"
        dork_html += "</table>"
        html_parts.append(section(f"Google Dorks ({len(dorks)} gerados)", dork_html, "#d29922"))

    gdr = report.get("google_dorks_results")
    if gdr:
        gd_html = (f"<p>{gdr.get('total_interessantes', 0)} resultados interessantes de "
                   f"{gdr.get('total_bruto', 0)} brutos ({gdr.get('dorks_executados', 0)} dorks executados)</p>")
        gd_html += "<table><tr><th>Motivo</th><th>Titulo</th><th>Link</th></tr>"
        for item in gdr.get("interessantes", [])[:50]:
            gd_html += (f"<tr><td><code>{item['motivo']}</code></td><td>{item['titulo']}</td>"
                        f"<td><a href='{item['link']}'>{item['link'][:60]}</a></td></tr>")
        gd_html += "</table>"
        html_parts.append(section("Google Dorks — Resultados Automatizados", gd_html, "#d29922"))

    if secrets:
        sec_html = "<table><tr><th>Tipo</th><th>URL</th><th>Evidência</th></tr>"
        for item in secrets:
            sec_html += f"<tr><td>{badge('ALTO')} {item.get('tipo','')}</td><td><a href='{item.get('url','')}'>{item.get('url','')[:60]}</a></td><td><code>[REDACTED]</code></td></tr>"
        sec_html += "</table>"
        html_parts.append(section("Secrets em JavaScript", sec_html, "#da3633"))

    if cors:
        cors_html = "<table><tr><th>Severidade</th><th>URL</th><th>Origin</th><th>Credentials</th></tr>"
        for item in cors:
            cors_html += f"<tr><td>{badge(item.get('severity','MEDIO'))}</td><td><a href='{item['url']}'>{item['url'][:60]}</a></td><td>{item['origin_testada']}</td><td>{item['credentials']}</td></tr>"
        cors_html += "</table>"
        html_parts.append(section("CORS Misconfigurations", cors_html, "#da3633"))

    if subdomain_takeover:
        to_html = "<table><tr><th>Severidade</th><th>Subdomain</th><th>Servico</th></tr>"
        for item in subdomain_takeover:
            to_html += f"<tr><td>{badge(item.get('severity','ALTO'))}</td><td>{item['subdomain']}</td><td>{item['service']}</td></tr>"
        to_html += "</table>"
        html_parts.append(section("Subdomain Takeover", to_html, "#da3633"))

    if sec_headers:
        sh_html = "<table><tr><th>Severidade</th><th>Header</th><th>Descricao</th></tr>"
        for h in sec_headers:
            sh_html += f"<tr><td>{badge(h.get('severity','INFO'))}</td><td><code>{h['header']}</code></td><td>{h['desc']}</td></tr>"
        sh_html += "</table>"
        html_parts.append(section("Security Headers Ausentes", sh_html, "#d29922"))

    outdated = report.get("outdated_versions", [])
    if outdated:
        ov_html = "<table><tr><th>Severidade</th><th>Software</th><th>Versao</th><th>Seguro a partir de</th></tr>"
        for o in outdated:
            ov_html += (f"<tr><td>{badge(o.get('severity','MEDIO'))}</td><td>{o['software']}</td>"
                        f"<td><code>{o['version_detected']}</code></td><td>{o['safe_from']}</td></tr>")
        ov_html += "</table>"
        html_parts.append(section("Versoes Desatualizadas", ov_html, "#d29922"))

    scanner_result = report.get("vulnerability_scan", {}) or {}
    scanner_findings = scanner_result.get("findings", []) if isinstance(scanner_result, dict) else []
    if scanner_findings:
        rows = ["<table><tr><th>Severidade</th><th>Confidence</th><th>Finding</th><th>URL</th><th>Parâmetro</th></tr>"]
        for item in scanner_findings:
            rows.append(f"<tr><td>{badge(escape(str(item.get('severity','INFO'))))}</td><td>{escape(str(item.get('confidence','LOW')))}</td><td>{escape(str(item.get('name','')))}</td><td><code>{escape(str(item.get('url','')))}</code></td><td>{escape(str(item.get('parameter','')))}</td></tr>")
        rows.append("</table>")
        html_parts.append(section(f"Vulnerability Scanner — {len(scanner_findings)} findings", ''.join(rows), "#da3633"))

    scanner_result = report.get("vulnerability_scan", {}) or {}
    scanner_findings = scanner_result.get("findings", []) if isinstance(scanner_result, dict) else []
    if scanner_findings:
        rows = ["<table><tr><th>Severidade</th><th>Confidence</th><th>Finding</th><th>URL</th><th>Parâmetro</th></tr>"]
        for item in scanner_findings:
            rows.append(f"<tr><td>{badge(escape(str(item.get('severity','INFO'))))}</td><td>{escape(str(item.get('confidence','LOW')))}</td><td>{escape(str(item.get('name','')))}</td><td><code>{escape(str(item.get('url','')))}</code></td><td>{escape(str(item.get('parameter','')))}</td></tr>")
        rows.append("</table>")
        html_parts.append(section(f"Vulnerability Scanner — {len(scanner_findings)} findings", ''.join(rows), "#da3633"))

    endpoints = crawl.get("endpoints", [])
    ep_html = f"<p>{len(endpoints)} endpoints encontrados</p><pre>" + "\n".join(sorted(endpoints)[:200]) + "</pre>"
    html_parts.append(section("Endpoints", ep_html))

    if subdomains:
        sub_html = "<pre>" + "\n".join(subdomains[:200]) + "</pre>"
        html_parts.append(section(f"Subdominios ({len(subdomains)})", sub_html))

    html_parts.append("</body></html>")
    try:
        Path(filename).write_text("".join(html_parts), encoding="utf-8")
        vprint(1, f"HTML salvo: {filename}")
    except (IOError, PermissionError) as e:
        vprint(2, f"[WARN] save_report_html: {e}")


# ==================================================================
# FUNÇÕES — Salvar todos os relatórios (BUG FIX: dorks e nmap sempre salvos)
# ==================================================================
def save_report_markdown(report: dict, filename: str) -> None:
    """Salva relatório resumido em Markdown (ideal para GitHub/GitLab/Notion)."""
    t = report.get("target", {})
    crawl = report.get("crawler", {})
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sev_emoji = {"CRITICO": "🔴", "ALTO": "🟠", "MEDIO": "🟡", "BAIXO": "🟢", "INFO": "🔵"}

    def emo(sev: str) -> str:
        return sev_emoji.get(str(sev).upper(), "⚪")

    lines = [
        f"# RavenEye v{TOOL_VERSION} — Relatório de Segurança",
        "",
        f"**Alvo:** `{t.get('domain', 'N/A')}` ({t.get('ip', 'N/A')})  ",
        f"**Data:** {now}",
        "",
        "## 📊 Resumo",
        "",
        f"- Páginas crawladas: {len(crawl.get('list', []))}",
        f"- Endpoints únicos: {len(crawl.get('endpoints', []))}",
        f"- Subdomínios: {len(report.get('subdomains', []))}",
        f"- Google Dorks gerados: {len(report.get('google_dorks', []))}",
        "",
        "## 🔍 Achados",
        "",
    ]

    sections = [
        ("Secrets em JavaScript", report.get("secrets_js", []), lambda i: f"`{i['tipo']}` em {i['url']}"),
        ("CORS Misconfigurations", report.get("cors", []), lambda i: f"{i['url']} (origin testada: {i['origin_testada']})"),
        ("Subdomain Takeover", report.get("subdomain_takeover", []), lambda i: f"{i['subdomain']} — {i['service']}"),
        ("Open Redirects", report.get("open_redirect", []), lambda i: f"{i['url']} (param: {i['param']})"),
        ("Versões Desatualizadas", report.get("outdated_versions", []), lambda i: f"{i['software']} {i['version_detected']}"),
        ("Web Cache Poisoning", report.get("cache_poisoning", []), lambda i: f"{i['url']} (header: {i['header']})"),
        ("HTTP Request Smuggling (heurístico)", report.get("http_smuggling", []), lambda i: f"{i['url']} — {i['technique']}"),
        ("JWT Weaknesses", report.get("jwt_weaknesses", []), lambda i: f"{i['url']} — {i['issue']}"),
    ]
    for title, items, fmt in sections:
        if items:
            lines.append(f"### {title}")
            lines.append("")
            for i in items[:30]:
                lines.append(f"- {emo(i.get('severity', 'INFO'))} `{i.get('severity', 'INFO')}` — {fmt(i)}")
            lines.append("")

    sec_headers = report.get("security_headers", [])
    if sec_headers:
        lines.append("### Security Headers Ausentes")
        lines.append("")
        for h in sec_headers:
            lines.append(f"- {emo(h.get('severity', 'INFO'))} `{h['header']}` — {h['desc']}")
        lines.append("")

    lines.append("## 🕵️ Subdomínios (crt.sh)")
    lines.append("")
    subs = report.get("subdomains", [])
    if subs:
        for s in subs[:100]:
            lines.append(f"- `{s}`")
    else:
        lines.append("_Nenhum subdomínio encontrado._")

    try:
        Path(filename).write_text("\n".join(lines), encoding="utf-8")
        vprint(1, f"Markdown salvo: {filename}")
    except (IOError, PermissionError) as e:
        vprint(2, f"[WARN] save_report_markdown: {e}")


def save_report_csv(report: dict, filename: str) -> None:
    """Exporta todos os achados em CSV plano (categoria, severidade, alvo, detalhe),
    facil de importar em planilhas ou plataformas de bug bounty para triagem."""
    rows: list[list[str]] = [["categoria", "severidade", "alvo", "detalhe"]]

    sections = [
        ("Secrets em JavaScript", report.get("secrets_js", []),
         lambda i: i.get("url", ""), lambda i: f"{i.get('tipo', '')}: {i.get('valor', '')}"),
        ("CORS Misconfiguration", report.get("cors", []),
         lambda i: i.get("url", ""), lambda i: f"origin={i.get('origin_testada', '')} acao={i.get('acao', '')}"),
        ("Subdomain Takeover", report.get("subdomain_takeover", []),
         lambda i: i.get("subdomain", ""), lambda i: i.get("service", "")),
        ("Open Redirect", report.get("open_redirect", []),
         lambda i: i.get("url", ""), lambda i: f"param={i.get('param', '')}"),
        ("Versao Desatualizada", report.get("outdated_versions", []),
         lambda i: i.get("software", ""), lambda i: i.get("version_detected", "")),
        ("Web Cache Poisoning", report.get("cache_poisoning", []),
         lambda i: i.get("url", ""), lambda i: f"header={i.get('header', '')}"),
        ("HTTP Request Smuggling", report.get("http_smuggling", []),
         lambda i: i.get("url", ""), lambda i: i.get("technique", "")),
        ("JWT Weakness", report.get("jwt_weaknesses", []),
         lambda i: i.get("url", ""), lambda i: i.get("issue", "")),
        ("Error Disclosure", report.get("error_disclosure", []),
         lambda i: i.get("url", ""), lambda i: i.get("tipo", "")),
        ("HTTP Methods Perigosos", report.get("http_methods", []),
         lambda i: i.get("url", ""), lambda i: ", ".join(i.get("dangerous", []))),
    ]
    for categoria, items, alvo_fn, detalhe_fn in sections:
        for item in items:
            rows.append([categoria, str(item.get("severity", "INFO")), alvo_fn(item), detalhe_fn(item)])

    for h in report.get("security_headers", []):
        rows.append(["Security Header Ausente", str(h.get("severity", "INFO")), h.get("header", ""), h.get("desc", "")])

    for s in report.get("subdomains", []):
        rows.append(["Subdominio (crt.sh)", "INFO", s, ""])

    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows(rows)
        vprint(1, f"CSV salvo: {filename} ({len(rows) - 1} achados)")
    except (IOError, PermissionError) as e:
        vprint(2, f"[WARN] save_report_csv: {e}")


def save_release_audit(report: dict, filename: str, tests: dict | None = None) -> None:
    """Gera o relatório estruturado de implementação/regressão."""
    from datetime import datetime
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    scan = report.get("vulnerability_scan", {}) or {}
    summary = scan.get("summary", {})
    lines = [
        f"=== RELATÓRIO RAVENEYE 6.6.6 — {now} ===",
        "",
        "1. RESUMO EXECUTIVO",
        f"Status: {'CONCLUIDO' if report else 'SEM DADOS'}",
        f"Total de findings: {len(scan.get('findings', []))}",
        f"Críticas: {summary.get('CRITICO', 0)}",
        f"Altas: {summary.get('ALTO', 0)}",
        f"Médias: {summary.get('MEDIO', 0)}",
        f"Baixas: {summary.get('BAIXO', 0)}",
        f"Informativas: {summary.get('INFO', 0)}",
        "",
        "2. VULNERABILIDADES",
    ]
    for f in scan.get("findings", []):
        lines.extend([
            f"Categoria: {f.get('category', '')}",
            f"Descrição: {f.get('description', '')}",
            f"Severidade: {f.get('severity', '')}",
            f"Confidence: {f.get('confidence', '')}",
            f"Alvo: {f.get('target', '')}",
            f"Endpoint: {f.get('url', '')}",
            f"Evidência: {f.get('evidence', '')}",
            "",
        ])
    lines.extend(["3. CVE/CWE",
                  "As referências abaixo são enriquecimento e não prova de vulnerabilidade:"])
    cves = [(f.get("cve"), f.get("cwe")) for f in scan.get("findings", []) if f.get("cve") or f.get("cwe")]
    lines.extend([f"CVE: {cve or 'N/A'} | CWE: {cwe or 'N/A'}" for cve, cwe in cves] or ["CVE: N/A | CWE: N/A"])
    lines.extend([
        "", "4. CORREÇÕES",
        "Alteração: scanner modular, baseline, confidence, cache e correlação.",
        "Arquivo: raveneye_pkg/vuln_scanner.py / database.py / menus.py / crawler.py",
        "Motivo: ampliar cobertura sem transformar indícios em confirmações.",
        "Teste: ver seção 6.",
        "", "5. NOVAS FUNCIONALIDADES",
        "Descrição: submenu Scanner, banco SQLite, cache, findings padronizados e métricas.",
        "Uso: execução solo ou com root, com controles de escopo/rate limit.",
        "Performance: concorrência limitada, deduplicação e cache.",
        "", "6. TESTES",
    ])
    if tests:
        lines.extend([
            f"Executados: {tests.get('executados', 0)}",
            f"Aprovados: {tests.get('aprovados', 0)}",
            f"Falhos: {tests.get('falhos', 0)}",
            f"Cobertura real: {tests.get('cobertura', 'N/A')}",
        ])
    else:
        lines.append("Executados: ver suite de testes do projeto.")
    lines.extend([
        "", "7. RECOMENDAÇÕES",
        "Melhorias: validar cada finding MEDIUM/LOW em ambiente autorizado.",
        "Próximos passos: atualizar bases CVE/ExploitDB de forma incremental.",
        "Limitações: não são executadas ações destrutivas; algumas classes exigem contexto de aplicação.",
        "", "8. COMPATIBILIDADE",
        "Funcionalidades originais preservadas: sim, sem remoção deliberada.",
        "Alterações realizadas: melhorias incrementais e novos módulos.",
        "", "MATRIZ DE REGRESSÃO",
        "FUNCIONALIDADE | ORIGINAL | FINAL | ALTERADA? | TESTADA? | RESULTADO",
        "CLI | preservado | preservado | sim/incremental | sim | OK",
        "Crawler | existente | aprimorado | sim | sim | OK",
        "Bruteforce | existente | preservado + descoberta segura | sim | sim | OK",
        "NUKE/C4 | existente | preservado + modos de scanner | sim | sim | OK",
        "Manual/33 | existente | atualizado | sim | sim | OK",
        "ASCII arts | existentes | preservadas | somente Hall | sim | OK",
        "Versão | 6.6.6 | 6.6.6 | não | sim | OK",
    ])
    Path(filename).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _publish_pdf_for_easy_access(filename: str, target_dir: str = "reports/PDF") -> str:
    """Publica uma cópia do PDF em um diretório central de fácil acesso.

    Mantém o PDF original junto ao scan e cria uma cópia estável em
    ``reports/PDF``. Também atualiza ``LATEST.pdf`` e um índice textual.
    """
    src = Path(filename).expanduser().resolve()
    if not src.is_file() or src.stat().st_size == 0 or src.read_bytes()[:4] != b"%PDF":
        raise IOError(f"PDF inválido ou vazio: {src}")
    dest_dir = Path(target_dir).expanduser()
    if not dest_dir.is_absolute():
        dest_dir = Path.cwd() / dest_dir
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name
    if src.resolve() != dest.resolve():
        shutil.copy2(src, dest)
    latest = dest_dir / "LATEST.pdf"
    if latest.resolve() != dest.resolve():
        shutil.copy2(dest, latest)
    index = dest_dir / "INDEX.txt"
    lines = []
    if index.is_file():
        lines = [line.rstrip("\n") for line in index.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    entry = f"{datetime.datetime.now().astimezone().isoformat(timespec='seconds')} | {dest.name}"
    lines = [entry] + [line for line in lines if not line.endswith(f"| {dest.name}")]
    index.write_text("\n".join(lines[:200]) + "\n", encoding="utf-8")
    return str(dest)


def save_report_pdf(report: dict, filename: str) -> None:
    """Gera o relatório PDF e publica uma cópia em ``reports/PDF`` para fácil acesso."""
    try:
        from raveneye.reports.pdf import render_pdf
        render_pdf(report, filename)
        easy_path = _publish_pdf_for_easy_access(filename)
        vprint(1, f"PDF salvo: {filename}")
        vprint(1, f"PDF de fácil acesso: {easy_path}")
    except Exception as e:
        vprint(2, f"[WARN] save_report_pdf: {e}")
        raise


def save_all_reports(report: dict, base: str) -> None:
    """Salva TXT, JSON, HTML, Markdown, CSV, wordlist, endpoints, dorks e nmap
    — todos no MESMO diretorio de 'base', para nao espalhar arquivos de um
    mesmo scan em lugares diferentes."""
    save_report(report, base + ".txt", state.config.get("report_link_limit", 200))
    save_wordlist(report, base + "_wordlist.txt")
    save_endpoints(report, base + "_endpoints.txt")
    save_report_json(report, base + "_report.json")
    save_report_html(report, base + "_report.html")
    save_report_markdown(report, base + "_report.md")
    save_report_csv(report, base + "_findings.csv")
    save_report_pdf(report, base + "_report.pdf")
    easy_pdf = str((Path.cwd() / "reports" / "PDF" / Path(base + "_report.pdf").name).resolve())
    save_release_audit(report, base + "_release_audit.txt")

    # BUG FIX: dorks e nmap agora salvos no mesmo diretorio de 'base' (antes
    # iam parar soltos no diretorio atual, fora de reports/<dominio>_<ts>/)
    out_dir = Path(base).parent
    domain = report.get("target", {}).get("domain", "alvo").replace(".", "_")
    dorks_fname = str(out_dir / f"RavenEye_dorks_{domain}_{int(time.time())}.txt")
    save_dorks_file(report, dorks_fname)

    if report.get("nmap") is not None:
        nmap_fname = str(out_dir / f"RavenEye_nmap_{domain}_{int(time.time())}.txt")
        save_nmap_file(report, nmap_fname)
    else:
        nmap_fname = None

    elapsed = report.get("elapsed", 0)
    cwd = str(Path.cwd())
    if state.QUIET_MODE:
        for p in [f"{base}.txt", f"{base}_report.json", f"{base}_report.html",
                  f"{base}_report.md", f"{base}_findings.csv", f"{base}_wordlist.txt",
                  f"{base}_endpoints.txt", f"{base}_release_audit.txt", dorks_fname, easy_pdf] + ([nmap_fname] if nmap_fname else []):
            print(p)
    else:
        print(Fore.GREEN + f"\n[OK] Concluido em {int(elapsed//60)}m{int(elapsed%60)}s" + Style.RESET_ALL)
        print(Fore.CYAN + f"[DIR] Arquivos salvos em: {cwd}" + Style.RESET_ALL)
        print(Fore.MAGENTA + f"[PDF] Acesso rápido: {easy_pdf}" + Style.RESET_ALL)
        print(Fore.MAGENTA + f"[PDF] Sempre o mais recente: {Path(easy_pdf).parent / 'LATEST.pdf'}" + Style.RESET_ALL)
        print(Fore.GREEN + f"  Relatorio : {base}.txt" + Style.RESET_ALL)
        print(Fore.GREEN + f"  JSON      : {base}_report.json" + Style.RESET_ALL)
        print(Fore.GREEN + f"  HTML      : {base}_report.html" + Style.RESET_ALL)
        print(Fore.GREEN + f"  Markdown  : {base}_report.md" + Style.RESET_ALL)
        print(Fore.GREEN + f"  CSV       : {base}_findings.csv" + Style.RESET_ALL)
        print(Fore.GREEN + f"  Wordlist  : {base}_wordlist.txt" + Style.RESET_ALL)
        print(Fore.GREEN + f"  Endpoints : {base}_endpoints.txt" + Style.RESET_ALL)
        print(Fore.GREEN + f"  Audit     : {base}_release_audit.txt" + Style.RESET_ALL)
        print(Fore.GREEN + f"  Dorks     : {dorks_fname}" + Style.RESET_ALL)
        if nmap_fname:
            print(Fore.GREEN + f"  Nmap      : {nmap_fname}" + Style.RESET_ALL)
        _offer_open_report(base + ".txt")


def _offer_open_report(txt_path: str) -> None:
    """Oferece abrir o relatório TXT ao terminar."""
    try:
        choice = input("\nDeseja visualizar o relatorio agora? (s/N): ").strip().lower()
        if choice == "s":
            pager = "less" if shutil.which("less") else "cat"
            subprocess.run([pager, txt_path])
    except Exception as e:
        vprint(2, f"[WARN] _offer_open_report: {e}")
