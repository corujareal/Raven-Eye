from __future__ import annotations

"""Todos os menus interativos (CLI) do RavenEye."""


import datetime
import asyncio
import json
import csv
import glob
import os
import random
import re
import shlex
import shutil
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from urllib.parse import urlsplit
from raveneye.network.domains import host_matches_rule
from raveneye_pkg.terminal import Fore, Style
from raveneye_pkg import state
from raveneye_pkg.state import vprint, set_verbose, _setup_logger, _sleep
from raveneye_pkg.constants import (
    CONFIG_FILE, EXTRA_PASSWORDS, TOOL_VERSION, USER_AGENTS,
)
from raveneye_pkg.config_io import save_config, get_api_key, get_google_cse_id, set_api_key, _safe_domain_filename, _sanitize_domain_input
from raveneye_pkg.network import resolve_host, ping_host, normalize_url, is_safe_url, request_url
from raveneye_pkg.ascii_art import (
    ascii_anarchy, ascii_raven_eye_logo, ascii_spider_web, ascii_skull,
    ascii_bruteforce, ascii_eye_double_pupil, ascii_radiation, ascii_book,
    ascii_books_stack, ascii_main_hall,
)
from raveneye_pkg.credits import show_credits, verify_integrity
from raveneye_pkg.scanners import (
    google_dork_search, run_google_dorks_search, run_searxng_dorks_search,
    brute_subdomains, get_nmap,
    normalize_dns_domain,
    check_virustotal, check_virustotal_domain, check_virustotal_ip,
    find_real_ip, get_subdomains_crtsh,
)
from raveneye_pkg.bruteforce import (
    get_wordlist_manager, CredentialAuditError,
    enumerate_paths, enumerate_endpoints, enumerate_parameters,
)
from raveneye.wordlists import WordlistError, WordlistInfo
from raveneye.bruteforce.checkpoint import CheckpointError
from raveneye.bruteforce import BruteForceEngine, CredentialAuditPolicy
from raveneye.bruteforce.protocols.http import Adapter as HTTPLoginAdapter
from raveneye_pkg.crawler import RavenCrawler
from raveneye_pkg.reports import save_all_reports
from raveneye_pkg.vuln_scanner import RavenVulnScanner

from raveneye.scanner.evidence import sanitize_url
from raveneye.core.targets import normalize_targets


from raveneye_pkg.state import PLAYWRIGHT_AVAILABLE
from raveneye.cli.log_viewer import watch as _watch_log, safe_delete as _safe_delete_log, export_category as _export_log_category, export_report_file as _export_report_file, format_menu as _log_format_menu, _safe_log_line


def _confirm_aggressive(target: str) -> bool:
    """Solicita confirmação antes de operações agressivas e registra em log de auditoria."""
    display_target = sanitize_url(target)
    if not display_target and re.fullmatch(r"[A-Za-z0-9._-]{1,253}", str(target).strip()):
        display_target = str(target).strip()
    display_target = display_target or "alvo informado"
    print(Fore.RED + f"""
[!] ATENCAO: Voce esta prestes a iniciar varredura agressiva em:
    {display_target}
    Confirme que tem AUTORIZACAO EXPLICITA para testar este alvo.
""" + Style.RESET_ALL)
    try:
        confirm = input("    Digite 'SIM' para continuar: ").strip()
        confirmed = confirm == "SIM"
        parsed = urlsplit(target)
        audit_target = ""
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            host = parsed.hostname.lower()
            try:
                port = parsed.port
            except ValueError:
                port = None
            authority = f"[{host}]" if ":" in host else host
            if port is not None and port != (443 if parsed.scheme == "https" else 80):
                authority = f"{authority}:{port}"
            audit_target = f"{parsed.scheme.lower()}://{authority}"
        else:
            audit_target = parsed.hostname or target.split("/", 1)[0][:253]
        with suppress(Exception):
            with open("raveneye_audit_log.txt", "a", encoding="utf-8") as f:
                f.write(f"{datetime.datetime.now().isoformat()} | alvo={audit_target} | "
                        f"confirmado={'SIM' if confirmed else 'NAO'}\n")
        return confirmed
    except Exception:
        return False


def _confirm_vulnerability_scanner(target: str) -> bool:
    """Ask for scanner-specific consent immediately before a scanner run."""
    display_target = sanitize_url(target)
    if not display_target and re.fullmatch(r"[A-Za-z0-9._-]{1,253}", str(target).strip()):
        display_target = str(target).strip()
    display_target = display_target or "alvo informado"
    print(Fore.RED + f"\n[!] O Scanner de Vulnerabilidades vai testar ativamente:\n    {display_target}" + Style.RESET_ALL)
    print(Fore.YELLOW + "Confirme autorização explícita para executar o Scanner neste alvo." + Style.RESET_ALL)
    try:
        confirmed = input("Digite 'SIM' para autorizar o Scanner: ").strip() == "SIM"
    except Exception:
        return False

    parsed = urlsplit(target)
    host = parsed.hostname or target.split("/", 1)[0][:253]
    try:
        port = parsed.port
    except ValueError:
        port = None
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    authority = f"[{host}]" if ":" in host else host
    if port is not None and port != default_port:
        authority = f"{authority}:{port}"
    audit_target = f"{parsed.scheme.lower()}://{authority}" if parsed.scheme else authority
    with suppress(Exception):
        with open("raveneye_audit_log.txt", "a", encoding="utf-8") as log:
            log.write(
                f"{datetime.datetime.now().isoformat()} | modulo=RavenVulnScanner | "
                f"alvo={audit_target} | autorizado={'SIM' if confirmed else 'NAO'}\n"
            )
    return confirmed


# ==================================================================
# FUNÇÕES — Google Hacking interativo
# ==================================================================
def menu_google_hacking() -> None:
    """Menu interativo de Google Dorks, com suporte opcional a múltiplos domínios."""
    _clear_screen()
    ascii_books_stack()
    while True:
        print(Fore.CYAN + "\n[ GOOGLE HACKING INTERATIVO ]" + Style.RESET_ALL)
        print("  1. Gerar consultas locais (RavenEye + personalizadas)")
        print("  2. Buscar automaticamente via SearXNG local em Docker")
        print("  3. Buscar automaticamente via Google Custom Search API")
        print("  99. Manual")
        print("  00. Voltar")
        sub = input("\nEscolha: ").strip()
        if sub == "00":
            break
        if sub == "99":
            show_manual("google_hacking")
            continue
        if sub not in ("1", "2", "3"):
            print("Opção inválida")
            continue
        targets = []
        if state.config.get("multi_target_enabled"):
            print(Fore.CYAN + f"Cole até {int(state.config.get('max_targets', 50))} domínios, um por linha. Linha vazia finaliza." + Style.RESET_ALL)
            while len(targets) < int(state.config.get("max_targets", 50)):
                raw = input(f"Domínio {len(targets)+1}: ").strip()
                if not raw:
                    break
                dom = _sanitize_domain_input(raw)
                if dom and dom not in targets:
                    targets.append(dom)
        else:
            raw = input("Domínio alvo (ex.: exemplo.com): ").strip()
            dom = _sanitize_domain_input(raw) if raw else ""
            if dom:
                targets = [dom]
        if not targets:
            print("Domínio inválido.")
            continue

        cse_key = get_api_key("google_cse")
        cse_id = get_google_cse_id()
        if sub == "3" and (not cse_key or not cse_id):
            print(Fore.RED + "[!] Configure 'Chave Google CSE' e 'Google CSE ID' no menu Configurações primeiro." + Style.RESET_ALL)
            continue

        for domain in targets:
            domain_safe = _safe_domain_filename(domain)
            try:
                if sub == "1":
                    dorks = google_dork_search(domain)
                    print(Fore.GREEN + f"\n{len(dorks)} dorks gerados para: {domain}" + Style.RESET_ALL)
                    for i, d in enumerate(dorks, 1):
                        print(f"  {i:2}. {d}")
                    save_choice = input("\nSalvar dorks em arquivo? (s/N): ").strip().lower()
                    if save_choice == "s":
                        fname = f"RavenEye_dorks_{domain_safe}_{int(time.time())}.txt"
                        Path(fname).write_text("\n".join(dorks), encoding="utf-8")
                        print(Fore.GREEN + f"[+] Dorks salvos em: {Path(fname).resolve()}" + Style.RESET_ALL)
                else:
                    dorks = google_dork_search(domain)
                    if sub == "2":
                        searx_url = state.config.get("searxng_url", "http://127.0.0.1:8080")
                        print(Fore.CYAN + f"\n[*] {domain}: consultando SearXNG local ({searx_url}); os payloads das consultas não serão gravados..." + Style.RESET_ALL)
                        resultado = run_searxng_dorks_search(dorks, domain, searx_url)
                    else:
                        print(Fore.CYAN + f"\n[*] {domain}: executando {len(dorks)} consultas via Google Custom Search API..." + Style.RESET_ALL)
                        resultado = run_google_dorks_search(dorks, domain, cse_key, cse_id)
                    print(Fore.GREEN + f"[+] {resultado['total_interessantes']} resultados interessantes de {resultado['total_bruto']} brutos" + Style.RESET_ALL)
                    for item in resultado["interessantes"][:30]:
                        print(Fore.YELLOW + f"\n  [{item['confidence']} / {item['motivo']}] {item['titulo']}" + Style.RESET_ALL)
                        print(f"  {item['link']}")
                        if item.get("snippet"):
                            print(f"  {item['snippet']}")
                    for aviso in resultado.get("erros", [])[:3]:
                        print(Fore.YELLOW + f"[!] {aviso}" + Style.RESET_ALL)
                    save_choice = input("Salvar resultados em arquivo? (s/N): ").strip().lower()
                    if save_choice == "s":
                        fname = f"RavenEye_dorks_resultados_{domain_safe}_{int(time.time())}.txt"
                        lines_out = [f"# RavenEye — resultados automatizados — {domain}", f"# Fonte: {resultado.get('provider', 'desconhecida')}", ""]
                        for item in resultado["interessantes"]:
                            lines_out += [f"[{item['confidence']} / {item['motivo']}] {item['titulo']}", f"  {item['link']}", f"  {item.get('snippet', '')}", ""]
                        Path(fname).write_text("\n".join(lines_out), encoding="utf-8")
                        print(Fore.GREEN + f"[+] Resultados salvos em: {Path(fname).resolve()}" + Style.RESET_ALL)
            except Exception as exc:
                print(Fore.RED + f"[ERRO] {domain}: {exc}" + Style.RESET_ALL)


# ==================================================================
# MENUS — Manual
# ==================================================================
def show_manual(context: str) -> None:
    """Exibe manual contextual interativo."""
    extra_manuals = {
        "principal": (
            "1 inicia os módulos; 2 abre Configurações; 3 mostra Créditos.\n"
            "00 encerra após salvar as configurações.\n"
        ),
        "hall": (
            "1 Crawler; 2 Crawler ofensivo; 3 Bruteforce; 4 Nmap; 5 NUKE/C4;\n"
            "6 Logs; 7 VirusTotal; 8 Google Hacking; 9 Scanner de Vulnerabilidades.\n"
            "00 volta ao menu principal.\n"
        ),
        "google_hacking": (
            "1 gera consultas locais; 2 consulta o SearXNG em Docker; 3 usa Google CSE.\n"
            "As buscas automatizadas exibem resultados do provedor selecionado.\n"
            "99 abre este manual; 00 volta.\n"
        ),
        "virustotal": (
            "1 consulta URL; 2 consulta domínio; 3 consulta endereço IP.\n"
            "Configure a chave VirusTotal em Configurações, opção 17.\n"
            "99 abre este manual; 00 volta.\n"
        ),
        "nmap": (
            "1 scan TCP leve; 2 scan privilegiado; 3 descoberta de IP real.\n"
            "4 enumera caminhos; 5 enumera endpoints; 6 enumera parâmetros HTTP.\n"
            "99 abre este manual; 00 volta. Confirme autorização antes de cada operação ativa.\n"
        ),
        "exports": (
            "Selecione um relatório, escolha CSV, JSONL ou PDF e indique o destino.\n"
            "A gravação exige confirmação explícita. 99 abre este manual; 00 volta.\n"
        ),
        "wordlists": (
            "Selecione uma lista verificada da categoria atual ou digite A para importar\n"
            "um arquivo UTF-8 local. O conteúdo das listas não é exibido.\n"
            "99 abre este manual; 00 cancela.\n"
        ),
        "config": (
            "1 máximo de páginas; 2 intervalo entre requisições; 3 agente do usuário;\n"
            "4 profundidade; 5 limite de tentativas de autenticação; 6 limite do relatório;\n"
            "7 verbosidade; 8 profundidade NUKE; 9 workers do crawler; 10 proxy;\n"
            "11 ano inicial do Wayback; 12 modo Google Hacking; 13 arquivo de escopo;\n"
            "14 renderização JS; 15 variação de cabeçalhos; 16 dorks personalizados;\n"
            "17 provedor de busca automática; 18 arquivo de log; 19 nível do log;\n"
            "20 limite DNS; 21 banco local; 22 taxa do scanner; 23 workers do scanner;\n"
            "24 cache do scanner; 25 múltiplos alvos; 26 URL SearXNG;\n"
            "27 tentativas por conta; 28 intervalo de autenticação;\n"
            "29 captura dinâmica SPA/XHR; 30 wordlist padrão de subdomínios;\n"
            "31 abre o submenu de chaves e IDs de API; 32 salva.\n"
            "99 manual; 00 voltar.\n"
        ),
        "api_keys": (
            "Configure as credenciais e identificadores usados pelas integrações.\n"
            "Os valores secretos não são exibidos; apenas seu estado configurado.\n"
            "9 salva; 99 abre este manual; 00 volta às configurações gerais.\n"
        ),
        "logs": (
            "Digite o número do arquivo para abrir; export inicia o fluxo guiado;\n"
            "delete <arquivo> move para a lixeira RavenEye após confirmação SIM;\n"
            "watch <arquivo> acompanha o arquivo. No leitor: grep, head, tail, less,\n"
            "clear, delete, watch e export. 99 manual; 00 volta.\n"
        ),
    }
    if context in extra_manuals:
        manual_titles = {
            "principal": "MENU PRINCIPAL", "hall": "SALÃO PRINCIPAL",
            "google_hacking": "GOOGLE HACKING", "virustotal": "VIRUSTOTAL",
            "nmap": "NMAP", "exports": "EXPORTAÇÃO", "wordlists": "WORDLISTS",
            "config": "CONFIGURAÇÕES", "api_keys": "CHAVES DE API",
            "logs": "LEITOR DE LOGS",
        }
        print(Fore.CYAN + f"\n[ MANUAL - {manual_titles[context]} ]" + Style.RESET_ALL)
        print(extra_manuals[context])
        input("\nPressione Enter para continuar...")
        return

    manuals: dict[str, dict | str] = {
        "crawler": {
            "1":  "Apenas Crawler — rastreia o site e coleta links do mesmo domínio.",
            "2":  "Crawler + IP — exibe IP resolvido e ping.",
            "3":  "Crawler + Whois — consulta informações de registro do domínio.",
            "4":  "Crawler + Wayback — snapshot do site no Archive.org.",
            "5":  "Crawler + Shodan — consulta IP no Shodan (requer chave API).",
            "6":  "Crawler + Nmap (leve) — varredura de portas sem privilégios administrativos, -D RND:5.",
            "7":  "Crawler + Wayback priorizado — prioriza URLs históricas do Wayback.",
            "8":  "Crawler + Probing de parâmetros — testa nomes de parâmetro comuns "
                  "(id, page, search, redirect...) e só registra os que realmente mudam "
                  "a resposta do servidor, comparada a uma linha de base.",
            "9":  "Crawler + descoberta de caminhos — adiciona caminhos sensíveis comuns à fila.",
            "10": "Crawler + Shodan + IP — combina Shodan e resolução de IP.",
            "11": "Crawler Completo — ativa todas as fontes de URL e APIs.",
            "*":  "Múltiplos alvos: após digitar cada URL, a ferramenta pergunta "
                  "'Deseja adicionar mais um alvo?'. Respondendo 's' adiciona outro; "
                  "'n' inicia o scan de todos na ordem em que foram adicionados, "
                  "um após o outro.",
        },
        "ofensivo": {
            "1": "Crawler + Shodan + Nmap (vulnerabilidades) — Nmap leve com scripts de detecção.",
            "2": "Crawler + Shodan + checagens HTTP de baixo impacto.",
            "3": "Crawler + Shodan + Nmap — varredura completa, -D RND:5 (requer privilégios administrativos).",
            "4": "Abre a auditoria HTTP governada, com confirmação, limite serial e wordlists classificadas.",
        },
        "bruteforce": {
            "1": "Auditoria de login HTTP — listas classificadas, taxa serial e limite por conta.",
            "2": "Auditoria de login HTTP — usuários e senhas em listas separadas.",
            "3": "Enumeração de subdomínios — resolução DNS ativa com a wordlist configurada ou uma lista importada. Não tenta autenticar.",
            "4": "Descoberta de diretórios/caminhos — enumeração HTTP limitada, sem autenticação.",
            "5": "Descoberta de endpoints — enumeração HTTP limitada, sem autenticação.",
            "6": "Sondagem de parâmetros — linha de base e marcador benigno, sem exploração.",
            "7": "Auditoria de login HTTP — lista combinada usuário:senha.",
        },
        "vulnerability": {
            "1": "Scanner com privilégios administrativos e enriquecimento CVE/CWE quando houver correspondência confiável.",
            "2": "Scanner sem privilégios administrativos, com linha de base, evidências e pontuação de confiança.",
        },
        "nuke": {
            "1": "NUKE — comportamento original, requer privilégios administrativos; sem Scanner de Vulnerabilidades.",
            "2": "C4 — comportamento original, sem privilégios administrativos; sem Scanner de Vulnerabilidades.",
            "3": "NUKE + Scanner de Vulnerabilidades (requer privilégios administrativos).",
            "4": "C4 + Scanner de Vulnerabilidades (sem privilégios administrativos).",
        },
        "config": (
            "Opções de configuração:\n"
            "  1 - Máximo de páginas do crawler\n"
            "  2 - Intervalo entre requisições (segundos)\n"
            "  3 - User-Agent\n"
            "  4 - Profundidade do crawler\n"
            "  5 - Tentativas globais de autenticação (máximo 100)\n"
            "  6 - Limite de links TXT por categoria\n"
            "  7 - Verbosidade (0 a 3; depuração redigida)\n"
            "  8 - Chave Shodan; 9 - Profundidade NUKE; 10 - Workers do crawler\n"
            " 11 - Proxy; 12 - Ano inicial do Wayback; 13 - Modo Google Hacking\n"
            " 14 - Arquivo de escopo; 15 - Renderização JavaScript\n"
            " 16 - Headers variados; 17 - Chave VirusTotal; 18 - Dorks personalizados\n"
            " 19 - Chave Google CSE; 20 - ID Google CSE; 21 - Provedor de busca\n"
            " 22 - Salvar; 23 - Arquivo de log; 24 - Nível de log; 25 - Limite DNS\n"
            " 26 - Banco local; 27 - Taxa do scanner; 28 - Workers do scanner; 29 - Cache do scanner\n"
            " 30 - Múltiplos alvos; 31 - URL do SearXNG Docker; 32 - Tentativas por conta\n"
            " 33 - Intervalo de autenticação; 34 - Chave Censys; 35 - Chave Netlas\n"
            " 36 - Chave LeakIX; 37 - Organização Censys (opcional)\n"
            " 38 - Captura dinâmica de SPA/XHR/fetch no engine async\n"
            " 99 - Este manual\n"
            " 00 - Voltar\n"
        ),
        "logs": (
            "Manual do Leitor de Logs:\n"
            "  Busca em reports/ (recursivo) e no diretório atual.\n"
            "  Categorias disponíveis:\n"
            "    TXT COMPLETO      — relatório principal com todos os achados\n"
            "    GOOGLE HACKING    — dorks gerados (locais + Custom Search API)\n"
            "    NMAP              — resultado da varredura de portas\n"
            "    CSV               — achados em formato planilha\n"
            "    MARKDOWN          — relatório resumido em .md\n"
            "    VIRUSTOTAL        — consultas independentes de URL/domínio/IP\n"
            "    SUBDOMÍNIOS       — resultado do bruteforce de subdomínios (DNS)\n"
            "    WORDLIST          — URLs crawladas\n"
            "    ENDPOINTS         — caminhos encontrados\n"
            "    LOG ESTRUTURADO   — raveneye.log (eventos internos da ferramenta)\n"
            "    AUDITORIA         — confirmações de autorização (digitou SIM)\n"
            "  Comandos após escolher arquivo:\n"
            "    grep <padrão>   filtra linhas pelo padrão\n"
            "    head <n>        mostra primeiras N linhas\n"
            "    tail <n>        mostra as últimas N linhas\n"
            "    less            paginação (se disponível)\n"
            "    clear           limpa a tela\n"
            "    sair            volta à seleção de arquivo\n"
            "  Padrões grep válidos: alfanuméricos, . - _ * ? | ^ $\n"
            "  99 - exibe este manual\n"
            "  00 - volta ao menu principal\n"
        ),
    }

    ctx_map = {
        "crawler": ("\n[ MANUAL - WEB CRAWLER MAPEAMENTO ]", manuals["crawler"]),
        "ofensivo": ("\n[ MANUAL - WEB CRAWLER OFENSIVO ]", manuals["ofensivo"]),
        "bruteforce": ("\n[ MANUAL - FORÇA BRUTA ]", manuals["bruteforce"]),
        "vulnerability": ("\n[ MANUAL - SCANNER DE VULNERABILIDADES ]", manuals["vulnerability"]),
        "nuke": ("\n[ MANUAL - NUKE/C4 ]", manuals["nuke"]),
        "config": ("\n[ MANUAL - CONFIGURAÇÕES ]", manuals["config"]),
        "logs": ("\n[ MANUAL - LEITOR DE LOGS ]", manuals["logs"]),
    }

    if context not in ctx_map:
        print(Fore.CYAN + "\nManual não disponível para este contexto." + Style.RESET_ALL)
        return

    title, content = ctx_map[context]
    print(Fore.CYAN + title + Style.RESET_ALL)

    if isinstance(content, dict):
        for k, v in content.items():
            print(Fore.WHITE + f"  {k:3} - " + Style.RESET_ALL + v)
    else:
        print(content)

    input("\nPressione Enter para continuar...")


# ==================================================================
# MENUS — Leitura de Logs (BUG FIX: novas categorias Nmap e Externos)
# ==================================================================
def _validate_grep_pattern(pattern: str) -> bool:
    """Valida pattern grep para evitar injeção de comando."""
    if not pattern:
        return False
    forbidden = [";", "&", "$(", "`", "\n", "\r", "&&", "||"]
    for f in forbidden:
        if f in pattern:
            return False
    if re.search(r"[^a-zA-Z0-9.\-_*?|^$\s\[\](){}+\\]", pattern):
        return False
    return True


def _is_log_subcategory(f: str) -> bool:
    """Retorna True se o arquivo é uma subcategoria (não relatorio principal)."""
    name = Path(f).name
    return any(tag in name for tag in [
        "_wordlist", "_endpoints", "_dorks_", "_nmap_", "_report.", "_findings.csv"
    ])


def _find_report_files(pattern: str) -> list[str]:
    """Busca arquivos de relatorio tanto em reports/ (recursivo, onde os scans
    normais salvam desde a reorganizacao de output) quanto no diretorio atual
    (arquivos soltos de ferramentas standalone como VirusTotal/subdominios,
    ou relatorios de versoes antigas). Ordenado do mais recente para o mais antigo."""
    found: set[str] = set()
    reports_dir = Path("reports")
    # Resolve every entry before presenting it.  The log menu is also used as
    # the source for ``watch``, ``delete`` and export operations; absolute
    # paths remove the ambiguity between a report in ``reports/`` and a file
    # with the same name in the caller's current directory.
    if reports_dir.is_dir():
        found.update(str(p.resolve()) for p in reports_dir.rglob(pattern))
    found.update(str(Path(p).resolve()) for p in glob.glob(pattern))
    return sorted(found, key=lambda f: Path(f).stat().st_mtime if Path(f).exists() else 0, reverse=True)


def _list_exportable_reports() -> list[str]:
    """Lista apenas artefatos de relatório exportáveis, numerados por idade."""
    patterns = (
        "RavenEye_*.txt", "RavenEye_*.json", "RavenEye_*.jsonl",
        "RavenEye_*.html", "RavenEye_*.csv", "RavenEye_*.md",
        "RavenEye_*.pdf",
    )
    found: set[str] = set()
    for pattern in patterns:
        found.update(_find_report_files(pattern))
    return sorted(
        (f for f in found if Path(f).is_file()),
        key=lambda f: Path(f).stat().st_mtime,
        reverse=True,
    )


def _export_report_submenu(source: str | None = None) -> None:
    """Fluxo guiado de exportacao: arquivo -> formato -> destino.

    Mantem a operacao longe do prompt de comando para reduzir ambiguidades.
    """
    _clear_screen()
    print(Fore.MAGENTA + "\n<===== EXPORTAR RELATÓRIO =====>" + Style.RESET_ALL)

    reports = [source] if source else _list_exportable_reports()
    if not reports:
        print(Fore.YELLOW + "\nNenhum arquivo de relatório encontrado." + Style.RESET_ALL)
        print("\n  99 - Manual")
        print("  00 - Voltar")
        choice = input("\nEscolha: ").strip()
        if choice == "99":
            show_manual("exports")
        return

    print(Fore.WHITE + "\nSelecione o arquivo que será exportado:\n" + Style.RESET_ALL)
    for idx, report in enumerate(reports, 1):
        try:
            size = Path(report).stat().st_size
            size_str = f"{size // 1024}KB" if size >= 1024 else f"{size}B"
        except OSError:
            size_str = "?"
        print(f"  {idx} - {report} [{size_str}]")
    print("\n  99 - Manual")
    print("  00 - Voltar")

    choice = input("\nArquivo: ").strip()
    if choice == "00":
        return
    if choice == "99":
        show_manual("exports")
        return
    if not choice.isdigit() or not (1 <= int(choice) <= len(reports)):
        print(Fore.RED + "[!] Arquivo inválido." + Style.RESET_ALL)
        input("Pressione Enter para continuar...")
        return

    selected = Path(reports[int(choice) - 1])
    _clear_screen()
    print(Fore.MAGENTA + "\n<===== EXPORTAR RELATÓRIO =====>" + Style.RESET_ALL)
    print(Fore.WHITE + f"\nArquivo selecionado: {selected}" + Style.RESET_ALL)
    print("\nSelecione o formato de exportação:\n")
    print("  1 - CSV   (.csv)")
    print("  2 - JSONL (.jsonl)")
    print("  3 - PDF   (.pdf)")
    print("\n  99 - Manual")
    print("  00 - Voltar")

    fmt_choice = input("\nFormato: ").strip()
    formats = {"1": ("csv", ".csv"), "2": ("jsonl", ".jsonl"), "3": ("pdf", ".pdf")}
    if fmt_choice == "00":
        return
    if fmt_choice == "99":
        show_manual("exports")
        return
    if fmt_choice not in formats:
        print(Fore.RED + "[!] Formato inválido." + Style.RESET_ALL)
        input("Pressione Enter para continuar...")
        return

    fmt, suffix = formats[fmt_choice]
    _clear_screen()
    print(Fore.MAGENTA + "\n<===== CONFIRMAR EXPORTAÇÃO =====>" + Style.RESET_ALL)
    print(f"\nArquivo de origem : {selected}")
    print(f"Formato escolhido : {fmt.upper()}")
    default_name = selected.stem + "_export" + suffix
    output_name = input(f"Arquivo de destino [{default_name}]: ").strip() or default_name
    output = Path(output_name)
    if output.suffix.lower() != suffix:
        output = output.with_suffix(suffix)

    print("\nResumo:")
    print(f"  Origem : {selected}")
    print(f"  Saída  : {output}")
    confirm = input("\nDigite 'SIM' para confirmar: ").strip()
    if confirm != "SIM":
        print(Fore.YELLOW + "[!] Exportação cancelada." + Style.RESET_ALL)
        input("Pressione Enter para continuar...")
        return

    try:
        # O exportador aceita logs JSONL. Para relatorios nao-JSONL, PDF/CSV/JSONL
        # sao derivados do conteudo textual sem executar comandos externos.
        dest = _export_report_file(str(selected), str(output), fmt)
        print(Fore.GREEN + f"\n[+] Exportado com sucesso: {dest}" + Style.RESET_ALL)
        if fmt == "pdf":
            print(Fore.WHITE + "    Validacao PDF: assinatura %PDF confirmada." + Style.RESET_ALL)
    except Exception as exc:
        print(Fore.RED + f"\n[!] Falha na exportação: {exc}" + Style.RESET_ALL)
    input("\nPressione Enter para voltar...")


def menu_logs() -> None:
    """Menu categorizado de leitura de logs com exportacao guiada."""
    _clear_screen()
    ascii_book()

    while True:
        search_dir = f"{Path.cwd()} (e reports/ recursivamente)"
        txt_todos = _find_report_files("RavenEye_*.txt")
        txt_dorks = _find_report_files("RavenEye_dorks_*.txt")
        txt_nmap = _find_report_files("RavenEye_nmap_*.txt")
        txt_wordlist = _find_report_files("RavenEye_*_wordlist.txt")
        txt_endpoints = _find_report_files("RavenEye_*_endpoints.txt")
        txt_csv = _find_report_files("RavenEye_*_findings.csv")
        txt_markdown = _find_report_files("RavenEye_*_report.md")
        txt_vt = _find_report_files("RavenEye_virustotal_*.txt")
        txt_subs = _find_report_files("RavenEye_subdomains_bf_*.txt")
        # Keep the canonical timestamped name and the compact legacy name
        # visible; both are produced by supported report paths.
        txt_events = sorted(set(
            _find_report_files("RavenEye_*_events.jsonl")
            + _find_report_files("RavenEye_events.jsonl")
        ), key=lambda item: Path(item).stat().st_mtime if Path(item).exists() else 0, reverse=True)
        txt_completos = [f for f in txt_todos if not _is_log_subcategory(f)]
        log_file_cfg = state.config.get("log_file", "raveneye.log")
        txt_structured_log = sorted(glob.glob(f"{log_file_cfg}*")) if log_file_cfg else []
        txt_audit = sorted(glob.glob("raveneye_audit_log.txt"))

        all_categorized = [
            ("<==== RELATÓRIO PRINCIPAL (TXT) ====>", txt_completos),
            ("<==== GOOGLE HACKING — Dorks ====>", txt_dorks),
            ("<==== NMAP — Portas e CVEs ====>", txt_nmap),
            ("<==== CSV — Achados ====>", txt_csv),
            ("<==== MARKDOWN ====>", txt_markdown),
            ("<==== VIRUSTOTAL (standalone) ====>", txt_vt),
            ("<==== SUBDOMÍNIOS (força bruta DNS) ====>", txt_subs),
            ("<==== WORDLIST — URLs crawladas ====>", txt_wordlist),
            ("<==== ENDPOINTS ====>", txt_endpoints),
            ("<==== EVENTOS DO SCAN — JSONL ====>", txt_events),
            ("<==== LOG ESTRUTURADO (raveneye.log) ====>", txt_structured_log),
            ("<==== AUDITORIA — autorizações confirmadas ====>", txt_audit),
        ]

        all_files: list[str] = []
        print(Fore.CYAN + "\n[ LEITOR DE LOGS ]" + Style.RESET_ALL)
        print(Fore.WHITE + f"  Buscando em: {search_dir}" + Style.RESET_ALL)
        file_idx = 1
        for cat_name, files in all_categorized:
            print(Fore.YELLOW + f"\n{cat_name}" + Style.RESET_ALL)
            if files:
                for f in files:
                    try:
                        size = Path(f).stat().st_size
                        size_str = f"{size//1024}KB" if size >= 1024 else f"{size}B"
                    except OSError:
                        size_str = "?"
                    print(f"  {file_idx}. {f}  [{size_str}]")
                    all_files.append(f)
                    file_idx += 1
            else:
                print(Fore.WHITE + "    (nenhum arquivo encontrado)" + Style.RESET_ALL)

        print(Fore.WHITE + "\n  export  - exportação guiada (arquivo -> formato -> destino)" + Style.RESET_ALL)
        print(Fore.WHITE + "  delete <arquivo> | watch <arquivo>" + Style.RESET_ALL)
        print(Fore.WHITE + "  99 - Manual" + Style.RESET_ALL)
        print(Fore.WHITE + "  00 - Sair" + Style.RESET_ALL)
        choice = input("> ").strip()

        if choice == "00":
            break
        if choice == "99":
            show_manual("logs")
            continue
        if choice.lower() == "export":
            _export_report_submenu()
            _clear_screen()
            ascii_book()
            continue

        parts = choice.split(maxsplit=1)
        command = parts[0].lower() if parts else ""
        argument = parts[1] if len(parts) > 1 else ""
        if command == "delete":
            if not argument.strip():
                print("Uso: delete <arquivo>; caminhos com espaços podem ser informados entre aspas.")
                continue
            try:
                target_name = _parse_log_path_argument(argument)
            except ValueError:
                print("Caminho inválido. Confira as aspas e tente novamente.")
                continue
            target = Path(target_name)
            print(Fore.YELLOW + f"\n[!] O arquivo sera movido para .raveneye_trash/: {target}" + Style.RESET_ALL)
            confirm = input("Digite 'SIM' para confirmar: ").strip()
            try:
                dest = _safe_delete_log(str(target), confirmation=confirm)
                print(Fore.GREEN + f"[+] Movido para: {dest}" + Style.RESET_ALL)
            except Exception as exc:
                print(Fore.RED + f"[!] Falha ao mover arquivo: {exc}" + Style.RESET_ALL)
            continue
        if command == "watch":
            if not argument.strip():
                print("Uso: watch <arquivo>; caminhos com espaços podem ser informados entre aspas.")
                continue
            try:
                target_name = _parse_log_path_argument(argument)
            except ValueError:
                print("Caminho inválido. Confira as aspas e tente novamente.")
                continue
            target = Path(target_name)
            if not target.is_file():
                print(Fore.RED + "[!] Arquivo de log não encontrado." + Style.RESET_ALL)
                continue
            print(Fore.CYAN + "[WATCH] Ctrl+C para parar." + Style.RESET_ALL)
            try:
                asyncio.run(_watch_log(str(target)))
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n[WATCH] encerrado." + Style.RESET_ALL)
            continue
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(all_files):
                _log_file_viewer(all_files[idx])
            else:
                print(Fore.RED + f"Número fora do intervalo (1–{len(all_files)})." + Style.RESET_ALL)
        else:
            print("Digite o número do arquivo, export, 99 para o manual ou 00 para sair.")


def _parse_log_path_argument(raw: str) -> str:
    """Accept a quoted path or an unquoted path containing spaces."""
    value = str(raw or "").strip()
    if not value:
        return ""
    if value[0] in {"'", '"'}:
        try:
            parts = shlex.split(value)
        except ValueError as exc:
            raise ValueError("aspas não fechadas") from exc
        if len(parts) != 1:
            raise ValueError("informe um único caminho")
        return parts[0]
    return value


def _log_file_viewer(filename: str) -> None:
    """Exibe arquivo de log com comandos interativos."""
    print(Fore.GREEN + f"\n[ LOG: {filename} ]" + Style.RESET_ALL)
    try:
        raw_lines = Path(filename).read_text(encoding="utf-8", errors="replace").splitlines()
        lines = [_safe_log_line(line).rstrip("\n") for line in raw_lines]
        print(f"  {len(lines)} linhas | Digite um comando ou 'sair'\n")
    except (IOError, FileNotFoundError) as e:
        print(Fore.RED + f"Erro ao abrir arquivo: {e}" + Style.RESET_ALL)
        return

    while True:
        print(Fore.WHITE + "  grep <padrão> | head <n> | tail <n> | less | clear | delete | watch | export | sair" + Style.RESET_ALL)
        print(Fore.MAGENTA + "  Exportação: CSV | JSONL | PDF" + Style.RESET_ALL)
        print(Fore.WHITE + "  99 - Manual  |  00 - Voltar" + Style.RESET_ALL)
        cmd = input(f"({Path(filename).name}) > ").strip()

        if not cmd or cmd.lower() in {"00", "sair"}:
            break
        if cmd == "99":
            show_manual("logs")
            continue
        command = cmd.split(maxsplit=1)[0].lower()

        if command == "grep" and cmd.lower().startswith("grep "):
            pattern = cmd[5:].strip()
            if not _validate_grep_pattern(pattern):
                print(Fore.RED + "[!] Padrão inválido. Use apenas letras, números e os símbolos . - _ * ? | ^ $." + Style.RESET_ALL)
                continue
            try:
                results = [l for l in lines if re.search(pattern, l, re.IGNORECASE)]
                print(Fore.CYAN + f"  {len(results)} resultados:" + Style.RESET_ALL)
                for r in results[:200]:
                    print(f"  {r}")
            except re.error as e:
                print(Fore.RED + f"Expressão regular inválida: {e}" + Style.RESET_ALL)

        elif command == "head":
            parts = cmd.split()
            n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
            for l in lines[:n]:
                print(l)

        elif command == "tail":
            parts = cmd.split()
            n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
            for l in lines[-n:]:
                print(l)

        elif command == "less":
            if shutil.which("less"):
                subprocess.run(["less", filename])
            else:
                for l in lines:
                    print(l)

        elif command == "clear":
            _clear_screen()
            print(Fore.GREEN + f"\n[ LOG: {filename} ]" + Style.RESET_ALL)

        elif command == "delete":
            confirm = input("Digite 'SIM' para mover este arquivo para .raveneye_trash/: ").strip()
            try:
                dest = _safe_delete_log(filename, confirmation=confirm)
                print(Fore.GREEN + f"[+] Movido para: {dest}" + Style.RESET_ALL)
                break
            except Exception as exc:
                print(Fore.RED + f"[!] Falha ao mover arquivo: {exc}" + Style.RESET_ALL)

        elif command == "watch":
            print(Fore.CYAN + "[WATCH] Ctrl+C para parar." + Style.RESET_ALL)
            try:
                asyncio.run(_watch_log(filename))
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n[WATCH] encerrado." + Style.RESET_ALL)

        elif command == "export":
            args = cmd.split(maxsplit=2)
            if len(args) == 3:
                try:
                    dest = _export_log_category(filename, args[1], args[2])
                    print(Fore.GREEN + f"[+] Exportado para: {dest}" + Style.RESET_ALL)
                except Exception as exc:
                    print(Fore.RED + f"[!] Falha na exportação: {exc}" + Style.RESET_ALL)
            else:
                _log_format_menu()
                print("Uso rápido: export <categoria> <arquivo.csv|arquivo.jsonl|arquivo.pdf>")

        else:
            print("Comando não reconhecido. Use grep, head, tail, less, clear, delete, watch, export, 99 ou 00.")


# ==================================================================
# MENU — Configurações
# ==================================================================
def menu_api_keys() -> None:
    """Configure API integration keys in a dedicated submenu."""
    while True:
        print(Fore.CYAN + "\n[ CHAVES DE API ]" + Style.RESET_ALL)
        print(f"  1 - Shodan:                 {'configurada' if get_api_key('shodan') else 'vazia'}")
        print(f"  2 - VirusTotal:             {'configurada' if get_api_key('virustotal') else 'vazia'}")
        print(f"  3 - Google CSE API:         {'configurada' if get_api_key('google_cse') else 'vazia'}")
        print(f"  4 - Google CSE ID:          {'configurado' if get_google_cse_id() else 'vazio'}")
        print(f"  5 - Censys:                 {'configurada' if get_api_key('censys') else 'vazia'}")
        print(f"  6 - Netlas:                 {'configurada' if get_api_key('netlas') else 'vazia'}")
        print(f"  7 - LeakIX:                 {'configurada' if get_api_key('leakix') else 'vazia'}")
        print(f"  8 - Organização Censys:     {'configurada' if state.config.get('censys_organization_id') or os.environ.get('CENSYS_ORGANIZATION_ID') else 'vazia'}")
        print("\n  9  - Salvar configurações")
        print("  99 - Manual")
        print("  00 - Voltar")

        op = input("> ").strip()
        if op == "00":
            break
        if op == "99":
            show_manual("api_keys")
            continue
        if op == "9":
            save_config(state.config)
            print(Fore.GREEN + f"Configurações salvas em {CONFIG_FILE}." + Style.RESET_ALL)
            continue

        providers = {
            "1": ("shodan", "Nova chave Shodan (Enter para remover): "),
            "2": ("virustotal", "Nova chave VirusTotal (Enter para remover): "),
            "3": ("google_cse", "Nova chave Google Custom Search API (Enter para remover): "),
            "5": ("censys", "Personal Access Token Censys (Enter para remover): "),
            "6": ("netlas", "Nova chave Netlas (Enter para remover): "),
            "7": ("leakix", "Nova chave LeakIX (Enter para remover): "),
        }
        if op in providers:
            provider, prompt = providers[op]
            set_api_key(provider, input(prompt).strip())
            print(Fore.GREEN + f"Chave {provider} atualizada. Use 9 para salvar." + Style.RESET_ALL)
        elif op == "4":
            state.config["google_cse_id"] = input(
                "Google CSE ID (Search Engine ID, Enter para remover): "
            ).strip()
            print(Fore.GREEN + "Google CSE ID atualizado. Use 9 para salvar." + Style.RESET_ALL)
        elif op == "8":
            state.config["censys_organization_id"] = input(
                "Organization ID Censys opcional (Enter para remover): "
            ).strip()
            print(Fore.GREEN + "Organização Censys atualizada. Use 9 para salvar." + Style.RESET_ALL)
        else:
            print("Opção inválida.")


def menu_config() -> None:
    """Menu de configurações gerais, separado das credenciais de API."""
    _clear_screen()

    while True:
        gh_mode = state.config.get("google_hacking_mode", "scan")
        print(Fore.WHITE + "\n[ CONFIGURAÇÕES GERAIS ]" + Style.RESET_ALL)
        print(f"  1  - Máximo de páginas:       {state.config['max_pages']}")
        print(f"  2  - Intervalo entre requisições: {state.config['delay']} s")
        print(f"  3  - User-Agent:              {state.config['user_agent'][:50]}...")
        print(f"  4  - Profundidade do crawler: {state.config['max_depth']}")
        print(f"  5  - Tentativas de autenticação: {min(100, int(state.config['bf_attempts']))} (máx. 100)")
        print(f"  6  - Limite de links TXT:     {state.config['report_link_limit']}")
        print(f"  7  - Verbosidade (0-3):       {state.VERBOSE_LEVEL}")
        print(Fore.RED + f"  8  - Profundidade NUKE:       {state.config.get('max_depth_nuke', 5)}" + Style.RESET_ALL)
        print(f"  9  - Workers do crawler:      {state.config.get('max_workers', 5)}")
        print(f"  10 - Proxy:                   {state.config.get('proxy', '') or 'nenhum'}")
        print(f"  11 - Ano inicial do Wayback:  {state.config.get('wayback_from_year', 2020)}")
        print(f"  12 - Google Hacking:          {gh_mode} (verificação integrada, modo interativo separado)")
        print(f"  13 - Arquivo de escopo:       {state.config.get('scope_file', '') or 'nenhum'}")
        print(f"  14 - Renderização JS:         {'ativa' if state.config.get('use_js_render') else 'inativa'}")
        print(f"  15 - Headers variados:        {'ativos' if state.config.get('stealth_mode') else 'inativos'}")
        print(f"  16 - Arquivo de consultas customizadas: {state.config.get('custom_dorks_file', '') or 'nenhum'}")
        print(f"  17 - Busca automática:        {state.config.get('dork_search_provider', 'none')} (none/searxng/google_cse)")
        print(f"  18 - Arquivo de log:          {state.config.get('log_file', '') or 'desativado'}")
        print(f"  19 - Nível do log:            {state.config.get('log_level', 'WARNING')}")
        print(f"  20 - Limite DNS:              {state.config.get('dns_rate_limit', 30)} req/s")
        print(f"  21 - Banco local:             {state.config.get('database_path', 'data/raveneye.db')}")
        print(f"  22 - Limite de taxa do scanner: {state.config.get('scanner_rate_limit', 8.0)} req/s")
        print(f"  23 - Workers do scanner:      {state.config.get('scanner_max_workers', 6)}")
        print(f"  24 - Cache do scanner:        {state.config.get('scan_cache_ttl', 3600)} s")
        print(f"  25 - Múltiplos alvos:         {'ATIVO' if state.config.get('multi_target_enabled') else 'INATIVO'}")
        print(f"  26 - URL SearXNG Docker:      {state.config.get('searxng_url', 'http://127.0.0.1:8080')}")
        print(f"  27 - Tentativas por conta:    {state.config.get('bf_attempts_per_user', 5)} (máx. 100)")
        print(f"  28 - Intervalo de autenticação: {state.config.get('bf_delay', 1.0)} s (mín. 1 s)")
        print(f"  29 - Captura dinâmica SPA/XHR: {'ativa' if state.config.get('headless_rendering') else 'inativa'} (crawler async)")
        print(f"  30 - Wordlist de subdomínios: {_configured_subdomain_wordlist_label()}")
        print("\n  31 - Configurar chaves e IDs de API")
        print(Fore.GREEN + "  32 - Salvar configurações" + Style.RESET_ALL)
        print()
        print(Fore.WHITE + "  99 - Manual" + Style.RESET_ALL)
        print(Fore.WHITE + "  00 - Voltar" + Style.RESET_ALL)

        selected = input("> ").strip()
        if selected == "00":
            break
        if selected == "99":
            show_manual("config")
            continue
        if selected == "31":
            menu_api_keys()
            continue
        if selected == "32":
            save_config(state.config)
            print(Fore.GREEN + f"Configurações salvas em {CONFIG_FILE}" + Style.RESET_ALL)
            continue

        op = {
            "1": "1", "2": "2", "3": "3", "4": "4", "5": "5", "6": "6", "7": "7",
            "8": "9", "9": "10", "10": "11", "11": "12", "12": "13", "13": "14",
            "14": "15", "15": "16", "16": "18", "17": "21", "18": "23", "19": "24",
            "20": "25", "21": "26", "22": "27", "23": "28", "24": "29", "25": "30",
            "26": "31", "27": "32", "28": "33", "29": "38", "30": "39",
        }.get(selected)
        if op is None:
            print("Opção inválida.")
            continue

        if op == "38":
            enabled = input("Ativar renderização headless no crawler async? (s/N): ").strip().lower() == "s"
            state.config["headless_rendering"] = enabled
            if enabled and not PLAYWRIGHT_AVAILABLE:
                print(Fore.YELLOW + "Playwright não está disponível; o installer instala o runtime completo e os browsers." + Style.RESET_ALL)
        elif op == "39":
            manager = get_wordlist_manager()
            chosen = _choose_wordlist(
                manager,
                "subdomains",
                default_id=str(state.config.get("subdomain_wordlist_id", "builtin_subdomains")),
            )
            if chosen:
                _path, info = chosen
                state.config["subdomain_wordlist_id"] = info.id
                print(Fore.GREEN + f"[+] Padrão de subdomínios: {info.label} ({info.entries} entradas). Use 32 para salvar." + Style.RESET_ALL)
        elif op == "1":
            try:
                v = int(input("Valor (1-999): "))
                if 1 <= v <= 999:
                    state.config["max_pages"] = v
            except Exception as e:
                vprint(2, f"[WARN] config op1: {e}")
        elif op == "2":
            try:
                v = float(input("Intervalo (s): "))
                if v >= 0:
                    state.config["delay"] = v
            except Exception as e:
                vprint(2, f"[WARN] config op2: {e}")
        elif op == "3":
            ua = input("Novo User-Agent (Enter p/ reset): ").strip()
            state.config["user_agent"] = ua if ua else USER_AGENTS[0]
        elif op == "4":
            try:
                v = int(input("Profundidade (0-10): "))
                if 0 <= v <= 10:
                    state.config["max_depth"] = v
                else:
                    print("Valor fora do intervalo permitido.")
            except Exception as e:
                vprint(2, f"[WARN] config op4: {e}")
        elif op == "5":
            try:
                v = int(input("Tentativas de autenticação nesta execução (1–100): "))
                if 1 <= v <= 100:
                    state.config["bf_attempts"] = v
                else:
                    print("Valor fora do intervalo permitido (1–100).")
            except Exception as e:
                vprint(2, f"[WARN] config op5: {e}")
        elif op == "6":
            try:
                v = int(input("Limite links: "))
                if v >= 1:
                    state.config["report_link_limit"] = v
            except Exception as e:
                vprint(2, f"[WARN] config op6: {e}")
        elif op == "7":
            try:
                v = int(input("Nível de verbosidade (0-3): "))
                if 0 <= v <= 3:
                    state.VERBOSE_LEVEL = v
                    set_verbose(v)
                    state.config["verbose"] = v
            except Exception as e:
                vprint(2, f"[WARN] config op7: {e}")
        elif op == "9":
            try:
                v = int(input("Profundidade NUKE (5-20): "))
                if 5 <= v <= 20:
                    state.config["max_depth_nuke"] = v
                else:
                    print("Valor fora do intervalo permitido (5–20).")
            except Exception as e:
                vprint(2, f"[WARN] config op9: {e}")
        elif op == "10":
            try:
                v = int(input("Tarefas simultâneas do crawler (1–20): "))
                if 1 <= v <= 20:
                    state.config["max_workers"] = v
            except Exception as e:
                vprint(2, f"[WARN] config op10: {e}")
        elif op == "11":
            proxy = input("Proxy (ex: http://127.0.0.1:8080 ou vazio p/ remover): ").strip()
            state.config["proxy"] = proxy
            if proxy and "socks" in proxy.lower():
                try:
                    import socks  # noqa: F401
                except ImportError:
                    print(Fore.YELLOW + "[!] requests[socks] não está instalado. Execute: pip install requests[socks]" + Style.RESET_ALL)
        elif op == "12":
            try:
                v = int(input("Ano inicial do Wayback (ex.: 2015): "))
                if 2000 <= v <= 2026:
                    state.config["wayback_from_year"] = v
            except Exception as e:
                vprint(2, f"[WARN] config op12: {e}")
        elif op == "13":
            mode = input("Modo Google Hacking ('scan' para integrado ou 'interativo'): ").strip().lower()
            if mode in ("scan", "interativo"):
                state.config["google_hacking_mode"] = mode
        elif op == "14":
            sf = input("Arquivo de escopo (um domínio por linha; Enter para remover): ").strip()
            state.config["scope_file"] = sf
        elif op == "15":
            v = input("Ativar JS Render Playwright? (s/N): ").strip().lower()
            state.config["use_js_render"] = (v == "s")
            if state.config["use_js_render"] and not PLAYWRIGHT_AVAILABLE:
                print(Fore.YELLOW + "[!] A renderização JS requer o pacote Playwright e um Chromium funcional; Firefox e WebKit são opcionais. Consulte 'raven doctor'." + Style.RESET_ALL)
        elif op == "16":
            v = input("Ativar Modo Stealth (headers variados p/ evadir fingerprint de WAF)? (s/N): ").strip().lower()
            state.config["stealth_mode"] = (v == "s")
        elif op == "18":
            path = input("Caminho do arquivo de dorks customizados (um por linha, Enter p/ remover): ").strip()
            state.config["custom_dorks_file"] = path
        elif op == "21":
            provider = input("Busca automática (none/searxng/google_cse): ").strip().lower()
            if provider in ("none", "searxng", "google_cse"):
                state.config["dork_search_provider"] = provider
            else:
                print("Opção inválida.")
        elif op == "31":
            url = input("URL local do SearXNG (ex: http://127.0.0.1:8080): ").strip()
            if url:
                state.config["searxng_url"] = url
        elif op == "23":
            path = input("Arquivo de log (Enter p/ desativar): ").strip()
            state.config["log_file"] = path
            _setup_logger(path, state.config.get("log_level", "WARNING"))
            print("Log reconfigurado." if path else "Log desativado.")
        elif op == "24":
            lvl = input("Nível do log (DEBUG/INFO/WARNING/ERROR): ").strip().upper()
            if lvl in ("DEBUG", "INFO", "WARNING", "ERROR"):
                state.config["log_level"] = lvl
                _setup_logger(state.config.get("log_file", ""), lvl)
            else:
                print("Nível inválido.")
        elif op == "25":
            try:
                v = int(input("Limite de requisições DNS por segundo (1-200): "))
                if 1 <= v <= 200:
                    state.config["dns_rate_limit"] = v
                else:
                    print("Valor fora do intervalo permitido (1–200).")
            except Exception as e:
                vprint(2, f"[WARN] config op25: {e}")


# ==================================================================
# FUNÇÕES — helpers para menus de scan
# ==================================================================
        elif op == "26":
            dbp = input("Caminho do banco SQLite (Enter = padrão): ").strip()
            state.config["database_path"] = dbp or "data/raveneye.db"
            try:
                path = initialize_database(state.config)
                print(Fore.GREEN + f"Banco verificado: {path}" + Style.RESET_ALL)
            except Exception as e:
                print(Fore.RED + f"[ERRO] banco: {e}" + Style.RESET_ALL)
        elif op == "27":
            try:
                v = float(input("Scanner rate limit (0.5-50 req/s): "))
                if 0.5 <= v <= 50:
                    state.config["scanner_rate_limit"] = v
            except Exception as e:
                vprint(2, f"[WARN] config op27: {e}")
        elif op == "28":
            try:
                v = int(input("Scanner workers (1-20): "))
                if 1 <= v <= 20:
                    state.config["scanner_max_workers"] = v
            except Exception as e:
                vprint(2, f"[WARN] config op28: {e}")
        elif op == "29":
            try:
                v = int(input("TTL cache scanner (60-86400 s): "))
                if 60 <= v <= 86400:
                    state.config["scan_cache_ttl"] = v
            except Exception as e:
                vprint(2, f"[WARN] config op29: {e}")
        elif op == "30":
            v = input("Ativar múltiplos links/alvos? (s/N): ").strip().lower()
            state.config["multi_target_enabled"] = (v == "s")
            if state.config["multi_target_enabled"]:
                try:
                    n = int(input(f"Máximo de alvos por operação (1-{state.config.get('max_targets', 50)}): ") or state.config.get("max_targets", 50))
                    if 1 <= n <= 500:
                        state.config["max_targets"] = n
                except Exception as e:
                    vprint(2, f"[WARN] config op30: {e}")
        elif op == "32":
            try:
                v = int(input("Limite por conta (1-100; padrão 5): "))
                if 1 <= v <= 100:
                    state.config["bf_attempts_per_user"] = v
                else:
                    print("Valor fora do intervalo permitido (1–100).")
            except Exception as e:
                vprint(2, f"[WARN] config op32: {e}")
        elif op == "33":
            try:
                v = float(input("Intervalo entre tentativas (1-60 segundos): "))
                if 1 <= v <= 60:
                    state.config["bf_delay"] = v
                else:
                    print("Valor fora do intervalo permitido (1–60).")
            except Exception as e:
                vprint(2, f"[WARN] config op33: {e}")
def _get_target() -> str:
    """Solicita URL alvo ao usuário. Aceita domínio ou URL completa."""
    raw = input("URL alvo (ex: exemplo.com ou https://exemplo.com): ").strip()
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


def _get_targets_multi(*, allow_multi: bool = True) -> list[str]:
    """Coleta alvos respeitando a opção global de múltiplos links.

    Com a opção ativa, aceita uma URL por linha e encerra com linha vazia.
    Com a opção inativa, solicita somente um alvo.
    """
    enabled = bool(state.config.get("multi_target_enabled", False)) and allow_multi
    max_targets = int(state.config.get("max_targets", 50) or 50)
    if not enabled:
        target = _get_target()
        return [target] if target else []
    print(Fore.CYAN + f"Cole até {max_targets} URLs, uma por linha. Linha vazia finaliza." + Style.RESET_ALL)
    values=[]
    while len(values) < max_targets:
        raw=input(f"URL {len(values)+1}: ").strip()
        if not raw:
            break
        values.append(raw)
    batch=normalize_targets(values, enabled=True, max_targets=max_targets)
    return list(batch.urls)

def _get_targets_for_safe_operation() -> list[str]:
    return _get_targets_multi(allow_multi=True)


def _get_crawl_params() -> tuple[int, int]:
    """Solicita max_pages e max_depth ao usuário."""
    try:
        mp = int(input(f"Max paginas ({state.config['max_pages']}): ") or state.config["max_pages"])
    except Exception:
        mp = state.config["max_pages"]
    try:
        md = int(input(f"Profundidade ({state.config['max_depth']}): ") or state.config["max_depth"])
    except Exception:
        md = state.config["max_depth"]
    return mp, md


def _load_scope() -> list[str]:
    """Carrega arquivo de scope se configurado."""
    sf = state.config.get("scope_file", "")
    if not sf:
        return []
    try:
        return [
            line.strip().lower()
            for line in Path(sf).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except Exception as e:
        vprint(2, f"[WARN] _load_scope: {e}")
        return []


def _load_scanner_scope() -> set[str] | None:
    """Load an explicitly configured scanner scope, failing closed on errors."""
    scope_file = str(state.config.get("scope_file", "") or "").strip()
    if not scope_file:
        return None
    try:
        rules = {
            line.strip().lower()
            for line in Path(scope_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"Arquivo de escopo do scanner indisponível: {exc}") from None
    if not rules:
        raise ValueError("Arquivo de escopo do scanner está vazio; operação bloqueada.")
    return rules


def _make_output_dir(target: str) -> Path:
    """Cria e retorna reports/<dominio>_<timestamp>_<rand>/ para organizar a saida
    de um scan, evitando que dezenas de arquivos se acumulem soltos no diretorio
    atual conforme a ferramenta e usada repetidamente.

    BUG FIX: se 'reports/' existir com permissoes erradas (ex: criada antes por
    um scan rodado com sudo, agora pertencente ao root), tenta pastas alternativas
    em vez de travar o programa com um PermissionError nao tratado.
    """
    domain_safe = _safe_domain_filename(target)
    suffix = f"{int(time.time())}_{random.randint(1000, 9999)}"
    candidates = [
        Path("reports") / f"{domain_safe}_{suffix}",
        Path.home() / "RavenEye_reports" / f"{domain_safe}_{suffix}",
        Path(f"RavenEye_reports_{domain_safe}_{suffix}"),
    ]
    for i, out_dir in enumerate(candidates):
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            if i > 0:
                print(Fore.YELLOW + f"[!] Sem permissão em 'reports/' — salvando em: {out_dir}" + Style.RESET_ALL)
            return out_dir
        except (PermissionError, OSError) as e:
            print(Fore.RED + f"[!] Não foi possível criar '{out_dir}': {e}" + Style.RESET_ALL)
            continue
    print(Fore.RED + "[!] Nenhuma pasta de saída pode ser criada. Salvando no diretório atual." + Style.RESET_ALL)
    print(Fore.WHITE + "    Dica: se 'reports/' pertence ao administrador do sistema (de uma varredura anterior com sudo), "
                        "rode: sudo chown -R $USER:$USER reports/" + Style.RESET_ALL)
    return Path(".")



def _run_vulnerability_scanner(
    target: str,
    root_mode: bool = False,
    scope_domains: set[str] | list[str] | None = None,
    scope_excludes: set[str] | list[str] | None = None,
) -> None:
    """Executa somente o scanner; não inicializa crawler nem módulos de recon."""
    scanner = RavenVulnScanner(
        target=target, root_mode=root_mode, urls=[target],
        max_workers=state.config.get("scanner_max_workers", 6),
        rate_limit=state.config.get("scanner_rate_limit", 8.0),
        active=True, timeout=min(30, int(state.config.get("scanner_timeout", 8))),
        enable_smuggling=bool(state.config.get("scanner_enable_smuggling", False)),
        scope_domains=scope_domains,
        scope_excludes=scope_excludes,
    )
    result = scanner.run()
    out_dir = _make_output_dir(target)
    report = {
        "target": {"domain": scanner.domain, "ip": resolve_host(scanner.domain) if scanner.domain else ""},
        "elapsed": result.get("elapsed", 0),
        "vulnerability_scan": result,
        "tech": result.get("technology", {}),
        "crawler": {"list": [], "endpoints": []},
    }
    save_all_reports(report, str(out_dir / f"RavenEye_VulnScanner_{'ROOT' if root_mode else 'SOLO'}"))


def _run_crawler(opts: dict, target: str, mp: int, md: int, root_mode: bool = False,
                 large_bf: bool = False, base_prefix: str = "RavenEye",
                 include_vuln_scanner: bool = False, preflight_enumeration: dict | None = None,
                 scanner_authorized: bool = False,
                 scope_domains_override: list[str] | None = None,
                 scope_excludes: set[str] | None = None) -> None:
    """Instancia e executa o crawler, salva relatórios em reports/<dominio>_<ts>/."""
    crawler = RavenCrawler(
        start_url=target, max_pages=mp, max_depth=md, delay=state.config["delay"],
        use_payload=opts.get("payload", False),
        use_google=opts.get("google", False),
        use_wayback=opts.get("wayback", False),
        include_shodan=opts.get("shodan", False),
        include_whois=opts.get("whois", False),
        include_archive=opts.get("archive", False),
        include_exploitdb=opts.get("exploitdb", False),
        include_nmap=opts.get("nmap", False),
        include_bruteforce=False,
        include_cache_poisoning=opts.get("cache_poisoning", False),
        include_smuggling=opts.get("smuggling", False),
        include_jwt=opts.get("jwt", False),
        include_virustotal=opts.get("virustotal", False),
        include_vuln_scanner=include_vuln_scanner,
        scanner_authorized=scanner_authorized,
        shodan_key=state.SHODAN_API_KEY,
        bf_attempts=state.config["bf_attempts"],
        root_mode=root_mode,
        large_bf=large_bf,
        scope_domains=_load_scope() if scope_domains_override is None else scope_domains_override,
        scope_excludes=scope_excludes,
    )
    rel = crawler.run()
    if preflight_enumeration:
        rel["http_enumeration"] = preflight_enumeration
    out_dir = _make_output_dir(target)
    base = str(out_dir / base_prefix)
    save_all_reports(rel, base)


# ==================================================================
# MENU — Web Crawler Mapeamento
# ==================================================================
def menu_crawler() -> None:
    """Menu de crawling passivo/recon."""
    _clear_screen()
    ascii_spider_web()
    gh_mode = state.config.get("google_hacking_mode", "scan")
    while True:
        print(Fore.CYAN + """
  1  - Apenas Crawler
  2  - Crawler + IP
  3  - Crawler + Whois
  4  - Crawler + Wayback
  5  - Crawler + Shodan
  6  - Crawler + Nmap (leve, -D RND:5)
  7  - Crawler + Wayback priorizado
  8  - Crawler + sondagem de parâmetros
  9  - Crawler + descoberta de caminhos
  10 - Crawler + Shodan + IP
  11 - Crawler Completo (todas as fontes)

  99 - Manual
  00 - Voltar
""" + Style.RESET_ALL)

        choice = input("Escolha: ").strip()
        if choice == "00":
            break
        if choice == "99":
            show_manual("crawler")
            continue
        if choice not in [str(i) for i in range(1, 12)]:
            print("Opção inválida")
            continue

        targets = _get_targets_multi()
        mp, md = _get_crawl_params()

        opts = {
            "shodan":   choice in ("5", "10", "11"),
            "whois":    choice in ("3", "11"),
            "archive":  choice in ("4", "11"),
            "exploitdb": choice == "11",
            "nmap":     choice in ("6", "11"),
            "wayback":  choice in ("7", "11"),
            "payload":  choice in ("8", "11"),
            "google":   choice in ("9", "11"),
            "cache_poisoning": choice == "11",
            "smuggling": choice == "11",
            "jwt": choice == "11",
            "virustotal": choice == "11" and bool(state.VIRUSTOTAL_API_KEY),
        }
        if choice == "11":
            opts = {k: True for k in opts}
            opts["virustotal"] = bool(state.VIRUSTOTAL_API_KEY)

        if gh_mode == "interativo" and opts.get("google"):
            menu_google_hacking()
            opts["google"] = False

        for idx, target in enumerate(targets, 1):
            if len(targets) > 1:
                print(Fore.CYAN + f"\n[*] Alvo {idx}/{len(targets)}: {sanitize_url(target) or 'alvo informado'}" + Style.RESET_ALL)
            # _offer_open_report (chamado dentro de save_all_reports) ja pergunta
            # Se a pessoa quer ver o relatório, a fila continua depois de fechar
            # ou dispensar a prévia.
            try:
                _run_crawler(opts, target, mp, md, base_prefix="RavenEye_crawler")
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print(Fore.RED + f"[!] Falha no alvo {sanitize_url(target) or 'alvo informado'}: {e}" + Style.RESET_ALL)
                if len(targets) > 1:
                    print(Fore.YELLOW + "[!] Seguindo para o próximo alvo da fila..." + Style.RESET_ALL)


# ==================================================================
# MENU — Web Crawler Ofensivo
# ==================================================================
def menu_ofensivo() -> None:
    """Menu de crawling ofensivo."""
    _clear_screen()
    ascii_skull()

    while True:
        print(Fore.YELLOW + """
  <=====> SEM ROOT <=====>
  1 - Crawler + Shodan + Nmap (vuln, -D RND:5)
  2 - Crawler + Shodan + checagens HTTP de baixo impacto

  <=====> COM ROOT <=====>
  3 - Crawler + Shodan + Nmap root (-sS -O -A -p-, -D RND:5)

  <=====> AUDITORIA HTTP GOVERNADA <=====>
  4 - Login HTTP serial, com wordlists classificadas e confirmação

  99 - Manual
  00 - Voltar
""" + Style.RESET_ALL)

        choice = input("Escolha: ").strip()
        if choice == "00":
            break
        if choice == "99":
            show_manual("ofensivo")
            continue
        if choice not in ("1", "2", "3", "4"):
            print("Opção inválida")
            continue

        if choice == "4":
            menu_bruteforce()
            continue

        root_mode = choice == "3"
        # Do this before an authorization prompt: a normal user should never
        # be asked to confirm a mode the process cannot run.
        if root_mode and os.geteuid() != 0:
            print(Fore.RED + "[!] Este perfil inclui recursos locais que exigem privilégios administrativos (root)." + Style.RESET_ALL)
            print(Fore.YELLOW + "    Para o modo web sem privilégios administrativos, escolha 2 (Crawler + Shodan + verificações HTTP)." + Style.RESET_ALL)
            print(Fore.YELLOW + "    O comando 'raven' é instalado no seu usuário; execute-o sem sudo." + Style.RESET_ALL)
            continue

        target = _get_target()
        if not _confirm_aggressive(target):
            print("Operação cancelada.")
            continue

        root_mode = choice == "3"
        if root_mode and os.geteuid() != 0:
            print(Fore.RED + "[!] Esta opção requer privilégios administrativos (sudo)." + Style.RESET_ALL)
            continue

        mp, md = _get_crawl_params()
        opts = {
            "shodan": True, "whois": True, "archive": True,
            "exploitdb": True, "payload": True, "google": True,
            "wayback": True,
            "nmap": choice in ("1", "3"),
        }
        _run_crawler(opts, target, mp, md, root_mode=root_mode,
                     base_prefix=f"RavenEye_off{'root' if root_mode else ''}")


# ==================================================================
# MENU — Bruteforce
# ==================================================================
def _configured_subdomain_wordlist_label() -> str:
    """Return the configured verified subdomain-list label for the config menu."""
    item_id = str(state.config.get("subdomain_wordlist_id", "builtin_subdomains"))
    manager = get_wordlist_manager()
    try:
        item = next(
            (entry for entry in manager.list("subdomains")
             if entry.id == item_id and entry.integrity == "verified"),
            None,
        )
    except (WordlistError, AttributeError):
        # A broken imported-list manifest should not hide the trusted bundled
        # subdomain list from the configuration or enumeration menus.
        list_builtins = getattr(manager, "list_builtins", None)
        item = next(
            (entry for entry in list_builtins("subdomains")
             if entry.id == item_id and entry.integrity == "verified"),
            None,
        ) if callable(list_builtins) else None
        if item is not None:
            return f"{item.label} ({item.entries}; catálogo importado inválido)"
    return f"{item.label} ({item.entries})" if item else "indisponível; selecione para corrigir"


def _choose_wordlist(
    manager, category: str, *, default_id: str | None = None,
) -> tuple[str, WordlistInfo] | None:
    """Select an existing classified list or add one without printing contents."""
    while True:
        print(Fore.CYAN + f"\n[ WORDLISTS: {category} ]" + Style.RESET_ALL)
        try:
            available = [item for item in manager.list(category) if item.integrity == "verified"]
        except WordlistError:
            # Keep vetted built-ins usable when user-imported metadata is
            # corrupt, while making it clear imported lists remain blocked.
            list_builtins = getattr(manager, "list_builtins", None)
            if not callable(list_builtins):
                print(Fore.RED + "Catálogo inválido; nenhuma wordlist será usada." + Style.RESET_ALL)
                return None
            available = [item for item in list_builtins(category) if item.integrity == "verified"]
            print(Fore.YELLOW + "[!] Catálogo de wordlists importadas inválido; apenas listas internas verificadas estão disponíveis." + Style.RESET_ALL)
        for index, item in enumerate(available, 1):
            configured = " [padrão]" if item.id == default_id else ""
            print(f"  {index}. {item.label} | {item.entries} entradas | sha256 {item.sha256[:12]} | {item.source}{configured}")
        if default_id and any(item.id == default_id for item in available):
            print("  D. Usar a wordlist padrão configurada")
        print("  A. Adicionar arquivo local e classifica-lo")
        if category != "subdomains":
            print("  99. Manual")
        print()
        print("  00. Cancelar")
        selected = input("Escolha: ").strip()
        if selected == "00":
            return None
        if selected == "99":
            if category == "subdomains":
                print("Opção inválida.")
            else:
                show_manual("wordlists")
            continue
        if selected.lower() == "d" and default_id:
            info = next((item for item in available if item.id == default_id), None)
            if info is None:
                print(Fore.YELLOW + "A wordlist padrão não está disponível; escolha outra ou pressione A para importar." + Style.RESET_ALL)
                continue
            try:
                return str(manager.path_for(info.id)), info
            except WordlistError as exc:
                print(Fore.RED + f"[!] Wordlist bloqueada: {exc}" + Style.RESET_ALL)
                continue
        if selected.lower() == "a":
            source = input("Caminho do arquivo UTF-8: ").strip()
            if not source:
                continue
            try:
                info = manager.add(source, category)
                print(Fore.GREEN + f"[+] Importada como {info.category}: {info.entries} entradas; sha256 {info.sha256[:12]}." + Style.RESET_ALL)
                return str(manager.path_for(info.id)), info
            except WordlistError as exc:
                print(Fore.RED + f"[!] Wordlist recusada: {exc}" + Style.RESET_ALL)
                continue
        try:
            index = int(selected) - 1
        except ValueError:
            print("Opção inválida.")
            continue
        if 0 <= index < len(available):
            info = available[index]
            try:
                return str(manager.path_for(info.id)), info
            except WordlistError as exc:
                print(Fore.RED + f"[!] Wordlist bloqueada: {exc}" + Style.RESET_ALL)


def menu_bruteforce() -> None:
    """Menu de força bruta (login e subdomínios)."""
    _clear_screen()
    ascii_bruteforce()

    while True:
        print(Fore.YELLOW + f"""
  <=====> AUDITORIA DE LOGIN HTTP (SEM ROOT) <=====>
  1 - Um usuário + lista de senhas

  2 - Listas separadas de usuários e senhas

  SSH: verificação de um par pela API; não percorre wordlists neste menu.
  Indisponíveis: FTP, SMB, RDP, MySQL, PostgreSQL, MongoDB, LDAP,
  SMTP, Redis e Telnet.

  <=====> SUBDOMÍNIOS (DNS, não requer root) <=====>
  3 - Enumeração de subdomínios (wordlist selecionável; padrão: {_configured_subdomain_wordlist_label()})

  <=====> ENUMERAÇÃO HTTP (NÃO AUTENTICA) <=====>
  4 - Descoberta de diretórios e caminhos
  5 - Descoberta de endpoints
  6 - Sondagem de parâmetros

  7 - Lista combinada usuário:senha

  99 - Manual
  00 - Voltar
""" + Style.RESET_ALL)

        choice = input("Escolha: ").strip()
        if choice == "00":
            break
        if choice == "99":
            show_manual("bruteforce")
            continue
        if choice not in ("1", "2", "3", "4", "5", "6", "7"):
            print("Opção inválida")
            continue

        if choice in ("4", "5", "6"):
            targets = _get_targets_for_safe_operation()
            if not targets:
                print("Operação cancelada.")
                continue
            for target in targets:
                if not _confirm_aggressive(target):
                    continue
                if choice == "4":
                    found = enumerate_paths(target)
                elif choice == "5":
                    found = enumerate_endpoints(target)
                else:
                    found = enumerate_parameters(target)
                fname = f"RavenEye_enum_{choice}_{_safe_domain_filename(target)}_{int(time.time())}.json"
                try:
                    Path(fname).write_text(json.dumps(found, ensure_ascii=False, indent=2), encoding="utf-8")
                    print(Fore.GREEN + f"[+] {len(found)} resultados para {sanitize_url(target) or 'alvo informado'}. Salvo em {fname}" + Style.RESET_ALL)
                except Exception as e:
                    print(Fore.RED + f"[ERRO] {e}" + Style.RESET_ALL)
            continue

        if choice == "3":
            if state.config.get("multi_target_enabled"):
                domains = []
                print(Fore.CYAN + f"Cole até {int(state.config.get('max_targets', 50))} domínios, um por linha. Linha vazia finaliza." + Style.RESET_ALL)
                while len(domains) < int(state.config.get("max_targets", 50)):
                    raw = input(f"Domínio {len(domains)+1}: ").strip()
                    if not raw:
                        break
                    dom = normalize_dns_domain(_sanitize_domain_input(raw))
                    if dom and dom not in domains:
                        domains.append(dom)
                    elif raw and not dom:
                        print(Fore.YELLOW + "Domínio inválido; ignorado." + Style.RESET_ALL)
            else:
                raw = input("Domínio alvo (ex.: exemplo.com): ").strip()
                dom = normalize_dns_domain(_sanitize_domain_input(raw)) if raw else None
                domains = [dom] if dom else []
            if not domains:
                print("Domínio inválido.")
                continue
            manager = get_wordlist_manager()
            chosen = _choose_wordlist(
                manager,
                "subdomains",
                default_id=str(state.config.get("subdomain_wordlist_id", "builtin_subdomains")),
            )
            if not chosen:
                print("Operação cancelada.")
                continue
            _wordlist_path, selected_list = chosen
            try:
                candidates = manager.read(selected_list.id)
            except WordlistError as exc:
                print(Fore.RED + f"[!] Wordlist bloqueada: {exc}" + Style.RESET_ALL)
                continue
            for domain in domains:
                normalized_domain = domain
                try:
                    scope_rules = _load_scanner_scope()
                except ValueError as exc:
                    print(Fore.RED + f"[!] Enumeração bloqueada: {exc}" + Style.RESET_ALL)
                    continue
                in_scope_candidates = candidates
                if scope_rules is not None:
                    in_scope_candidates = [
                        candidate for candidate in candidates
                        if any(
                            host_matches_rule(f"{candidate}.{normalized_domain}", rule)
                            for rule in scope_rules
                        )
                    ]
                    if not in_scope_candidates:
                        print(Fore.YELLOW + f"[!] {domain}: nenhum candidato da wordlist está coberto pelo escopo configurado." + Style.RESET_ALL)
                        continue
                print(Fore.CYAN + f"\nPreflight DNS: {normalized_domain}; wordlist {selected_list.label} ({len(in_scope_candidates)} candidatos; até 2 probes wildcard" + (", candidatos filtrados pelo escopo" if scope_rules is not None else "") + ")." + Style.RESET_ALL)
                if not _confirm_aggressive(normalized_domain):
                    print("Operação cancelada.")
                    continue
                try:
                    domain_safe = _safe_domain_filename(normalized_domain)
                    found = brute_subdomains(
                        normalized_domain,
                        wordlist=in_scope_candidates,
                        scope_rules=scope_rules,
                    )
                    if found:
                        fname = f"RavenEye_subdomains_bf_{domain_safe}_{int(time.time())}.txt"
                        labels = {
                            "wildcard_ambiguous": "AMBÍGUO: DNS wildcard",
                            "unverified": "NÃO VERIFICADO: wildcard",
                            "confirmed": "DNS específico",
                        }
                        lines = []
                        for item in found:
                            addresses = ", ".join(item.get("ips", [item["ip"]]))
                            status = labels.get(item.get("confidence", "confirmed"), "NÃO VERIFICADO")
                            lines.append(f"{item['subdomain']}  ->  {addresses}  [{status}]")
                        Path(fname).write_text("\n".join(lines), encoding="utf-8")
                        confirmed = sum(item.get("confidence") == "confirmed" for item in found)
                        ambiguous = sum(item.get("confidence") == "wildcard_ambiguous" for item in found)
                        unverified = sum(item.get("confidence") == "unverified" for item in found)
                        print(Fore.GREEN + f"[+] {normalized_domain}: {confirmed} respostas específicas, {ambiguous} ambíguas, {unverified} não verificadas. Relatório: {fname}" + Style.RESET_ALL)
                    else:
                        print(Fore.YELLOW + f"[+] {normalized_domain}: nenhum subdomínio resolvido pela lista selecionada." + Style.RESET_ALL)
                except Exception as e:
                    print(Fore.RED + f"[ERRO] {normalized_domain}: {e}" + Style.RESET_ALL)
            continue

        login_url = input("URL do formulario de login (HTTP/S): ").strip()
        if not login_url.lower().startswith(("http://", "https://")):
            login_url = "https://" + login_url
        try:
            parsed_login = urlsplit(login_url)
            if parsed_login.scheme.lower() not in ("http", "https") or not parsed_login.hostname or parsed_login.username or parsed_login.password:
                raise ValueError
            display_login = f"{parsed_login.scheme.lower()}://{parsed_login.hostname.lower()}:{parsed_login.port or (443 if parsed_login.scheme.lower() == 'https' else 80)}"
        except ValueError:
            print(Fore.RED + "URL inválida; use HTTP/S sem credenciais embutidas." + Style.RESET_ALL)
            continue
        manager = get_wordlist_manager()
        userlist_path = None
        combo_mode = choice == "7"
        username = ""
        selected_list = None
        if combo_mode:
            chosen = _choose_wordlist(manager, "combos")
            if not chosen:
                print("Operação cancelada.")
                continue
            wordlist_path, selected_list = chosen
        else:
            users_mode = "1" if choice == "1" else input("Usuários: 1=um usuário, 2=lista de usuários [2]: ").strip() or "2"
            if users_mode == "1":
                username = input("Usuário de teste: ").strip()
                if not username:
                    print("Usuário vazio.")
                    continue
            elif users_mode == "2":
                chosen_users = _choose_wordlist(manager, "users")
                if not chosen_users:
                    print("Operação cancelada.")
                    continue
                userlist_path, _user_list = chosen_users
            else:
                print("Opção inválida.")
                continue
            chosen = _choose_wordlist(manager, "passwords")
            if not chosen:
                print("Operação cancelada.")
                continue
            wordlist_path, selected_list = chosen

        user_field = input("Campo do usuário (padrão 'username'): ").strip() or "username"
        pass_field = input("Campo da senha (padrão 'password'): ").strip() or "password"
        success_marker = input("Marcador exclusivo de sucesso (opcional; Enter usa redirecionamento heurístico): ")
        try:
            threads = int(input("Concorrência HTTP (somente 1; padrão 1): ") or "1")
            delay = float(input(f"Intervalo entre tentativas, mín. 1 s (padrão {state.config.get('bf_delay', 1.0)}): ") or state.config.get("bf_delay", 1.0))
            timeout = float(input("Tempo limite por requisição em segundos, máx. 30 (padrão 8): ") or "8")
            default_attempts = min(100, max(1, int(state.config.get("bf_attempts", 100))))
            max_attempts = int(input(f"Limite global (1-100, padrão {default_attempts}): ") or default_attempts)
        except ValueError:
            print("Configuração inválida; operação cancelada.")
            continue
        if threads != 1 or not 1 <= delay <= 60 or not 1 <= timeout <= 30 or not 1 <= max_attempts <= 100:
            print(Fore.YELLOW + "Configuração fora dos limites seguros (1 thread, intervalo 1-60 s, tempo limite 1-30 s, máximo 100)." + Style.RESET_ALL)
            continue
        stop_response = input("Parar no primeiro indicador de sucesso? (S/n): ").strip().lower()
        if stop_response not in ("", "s", "sim"):
            print(Fore.YELLOW + "Execução cancelada: o modo seguro exige interrupção no primeiro indicador de sucesso." + Style.RESET_ALL)
            continue
        resumable = input("Salvar checkpoint local redigido? (S/n): ").strip().lower() not in ("n", "nao", "não")
        resume = False
        if resumable:
            resume = input("Retomar checkpoint compatível, se existir? (s/N): ").strip().lower() in ("s", "sim")

        print(Fore.CYAN + f"\nPreflight HTTP: alvo {display_login}; lista {selected_list.label} ({selected_list.category}, {selected_list.entries} entradas)." + Style.RESET_ALL)
        print(Fore.CYAN + f"Concorrência: 1 | limite global: {max_attempts} | por conta: {min(100, int(state.config.get('bf_attempts_per_user', 5)))} | intervalo: {delay:g}s | tempo limite: {timeout:g}s." + Style.RESET_ALL)
        if not _confirm_aggressive(display_login):
            print("Operação cancelada.")
            continue

        try:
            per_account_limit = min(
                100, max(1, int(state.config.get("bf_attempts_per_user", 5) or 5))
            )
            policy = CredentialAuditPolicy(
                max_attempts=100,
                lockout_threshold=per_account_limit,
            )
            audit_result = asyncio.run(HTTPLoginAdapter(
                BruteForceEngine(policy, wordlist_manager=manager)
            ).audit(
                login_url,
                username,
                username_field=user_field,
                password_field=pass_field,
                wordlist_path=wordlist_path,
                userlist_path=userlist_path,
                combo_mode=combo_mode,
                delay=delay,
                timeout=timeout,
                resumable=resumable,
                resume=resume,
                threads=threads,
                max_attempts=max_attempts,
                per_user_limit=per_account_limit,
                success_marker=success_marker,
                preflight_confirmed=True,
            ))
            found = audit_result.status == "possible_match"
            attempts = audit_result.attempts
        except (CredentialAuditError, WordlistError, CheckpointError) as exc:
            print(Fore.RED + f"[!] Auditoria bloqueada: {exc}" + Style.RESET_ALL)
            continue
        if found:
            print(Fore.GREEN + f"\n[+] Indicador de sucesso observado após {attempts} tentativa(s); credencial redigida." + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + f"\nSem indicador de sucesso em {attempts} tentativa(s); confira o estado do checkpoint/servidor." + Style.RESET_ALL)


# ==================================================================
# MENU — NUKE
# ==================================================================

def _clear_screen() -> None:
    """Limpa o terminal sem shell, compatível com Linux/Termux/Windows."""
    try:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()
    except Exception:
        print("\n" * 3)


def menu_vulnerability_scanner() -> None:
    """Scanner de vulnerabilidades independente do NUKE/C4."""
    _clear_screen()
    ascii_anarchy()
    while True:
        print(Fore.CYAN + """
  [ SCANNER DE VULNERABILIDADES ]

  1 - Scanner com privilégios administrativos e enriquecimento CVE (quando houver correspondência)
  2 - Scanner sem privilégios administrativos e sem enriquecimento CVE adicional

  99 - Manual
  00 - Voltar
""" + Style.RESET_ALL)
        choice = input("Escolha: ").strip()
        if choice == "00":
            break
        if choice == "99":
            show_manual("vulnerability")
            continue
        if choice not in ("1", "2"):
            print("Opção inválida")
            continue
        targets = _get_targets_for_safe_operation()
        if not targets:
            print("Operação cancelada.")
            continue
        try:
            scanner_scope = _load_scanner_scope()
        except ValueError as exc:
            print(Fore.RED + f"[!] Scanner bloqueado: {exc}" + Style.RESET_ALL)
            continue
        root_mode = choice == "1"
        if root_mode and os.geteuid() != 0:
            print(Fore.RED + "[!] Esta modalidade requer privilégios administrativos (sudo)." + Style.RESET_ALL)
            continue
        for target in targets:
            if not _confirm_vulnerability_scanner(target):
                continue
            try:
                _run_vulnerability_scanner(
                    target, root_mode=root_mode, scope_domains=scanner_scope,
                )
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                print(Fore.RED + f"[!] Falha no alvo {sanitize_url(target) or 'alvo informado'}: {exc}" + Style.RESET_ALL)


def menu_nuke() -> None:
    """Orquestrador completo de recon + auditoria segura; scanner continua separado."""
    _clear_screen()
    ascii_radiation()
    while True:
        print(Fore.RED + """
  <=====> SEM SCANNER <=====>
  1 - NUKE (completo, todos os módulos; Nmap agressivo; requer privilégios administrativos)
  2 - C4 (parcial, sem recursos que exigem privilégios administrativos)

  <=====> COM SCANNER DE VULNERABILIDADES <=====>
  3 - NUKE + Scanner (requer privilégios administrativos)
  4 - C4 + Scanner (sem privilégios administrativos)

  99 - Manual
  00 - Voltar
""" + Style.RESET_ALL)
        choice = input("Escolha: ").strip()
        if choice == "00":
            break
        if choice == "99":
            show_manual("nuke")
            continue
        if choice not in ("1", "2", "3", "4"):
            print("Opção inválida")
            continue

        root_mode = choice in ("1", "3")
        if root_mode and os.geteuid() != 0:
            print(Fore.RED + "[!] Esta opção usa recursos locais que exigem privilégios administrativos (detecção SYN/OS do Nmap)." + Style.RESET_ALL)
            print(Fore.YELLOW + "    Para o fluxo equivalente sem privilégios, escolha C4 ou C4 + Scanner." + Style.RESET_ALL)
            print(Fore.YELLOW + "    Se 'sudo raven' ainda não funciona, rode novamente: sh ~/.local/share/raveneye/installer/install.sh" + Style.RESET_ALL)
            continue

        includes_scanner = choice in ("3", "4")
        scanner_scope = None
        if includes_scanner:
            try:
                scanner_scope = _load_scanner_scope()
            except ValueError as exc:
                print(Fore.RED + f"[!] Scanner bloqueado: {exc}" + Style.RESET_ALL)
                continue

        target = _get_target()
        if not target or not _confirm_aggressive(target):
            print("Operação cancelada.")
            continue

        if includes_scanner and not _confirm_vulnerability_scanner(target):
            print("Execução cancelada: autorização do Scanner não confirmada.")
            continue

        depth = max(5, state.config.get("max_depth_nuke", 5))
        mp = state.config["max_pages"]
        opts = {
            "shodan": True, "whois": True, "archive": True,
            "exploitdb": True, "nmap": True, "wayback": True,
            "payload": True, "google": True,
        }
        # NUKE/C4 inclui também a enumeração HTTP não autenticada que existe no
        # menu de Bruteforce. Ela é mantida separada do Scanner de Vulnerabilidades:
        # aqui descobrimos superfície; o Scanner decide se algo é uma vulnerabilidade.
        enum_results = {
            "paths": enumerate_paths(target, limit=int(state.config.get("enum_paths_limit", 200))),
            "endpoints": enumerate_endpoints(target, limit=int(state.config.get("enum_endpoints_limit", 200))),
            "parameters": enumerate_parameters(target, limit=int(state.config.get("enum_parameters_limit", 60))),
        }
        _run_crawler(
            opts, target, mp, depth, root_mode=root_mode,
            large_bf=True, base_prefix=f"RavenEye_{'NUKE' if root_mode else 'C4'}",
            include_vuln_scanner=includes_scanner,
            scanner_authorized=includes_scanner,
            preflight_enumeration=enum_results,
            scope_domains_override=sorted(scanner_scope) if scanner_scope is not None else None,
        )


def menu_principal() -> None:
    """Menu principal do RavenEye."""
    _clear_screen()
    first_run = True
    while True:
        # Checagem de integridade dos créditos a cada iteração do menu: remover
        # esta chamada de um único ponto do código não é suficiente, pois ela
        # também ocorre na inicialização (ver RavenEye.py).
        verify_integrity()
        ascii_raven_eye_logo()
        if first_run:
            print(Fore.GREEN + f"  RavenEye v{TOOL_VERSION} iniciado." + Style.RESET_ALL)
            print(Fore.WHITE + f"  Wordlist embutida: {len(EXTRA_PASSWORDS)} senhas" + Style.RESET_ALL)
            print(Fore.WHITE + f"  Consultas Google: {len(google_dork_search('example.com'))} integradas" + Style.RESET_ALL)
            print()
            first_run = False
        print(Fore.CYAN + "  1. INICIAR" + Style.RESET_ALL)
        print(Fore.CYAN + "  2. CONFIGURAÇÕES" + Style.RESET_ALL)
        print(Fore.CYAN + "  3. CRÉDITOS" + Style.RESET_ALL)
        print()
        print(Fore.CYAN + "  00. SAIR" + Style.RESET_ALL)

        op = input("\nEscolha: ").strip()

        if op == "1":
            _menu_sala_principal()
        elif op == "2":
            menu_config()
        elif op == "3":
            show_credits()
            input("\n  Pressione Enter para voltar...")
        elif op == "00":
            save_config(state.config)
            print("\nEncerrando. Configurações salvas.\n")
            sys.exit(0)
        else:
            print("Opção inválida")


def _menu_sala_principal() -> None:
    """Submenu Salão Principal."""
    _clear_screen()
    ascii_main_hall()
    while True:
        print(Fore.MAGENTA + "\n  ============================" + Style.RESET_ALL)
        print(Fore.MAGENTA + "       SALÃO PRINCIPAL" + Style.RESET_ALL)
        print(Fore.MAGENTA + "  ============================" + Style.RESET_ALL)

        print(Fore.CYAN + """
  1. WEB CRAWLER MAPEAMENTO
  2. WEB CRAWLER OFENSIVO
  3. FORÇA BRUTA
  4. NMAP
  5. NUKE
  6. LEITURA DE LOGS
  7. VIRUSTOTAL
  8. GOOGLE HACKING
  9. SCANNER DE VULNERABILIDADES

  00. VOLTAR
""" + Style.RESET_ALL)

        sub = input("Escolha: ").strip()

        if sub == "00":
            break
        if sub == "7":
            menu_virustotal()
            continue
        if sub == "8":
            menu_google_hacking()
            continue
        if sub == "9":
            menu_vulnerability_scanner()
            continue

        if sub == "1":
            menu_crawler()
        elif sub == "2":
            menu_ofensivo()
        elif sub == "3":
            menu_bruteforce()
        elif sub == "4":
            _menu_nmap_standalone()
        elif sub == "5":
            menu_nuke()
        elif sub == "6":
            menu_logs()
        else:
            print("Opção inválida")


def menu_virustotal() -> None:
    """Menu standalone do VirusTotal; múltiplos alvos somente quando habilitados."""
    _clear_screen()
    while True:
        print(Fore.CYAN + "\n[ VIRUSTOTAL ]" + Style.RESET_ALL)
        print(f"  Chave configurada: {'sim' if state.VIRUSTOTAL_API_KEY else 'não — configure em Configurações'}")
        print("\n  1. Verificar URL\n  2. Verificar domínio\n  3. Verificar IP")
        print("  99. Manual")
        print("  00. Voltar\n")
        sub = input("Escolha: ").strip()
        if sub == "00": break
        if sub == "99":
            show_manual("virustotal")
            continue
        if sub not in ("1", "2", "3"): print("Opção inválida"); continue
        if not state.VIRUSTOTAL_API_KEY:
            print(Fore.RED + "[!] Chave VirusTotal não configurada. Acesse Configurações > opção 17." + Style.RESET_ALL)
            continue
        values=[]
        if state.config.get("multi_target_enabled"):
            print(Fore.CYAN + f"Cole até {int(state.config.get('max_targets', 50))} alvos, um por linha. Linha vazia finaliza." + Style.RESET_ALL)
            while len(values) < int(state.config.get("max_targets", 50)):
                raw=input(f"Alvo {len(values)+1}: ").strip()
                if not raw: break
                if sub == "2": raw = _sanitize_domain_input(raw)
                if raw and raw not in values: values.append(raw)
        else:
            raw=input("URL a verificar: " if sub=="1" else "Domínio a verificar (ex: exemplo.com): " if sub=="2" else "IP a verificar (ex: 1.2.3.4): ").strip()
            if sub=="2" and raw: raw=_sanitize_domain_input(raw)
            if raw: values=[raw]
        for alvo in values:
            try:
                print(Fore.CYAN + f"[*] Consultando VirusTotal: {alvo}" + Style.RESET_ALL)
                resultado = check_virustotal(alvo, state.VIRUSTOTAL_API_KEY) if sub=="1" else check_virustotal_domain(alvo, state.VIRUSTOTAL_API_KEY) if sub=="2" else check_virustotal_ip(alvo, state.VIRUSTOTAL_API_KEY)
                if resultado.get("error"):
                    print(Fore.RED + f"[!] {resultado['error']}" + Style.RESET_ALL)
                    continue
                print(Fore.GREEN + f"\n--- Resultado para {alvo} ---" + Style.RESET_ALL)
                for k,v in resultado.items(): print(f"  {k}: {v}")
            except Exception as exc:
                print(Fore.RED + f"[ERRO] {alvo}: {exc}" + Style.RESET_ALL)


def _menu_nmap_standalone() -> None:
    """Menu Nmap autônomo."""
    _clear_screen()
    ascii_eye_double_pupil()
    while True:
        print(Fore.GREEN + """
  [ NMAP ]

  1 - Varredura leve (sem root, -sT -sV -D RND:5)
  2 - Varredura agressiva (com root, -sS -O -A -p- -D RND:5)
  3 - Descobrir IP real (por trás de CDN/WAF como Cloudflare)

  4 - Descobrir diretórios/caminhos HTTP
  5 - Descobrir endpoints HTTP
  6 - Descobrir parâmetros HTTP

  99 - Manual
  00 - Voltar
""" + Style.RESET_ALL)
        choice = input("Escolha: ").strip()
        if choice == "00":
            break
        if choice == "99":
            show_manual("nmap")
            continue
        if choice not in ("1", "2", "3", "4", "5", "6"):
            print("Opção inválida")
            continue

        if choice in ("4", "5", "6"):
            target = _get_target()
            if not target or not _confirm_aggressive(target):
                print("Operação cancelada.")
                continue
            if choice == "4":
                found = enumerate_paths(target)
            elif choice == "5":
                found = enumerate_endpoints(target)
            else:
                found = enumerate_parameters(target)
            fname = f"RavenEye_enum_{choice}_{_safe_domain_filename(target)}_{int(time.time())}.json"
            try:
                Path(fname).write_text(json.dumps(found, ensure_ascii=False, indent=2), encoding="utf-8")
                print(Fore.GREEN + f"[+] {len(found)} resultados. Salvo em {fname}" + Style.RESET_ALL)
            except Exception as e:
                print(Fore.RED + f"[ERRO] {e}" + Style.RESET_ALL)
            continue

        if choice == "3":
            raw_target = input("Domínio alvo (ex.: exemplo.com): ").strip()
            if not raw_target:
                continue
            domain = _sanitize_domain_input(raw_target)
            domain_safe = _safe_domain_filename(raw_target)
            print(Fore.CYAN + f"[*] Consultando crt.sh e verificando faixas do Cloudflare para {domain}..." + Style.RESET_ALL)
            subdomains = get_subdomains_crtsh(domain)
            result = find_real_ip(domain, subdomains)
            if not result["dominio_atras_de_cdn"]:
                print(Fore.GREEN + f"\n[OK] {domain} não parece estar atrás de um CDN/WAF conhecido "
                                    f"(IP: {result['ip_principal']}) — o IP resolvido já é o real." + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + f"\n[!] {domain} está atrás de {result['cdn_detectado']} "
                                     f"(faixas: {result['fonte_ranges']})" + Style.RESET_ALL)
                if result["candidatos"]:
                    print(Fore.GREEN + f"\n{len(result['candidatos'])} candidato(s) a IP real:" + Style.RESET_ALL)
                    for c in result["candidatos"]:
                        print(f"  {c['ip']}  <- {c['subdominio']}")
                        print(f"    {c['motivo']}")
                    top = result["candidatos"][0]
                    ping_result = ping_host(top["ip"])
                    print(Fore.CYAN + f"\n[*] Ping direto em {top['ip']}: {ping_result}" + Style.RESET_ALL)
                    print(Fore.YELLOW + "\n[!] Confirme manualmente antes de testar contra esse IP — "
                                         "pode estar fora do escopo do programa de bug bounty." + Style.RESET_ALL)
                else:
                    print(Fore.WHITE + "\nNenhum candidato encontrado (subdomínios conhecidos também "
                                        "estão atrás do CDN, sem IP declarado no SPF)." + Style.RESET_ALL)
            save_choice = input("\nSalvar resultado em arquivo? (s/N): ").strip().lower()
            if save_choice == "s":
                fname = f"RavenEye_realip_{domain_safe}_{int(time.time())}.txt"
                try:
                    lines = [
                        f"# RavenEye — Descoberta de IP real — {domain}",
                        f"# Gerado em: {datetime.datetime.now().isoformat()}",
                        f"CDN detectado: {result.get('cdn_detectado', 'Nenhum')}",
                        f"IP principal: {result.get('ip_principal', 'N/A')}",
                        "",
                    ]
                    for c in result["candidatos"]:
                        lines.append(f"{c['ip']}  <- {c['subdominio']}  ({c['motivo']})")
                    Path(fname).write_text("\n".join(lines), encoding="utf-8")
                    print(Fore.GREEN + f"[+] Salvo em: {fname}" + Style.RESET_ALL)
                except Exception as e:
                    print(Fore.RED + f"[ERRO] Não foi possível salvar: {e}" + Style.RESET_ALL)
            input("\nPressione Enter para continuar...")
            continue

        root_mode = (choice == "2")
        if root_mode and os.geteuid() != 0:
            print(Fore.RED + "[!] A varredura agressiva requer privilégios administrativos (sudo)." + Style.RESET_ALL)
            continue

        raw_target = input("IP ou domínio alvo: ").strip()
        target = _sanitize_domain_input(raw_target)
        target_safe = _safe_domain_filename(raw_target)
        ip = resolve_host(target) or target
        print(Fore.CYAN + f"[*] Alvo: {ip}" + Style.RESET_ALL)
        result = get_nmap(ip, root_mode=root_mode)

        if isinstance(result, dict):
            print(Fore.GREEN + f"\nPortas abertas: {len(result.get('portas', []))}" + Style.RESET_ALL)
            print(Fore.RED + f"CVEs detectadas: {len(result.get('vulns', []))}" + Style.RESET_ALL)
            if result.get("erro"):
                print(Fore.RED + f"Erro: {result['erro']}" + Style.RESET_ALL)
            fname = f"RavenEye_nmap_{target_safe}_{int(time.time())}.txt"
            try:
                lines = [
                    f"# RavenEye Nmap Standalone — {target} ({ip})",
                    f"# Gerado em: {datetime.datetime.now().isoformat()}",
                    f"# Status: {result.get('status', 'N/A')}",
                    "",
                    f"## PORTAS ({len(result.get('portas', []))})",
                ]
                lines.extend(result.get("portas", []))
                if result.get("vulns"):
                    lines.append("\n## CVEs")
                    lines.extend(result["vulns"])
                if result.get("raw"):
                    lines.append("\n## RAW")
                    lines.extend(result["raw"].splitlines()[:50])
                Path(fname).write_text("\n".join(lines), encoding="utf-8")
                print(Fore.GREEN + f"[+] Resultado salvo: {fname}" + Style.RESET_ALL)
            except Exception as e:
                vprint(2, f"[WARN] falha ao salvar o resultado Nmap: {e}")
        else:
            print(result)
        input("\nPressione Enter para continuar...")
