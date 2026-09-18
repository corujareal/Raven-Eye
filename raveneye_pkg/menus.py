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
import shutil
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from raveneye_pkg.terminal import Fore, Style
from raveneye_pkg import state
from raveneye_pkg.state import vprint, set_verbose, _setup_logger, _sleep
from raveneye_pkg.constants import (
    CONFIG_FILE, EXTRA_PASSWORDS, SUBDOMAIN_WORDLIST, TOOL_VERSION, USER_AGENTS,
)
from raveneye_pkg.config_io import save_config, _safe_domain_filename, _sanitize_domain_input
from raveneye_pkg.network import resolve_host, ping_host, normalize_url, is_safe_url, request_url
from raveneye_pkg.ascii_art import (
    ascii_anarchy, ascii_raven_eye_logo, ascii_spider_web, ascii_skull,
    ascii_bruteforce, ascii_eye_double_pupil, ascii_radiation, ascii_book,
    ascii_books_stack, ascii_main_hall,
)
from raveneye_pkg.credits import show_credits, verify_integrity
from raveneye_pkg.scanners import (
    google_dork_search, run_google_dorks_search, brute_subdomains, get_nmap,
    check_virustotal, check_virustotal_domain, check_virustotal_ip,
    find_real_ip, get_subdomains_crtsh,
)
from raveneye_pkg.bruteforce import (
    bruteforce_login, enumerate_paths, enumerate_endpoints, enumerate_parameters,
)
from raveneye_pkg.crawler import RavenCrawler
from raveneye_pkg.reports import save_all_reports
from raveneye_pkg.vuln_scanner import RavenVulnScanner
from raveneye.core.targets import normalize_targets


from raveneye_pkg.state import PLAYWRIGHT_AVAILABLE
from raveneye.cli.log_viewer import watch as _watch_log, safe_delete as _safe_delete_log, export_category as _export_log_category, export_report_file as _export_report_file, format_menu as _log_format_menu


def _confirm_aggressive(target: str) -> bool:
    """Solicita confirmação antes de operações agressivas e registra em log de auditoria."""
    print(Fore.RED + f"""
[!] ATENCAO: Voce esta prestes a iniciar varredura agressiva em:
    {target}
    Confirme que tem AUTORIZACAO EXPLICITA para testar este alvo.
""" + Style.RESET_ALL)
    try:
        confirm = input("    Digite 'SIM' para continuar: ").strip()
        confirmed = confirm == "SIM"
        with suppress(Exception):
            with open("raveneye_audit_log.txt", "a", encoding="utf-8") as f:
                f.write(f"{datetime.datetime.now().isoformat()} | alvo={target} | "
                        f"confirmado={'SIM' if confirmed else 'NAO'}\n")
        return confirmed
    except Exception:
        return False


# ==================================================================
# FUNÇÕES — Google Hacking interativo
# ==================================================================
def menu_google_hacking() -> None:
    """Menu interativo de Google Dorks, com suporte opcional a múltiplos domínios."""
    _clear_screen()
    ascii_books_stack()
    while True:
        print(Fore.CYAN + "\n[ GOOGLE HACKING INTERATIVO ]" + Style.RESET_ALL)
        print("  1. Gerar dorks locais (RavenEye built-in + customizados)")
        print("  2. Buscar automaticamente via Google Custom Search API (filtra resultados interessantes)")
        print("  0. Voltar")
        sub = input("\nEscolha: ").strip()
        if sub == "0":
            break
        if sub not in ("1", "2"):
            print("Opcao invalida")
            continue
        targets = []
        if state.config.get("multi_target_enabled"):
            print(Fore.CYAN + f"Cole até {int(state.config.get('max_targets', 50))} domínios, um por linha. Linha vazia finaliza." + Style.RESET_ALL)
            while len(targets) < int(state.config.get("max_targets", 50)):
                raw = input(f"Dominio {len(targets)+1}: ").strip()
                if not raw:
                    break
                dom = _sanitize_domain_input(raw)
                if dom and dom not in targets:
                    targets.append(dom)
        else:
            raw = input("Dominio alvo (ex: exemplo.com): ").strip()
            dom = _sanitize_domain_input(raw) if raw else ""
            if dom:
                targets = [dom]
        if not targets:
            print("Dominio invalido.")
            continue

        cse_key = state.config.get("_google_cse_decoded", "")
        cse_id = state.config.get("google_cse_id", "")
        if sub == "2" and (not cse_key or not cse_id):
            print(Fore.RED + "[!] Configure 'Chave Google CSE' e 'Google CSE ID' no menu Configuracoes primeiro." + Style.RESET_ALL)
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
                    print(Fore.CYAN + f"\n[*] {domain}: executando {len(dorks)} dorks via Google Custom Search API..." + Style.RESET_ALL)
                    resultado = run_google_dorks_search(dorks, domain, cse_key, cse_id)
                    print(Fore.GREEN + f"[+] {resultado['total_interessantes']} resultados interessantes de {resultado['total_bruto']} brutos" + Style.RESET_ALL)
                    for item in resultado["interessantes"][:30]:
                        print(Fore.YELLOW + f"\n  [{item['motivo']}] {item['titulo']}" + Style.RESET_ALL)
                        print(f"  {item['link']}")
                    save_choice = input("Salvar resultados em arquivo? (s/N): ").strip().lower()
                    if save_choice == "s":
                        fname = f"RavenEye_dorks_resultados_{domain_safe}_{int(time.time())}.txt"
                        lines_out = [f"# RavenEye — Google Dorks — {domain}", ""]
                        for item in resultado["interessantes"]:
                            lines_out += [f"[{item['motivo']}] {item['titulo']}", f"  {item['link']}", ""]
                        Path(fname).write_text("\n".join(lines_out), encoding="utf-8")
                        print(Fore.GREEN + f"[+] Resultados salvos em: {Path(fname).resolve()}" + Style.RESET_ALL)
            except Exception as exc:
                print(Fore.RED + f"[ERRO] {domain}: {exc}" + Style.RESET_ALL)


# ==================================================================
# MENUS — Manual
# ==================================================================
def show_manual(context: str) -> None:
    """Exibe manual contextual interativo."""
    manuals: dict[str, dict | str] = {
        "crawler": {
            "1":  "Apenas Crawler — rastreia o site e coleta links do mesmo dominio.",
            "2":  "Crawler + IP — exibe IP resolvido e ping.",
            "3":  "Crawler + Whois — consulta informacoes de registro do dominio.",
            "4":  "Crawler + Wayback — snapshot do site no Archive.org.",
            "5":  "Crawler + Shodan — consulta IP no Shodan (requer chave API).",
            "6":  "Crawler + Nmap (leve) — varredura de portas sem root, -D RND:5.",
            "7":  "Crawler + Wayback Priority — prioriza URLs historicas do Wayback.",
            "8":  "Crawler + Probing de Parametros — testa nomes de parametro comuns "
                  "(id, page, search, redirect...) e so registra os que realmente mudam "
                  "a resposta do servidor, comparado a um baseline.",
            "9":  "Crawler + Path Guessing — adiciona paths sensiveis comuns a fila.",
            "10": "Crawler + Shodan + IP — combina Shodan e resolucao de IP.",
            "11": "Crawler Completo — ativa todas as fontes de URL e APIs.",
            "*":  "Multiplos alvos: apos digitar cada URL, a ferramenta pergunta "
                  "'Deseja adicionar mais um alvo?'. Respondendo 's' adiciona outro; "
                  "'n' inicia o scan de todos na ordem em que foram adicionados, "
                  "um apos o outro.",
        },
        "ofensivo": {
            "1": "Crawler + Shodan + Nmap (vuln) — Nmap leve com scripts de deteccao.",
            "2": "Crawler + Shodan + Varredura Web — testa endpoints comuns.",
            "3": "Crawler + Shodan + Nmap root — varredura completa, -D RND:5 (requer root).",
            "4": "Crawler + Shodan + Bruteforce — forca bruta com wordlist grande + embutida (requer root).",
        },
        "bruteforce": {
            "1": "Bruteforce de login comum — wordlist media + EXTRA_PASSWORDS embutida (~{} senhas BR/int).".format(len(EXTRA_PASSWORDS)),
            "2": "Bruteforce de login root — wordlist grande + EXTRA_PASSWORDS, CSRF, lockout detection.",
            "3": "Bruteforce de subdominios — resolucao DNS ativa com wordlist embutida (~{} candidatos). Nao tenta autenticar.".format(len(SUBDOMAIN_WORDLIST)),
            "4": "Bruteforce de diretorios/paths — descoberta HTTP limitada, sem autenticação.",
            "5": "Bruteforce de endpoints — descoberta HTTP limitada, sem autenticação.",
            "6": "Bruteforce de parametros — baseline e marcador benigno, sem exploração.",
        },
        "vulnerability": {
            "1": "Scanner com root — execução completa e enriquecimento CVE/CWE quando houver correspondência confiável.",
            "2": "Scanner solo — detecção sem privilégios, com baseline, evidências e confidence score.",
        },
        "nuke": {
            "1": "NUKE (root) — comportamento original, sem Scanner de Vulnerabilidades.",
            "2": "C4 (sem root) — comportamento original, sem Scanner de Vulnerabilidades.",
            "3": "NUKE + Scanner de Vulnerabilidades (root).",
            "4": "C4 + Scanner de Vulnerabilidades (sem root).",
        },
        "config": (
            "Opcoes de configuracao:\n"
            "  1 - Max paginas: quantas URLs o crawler vai visitar\n"
            "  2 - Delay: pausa entre requests (segundos)\n"
            "  3 - User-Agent: header identificador do browser\n"
            "  4 - Profundidade: quantos niveis de links seguir\n"
            "  5 - Tentativas BF: limite de senhas no bruteforce (max: 50000)\n"
            "  6 - Limite links TXT: max de links por categoria no relatorio\n"
            "  7 - Verbose: 0=silencioso, 1=progresso, 2=erros, 3=senhas\n"
            "  8 - Chave Shodan: API key para consultas Shodan\n"
            "  9 - Profundidade NUKE (5-20)\n"
            " 10 - Threads do crawler (1-20)\n"
            " 11 - Proxy: HTTP ou SOCKS5\n"
            " 12 - Ano inicial Wayback\n"
            " 13 - Google Hacking: 'scan' (integrado) ou 'interativo'\n"
            " 14 - Scope: arquivo com dominios permitidos\n"
            " 15 - Usar JS Render (Playwright)\n"
            " 22 - Salvar configuracoes no arquivo JSON\n"
            " 00 - Voltar\n"
            " 99 - Este manual\n"
        ),
        "logs": (
            "Manual do Leitor de Logs:\n"
            "  Busca em reports/ (recursivo) e no diretorio atual.\n"
            "  Categorias disponiveis:\n"
            "    TXT COMPLETO      — relatorio principal com todos os achados\n"
            "    GOOGLE HACKING    — dorks gerados (locais + Custom Search API)\n"
            "    NMAP              — resultado da varredura de portas\n"
            "    CSV               — achados em formato planilha\n"
            "    MARKDOWN          — relatorio resumido em .md\n"
            "    VIRUSTOTAL        — consultas standalone de URL/dominio/IP\n"
            "    SUBDOMINIOS       — resultado do bruteforce de subdominios (DNS)\n"
            "    WORDLIST          — URLs crawladas\n"
            "    ENDPOINTS         — caminhos encontrados\n"
            "    LOG ESTRUTURADO   — raveneye.log (eventos internos da ferramenta)\n"
            "    AUDITORIA         — confirmacoes de autorizacao (digitou SIM)\n"
            "  Comandos apos escolher arquivo:\n"
            "    grep <padrao>   filtra linhas com o padrao\n"
            "    head <n>        mostra primeiras N linhas\n"
            "    tail <n>        mostra ultimas N linhas\n"
            "    less            paginacao (se disponivel)\n"
            "    clear           limpa a tela\n"
            "    sair            volta a selecao de arquivo\n"
            "  Padroes grep validos: alfanumericos, . - _ * ? | ^ $\n"
            "  00 - volta ao menu principal\n"
            "  99 - exibe este manual\n"
        ),
    }

    ctx_map = {
        "crawler": ("\n[ MANUAL - WEB CRAWLER MAPEAMENTO ]", manuals["crawler"]),
        "ofensivo": ("\n[ MANUAL - WEB CRAWLER OFENSIVO ]", manuals["ofensivo"]),
        "bruteforce": ("\n[ MANUAL - BRUTEFORCE ]", manuals["bruteforce"]),
        "vulnerability": ("\n[ MANUAL - SCANNER DE VULNERABILIDADES ]", manuals["vulnerability"]),
        "nuke": ("\n[ MANUAL - NUKE/C4 ]", manuals["nuke"]),
        "config": ("\n[ MANUAL - CONFIGURACOES ]", manuals["config"]),
        "logs": ("\n[ MANUAL - LEITOR DE LOGS ]", manuals["logs"]),
    }

    if context not in ctx_map:
        print(Fore.CYAN + "\nManual nao disponivel para este contexto." + Style.RESET_ALL)
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
    if reports_dir.is_dir():
        found.update(str(p) for p in reports_dir.rglob(pattern))
    found.update(glob.glob(pattern))
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
    print(Fore.MAGENTA + "\n<===== EXPORTAR RELATORIO =====>" + Style.RESET_ALL)

    reports = [source] if source else _list_exportable_reports()
    if not reports:
        print(Fore.YELLOW + "\nNenhum arquivo de relatorio encontrado." + Style.RESET_ALL)
        input("\nPressione Enter para voltar...")
        return

    print(Fore.WHITE + "\nSelecione o arquivo que sera exportado:\n" + Style.RESET_ALL)
    for idx, report in enumerate(reports, 1):
        try:
            size = Path(report).stat().st_size
            size_str = f"{size // 1024}KB" if size >= 1024 else f"{size}B"
        except OSError:
            size_str = "?"
        print(f"  {idx} - {report} [{size_str}]")
    print("\n  00 - Voltar")

    choice = input("\nArquivo: ").strip()
    if choice == "00":
        return
    if not choice.isdigit() or not (1 <= int(choice) <= len(reports)):
        print(Fore.RED + "[!] Arquivo invalido." + Style.RESET_ALL)
        input("Pressione Enter para continuar...")
        return

    selected = Path(reports[int(choice) - 1])
    _clear_screen()
    print(Fore.MAGENTA + "\n<===== EXPORTAR RELATORIO =====>" + Style.RESET_ALL)
    print(Fore.WHITE + f"\nArquivo selecionado: {selected}" + Style.RESET_ALL)
    print("\nSelecione o formato de exportacao:\n")
    print("  1 - CSV   (.csv)")
    print("  2 - JSONL (.jsonl)")
    print("  3 - PDF   (.pdf)")
    print("\n  00 - Voltar")

    fmt_choice = input("\nFormato: ").strip()
    formats = {"1": ("csv", ".csv"), "2": ("jsonl", ".jsonl"), "3": ("pdf", ".pdf")}
    if fmt_choice == "00":
        return
    if fmt_choice not in formats:
        print(Fore.RED + "[!] Formato invalido." + Style.RESET_ALL)
        input("Pressione Enter para continuar...")
        return

    fmt, suffix = formats[fmt_choice]
    _clear_screen()
    print(Fore.MAGENTA + "\n<===== CONFIRMAR EXPORTACAO =====>" + Style.RESET_ALL)
    print(f"\nArquivo de origem : {selected}")
    print(f"Formato escolhido : {fmt.upper()}")
    default_name = selected.stem + "_export" + suffix
    output_name = input(f"Arquivo de destino [{default_name}]: ").strip() or default_name
    output = Path(output_name)
    if output.suffix.lower() != suffix:
        output = output.with_suffix(suffix)

    print("\nResumo:")
    print(f"  Origem : {selected}")
    print(f"  Saida  : {output}")
    confirm = input("\nDigite 'SIM' para confirmar: ").strip()
    if confirm != "SIM":
        print(Fore.YELLOW + "[!] Exportacao cancelada." + Style.RESET_ALL)
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
        print(Fore.RED + f"\n[!] Falha na exportacao: {exc}" + Style.RESET_ALL)
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
        txt_completos = [f for f in txt_todos if not _is_log_subcategory(f)]
        log_file_cfg = state.config.get("log_file", "raveneye.log")
        txt_structured_log = sorted(glob.glob(f"{log_file_cfg}*")) if log_file_cfg else []
        txt_audit = sorted(glob.glob("raveneye_audit_log.txt"))

        all_categorized = [
            ("<==== RELATORIO PRINCIPAL (TXT) ====>", txt_completos),
            ("<==== GOOGLE HACKING — Dorks ====>", txt_dorks),
            ("<==== NMAP — Portas e CVEs ====>", txt_nmap),
            ("<==== CSV — Achados ====>", txt_csv),
            ("<==== MARKDOWN ====>", txt_markdown),
            ("<==== VIRUSTOTAL (standalone) ====>", txt_vt),
            ("<==== SUBDOMINIOS (bruteforce DNS) ====>", txt_subs),
            ("<==== WORDLIST — URLs crawladas ====>", txt_wordlist),
            ("<==== ENDPOINTS ====>", txt_endpoints),
            ("<==== LOG ESTRUTURADO (raveneye.log) ====>", txt_structured_log),
            ("<==== AUDITORIA — autorizacoes confirmadas ====>", txt_audit),
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

        print(Fore.WHITE + "\n  export  - exportacao guiada (arquivo -> formato -> destino)" + Style.RESET_ALL)
        print(Fore.WHITE + "  delete <arquivo> | watch <arquivo>" + Style.RESET_ALL)
        print(Fore.WHITE + "  00 - sair   99 - manual\n" + Style.RESET_ALL)
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

        parts = choice.split(maxsplit=2)
        command = parts[0].lower() if parts else ""
        if command == "delete" and len(parts) == 2:
            target = Path(parts[1])
            print(Fore.YELLOW + f"\n[!] O arquivo sera movido para .raveneye_trash/: {target}" + Style.RESET_ALL)
            confirm = input("Digite 'SIM' para confirmar: ").strip()
            try:
                dest = _safe_delete_log(str(target), confirmation=confirm)
                print(Fore.GREEN + f"[+] Movido para: {dest}" + Style.RESET_ALL)
            except Exception as exc:
                print(Fore.RED + f"[!] Falha ao mover arquivo: {exc}" + Style.RESET_ALL)
            continue
        if command == "watch" and len(parts) == 2:
            target = Path(parts[1])
            if not target.is_file():
                print(Fore.RED + "[!] Arquivo de log nao encontrado." + Style.RESET_ALL)
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
                print(Fore.RED + f"Numero fora do intervalo (1-{len(all_files)})." + Style.RESET_ALL)
        else:
            print("Digite um numero de arquivo, export, 00 para sair ou 99 para o manual.")


def _log_file_viewer(filename: str) -> None:
    """Exibe arquivo de log com comandos interativos."""
    print(Fore.GREEN + f"\n[ LOG: {filename} ]" + Style.RESET_ALL)
    try:
        lines = Path(filename).read_text(encoding="utf-8", errors="ignore").splitlines()
        print(f"  {len(lines)} linhas | Digite um comando ou 'sair'\n")
    except (IOError, FileNotFoundError) as e:
        print(Fore.RED + f"Erro ao abrir arquivo: {e}" + Style.RESET_ALL)
        return

    while True:
        print(Fore.WHITE + "  grep <padrao> | head <n> | tail <n> | less | clear | delete | watch | export | sair" + Style.RESET_ALL)
        print(Fore.MAGENTA + "  Exportacao: CSV | JSONL | PDF" + Style.RESET_ALL)
        cmd = input(f"({Path(filename).name}) > ").strip()

        if not cmd or cmd == "sair":
            break

        if cmd.startswith("grep "):
            pattern = cmd[5:].strip()
            if not _validate_grep_pattern(pattern):
                print(Fore.RED + "[!] Padrao invalido. Use apenas: alfanumericos, . - _ * ? | ^ $" + Style.RESET_ALL)
                continue
            try:
                results = [l for l in lines if re.search(pattern, l, re.IGNORECASE)]
                print(Fore.CYAN + f"  {len(results)} resultados:" + Style.RESET_ALL)
                for r in results[:200]:
                    print(f"  {r}")
            except re.error as e:
                print(Fore.RED + f"Regex invalido: {e}" + Style.RESET_ALL)

        elif cmd.startswith("head"):
            parts = cmd.split()
            n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
            for l in lines[:n]:
                print(l)

        elif cmd.startswith("tail"):
            parts = cmd.split()
            n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
            for l in lines[-n:]:
                print(l)

        elif cmd == "less":
            if shutil.which("less"):
                subprocess.run(["less", filename])
            else:
                for l in lines:
                    print(l)

        elif cmd == "clear":
            _clear_screen()
            print(Fore.GREEN + f"\n[ LOG: {filename} ]" + Style.RESET_ALL)

        elif cmd == "delete":
            confirm = input("Digite 'SIM' para mover este arquivo para .raveneye_trash/: ").strip()
            try:
                dest = _safe_delete_log(filename, confirmation=confirm)
                print(Fore.GREEN + f"[+] Movido para: {dest}" + Style.RESET_ALL)
                break
            except Exception as exc:
                print(Fore.RED + f"[!] Falha ao mover arquivo: {exc}" + Style.RESET_ALL)

        elif cmd == "watch":
            print(Fore.CYAN + "[WATCH] Ctrl+C para parar." + Style.RESET_ALL)
            try:
                asyncio.run(_watch_log(filename))
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n[WATCH] encerrado." + Style.RESET_ALL)

        elif cmd == "export":
            _log_format_menu()
            print("Uso rapido: export <categoria> <saida.csv|saida.jsonl|saida.pdf>")
        elif cmd.startswith("export "):
            args = cmd.split(maxsplit=2)
            if len(args) != 3:
                print("Uso: export <categoria> <saida.csv/jsonl/pdf>")
                continue
            try:
                dest = _export_log_category(filename, args[1], args[2])
                print(Fore.GREEN + f"[+] Exportado para: {dest}" + Style.RESET_ALL)
            except Exception as exc:
                print(Fore.RED + f"[!] Falha na exportacao: {exc}" + Style.RESET_ALL)

        else:
            print("Comando nao reconhecido. Opcoes: grep, head, tail, less, clear, delete, watch, export, sair")


# ==================================================================
# MENU — Configurações
# ==================================================================
def menu_config() -> None:
    """Menu de configurações persistentes com manual integrado."""
    _clear_screen()

    while True:
        gh_mode = state.config.get("google_hacking_mode", "scan")
        print(Fore.WHITE + "\n[ CONFIGURACOES ]" + Style.RESET_ALL)
        print(f"  1  - Max paginas:          {state.config['max_pages']}")
        print(f"  2  - Delay (s):            {state.config['delay']}")
        print(f"  3  - User-Agent:           {state.config['user_agent'][:50]}...")
        print(f"  4  - Profundidade:         {state.config['max_depth']}")
        print(f"  5  - Tentativas BF:        {state.config['bf_attempts']} (max: 50000)")
        print(f"  6  - Limite links TXT:     {state.config['report_link_limit']}")
        print(f"  7  - Verbose (0-3):        {state.VERBOSE_LEVEL}")
        print(Fore.RED + f"  9  - Profundidade NUKE:    {state.config.get('max_depth_nuke', 5)}" + Style.RESET_ALL)
        print(f"  10 - Threads crawler:      {state.config.get('max_workers', 5)}")
        print(f"  11 - Proxy:                {state.config.get('proxy', '') or 'nenhum'}")
        print(f"  12 - Ano inicial Wayback:  {state.config.get('wayback_from_year', 2020)}")
        print(f"  13 - Google Hacking:       {gh_mode} (scan=integrado, interativo=separado)")
        if gh_mode == "interativo":
            print(f"  14 - Scope (arquivo):      {state.config.get('scope_file', '') or 'nenhum'}")
            print(f"  15 - JS Render (Playwright): {'ativo' if state.config.get('use_js_render') else 'inativo'}")
        print(f"  16 - Modo Stealth (headers): {'ativo' if state.config.get('stealth_mode') else 'inativo'}")
        print(f"  18 - Arquivo de dorks customizados: {state.config.get('custom_dorks_file', '') or 'nenhum'}")
        print(f"  23 - Log em arquivo:       {state.config.get('log_file', '') or 'desativado'}")
        print(f"  24 - Nivel do log:         {state.config.get('log_level', 'WARNING')}")
        print(f"  25 - Rate limit DNS (req/s): {state.config.get('dns_rate_limit', 30)}")
        print(f"  26 - Banco local:             {state.config.get('database_path', 'data/raveneye.db')}")
        print(f"  27 - Scanner rate limit:     {state.config.get('scanner_rate_limit', 8.0)} req/s")
        print(f"  28 - Scanner workers:        {state.config.get('scanner_max_workers', 6)}")
        print(f"  29 - Cache scanner TTL:      {state.config.get('scan_cache_ttl', 3600)} s")
        print(f"  30 - Múltiplos links/alvos:  {'ATIVO' if state.config.get('multi_target_enabled') else 'INATIVO'}")
        print()
        print(Fore.CYAN + "  --- Chaves de API ---" + Style.RESET_ALL)
        print(f"  8  - Chave Shodan:         {'configurada' if state.SHODAN_API_KEY else 'vazia'}")
        print(f"  17 - Chave VirusTotal:     {'configurada' if state.VIRUSTOTAL_API_KEY else 'vazia'}")
        print(f"  19 - Chave Google CSE:     {'configurada' if state.GOOGLE_CSE_API_KEY else 'vazia'}")
        print(f"  20 - Google CSE ID:        {state.config.get('google_cse_id', '') or 'vazio'}")
        print()
        print(Fore.GREEN + "  22 - Salvar configuracoes" + Style.RESET_ALL)
        print(Fore.WHITE + "  00 - Voltar  |  99 - Manual" + Style.RESET_ALL)

        op = input("> ").strip()

        if op == "00":
            break
        elif op == "22":
            save_config(state.config)
            print(Fore.GREEN + f"Configuracoes salvas em {CONFIG_FILE}" + Style.RESET_ALL)
        elif op == "99":
            show_manual("config")
        elif op == "1":
            try:
                v = int(input("Valor (1-999): "))
                if 1 <= v <= 999:
                    state.config["max_pages"] = v
            except Exception as e:
                vprint(2, f"[WARN] config op1: {e}")
        elif op == "2":
            try:
                v = float(input("Delay (s): "))
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
                    print("Fora do intervalo")
            except Exception as e:
                vprint(2, f"[WARN] config op4: {e}")
        elif op == "5":
            # MELHORIA: limite aumentado para 50000
            try:
                v = int(input("Tentativas BF (10-50000): "))
                if 10 <= v <= 50000:
                    state.config["bf_attempts"] = v
                else:
                    print("Fora do intervalo (10-50000)")
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
                v = int(input("Nivel verbose (0-3): "))
                if 0 <= v <= 3:
                    state.VERBOSE_LEVEL = v
                    set_verbose(v)
                    state.config["verbose"] = v
            except Exception as e:
                vprint(2, f"[WARN] config op7: {e}")
        elif op == "8":
            key = input("Nova chave Shodan (Enter p/ remover): ").strip()
            state.SHODAN_API_KEY = key
            print("Chave Shodan atualizada.")
        elif op == "9":
            try:
                v = int(input("Profundidade NUKE (5-20): "))
                if 5 <= v <= 20:
                    state.config["max_depth_nuke"] = v
                else:
                    print("Fora do intervalo (5-20)")
            except Exception as e:
                vprint(2, f"[WARN] config op9: {e}")
        elif op == "10":
            try:
                v = int(input("Threads (1-20): "))
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
                    print(Fore.YELLOW + "[!] requests[socks] nao instalado. Execute: pip install requests[socks]" + Style.RESET_ALL)
        elif op == "12":
            try:
                v = int(input("Ano inicial Wayback (ex: 2015): "))
                if 2000 <= v <= 2026:
                    state.config["wayback_from_year"] = v
            except Exception as e:
                vprint(2, f"[WARN] config op12: {e}")
        elif op == "13":
            mode = input("Modo Google Hacking ('scan' ou 'interativo'): ").strip().lower()
            if mode in ("scan", "interativo"):
                state.config["google_hacking_mode"] = mode
        elif op == "14" and gh_mode == "interativo":
            sf = input("Arquivo de scope (um dominio por linha, Enter p/ remover): ").strip()
            state.config["scope_file"] = sf
        elif op == "15" and gh_mode == "interativo":
            v = input("Ativar JS Render Playwright? (s/N): ").strip().lower()
            state.config["use_js_render"] = (v == "s")
            if state.config["use_js_render"] and not PLAYWRIGHT_AVAILABLE:
                print(Fore.YELLOW + "[!] Playwright nao instalado. Execute: pip install playwright && playwright install chromium" + Style.RESET_ALL)
        elif op == "16":
            v = input("Ativar Modo Stealth (headers variados p/ evadir fingerprint de WAF)? (s/N): ").strip().lower()
            state.config["stealth_mode"] = (v == "s")
        elif op == "17":
            key = input("Nova chave VirusTotal (Enter p/ remover): ").strip()
            state.VIRUSTOTAL_API_KEY = key
            print("Chave VirusTotal atualizada.")
        elif op == "18":
            path = input("Caminho do arquivo de dorks customizados (um por linha, Enter p/ remover): ").strip()
            state.config["custom_dorks_file"] = path
        elif op == "19":
            key = input("Nova chave Google Custom Search API (Enter p/ remover): ").strip()
            state.GOOGLE_CSE_API_KEY = key
            print("Chave Google CSE atualizada.")
        elif op == "20":
            cse_id = input("Google CSE ID (Search Engine ID, Enter p/ remover): ").strip()
            state.config["google_cse_id"] = cse_id
        elif op == "23":
            path = input("Arquivo de log (Enter p/ desativar): ").strip()
            state.config["log_file"] = path
            _setup_logger(path, state.config.get("log_level", "WARNING"))
            print("Log reconfigurado." if path else "Log desativado.")
        elif op == "24":
            lvl = input("Nivel do log (DEBUG/INFO/WARNING/ERROR): ").strip().upper()
            if lvl in ("DEBUG", "INFO", "WARNING", "ERROR"):
                state.config["log_level"] = lvl
                _setup_logger(state.config.get("log_file", ""), lvl)
            else:
                print("Nivel invalido.")
        elif op == "25":
            try:
                v = int(input("Rate limit DNS em requisicoes/segundo (1-200): "))
                if 1 <= v <= 200:
                    state.config["dns_rate_limit"] = v
                else:
                    print("Fora do intervalo (1-200)")
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
                print(Fore.YELLOW + f"[!] Sem permissao em 'reports/' — salvando em: {out_dir}" + Style.RESET_ALL)
            return out_dir
        except (PermissionError, OSError) as e:
            print(Fore.RED + f"[!] Nao foi possivel criar '{out_dir}': {e}" + Style.RESET_ALL)
            continue
    print(Fore.RED + "[!] Nenhuma pasta de saida pode ser criada. Salvando no diretorio atual." + Style.RESET_ALL)
    print(Fore.WHITE + "    Dica: se 'reports/' pertence ao root (de um scan anterior com sudo), "
                        "rode: sudo chown -R $USER:$USER reports/" + Style.RESET_ALL)
    return Path(".")



def _run_vulnerability_scanner(target: str, root_mode: bool = False) -> None:
    """Executa somente o scanner; não inicializa crawler nem módulos de recon."""
    scanner = RavenVulnScanner(
        target=target, root_mode=root_mode, urls=[target],
        max_workers=state.config.get("scanner_max_workers", 6),
        rate_limit=state.config.get("scanner_rate_limit", 8.0),
        active=True, timeout=min(30, int(state.config.get("scanner_timeout", 8))),
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
                 include_vuln_scanner: bool = False, preflight_enumeration: dict | None = None) -> None:
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
        shodan_key=state.SHODAN_API_KEY,
        bf_attempts=state.config["bf_attempts"],
        root_mode=root_mode,
        large_bf=large_bf,
        scope_domains=_load_scope(),
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
  7  - Crawler + Wayback Priority
  8  - Crawler + Probing de Parametros
  9  - Crawler + Path Guessing
  10 - Crawler + Shodan + IP
  11 - Crawler Completo (todas as fontes)

  00 - Voltar   33 - Manual
""" + Style.RESET_ALL)

        choice = input("Escolha: ").strip()
        if choice == "00":
            break
        if choice == "33":
            show_manual("crawler")
            continue
        if choice not in [str(i) for i in range(1, 12)]:
            print("Opcao invalida")
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
                print(Fore.CYAN + f"\n[*] Alvo {idx}/{len(targets)}: {target}" + Style.RESET_ALL)
            # _offer_open_report (chamado dentro de save_all_reports) ja pergunta
            # se a pessoa quer ver o relatorio; assim que ela fecha (ou nega),
            # o proximo alvo da fila comeca imediatamente.
            try:
                _run_crawler(opts, target, mp, md, base_prefix="RavenEye_crawler")
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print(Fore.RED + f"[!] Falha no alvo {target}: {e}" + Style.RESET_ALL)
                if len(targets) > 1:
                    print(Fore.YELLOW + "[!] Seguindo para o proximo alvo da fila..." + Style.RESET_ALL)


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
  2 - Crawler + Shodan + Varredura de Vulnerabilidades Web

  <=====> COM ROOT <=====>
  3 - Crawler + Shodan + Nmap root (-sS -O -A -p-, -D RND:5)
  4 - Crawler + Shodan + Bruteforce Avancado (wordlist grande + embutida)

  00 - Voltar   33 - Manual
""" + Style.RESET_ALL)

        choice = input("Escolha: ").strip()
        if choice == "00":
            break
        if choice == "33":
            show_manual("ofensivo")
            continue
        if choice not in ("1", "2", "3", "4"):
            print("Opcao invalida")
            continue

        root_mode = choice in ("1", "3")
        # Do this before an authorization prompt: a normal user should never
        # be asked to confirm a mode the process cannot run.
        if root_mode and os.geteuid() != 0:
            print(Fore.RED + "[!] Este perfil inclui recursos locais que exigem root." + Style.RESET_ALL)
            print(Fore.YELLOW + "    Para crawler + scanner sem root, escolha 4 (C4 + Scanner)." + Style.RESET_ALL)
            print(Fore.YELLOW + "    O comando 'raven' é instalado no seu usuário; execute-o sem sudo." + Style.RESET_ALL)
            continue

        target = _get_target()
        if not _confirm_aggressive(target):
            print("Operacao cancelada.")
            continue

        root_mode = choice in ("3", "4")
        if root_mode and os.geteuid() != 0:
            print(Fore.RED + "[!] Esta opcao requer root (sudo)." + Style.RESET_ALL)
            continue

        mp, md = _get_crawl_params()
        opts = {
            "shodan": True, "whois": True, "archive": True,
            "exploitdb": True, "payload": True, "google": True,
            "wayback": True,
            "nmap": choice in ("1", "3"),
        }
        large_bf = (choice == "4")
        _run_crawler(opts, target, mp, md, root_mode=root_mode,
                     large_bf=large_bf, base_prefix=f"RavenEye_off{'root' if root_mode else ''}")


# ==================================================================
# MENU — Bruteforce
# ==================================================================
def menu_bruteforce() -> None:
    """Menu de bruteforce (login e subdominios)."""
    _clear_screen()
    ascii_bruteforce()

    while True:
        print(Fore.YELLOW + f"""
  <=====> LOGIN (SEM ROOT) <=====>
  1 - Bruteforce de login (wordlist media + {len(EXTRA_PASSWORDS)} senhas embutidas)

  <=====> LOGIN (COM ROOT) <=====>
  2 - Bruteforce de login root (wordlist grande + embutida, ~50k senhas)

  <=====> SUBDOMINIOS (DNS, nao requer root) <=====>
  3 - Bruteforce de subdominios (wordlist embutida, {len(SUBDOMAIN_WORDLIST)} candidatos)

  <=====> ENUMERACAO HTTP (NAO AUTENTICA) <=====>
  4 - Bruteforce de diretorios/paths
  5 - Bruteforce de endpoints
  6 - Bruteforce de parametros

  00 - Voltar   33 - Manual
""" + Style.RESET_ALL)

        choice = input("Escolha: ").strip()
        if choice == "00":
            break
        if choice == "33":
            show_manual("bruteforce")
            continue
        if choice not in ("1", "2", "3", "4", "5", "6"):
            print("Opcao invalida")
            continue

        if choice in ("4", "5", "6"):
            targets = _get_targets_for_safe_operation()
            if not targets:
                print("Operacao cancelada.")
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
                    print(Fore.GREEN + f"[+] {len(found)} resultados para {target}. Salvo em {fname}" + Style.RESET_ALL)
                except Exception as e:
                    print(Fore.RED + f"[ERRO] {e}" + Style.RESET_ALL)
            continue

        if choice == "3":
            if state.config.get("multi_target_enabled"):
                domains = []
                print(Fore.CYAN + f"Cole até {int(state.config.get('max_targets', 50))} domínios, um por linha. Linha vazia finaliza." + Style.RESET_ALL)
                while len(domains) < int(state.config.get("max_targets", 50)):
                    raw = input(f"Dominio {len(domains)+1}: ").strip()
                    if not raw:
                        break
                    dom = _sanitize_domain_input(raw)
                    if dom and dom not in domains:
                        domains.append(dom)
            else:
                raw = input("Dominio alvo (ex: exemplo.com): ").strip()
                dom = _sanitize_domain_input(raw) if raw else ""
                domains = [dom] if dom else []
            if not domains:
                print("Dominio invalido.")
                continue
            for domain in domains:
                try:
                    domain_safe = _safe_domain_filename(domain)
                    found = brute_subdomains(domain)
                    if found:
                        fname = f"RavenEye_subdomains_bf_{domain_safe}_{int(time.time())}.txt"
                        lines = [f"{item['subdomain']}  ->  {item['ip']}" for item in found]
                        Path(fname).write_text("\n".join(lines), encoding="utf-8")
                        print(Fore.GREEN + f"[+] {domain}: resultado salvo: {fname}" + Style.RESET_ALL)
                except Exception as e:
                    print(Fore.RED + f"[ERRO] {domain}: {e}" + Style.RESET_ALL)
            continue

        root_mode = (choice == "2")
        if root_mode and os.geteuid() != 0:
            print(Fore.RED + "[!] Modo root requer sudo." + Style.RESET_ALL)
            continue

        login_url = input("URL do formulario de login: ").strip()
        if not login_url.startswith(("http://", "https://")):
            login_url = "https://" + login_url

        if not _confirm_aggressive(login_url):
            print("Operacao cancelada.")
            continue

        username = input("Usuario alvo: ").strip()
        user_field = input("Campo username (padrao 'username'): ").strip() or "username"
        pass_field = input("Campo password (padrao 'password'): ").strip() or "password"

        found, attempts = bruteforce_login(
            login_url, username, user_field, pass_field, root_mode=root_mode
        )
        if found:
            print(Fore.GREEN + f"\n[+] SUCESSO! Senha: {found} apos {attempts} tentativas." + Style.RESET_ALL)
        else:
            print(Fore.RED + f"\nFalha. Nenhuma senha valida em {attempts} tentativas." + Style.RESET_ALL)


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

  1 - Scanner de vulnerabilidade + CVE entregue (se houver encontro)
  2 - Scanner de vulnerabilidade solo

  0 - Voltar   33 - Manual
""" + Style.RESET_ALL)
        choice = input("Escolha: ").strip()
        if choice == "0":
            break
        if choice == "33":
            show_manual("vulnerability")
            continue
        if choice not in ("1", "2"):
            print("Opcao invalida")
            continue
        targets = _get_targets_for_safe_operation()
        if not targets:
            print("Operacao cancelada.")
            continue
        root_mode = choice == "1"
        if root_mode and os.geteuid() != 0:
            print(Fore.RED + "[!] A modalidade com root requer sudo." + Style.RESET_ALL)
            continue
        for target in targets:
            if not _confirm_aggressive(target):
                continue
            try:
                _run_vulnerability_scanner(target, root_mode=root_mode)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                print(Fore.RED + f"[!] Falha no alvo {target}: {exc}" + Style.RESET_ALL)


def menu_nuke() -> None:
    """Orquestrador completo de recon + auditoria segura; scanner continua separado."""
    _clear_screen()
    ascii_radiation()
    while True:
        print(Fore.RED + """
  <=====> SEM SCANNER <=====>
  1 - NUKE (Total, todos os modulos, Nmap agressivo, requer root)
  2 - C4 (Ataque parcial, sem funcionalidades root)

  <=====> COM SCANNER DE VULNERABILIDADES <=====>
  3 - NUKE + Scanner (requer root)
  4 - C4 + Scanner (sem root)

  00 - Voltar   33 - Manual
""" + Style.RESET_ALL)
        choice = input("Escolha: ").strip()
        if choice == "00":
            break
        if choice == "33":
            show_manual("nuke")
            continue
        if choice not in ("1", "2", "3", "4"):
            print("Opcao invalida")
            continue

        root_mode = choice in ("1", "3")
        if root_mode and os.geteuid() != 0:
            print(Fore.RED + "[!] Esta opção usa apenas recursos locais que exigem root (Nmap SYN/OS detection)." + Style.RESET_ALL)
            print(Fore.YELLOW + "    Para o fluxo equivalente sem privilégios, escolha C4 ou C4 + Scanner." + Style.RESET_ALL)
            print(Fore.YELLOW + "    Se 'sudo raven' ainda não funciona, rode novamente: sh ~/.local/share/raveneye/installer/install.sh" + Style.RESET_ALL)
            continue

        target = _get_target()
        if not target or not _confirm_aggressive(target):
            print("Operacao cancelada.")
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
            include_vuln_scanner=choice in ("3", "4"),
            preflight_enumeration=enum_results,
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
            print(Fore.WHITE + f"  Google Dorks: {len(google_dork_search('example.com'))} dorks built-in" + Style.RESET_ALL)
            print()
            first_run = False
        print(Fore.CYAN + "  1. INICIAR" + Style.RESET_ALL)
        print(Fore.CYAN + "  2. CONFIGURACOES" + Style.RESET_ALL)
        print(Fore.CYAN + "  3. CREDITOS" + Style.RESET_ALL)
        print(Fore.CYAN + "  4. SAIR" + Style.RESET_ALL)

        op = input("\nEscolha: ").strip()

        if op == "1":
            _menu_sala_principal()
        elif op == "2":
            menu_config()
        elif op == "3":
            show_credits()
            print(Fore.WHITE + "  I see you v" + TOOL_VERSION + Style.RESET_ALL)
            input("\n  Pressione Enter para voltar...")
        elif op == "4":
            save_config(state.config)
            print("\nEncerrando. Configuracoes salvas.\n")
            sys.exit(0)
        else:
            print("Opcao invalida")


def _menu_sala_principal() -> None:
    """Submenu Salão Principal."""
    _clear_screen()
    ascii_main_hall()
    gh_mode = state.config.get("google_hacking_mode", "scan")

    while True:
        print(Fore.MAGENTA + "\n  ============================" + Style.RESET_ALL)
        print(Fore.MAGENTA + "       SALAO PRINCIPAL" + Style.RESET_ALL)
        print(Fore.MAGENTA + "  ============================" + Style.RESET_ALL)

        if gh_mode == "interativo":
            print(Fore.CYAN + """
  1. WEB CRAWLER MAPEAMENTO
  2. WEB CRAWLER OFENSIVO
  3. BRUTEFORCE
  4. NMAP
  5. NUKE
  6. LEITURA DE LOGS
  7. GOOGLE HACKING
  8. VIRUSTOTAL
  9. VOLTAR
  10. SCANNER DE VULNERABILIDADES
""" + Style.RESET_ALL)
            voltar_opcao = "9"
        else:
            print(Fore.CYAN + """
  1. WEB CRAWLER MAPEAMENTO
  2. WEB CRAWLER OFENSIVO
  3. BRUTEFORCE
  4. NMAP
  5. NUKE
  6. LEITURA DE LOGS
  7. VIRUSTOTAL
  8. VOLTAR
  9. SCANNER DE VULNERABILIDADES
""" + Style.RESET_ALL)
            voltar_opcao = "8"

        sub = input("Escolha: ").strip()

        if sub == voltar_opcao:
            break
        if gh_mode == "interativo" and sub == "7":
            menu_google_hacking()
            continue
        if gh_mode != "interativo" and sub == "7":
            menu_virustotal()
            continue
        if gh_mode == "interativo" and sub == "8":
            menu_virustotal()
            continue
        if gh_mode == "interativo" and sub == "10":
            menu_vulnerability_scanner()
            continue
        if gh_mode != "interativo" and sub == "9":
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
        elif sub not in (voltar_opcao,):
            print("Opcao invalida")


def menu_virustotal() -> None:
    """Menu standalone do VirusTotal; múltiplos alvos somente quando habilitados."""
    _clear_screen()
    while True:
        print(Fore.CYAN + "\n[ VIRUSTOTAL ]" + Style.RESET_ALL)
        print(f"  Chave configurada: {'sim' if state.VIRUSTOTAL_API_KEY else 'NAO — configure em Configuracoes'}")
        print("\n  1. Verificar URL\n  2. Verificar dominio\n  3. Verificar IP\n  0. Voltar\n")
        sub = input("Escolha: ").strip()
        if sub == "0": break
        if sub not in ("1", "2", "3"): print("Opcao invalida"); continue
        if not state.VIRUSTOTAL_API_KEY:
            print(Fore.RED + "[!] Chave VirusTotal nao configurada. Va em Configuracoes > opcao 17." + Style.RESET_ALL)
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
            raw=input("URL a verificar: " if sub=="1" else "Dominio a verificar (ex: exemplo.com): " if sub=="2" else "IP a verificar (ex: 1.2.3.4): ").strip()
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
    _clear_screen()
    """Menu Nmap autônomo."""
    ascii_eye_double_pupil()
    while True:
        print(Fore.GREEN + """
  [ NMAP ]

  1 - Scan leve (sem root, -sT -sV -D RND:5)
  2 - Scan agressivo (com root, -sS -O -A -p- -D RND:5)
  3 - Descobrir IP real (por tras de CDN/WAF como Cloudflare)

  00 - Voltar
""" + Style.RESET_ALL)
        choice = input("Escolha: ").strip()
        if choice == "00":
            break
        if choice not in ("1", "2", "3", "4", "5", "6"):
            print("Opcao invalida")
            continue

        if choice in ("4", "5", "6"):
            target = _get_target()
            if not target or not _confirm_aggressive(target):
                print("Operacao cancelada.")
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
            raw_target = input("Dominio alvo (ex: exemplo.com): ").strip()
            if not raw_target:
                continue
            domain = _sanitize_domain_input(raw_target)
            domain_safe = _safe_domain_filename(raw_target)
            print(Fore.CYAN + f"[*] Consultando crt.sh e testando ranges do Cloudflare para {domain}..." + Style.RESET_ALL)
            subdomains = get_subdomains_crtsh(domain)
            result = find_real_ip(domain, subdomains)
            if not result["dominio_atras_de_cdn"]:
                print(Fore.GREEN + f"\n[OK] {domain} nao parece estar atras de um CDN/WAF conhecido "
                                    f"(IP: {result['ip_principal']}) — o IP resolvido ja e o real." + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + f"\n[!] {domain} esta atras de {result['cdn_detectado']} "
                                     f"(ranges: {result['fonte_ranges']})" + Style.RESET_ALL)
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
                    print(Fore.WHITE + "\nNenhum candidato encontrado (subdominios conhecidos tambem "
                                        "estao atras do CDN, sem IP declarado no SPF)." + Style.RESET_ALL)
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
                    print(Fore.RED + f"[ERRO] Nao foi possivel salvar: {e}" + Style.RESET_ALL)
            input("\nPressione Enter para continuar...")
            continue

        root_mode = (choice == "2")
        if root_mode and os.geteuid() != 0:
            print(Fore.RED + "[!] Scan agressivo requer root." + Style.RESET_ALL)
            continue

        raw_target = input("IP ou dominio alvo: ").strip()
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
                vprint(2, f"[WARN] nmap standalone save: {e}")
        else:
            print(result)
        input("\nPressione Enter para continuar...")
