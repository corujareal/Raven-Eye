from __future__ import annotations

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==================================================================
                 RAVEN EYE - I see you
==================================================================
                 Propriedade: TΛNDΛI SΞC
                      Feito por: Thiago
                         Versão: 6.6.6
==================================================================
- Interface ASCII com menus aninhados
- Configurações persistentes com auto-save
- Recon avançado: crt.sh, DNS Zone Transfer, SPF/DMARC
- Detecção de Subdomain Takeover e bruteforce de subdominios (DNS)
- Extração de Secrets em JavaScript (com desofuscacao via jsbeautifier)
- CORS Misconfiguration, Security Headers, Open Redirects
- Web Cache Poisoning, HTTP Request Smuggling (heuristico), JWT Weaknesses
- Google Dorks: geracao local + busca automatizada via Google Custom Search API
- Bruteforce de login com CSRF, jitter e lockout detection
- Wordlist de senhas embutida (brasileira + internacional)
- Crawler multi-threaded com renderização JavaScript via Playwright do runtime completo
- Suporte a multiplos alvos em fila no Crawler Mapeamento
- Integrações por chave API: Shodan, VirusTotal, Google CSE, Censys, Netlas e LeakIX
- Relatório em TXT, JSON, HTML (dark theme) e Markdown
- Leitura de logs categorizada com manual integrado
- Suporte a proxy HTTP/SOCKS5
- Log de auditoria de autorizacoes confirmadas
- Compatível: Debian, Ubuntu, Arch, Fedora, Termux
"""


import argparse
import importlib.util
import os
import sys
from pathlib import Path

# Bootstrap de ambiente: quando o projeto e executado a partir do proprio diretorio,
# o launcher prefere o interpretador do venv ativo e nao exige um caminho absoluto.
PROJECT_ROOT = Path(__file__).resolve().parent
# Installed releases keep third-party packages in `_vendor` so the installer
# remains independent of venv activation and system site-packages.
_VENDOR_DIR = PROJECT_ROOT / "_vendor"
if _VENDOR_DIR.is_dir() and str(_VENDOR_DIR) not in sys.path:
    sys.path.insert(0, str(_VENDOR_DIR))
# Se chamado como `sudo python3 RavenEye.py`, use automaticamente o venv local
# quando ele existir. Isso evita exigir caminho absoluto do interpretador.
_LOCAL_VENV_PY = PROJECT_ROOT / ".venv" / "bin" / "python3"
if hasattr(os, "geteuid") and os.geteuid() == 0 and not os.environ.get("VIRTUAL_ENV") and _LOCAL_VENV_PY.exists():
    if Path(sys.executable).resolve() != _LOCAL_VENV_PY.resolve():
        os.execv(str(_LOCAL_VENV_PY), [str(_LOCAL_VENV_PY), str(Path(__file__).resolve()), *sys.argv[1:]])
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

def _venv_site_packages() -> list[str]:
    candidates = []
    v = os.environ.get("VIRTUAL_ENV")
    if v:
        candidates.extend([
            str(Path(v) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"),
            str(Path(v) / "Lib" / "site-packages"),
        ])
    return [x for x in candidates if Path(x).is_dir()]

for _sp in _venv_site_packages():
    if _sp not in sys.path:
        sys.path.insert(0, _sp)

# Keep bootstrap diagnostics independent of the legacy UI dependency stack.
# This allows `doctor` to diagnose a broken/fresh environment instead of
# failing on the first optional/legacy import (for example colorama).
_BOOT_CMD = next((x for x in sys.argv[1:] if x in {"crawler","scanner","scan","nuke","full","full-scan","bruteforce","offensive","report","database","logs","doctor"}), None)
if _BOOT_CMD == "doctor" and not any(x in sys.argv[1:] for x in ("-h", "--help")):
    from raveneye_pkg.doctor import run_doctor, render_doctor
    result = run_doctor()
    if "--json" in sys.argv[1:]:
        import json as _json
        print(_json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(render_doctor(result))
    raise SystemExit(0 if result.get("ok") else 1)

# Keep help usable on a fresh install before optional/runtime dependencies exist.
# The bootstrap help intentionally mirrors the real argparse surface so `-h`
# remains useful even before requirements are installed.
if importlib.util.find_spec("colorama") is None and (any(x in sys.argv[1:] for x in ("-h", "--help")) or ("report" in sys.argv[1:] and "--version" in sys.argv[1:])):
    _cmd = next((x for x in sys.argv[1:] if x in {"crawler","scanner","scan","nuke","full","full-scan","bruteforce","offensive","report","database","logs","doctor"}), None)
    if _cmd is None:
        print("""RavenEye v6.6.6 — I see you

Uso: raven [comando] [alvo] [opções]

Sem argumentos, o raven abre o menu interativo (estilo nmap: basta digitar
"raven" e navegar pelos módulos). Para uso direto/scriptável, use um comando:

Comandos:
  scanner <URL>       Scanner de vulnerabilidades independente
  crawler <URL>       Crawler e reconhecimento web
  full <URL>          Descoberta + scanner + persistência + relatórios
  nuke <URL>          Orquestrador NUKE/C4 governado
  offensive <URL>     Reconhecimento ofensivo governado
  bruteforce <URL>    Auditoria de autenticação/enumeração governada
  report              Operações de relatório
  database            Verificação do banco local
  logs                Operações de logs
  doctor              Autodiagnóstico local (ambiente/dependências)

Atalhos comuns:
  -p/--pages N         Limite de páginas (crawler/full)
  -n/--nmap            Enriquecimento Nmap
  -s/--shodan          Enriquecimento Shodan
  -o/--output PATH     Saída
  -q/--quiet           Silencia mensagens decorativas

Compatibilidade legada (sem instalar via installer/):
  python3 RavenEye.py -u https://alvo.com -m scanner

Use `raven <comando> -h` para a ajuda específica de cada comando.""")
    elif _cmd == "report":
        print("""RavenEye v6.6.6 — report

Formatos disponíveis: TXT, JSON, HTML, CSV, Markdown, PDF
Uso: raven report [--version] [--format FORMAT] [--output PATH]

--format aceita: txt, json, html, csv, markdown, pdf
""")
    elif _cmd == "doctor":
        print("""RavenEye v6.6.6 — doctor

Uso: raven doctor [--json]

Executa somente verificações locais: Python, venv/Termux, dependências do runtime completo, permissões e browsers Playwright.
Nenhuma requisição de rede é realizada.
""")
    elif _cmd in {"scanner","scan"}:
        print("""RavenEye v6.6.6 — scanner

Uso: raven scanner <URL> [opções]

Opções:
  -r, --root             Modo privilegiado autorizado
  --scope PATTERN        Domínio/escopo permitido (repetível)
  --exclude PATTERN      Exclusão de escopo (repetível)
  -o, --output PATH      Diretório/base de saída
  -v, --verbose LEVEL    Verbosidade: 0..3
  -q, --quiet            Suprime mensagens decorativas
  --timeout SECONDS      Timeout do scanner
  --rate REQUESTS/S      Limite de requisições
  -h, --help             Mostra esta ajuda

O Scanner é independente do crawler e do NUKE/C4.""")
    elif _cmd == "crawler":
        print("""RavenEye v6.6.6 — crawler

Uso: raven crawler <URL> [opções]

Opções:
  -d, --depth N           Profundidade máxima
  -p, --pages N           Limite de páginas
  -t, --threads N         Workers/conexões configuráveis
  --engine {legacy,async} Motor do crawler (padrão: legacy)
  --headless              Captura XHR/fetch de SPA via Playwright (exige --engine async)
  --proxy URL             Proxy HTTP/SOCKS
  -n, --nmap              Enriquecimento Nmap
  -s, --shodan            Enriquecimento Shodan
  --scope PATTERN         Escopo permitido (repetível)
  --exclude PATTERN       Exclusão de escopo (repetível)
  -o, --output PATH       Saída
  -v, --verbose LEVEL     Verbosidade: 0..3
  -q, --quiet             Suprime mensagens decorativas
  -h, --help              Mostra esta ajuda""")
    elif _cmd in {"full","full-scan"}:
        print("""RavenEye v6.6.6 — full

Uso: raven full <URL> [opções]

Opções:
  -p, --pages N          Limite de URLs
  --scope PATTERN         Escopo permitido (repetível)
  --exclude PATTERN       Exclusão de escopo (repetível)
  -o, --output PATH       Diretório de relatórios
  -v, --verbose LEVEL     Verbosidade: 0..3
  -q, --quiet             Suprime mensagens decorativas
  -h, --help              Mostra esta ajuda""")
    elif _cmd == "nuke":
        print("""RavenEye v6.6.6 — nuke

Uso: raven nuke <URL> [opções]

Opções:
  -s, --with-scanner      Inclui o Scanner independente após o fluxo governado
  -r, --root              Modo privilegiado autorizado
  --scope PATTERN         Escopo permitido (repetível)
  --exclude PATTERN       Exclusão de escopo (repetível)
  -o, --output PATH       Saída
  -v, --verbose LEVEL     Verbosidade: 0..3
  -q, --quiet             Suprime mensagens decorativas
  -h, --help              Mostra esta ajuda

Operações agressivas continuam sujeitas a confirmação/autorização.""")
    else:
        print(f"RavenEye v6.6.6 — {_cmd}\n\nUse `python3 RavenEye.py { _cmd } -h` após instalar as dependências para a ajuda completa.")
    raise SystemExit(0)

from raveneye_pkg import state
from raveneye_pkg.state import set_verbose, _setup_logger, logger, check_dependencies
from raveneye_pkg.config_io import load_config, get_api_key
from raveneye_pkg.constants import TOOL_VERSION
from raveneye_pkg.database import initialize as initialize_database, integrity_check as database_integrity_check
from raveneye_pkg.menus import (
    menu_principal, _run_crawler, _run_vulnerability_scanner, _load_scope,
    _load_scanner_scope,
    _confirm_aggressive, _confirm_vulnerability_scanner,
)
from raveneye.core.targets import normalize_target
from raveneye_pkg.credits import verify_integrity


# ==================================================================
# ARGPARSE — CLI unificada (mantém compatibilidade com a CLI legada)
# ==================================================================
COMMANDS = {"crawler", "scanner", "nuke", "full", "bruteforce", "offensive", "report", "database", "logs", "doctor"}


def _add_common_target_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("url", nargs="?", help="URL alvo")
    parser.add_argument("-o", "--output", help="Nome base/diretório de saída")
    parser.add_argument("--scope", action="append", default=[], help="Domínio/escopo permitido; pode ser repetido")
    parser.add_argument("--exclude", action="append", default=[], help="Padrão de exclusão; pode ser repetido")
    parser.add_argument("-v", "--verbose", type=int, choices=[0, 1, 2, 3], default=0)
    parser.add_argument("-q", "--quiet", action="store_true", help="Suprime ASCII art e mensagens decorativas")


def _build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raven",
        description=f"RavenEye v{TOOL_VERSION} — I see you\n\nSem argumentos, abre o menu interativo (estilo nmap).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "COMANDOS:\n"
            "  scanner <URL>       Scanner de vulnerabilidades independente\n"
            "  crawler <URL>       Descoberta/crawling\n"
            "  full <URL>          Crawl + scanner + persistência + relatórios\n"
            "  nuke <URL>          Orquestração NUKE/C4 governada\n"
            "  offensive <URL>     Reconhecimento ofensivo governado\n"
            "  bruteforce <URL>    Auditoria de autenticação/enumeração governada\n"
            "  report              Ferramentas de relatório\n"
            "  database            Verificação do banco local\n"
            "  logs                Operações de logs\n"
            "  doctor              Autodiagnóstico local (sem rede)\n\n"
            "ATALHOS DE COMPATIBILIDADE:\n"
            "  -p/--pages N        Limite de páginas\n"
            "  -n/--nmap           Enriquecimento Nmap\n"
            "  -s/--shodan         Enriquecimento Shodan\n"
            "  -o/--output PATH    Saída\n"
            "  -q/--quiet          Silencia mensagens decorativas\n\n"
            "EXEMPLOS:\n"
            "  raven                                    # menu interativo\n"
            "  raven scanner https://alvo.example\n"
            "  raven crawler https://alvo.example -p 100 -n -s\n"
            "  raven full https://alvo.example -o saida/\n"
            "  raven doctor --json\n\n"
            "Compatibilidade legada (execução sem installer/):\n"
            "  python3 RavenEye.py -u https://alvo.com -m scanner\n\n"
            "Use 'raven <comando> -h' para a ajuda de cada comando."
        ),
    )
    parser.add_argument("--version", action="version", version=f"RavenEye {TOOL_VERSION} — I see you")
    sub = parser.add_subparsers(dest="command", metavar="COMANDO")

    # Crawler
    p = sub.add_parser("crawler", aliases=["crawl"], help="Executa somente descoberta/crawling")
    _add_common_target_options(p)
    p.add_argument("-d", "--depth", type=int)
    p.add_argument("-p", "--pages", type=int)
    p.add_argument("-t", "--threads", type=int)
    p.add_argument("--engine", choices=["legacy", "async"], default="legacy",
                   help="Motor do crawler; legacy preserva relatórios/enriquecimentos atuais")
    p.add_argument("--headless", action="store_true",
                   help="Renderiza shells SPA e captura XHR/fetch em escopo; exige --engine async")
    p.add_argument("--proxy")
    p.add_argument("-n", "--nmap", action="store_true", help="Ativa enriquecimento Nmap")
    p.add_argument("-s", "--shodan", action="store_true", help="Ativa enriquecimento Shodan")

    # Scanner — independente do crawler
    p = sub.add_parser("scanner", aliases=["scan"], help="Scanner de vulnerabilidades independente do crawler/NUKE")
    _add_common_target_options(p)
    p.add_argument("-r", "--root", action="store_true", help="Usa o modo privilegiado quando a operação autorizada exigir")
    p.add_argument("--timeout", type=int, default=None, help="Timeout por etapa, em segundos")
    p.add_argument("--rate", type=float, default=None, help="Limite de requisições por segundo")

    # Full
    p = sub.add_parser("full", aliases=["full-scan"], help="Crawl + scanner + persistência + relatórios")
    _add_common_target_options(p)
    p.add_argument("-p", "--pages", type=int, default=100)

    # NUKE / offensive: mantém uma entrada CLI clara, mas continua governado pela confirmação/autorização.
    p = sub.add_parser("nuke", help="Orquestrador NUKE/C4 governado; não substitui o Scanner")
    _add_common_target_options(p)
    p.add_argument("-s", "--with-scanner", action="store_true", help="Inclui o Scanner independente após a etapa governada")
    p.add_argument("-r", "--root", action="store_true", help="Solicita modo privilegiado autorizado")

    p = sub.add_parser("offensive", help="Reconhecimento ofensivo governado")
    _add_common_target_options(p)
    p.add_argument("-r", "--root", action="store_true", help="Solicita modo privilegiado autorizado")

    p = sub.add_parser("bruteforce", help="Auditoria de autenticação/enumeração governada")
    _add_common_target_options(p)
    p.add_argument("-r", "--root", action="store_true", help="Solicita modo privilegiado autorizado")

    p = sub.add_parser("report", help="Operações de relatório")
    p.add_argument("--version", action="store_true", help="Mostra formatos suportados")
    p.add_argument("-f", "--format", choices=["txt", "json", "html", "csv", "markdown", "pdf"], default="pdf", help="Formato do relatório")
    p.add_argument("-o", "--output", default="report", help="Arquivo de saída (extensão pode ser omitida)")

    p = sub.add_parser("database", help="Verifica o banco local")
    p.add_argument("-i", "--integrity", action="store_true", help="Executa integrity check")

    p = sub.add_parser("logs", help="Operações de logs")
    p.add_argument("-w", "--watch", metavar="ARQUIVO")
    p.add_argument("-d", "--delete", metavar="ARQUIVO")
    p.add_argument("-e", "--export", metavar="ARQUIVO")
    p.add_argument("-c", "--category", metavar="NOME")
    p.add_argument("-o", "--output", metavar="ARQUIVO")

    p = sub.add_parser("doctor", help="Autodiagnóstico local: Python, dependências do runtime, banco e browsers")
    p.add_argument("-j", "--json", action="store_true", help="Emite resultado estruturado em JSON")

    # Compatibilidade 100% com a CLI antiga: estes argumentos continuam válidos sem subcomando.
    parser.add_argument("--url", "-u", dest="legacy_url")
    parser.add_argument("--mode", "-m", choices=["crawler", "offensive", "bruteforce", "nuke", "full", "scanner"], default=None)
    parser.add_argument("--depth", "-d", dest="legacy_depth", type=int)
    parser.add_argument("--pages", "-p", dest="legacy_pages", type=int)
    parser.add_argument("--proxy", dest="legacy_proxy")
    parser.add_argument("--output", "-o", dest="legacy_output")
    parser.add_argument("--threads", "-t", dest="legacy_threads", type=int)
    parser.add_argument("--verbose", "-v", dest="legacy_verbose", type=int, choices=[0, 1, 2, 3], default=0)
    parser.add_argument("-S", "--scope", dest="legacy_scope", help="Arquivo/padrão de escopo permitido")
    parser.add_argument("-n", "--nmap", action="store_true", dest="legacy_nmap", help="Ativa enriquecimento Nmap")
    parser.add_argument("-s", "--shodan", action="store_true", dest="legacy_shodan", help="Ativa enriquecimento Shodan")
    parser.add_argument("-r", "--scanner-root", action="store_true", dest="legacy_scanner_root", help="Modo privilegiado autorizado")
    parser.add_argument("--quiet", "-q", action="store_true", dest="legacy_quiet")
    parser.add_argument("--log-file", dest="legacy_log_file")
    return parser


def _apply_cli_runtime(args) -> None:
    verbose = getattr(args, "verbose", getattr(args, "legacy_verbose", 0)) or 0
    if verbose:
        state.VERBOSE_LEVEL = verbose
        set_verbose(verbose)
    if getattr(args, "quiet", False) or getattr(args, "legacy_quiet", False):
        state.QUIET_MODE = True


def _run_command(args) -> bool:
    """Executa a CLI nova. Retorna False quando não há subcomando."""
    command = getattr(args, "command", None)
    if not command:
        return False
    _apply_cli_runtime(args)
    if command in {"scanner", "scan"}:
        if not args.url:
            raise SystemExit("scanner: URL obrigatória; use 'raven scanner -h'")
        target = normalize_target(args.url)
        if not target:
            raise SystemExit("scanner: alvo inválido; informe um domínio ou URL HTTP(S).")
        try:
            scanner_scope = set(args.scope or []) or _load_scanner_scope()
        except ValueError as exc:
            raise SystemExit(f"scanner bloqueado: {exc}") from None
        if not _confirm_vulnerability_scanner(target):
            raise SystemExit("Scanner cancelado: autorização não confirmada.")
        _run_vulnerability_scanner(
            target, root_mode=bool(args.root), scope_domains=scanner_scope,
            scope_excludes=set(args.exclude or []),
        )
        return True
    if command in {"crawler", "crawl"}:
        if not args.url: raise SystemExit("crawler: URL obrigatória")
        if args.engine == "async":
            _run_async_crawler(args)
            return True
        if args.headless:
            raise SystemExit("crawler --headless exige --engine async")
        if args.proxy: state.config["proxy"] = args.proxy
        if args.threads: state.config["max_workers"] = max(1, min(20, args.threads))
        opts={"google":True,"wayback":False,"payload":False,"nmap":args.nmap,"shodan":args.shodan}
        cli_scope = sorted(set(_load_scope()) | set(args.scope or []))
        _run_crawler(
            opts, args.url, args.pages or state.config["max_pages"],
            args.depth or state.config["max_depth"], base_prefix=args.output or "RavenEye_crawler",
            scope_domains_override=cli_scope, scope_excludes=set(args.exclude or []),
        )
        return True
    if command in {"full", "full-scan"}:
        if not args.url: raise SystemExit("full: URL obrigatória")
        from raveneye.core.orchestrator import RavenOrchestrator
        from raveneye.crawler.filters import Scope
        import asyncio
        cfg = load_config(); cfg.max_pages=args.pages
        target = normalize_target(args.url)
        if not target:
            raise SystemExit("full: alvo inválido; informe um domínio ou URL HTTP(S).")
        if not _confirm_aggressive(target) or not _confirm_vulnerability_scanner(target):
            raise SystemExit("Full scan cancelado: autorização não confirmada.")
        scope=Scope(domains=set(args.scope) if args.scope else None, excludes=set(args.exclude))
        out=args.output or "reports/full-scan"
        run=asyncio.run(RavenOrchestrator(cfg).full_passive(target,output_dir=out,scope=scope))
        print(f"Full scan concluído: {len(run.urls)} URLs, {len(run.findings)} findings, scan_id={run.scan_id}")
        return True
    if command in {"nuke", "offensive", "bruteforce"}:
        # O modo interativo existente continua sendo a autoridade para as operações governadas.
        # A CLI explícita evita executar um fluxo privilegiado sem a confirmação já existente.
        print("Este comando usa o fluxo interativo governado do RavenEye. Execute sem subcomando para abrir o menu principal.")
        menu_principal()
        return True
    if command == "database":
        print("integrity=OK" if database_integrity_check() else "integrity=FAILED")
        return True
    if command == "doctor":
        from raveneye_pkg.doctor import run_doctor, render_doctor
        result = run_doctor(state.config)
        if args.json:
            import json
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(render_doctor(result))
        return True
    if command == "report":
        formats = "TXT, JSON, HTML, CSV, Markdown, PDF"
        if args.version:
            print(f"Formatos disponíveis: {formats}")
            return True
        # The report command is intentionally explicit: generation consumes an
        # existing JSON report payload, avoiding a hidden network scan.
        print(f"Formatos disponíveis: {formats}")
        print(f"Formato selecionado: {args.format.upper()}")
        print("Use o menu de relatórios ou passe um relatório JSON existente para geração.")
        return True
    if command == "logs":
        from raveneye.cli.log_viewer import watch as watch_log, safe_delete, export_category
        import asyncio
        if args.watch: asyncio.run(watch_log(args.watch)); return True
        if args.delete:
            try:
                dest = safe_delete(args.delete, confirmation=input("Digite SIM para mover o arquivo para a lixeira: "))
            except (OSError, ValueError) as exc:
                raise SystemExit(f"logs --delete: não foi possível mover o arquivo: {exc}") from None
            print(f"Arquivo movido para a lixeira RavenEye: {dest}")
            return True
        if args.export:
            if not args.category or not args.output: raise SystemExit("logs --export exige --category e --output")
            export_category(args.export,args.category,args.output); return True
        raise SystemExit("logs exige --watch, --delete ou --export")
    return False


def _run_async_crawler(args) -> None:
    """Run the additive async crawler for basic, scoped HTTP discovery."""
    if args.nmap or args.shodan or args.proxy or state.config.get("proxy"):
        raise SystemExit(
            "crawler --engine async não oferece Nmap, Shodan ou proxy; use --engine legacy para preservar esses recursos."
        )
    import asyncio
    import datetime
    import re
    from urllib.parse import urlsplit
    from raveneye.core.config import load_config as load_async_config
    from raveneye.core.targets import normalize_target
    from raveneye.crawler.engine import Crawler
    from raveneye.crawler.filters import Scope

    target = normalize_target(args.url)
    if not target:
        raise SystemExit("crawler: URL HTTP(S) inválida")
    config = load_async_config()
    config.headless_rendering = bool(
        args.headless or state.config.get("headless_rendering", False)
        or config.headless_rendering
    )
    config.max_pages = max(1, int(args.pages or state.config.get("max_pages", config.max_pages)))
    config.crawl_max_depth = max(0, int(args.depth if args.depth is not None else state.config.get("max_depth", config.crawl_max_depth)))
    if args.threads:
        workers = max(1, min(1000, int(args.threads)))
        config.concurrency = workers
        config.worker_count = workers
        config.connection_limit = max(config.connection_limit, workers)

    scope_domains = set(config.scope.include_domains) | set(args.scope or [])
    if not scope_domains:
        scope_domains = None
    excludes = set(config.scope.exclude) | set(args.exclude or [])
    scope = Scope(
        domains=scope_domains,
        excludes=excludes,
        regex=list(config.scope.include_regex),
        paths=list(config.scope.include_paths),
    )
    if args.output:
        output = Path(args.output).expanduser()
        if output.exists() and output.is_dir():
            output = output / "crawl.jsonl"
        elif output.suffix.lower() != ".jsonl":
            output = output.with_suffix(output.suffix + ".jsonl" if output.suffix else ".jsonl")
    else:
        host = re.sub(r"[^a-zA-Z0-9_.-]", "_", urlsplit(target).hostname or "target")
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output = Path("reports") / f"async-crawl_{host}_{stamp}.jsonl"
    output.parent.mkdir(parents=True, exist_ok=True)
    crawler = Crawler(config, scope=scope)
    asyncio.run(crawler.crawl([target], str(output), retain_results=False, retain_forms=False))
    count = crawler.telemetry.snapshot().get("urls_crawled", 0)
    print(f"Crawler async concluído: {count} respostas registradas em {output.resolve()}")
    print(f"JSONL versionado: {output.with_name(output.stem + '_forms.jsonl').resolve()} (formulários)")


def _run_noninteractive(args: argparse.Namespace) -> None:
    """Executa a CLI legada, preservada para backward compatibility."""
    if args.legacy_proxy: state.config["proxy"] = args.legacy_proxy
    if args.legacy_threads: state.config["max_workers"] = max(1, min(20, args.legacy_threads))
    if args.legacy_verbose:
        state.VERBOSE_LEVEL = args.legacy_verbose; set_verbose(args.legacy_verbose)
    if args.legacy_scope: state.config["scope_file"] = args.legacy_scope
    target = args.legacy_url
    if not target.startswith(("http://", "https://")): target = "https://" + target
    mp=args.legacy_pages or state.config["max_pages"]; md=args.legacy_depth or state.config["max_depth"]
    mode=args.mode or "crawler"
    if mode == "scanner":
        target = normalize_target(target)
        if not target:
            raise SystemExit("scanner: alvo inválido; informe um domínio ou URL HTTP(S).")
        try:
            scanner_scope = _load_scanner_scope()
        except ValueError as exc:
            raise SystemExit(f"scanner bloqueado: {exc}") from None
        if not _confirm_vulnerability_scanner(target):
            raise SystemExit("Scanner cancelado: autorização não confirmada.")
        _run_vulnerability_scanner(
            target, root_mode=bool(args.legacy_scanner_root),
            scope_domains=scanner_scope,
        )
        return
    opts={"google":True,"wayback":mode in {"offensive","nuke","full"},"payload":mode in {"offensive","nuke","full"},"shodan":args.legacy_shodan or mode in {"offensive","nuke","full"},"exploitdb":mode in {"offensive","nuke","full"},"nmap":args.legacy_nmap or mode in {"offensive","nuke","full"}}
    _run_crawler(opts,target,mp,md,root_mode=bool(args.legacy_scanner_root),base_prefix=args.legacy_output or f"RavenEye_{mode}",include_vuln_scanner=False)


# ==================================================================
# MAIN
# ==================================================================
def main() -> None:
    """Ponto de entrada principal."""

    # Checagem de integridade dos créditos ANTES de qualquer outra coisa.
    # Também é checada a cada iteração do menu principal (raveneye_pkg/menus.py),
    # então remover esta chamada isoladamente não desativa a proteção.
    verify_integrity()

    # Parse informational commands before loading configuration or initializing
    # the database. In particular, `raven -h` and `raven report --version` must
    # remain read-only and usable while an installation is being diagnosed.
    parser = _build_argparser()
    args = parser.parse_args()

    if args.command == "report" and args.version:
        print("Formatos disponíveis: TXT, JSON, HTML, CSV, Markdown, PDF")
        return

    state.config = load_config()
    try:
        db_path = initialize_database(state.config)
        if database_integrity_check():
            state.logger.info(f"Banco local inicializado: {db_path}")
    except Exception as exc:
        state.logger.warning(f"Banco local indisponível: {exc}")
    state.SHODAN_API_KEY = get_api_key("shodan")
    state.VIRUSTOTAL_API_KEY = get_api_key("virustotal")
    state.GOOGLE_CSE_API_KEY = get_api_key("google_cse")
    state.CENSYS_API_KEY = get_api_key("censys")
    state.NETLAS_API_KEY = get_api_key("netlas")
    state.LEAKIX_API_KEY = get_api_key("leakix")
    state.VERBOSE_LEVEL = state.config.get("verbose", 0)
    set_verbose(state.VERBOSE_LEVEL)

    log_file = getattr(args, "legacy_log_file", None) or state.config.get("log_file", "raveneye.log")
    _setup_logger(log_file, state.config.get("log_level", "WARNING"))
    state.logger.info(f"RavenEye v{TOOL_VERSION} iniciado (pid={os.getpid()})")

    if getattr(args, "legacy_quiet", False):
        state.QUIET_MODE = True

    check_dependencies()
    if _run_command(args):
        return
    if args.legacy_url:
        _run_noninteractive(args)
        return
    menu_principal()

if __name__ == "__main__":
    main()
