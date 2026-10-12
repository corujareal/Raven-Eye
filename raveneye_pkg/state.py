from __future__ import annotations

"""Estado global compartilhado: config, chaves de API, sessao HTTP,
logger e disponibilidade do runtime completo.

Outros modulos importam este modulo INTEIRO (``from raveneye_pkg import
state``) e acessam tudo via atributo (``state.config``,
``state.SHODAN_API_KEY`` etc.) — nunca ``from raveneye_pkg.state import
config``, que congelaria uma referencia obsoleta assim que main()
reatribui ``state.config = load_config()``.
"""


import logging
from logging.handlers import RotatingFileHandler
import os
import signal
import sys
import time
import requests
from raveneye.core.logger import RedactionFilter, redact


from raveneye_pkg.terminal import init, Fore, Style
init(autoreset=True)

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    import dns.zone
    import dns.query
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    import jwt as _pyjwt
    PYJWT_AVAILABLE = True
except ImportError:
    PYJWT_AVAILABLE = False

try:
    import jsbeautifier
    JSBEAUTIFIER_AVAILABLE = True
except ImportError:
    JSBEAUTIFIER_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

    def tqdm(iterable, *args, **kwargs):  # fallback no-op
        return iterable


# ==================================================================
# VARIÁVEIS GLOBAIS
# ==================================================================
SHODAN_API_KEY: str = os.environ.get("SHODAN_API_KEY", "")


VIRUSTOTAL_API_KEY: str = os.environ.get("VIRUSTOTAL_API_KEY", "")


GOOGLE_CSE_API_KEY: str = os.environ.get("GOOGLE_CSE_API_KEY", "")

CENSYS_API_KEY: str = os.environ.get("CENSYS_API_KEY", "")
NETLAS_API_KEY: str = os.environ.get("NETLAS_API_KEY", "")
LEAKIX_API_KEY: str = os.environ.get("LEAKIX_API_KEY", "")


VERBOSE_LEVEL: int = 0


QUIET_MODE: bool = False


config: dict = {}


# ==================================================================
# SESSION GLOBAL com connection pooling
# ==================================================================
_SESSION = requests.Session()


# ==================================================================
# LOGGER — estruturado, configuravel (arquivo rotativo)
# ==================================================================
logger = logging.getLogger("RavenEye")


def _setup_logger(log_file: str, level_name: str = "WARNING") -> None:
    """Configura o logger para escrever em arquivo rotativo (5MB x 3 backups).

    Mantido separado dos prints coloridos do terminal (que continuam existindo
    para o operador interativo) — o logger existe para permitir integracao
    com outras ferramentas via arquivo/pipe sem depender de parsear a saida
    colorida do terminal.
    """
    logger.handlers.clear()
    if not log_file:
        return
    try:
        handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        ))
        handler.addFilter(RedactionFilter())
        level = getattr(logging, level_name.upper(), logging.WARNING)
        handler.setLevel(level)
        logger.addHandler(handler)
    except (OSError, PermissionError) as e:
        print(f"[WARN] Nao foi possivel abrir log '{log_file}': {e}", file=sys.stderr)


# ==================================================================
# FUNÇÕES — verbose e sleep
# ==================================================================
def vprint(level: int, *args, **kwargs) -> None:
    """Imprime no console somente se VERBOSE_LEVEL >= level, e sempre registra
    no logger estruturado (arquivo), independente do verbose do terminal."""
    msg = " ".join(str(a) for a in args)
    if msg:
        log_level = logging.DEBUG if level >= 3 else logging.INFO if level >= 1 else logging.WARNING
        # Mensagens marcadas com [WARN]/[ERRO] no texto sobem de nivel no log,
        # mesmo que vprint tenha sido chamado com level baixo
        if "[WARN]" in msg:
            log_level = logging.WARNING
        elif "[ERRO]" in msg or "[ERROR]" in msg:
            log_level = logging.ERROR
        logger.log(log_level, redact(msg))
    if VERBOSE_LEVEL >= level:
        print(*args, **kwargs, flush=True)


def set_verbose(level: int) -> None:
    """Define o nível global de verbose."""
    global VERBOSE_LEVEL
    VERBOSE_LEVEL = level


def _sleep(seconds: float) -> None:
    """Wrapper de time.sleep respeitando SIGINT."""
    try:
        time.sleep(seconds)
    except Exception as e:
        vprint(2, f"[WARN] _sleep: {e}")


# ==================================================================
# FUNÇÕES — tratamento de interrupção
# ==================================================================
def signal_handler(sig, frame) -> None:
    """Handler de SIGINT: salva config e encerra."""
    print("\n\n" + Fore.RED + "[!] Operacao interrompida pelo usuario." + Style.RESET_ALL)
    try:
        from raveneye_pkg.config_io import save_config
        save_config(config)
    except Exception as exc:
        logger.warning("Falha ao salvar config durante SIGINT: %s", exc)
    sys.exit(0)


# ==================================================================
# FUNÇÕES — dependências
# ==================================================================
def check_dependencies() -> None:
    """Reject missing Python runtime packages; browser engines stay optional.

    Browser availability is reported by ``raven doctor`` and checked when a
    headless crawl is requested. It must not block the CLI, scanner, or the
    static crawler merely because Firefox or WebKit is not installed.
    """
    from raveneye_pkg.doctor import REQUIRED_DEPENDENCIES, _available

    modules = list(REQUIRED_DEPENDENCIES)
    if sys.platform == "linux":
        modules.append("uvloop")
    missing = [name for name in modules if not _available(name)]
    if missing:
        print(Fore.RED + "[ERRO] Runtime incompleto (pacotes: " + ", ".join(missing) + ")." + Style.RESET_ALL)
        print(Fore.YELLOW + "Execute novamente installer/install.sh com acesso à rede e, no Linux, sudo." + Style.RESET_ALL)
        raise SystemExit(1)



signal.signal(signal.SIGINT, signal_handler)
