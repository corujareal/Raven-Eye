from __future__ import annotations

"""HTTP(S) credential audit, classified wordlists, and safe enumeration.

Subdomain candidate resolution in scanners.py is DNS enumeration, not login
authentication. Other credential protocol adapters are explicitly unavailable.
"""


import hashlib
import itertools
import json
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from bs4 import BeautifulSoup
from raveneye_pkg.terminal import Fore, Style
from raveneye_pkg import state
from raveneye_pkg.state import vprint, _sleep
from raveneye_pkg.network import request_url, normalize_url, is_safe_url
from raveneye_pkg.constants import EXTRA_PASSWORDS, SUBDOMAIN_WORDLIST
from raveneye.wordlists import WordlistManager
from raveneye.network.domains import host_matches_rule
from raveneye.bruteforce.http_client import ProtectedLoginClient, ProtectedRequestError
from raveneye.bruteforce.checkpoint import CheckpointStore
from raveneye.scanner.evidence import sanitize_url


# ==================================================================
# FUNÇÕES — Wordlists classificadas
# ==================================================================
_PASSWORD_FALLBACK = tuple(dict.fromkeys(EXTRA_PASSWORDS + [
    "123456", "password", "admin", "12345", "12345678", "root", "toor",
    "admin123", "qwerty", "abc123", "senha", "1234", "123456789",
    "letmein", "welcome", "monkey", "dragon", "master", "login", "pass",
]))


def get_wordlist_manager(root: str | Path | None = None) -> WordlistManager:
    """Create the classified wordlist catalog with RavenEye's bundled lists."""
    return WordlistManager(
        root,
        builtins={
            "builtin_subdomains": (
                "subdomains",
                "RavenEye common subdomains",
                SUBDOMAIN_WORDLIST,
            ),
            "builtin_passwords": (
                "passwords",
                "RavenEye common passwords",
                _PASSWORD_FALLBACK,
            )
        },
    )


def get_wordlist(large: bool = False) -> str:
    """Return a private local password list for the legacy path-based API.

    Arjun's remote dictionaries contain parameter names, so they must not be
    treated as passwords. ``large`` stays accepted for API compatibility.
    """
    del large
    return str(get_wordlist_manager().path_for("builtin_passwords"))


# ==================================================================
# FUNÇÕES — Bruteforce
# ==================================================================
class CredentialAuditError(RuntimeError):
    """A credential audit did not pass local safety or input checks."""


_CSRF_NAME_PATTERNS = (
    r"csrf", r"token", r"_token", r"authenticity_token",
    r"csrfmiddlewaretoken", r"__RequestVerificationToken",
)
_LOCKOUT_TERMS = (
    "account locked", "account is locked", "temporarily locked",
    "too many attempts", "try again later", "rate limit", "account blocked",
)


def _extract_csrf(html: str, *, form=None) -> dict[str, str]:
    extra: dict[str, str] = {}
    soup = BeautifulSoup(html, "html.parser")
    container = form if form is not None else soup
    for inp in container.find_all("input", {"type": ["hidden", "text"]}):
        name = str(inp.get("name", ""))
        value = str(inp.get("value", ""))
        if name and value and any(re.search(pattern, name, re.I) for pattern in _CSRF_NAME_PATTERNS):
            extra[name] = value
    meta = soup.find("meta", {"name": "csrf-token"})
    if meta and meta.get("content"):
        extra["csrf-token"] = str(meta["content"])
    return extra


def _login_form_details(
    html: str,
    base_url: str,
    username_field: str,
    password_field: str,
    client: ProtectedLoginClient,
) -> tuple[str, dict[str, str]]:
    """Resolve the matching same-origin POST form and its own anti-CSRF fields.

    Pages commonly contain several forms. Taking a token from an unrelated
    search/logout form can make every credential attempt look invalid, so a
    form is selected only when it contains both configured credential fields.
    If the page has no recognizable form, preserve the explicitly supplied URL
    behavior for API/JavaScript login endpoints.
    """
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        names = {
            str(control.get("name", ""))
            for control in form.find_all(["input", "select", "textarea"])
            if control.get("name")
        }
        if username_field not in names or password_field not in names:
            continue
        method = str(form.get("method", "get")).strip().casefold()
        if method != "post":
            raise CredentialAuditError(
                "O formulario de login identificado nao usa POST; auditoria interrompida sem enviar credenciais."
            )
        action = urljoin(base_url, str(form.get("action", "")).strip() or base_url)
        try:
            client.validate_origin(action)
        except ProtectedRequestError:
            raise CredentialAuditError(
                "A acao do formulario sai da origem confirmada; auditoria interrompida sem enviar credenciais."
            ) from None
        return action, _extract_csrf(html, form=form)
    return base_url, _extract_csrf(html)


def _check_auth_scope(login_url: str) -> None:
    scope_file = str(state.config.get("scope_file", "") or "").strip()
    if not scope_file:
        return
    try:
        patterns = [
            line.strip()
            for line in Path(scope_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except (OSError, UnicodeError):
        raise CredentialAuditError("Arquivo de scope configurado, mas indisponivel; operacao bloqueada.") from None
    host = urlsplit(login_url).hostname or ""
    if not patterns or not any(host_matches_rule(host, pattern) for pattern in patterns):
        raise CredentialAuditError("Host fora do scope configurado; operacao bloqueada.")


def _checkpoint_fingerprint(
    users: list[str], wordlist_hashes: list[str], mode: str, policy: dict | None = None,
) -> str:
    material = json.dumps(
        {"mode": mode, "users": users, "lists": wordlist_hashes, "policy": policy or {}},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _policy_fingerprint(policy: dict) -> str:
    material = json.dumps(policy, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _auth_checkpoint_root(manager: WordlistManager) -> Path:
    return manager.root.parent / "checkpoints"


def _checkpoint_target(login_url: str) -> str:
    """Return a private identity input bound to the exact HTTP form endpoint.

    CheckpointStore HMACs this value locally; it is never written to the
    checkpoint. Fragments are omitted because HTTP does not send them.
    """
    try:
        parts = urlsplit(login_url)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").rstrip(".").lower()
        if (
            scheme not in {"http", "https"}
            or not host
            or parts.username is not None
            or parts.password is not None
        ):
            raise ValueError
        port = parts.port or (443 if scheme == "https" else 80)
        netloc = f"[{host}]" if ":" in host else host
        path = parts.path or "/"
        return f"{scheme}://{netloc}:{port}{path}" + (f"?{parts.query}" if parts.query else "")
    except (ValueError, UnicodeError):
        raise CredentialAuditError("URL de login invalida; credenciais embutidas nao sao aceitas.") from None


def _is_explicit_success(response_url: str, login_url: str, text: str, marker: str) -> tuple[bool, str]:
    if marker:
        # A caller-provided exclusive marker is the selected success signal.
        # Falling through to a redirect heuristic when it is absent turns
        # MFA, onboarding, or generic dashboard redirects into false matches.
        return (True, "marker") if marker.casefold() in text.casefold() else (False, "none")
    # A same-origin post-login path change is useful but not conclusive.
    result = urlsplit(response_url)
    original = urlsplit(login_url)
    if result.path.rstrip("/") != original.path.rstrip("/") and not any(
        token in result.path.casefold() for token in ("login", "signin", "auth", "error")
    ):
        return True, "redirect_heuristic"
    return False, "none"


def bruteforce_login(
    login_url: str, username: str,
    username_field: str = "username", password_field: str = "password",
    wordlist_path: str | None = None, root_mode: bool = False,
    use_extra_passwords: bool = True,
    *, userlist_path: str | None = None, combo_mode: bool = False,
    delay: float | None = None, timeout: float = 8.0,
    stop_on_success: bool = True, resumable: bool = False, resume: bool = False,
    threads: int = 1, max_attempts: int | None = None,
    per_user_limit: int | None = None, success_marker: str = "",
    preflight_confirmed: bool = False, _wordlist_manager: WordlistManager | None = None,
    _cancel_event: threading.Event | None = None,
) -> tuple[str | None, int]:
    """Run a single-threaded, explicitly confirmed HTTP credential audit.

    The legacy return shape is preserved for callers, but the secret is never
    printed or logged. A confirmed marker is preferred; redirect-only matches
    are heuristic and must be described as possible by the caller.
    """
    if not preflight_confirmed:
        raise CredentialAuditError("Confirme o alvo no preflight antes de executar autenticacao.")
    if not stop_on_success:
        raise CredentialAuditError("O fluxo seguro exige stop-on-success.")
    if int(threads) != 1:
        raise CredentialAuditError("HTTP login suporta somente uma thread por conta.")
    try:
        parts = urlsplit(login_url)
    except ValueError:
        raise CredentialAuditError("URL de login invalida.") from None
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
    ):
        raise CredentialAuditError("URL de login precisa ser HTTP(S) com host valido.")
    _check_auth_scope(login_url)

    manager = _wordlist_manager or get_wordlist_manager()
    wordlist_hashes: list[str] = []
    users: list[str]
    if userlist_path:
        user_info = manager.add(userlist_path, "users")
        users = manager.read(user_info.id)
        wordlist_hashes.append(user_info.sha256)
    elif combo_mode:
        users = []
        wordlist_hashes.append(hashlib.sha256(b"combo-users").hexdigest())
    else:
        users = [str(username)] if str(username) else []
        wordlist_hashes.append(hashlib.sha256(str(username).encode("utf-8")).hexdigest())
    if not users and not combo_mode:
        raise CredentialAuditError("Nenhum usuario foi selecionado.")

    if combo_mode:
        if not wordlist_path:
            raise CredentialAuditError("Modo combo requer uma wordlist classificada como combos.")
        combo_info = manager.add(wordlist_path, "combos")
        raw_combos = manager.read(combo_info.id)
        pairs: list[tuple[str, str]] = []
        seen_pairs: set[tuple[str, str]] = set()
        for line in raw_combos:
            candidate_user, separator, candidate_password = line.partition(":")
            if separator and candidate_user and candidate_password:
                pair = (candidate_user, candidate_password)
                if pair not in seen_pairs:
                    pairs.append(pair)
                    seen_pairs.add(pair)
        if not pairs:
            raise CredentialAuditError("A lista combo nao possui entradas user:password validas.")
        wordlist_hashes.append(combo_info.sha256)
        planned = pairs
        mode = "combos"
    else:
        if wordlist_path:
            password_info = manager.add(wordlist_path, "passwords")
            passwords = manager.read(password_info.id)
            wordlist_hashes.append(password_info.sha256)
        else:
            password_info = next(info for info in manager.list("passwords") if info.id == "builtin_passwords")
            passwords = manager.read(password_info.id)
            wordlist_hashes.append(password_info.sha256)
        if use_extra_passwords:
            # Keep an explicitly selected list first so the default per-account
            # cap does not silently hide every user-supplied candidate.
            passwords = list(dict.fromkeys(passwords + list(_PASSWORD_FALLBACK)))
        planned = itertools.product(users, passwords)
        mode = "separate"

    configured_cap = int(state.config.get("bf_attempts", 500) or 500)
    requested_cap = int(max_attempts) if max_attempts is not None else configured_cap
    total_cap = min(100, max(1, configured_cap), max(1, requested_cap))
    per_account_cap = int(per_user_limit if per_user_limit is not None else state.config.get("bf_attempts_per_user", 5))
    per_account_cap = min(100, max(1, per_account_cap))
    counts: dict[str, int] = {}
    bounded: list[tuple[str, str]] = []
    for pair in planned:
        if counts.get(pair[0], 0) >= per_account_cap:
            continue
        bounded.append(pair)
        counts[pair[0]] = counts.get(pair[0], 0) + 1
        if len(bounded) >= total_cap:
            break
    if not bounded:
        raise CredentialAuditError("Nenhuma tentativa dentro dos limites configurados.")

    delay_value = state.config.get("bf_delay", 1.0) if delay is None else delay
    try:
        pause = min(60.0, max(1.0, float(delay_value)))
    except (TypeError, ValueError):
        pause = 1.0
    try:
        timeout_value = min(30.0, max(1.0, float(timeout)))
    except (TypeError, ValueError):
        timeout_value = 8.0
    if resume:
        resumable = True

    source_fingerprint = _checkpoint_fingerprint(users, wordlist_hashes, mode)
    policy = {
        "global_cap": total_cap,
        "per_account_cap": per_account_cap,
        "delay": pause,
        "timeout": timeout_value,
        "username_field": str(username_field),
        "password_field": str(password_field),
        "success_marker": hashlib.sha256(str(success_marker).encode("utf-8")).hexdigest(),
    }
    policy_fingerprint = _policy_fingerprint(policy)
    checkpoint_store = CheckpointStore(_auth_checkpoint_root(manager))
    origin = f"{parts.scheme.lower()}://{parts.hostname.lower()}:{parts.port or (443 if parts.scheme.lower() == 'https' else 80)}"
    checkpoint_target = _checkpoint_target(login_url)
    checkpoint_identity = checkpoint_store.identity(checkpoint_target, "raveneye-http-audit") if resumable else ""
    legacy_checkpoint_identity = checkpoint_store.identity(origin, "raveneye-http-audit") if resumable else ""
    source_id = checkpoint_store.identity("", source_fingerprint) if resumable else ""
    policy_id = checkpoint_store.identity("", policy_fingerprint) if resumable else ""
    checkpoint: dict = {
        "state": "running",
        "next_index": 0,
        "attempted": 0,
        "total": len(bounded),
        "mode": mode,
        "source_id": source_id,
        "policy_id": policy_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "blocked_reason": "",
    }
    if resumable:
        existing = checkpoint_store.load(checkpoint_identity)
        if resume and existing is None and legacy_checkpoint_identity != checkpoint_identity:
            legacy = checkpoint_store.load(legacy_checkpoint_identity)
            if legacy is not None:
                raise CredentialAuditError(
                    "Checkpoint antigo nao identifica o formulario; retomada bloqueada por seguranca."
                )
            raise CredentialAuditError(
                "Checkpoint compativel nao encontrado para este formulario; nenhuma tentativa foi executada."
            )
        if existing:
            if existing.get("state") == "blocked":
                raise CredentialAuditError("Checkpoint bloqueado por sinal do servidor; remova-o apenas apos revisar o alvo e o bloqueio.")
            if existing.get("source_id") != source_id or existing.get("policy_id") != policy_id:
                if resume or existing.get("state") in {"running", "interrupted", "paused", "inflight"}:
                    raise CredentialAuditError("Dados da retomada mudaram; checkpoint preservado e execucao bloqueada.")
            if existing.get("state") in {"blocked", "completed"}:
                if resume:
                    raise CredentialAuditError("Este checkpoint esta bloqueado ou concluido e nao pode ser retomado.")
                checkpoint_store.save(checkpoint_identity, checkpoint)
            elif resume:
                checkpoint = existing
                if not (0 <= int(checkpoint.get("next_index", -1)) <= len(bounded)):
                    raise CredentialAuditError("Indice do checkpoint invalido; retomada bloqueada.")
                if checkpoint.get("state") == "inflight":
                    # The process may have died after sending a POST but before
                    # recording its result. Count and skip one uncertain item
                    # rather than risking a duplicate authentication attempt.
                    uncertain_index = int(checkpoint.get("inflight_index", checkpoint["next_index"]))
                    checkpoint.update({
                        "state": "running",
                        "next_index": min(len(bounded), uncertain_index + 1),
                        "attempted": int(checkpoint.get("attempted", 0)) + 1,
                        "blocked_reason": "uncertain_inflight_item_skipped",
                    })
                    checkpoint_store.save(checkpoint_identity, checkpoint)
            elif existing.get("state") in {"running", "interrupted", "paused", "inflight"}:
                raise CredentialAuditError("Checkpoint existente; confirme a retomada para evitar repetir tentativas.")
        elif resumable:
            checkpoint_store.save(checkpoint_identity, checkpoint)

    display_target = f"{parts.scheme.lower()}://{parts.hostname.lower()}:{parts.port or (443 if parts.scheme.lower() == 'https' else 80)}"
    print(Fore.CYAN + f"[*] Auditoria HTTP confirmada para {display_target}; taxa serial, limite {len(bounded)} tentativa(s)." + Style.RESET_ALL)
    if resume and int(checkpoint.get("next_index", 0)):
        print(Fore.CYAN + f"[*] Retomando do item {int(checkpoint['next_index']) + 1}." + Style.RESET_ALL)

    try:
        client = ProtectedLoginClient(login_url, timeout=timeout_value)
    except ProtectedRequestError as exc:
        raise CredentialAuditError(str(exc)) from None
    started = time.monotonic()
    attempts = int(checkpoint.get("attempted", 0))
    next_index = int(checkpoint.get("next_index", 0))
    inflight_index: int | None = None
    success_marker_active = bool(success_marker)
    refreshed_csrf: dict[str, str] = {}
    refreshed_post_url = ""
    post_url = login_url
    try:
        for index in range(next_index, len(bounded)):
            next_index = index
            if _cancel_event is not None and _cancel_event.is_set():
                checkpoint.update({
                    "state": "interrupted",
                    "blocked_reason": "cancelled_before_attempt",
                    "next_index": index,
                    "attempted": attempts,
                })
                if resumable:
                    checkpoint_store.save(checkpoint_identity, checkpoint)
                break
            candidate_user, candidate_password = bounded[index]
            try:
                if refreshed_csrf:
                    csrf = refreshed_csrf
                    refreshed_csrf = {}
                    if refreshed_post_url:
                        post_url = refreshed_post_url
                        refreshed_post_url = ""
                else:
                    form = client.request("GET", login_url)
                    if form.status_code in {401, 403, 423, 429, 503}:
                        checkpoint.update({
                            "state": "blocked",
                            "blocked_reason": f"http_{form.status_code}",
                            "next_index": index,
                            "attempted": attempts,
                        })
                        if resumable:
                            checkpoint_store.save(checkpoint_identity, checkpoint)
                        break
                    if success_marker_active and success_marker.casefold() in form.text.casefold():
                        success_marker_active = False
                        print(Fore.YELLOW + "[!] Marcador de sucesso ja aparece antes da autenticacao; usando somente o sinal heuristico POSSIBLE." + Style.RESET_ALL)
                    post_url, csrf = _login_form_details(
                        form.text, form.url, str(username_field), str(password_field), client,
                    )
                post_data: dict[str, str] = {
                    str(username_field): candidate_user,
                    str(password_field): candidate_password,
                }
                post_data.update(csrf)
            except ProtectedRequestError:
                checkpoint.update({"state": "interrupted", "blocked_reason": "protected_get_error", "next_index": index, "attempted": attempts})
                if resumable:
                    checkpoint_store.save(checkpoint_identity, checkpoint)
                vprint(2, "[WARN] credential audit stopped before posting credentials")
                break

            # Async callers can cancel while the preflight GET is in flight.
            # Do not send the next credential after cancellation is observed.
            if _cancel_event is not None and _cancel_event.is_set():
                checkpoint.update({
                    "state": "interrupted",
                    "blocked_reason": "cancelled_before_post",
                    "next_index": index,
                    "attempted": attempts,
                })
                if resumable:
                    checkpoint_store.save(checkpoint_identity, checkpoint)
                break

            if resumable:
                checkpoint.update({
                    "state": "inflight",
                    "inflight_index": index,
                    "next_index": index,
                    "attempted": attempts,
                    "blocked_reason": "",
                })
                checkpoint_store.save(checkpoint_identity, checkpoint)
            inflight_index = index
            try:
                response = client.request("POST", post_url, data=post_data)
            except ProtectedRequestError:
                checkpoint.update({"state": "inflight", "blocked_reason": "protected_post_error"})
                if resumable:
                    checkpoint.update({"inflight_index": index, "next_index": index, "attempted": attempts})
                    checkpoint_store.save(checkpoint_identity, checkpoint)
                vprint(2, "[WARN] credential audit stopped after a protected POST error")
                break

            attempts += 1
            inflight_index = None
            body_lower = response.text.casefold()
            blocked = response.status_code in {403, 423, 429, 503} or any(
                term in body_lower for term in _LOCKOUT_TERMS
            )
            if blocked:
                checkpoint.update({
                    "state": "blocked",
                    "blocked_reason": "server_rate_or_lockout_signal",
                    "next_index": index + 1,
                    "attempted": attempts,
                })
                print(Fore.YELLOW + "\n[!] Sinal de limite/bloqueio do servidor; auditoria interrompida sem retry." + Style.RESET_ALL)
                if resumable:
                    checkpoint_store.save(checkpoint_identity, checkpoint)
                break

            active_marker = success_marker if success_marker_active else ""
            matched, match_kind = _is_explicit_success(response.url, login_url, response.text, active_marker)
            if not matched:
                # A fresh token in the post response can replace a separate
                # GET on the next attempt. If the application omits it, the
                # next iteration performs the original GET-before-POST flow.
                refreshed_post_url, refreshed_csrf = _login_form_details(
                    response.text, response.url, str(username_field), str(password_field), client,
                )
            checkpoint.update({
                "state": "completed" if matched else "running",
                "next_index": index + 1,
                "attempted": attempts,
                "blocked_reason": "",
            })
            next_index = index + 1
            if resumable:
                checkpoint_store.save(checkpoint_identity, checkpoint)
            print(f"\r[{index + 1}/{len(bounded)}] tentativa(s) concluída(s)", end="", flush=True)
            if matched:
                label = "marcador configurado" if match_kind == "marker" else "redirecionamento heuristico (POSSIBLE)"
                print(Fore.GREEN + f"\n[+] Possivel credencial valida observada ({label}); segredo redigido." + Style.RESET_ALL)
                return candidate_password, attempts
            if index + 1 < len(bounded):
                if _cancel_event is None:
                    _sleep(pause)
                else:
                    _cancel_event.wait(pause)
        if checkpoint.get("state") == "running":
            checkpoint.update({"state": "completed", "next_index": len(bounded), "attempted": attempts})
        if resumable:
            checkpoint_store.save(checkpoint_identity, checkpoint)
        if checkpoint.get("state") == "blocked":
            return None, attempts
        if checkpoint.get("state") in {"interrupted", "inflight"}:
            print(Fore.YELLOW + f"\nAuditoria interrompida; nenhum retry automatico ({attempts} tentativa(s))." + Style.RESET_ALL)
            return None, attempts
        print(Fore.RED + f"\nAuditoria concluida sem indicador de sucesso em {attempts} tentativa(s)." + Style.RESET_ALL)
        return None, attempts
    except KeyboardInterrupt:
        if inflight_index is not None:
            checkpoint.update({
                "state": "inflight",
                "inflight_index": inflight_index,
                "next_index": inflight_index,
                "attempted": attempts,
                "blocked_reason": "interrupt_during_post",
            })
        else:
            checkpoint.update({"state": "interrupted", "next_index": next_index, "attempted": attempts})
        if resumable:
            checkpoint_store.save(checkpoint_identity, checkpoint)
        message = "checkpoint redigido salvo" if resumable else "nenhum checkpoint configurado"
        print(Fore.YELLOW + f"\nAuditoria interrompida; {message}." + Style.RESET_ALL)
        return None, attempts
    finally:
        client.close()


# ==================================================================
# ENUMERAÇÃO SEGURA — modalidades adicionais do módulo Bruteforce
# ==================================================================
_DEFAULT_ENUM_WORDS = (
    "admin", "api", "api/v1", "api/v2", "login", "signin", "dashboard",
    "robots.txt", "sitemap.xml", "health", "status", "docs", "swagger",
    "openapi.json", "graphql", "assets", "static", "uploads", "backup",
    ".well-known", ".git/HEAD", "config", "debug", "test", "staging",
)


def _enumeration_request(
    url: str, timeout: int = 6, *, probe_value: str = "",
) -> dict | None:
    """GET de descoberta com escopo e limites; não autentica nem envia payload."""
    if not is_safe_url(url):
        return None
    body, err = request_url(url, timeout=timeout, max_retries=1, backoff_cap=4)
    safe_url = sanitize_url(url) or "[URL OMITTED]"

    def redact_probe(value: str) -> str:
        if probe_value:
            return re.sub(re.escape(probe_value), "[redacted]", value, flags=re.IGNORECASE)
        return value

    if body is None:
        return {"url": safe_url, "status": 0, "error": redact_probe(err or "request failed")}
    return {
        "url": safe_url,
        "status": 200,
        "length": len(body),
        "sample": redact_probe(body[:180]),
    }


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
        result = _enumeration_request(url, probe_value=marker)
        if result:
            result["kind"] = "parameter"
            result["parameter"] = name
            result["changed_from_baseline"] = abs(int(result.get("length", 0)) - base_len) > max(50, int(base_len * 0.15))
            results.append(result)
        _sleep(max(0.05, float(state.config.get("delay", 0.3)) / 2))
    return results
