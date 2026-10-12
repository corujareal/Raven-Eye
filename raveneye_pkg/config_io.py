from __future__ import annotations

"""Carregamento e persistencia da configuracao (raven_eye_config.json)."""


import base64
import json
import os
import re
import stat
import sys
from pathlib import Path
from raveneye_pkg.terminal import Fore, Style
from raveneye_pkg import state
from raveneye_pkg.constants import CONFIG_FILE, DEFAULT_CONFIG


_API_KEY_SPECS = {
    "shodan": ("shodan_api_key", "_shodan_decoded", "SHODAN_API_KEY"),
    "virustotal": ("virustotal_api_key", "_vt_decoded", "VIRUSTOTAL_API_KEY"),
    "google_cse": ("google_cse_api_key", "_google_cse_decoded", "GOOGLE_CSE_API_KEY"),
    "censys": ("censys_api_key", "_censys_decoded", "CENSYS_API_KEY"),
    "netlas": ("netlas_api_key", "_netlas_decoded", "NETLAS_API_KEY"),
    "leakix": ("leakix_api_key", "_leakix_decoded", "LEAKIX_API_KEY"),
}
_ENVIRONMENT_LOADED = False


def load_environment(*, force: bool = False) -> None:
    """Load the nearest project/user ``.env`` without replacing exported vars."""
    global _ENVIRONMENT_LOADED
    if _ENVIRONMENT_LOADED and not force:
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        # Doctor reports an incomplete full runtime; explicitly exported
        # environment variables remain usable while that is repaired.
        _ENVIRONMENT_LOADED = True
        return
    directory = Path.cwd()
    for parent in (directory, *directory.parents):
        candidate = parent / ".env"
        if candidate.is_file():
            load_dotenv(candidate, override=False)
            break
    _ENVIRONMENT_LOADED = True


def _decode_secret(raw: str) -> str:
    if not raw:
        return ""
    try:
        return base64.b64decode(raw, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        # Backward compatibility for configuration files that stored a key in
        # plain text before the current obfuscation format.
        return raw


def get_api_key(provider: str) -> str:
    """Return the active key, preferring an explicitly supplied environment value."""
    load_environment()
    try:
        _field, decoded_field, global_name = _API_KEY_SPECS[provider]
    except KeyError as exc:
        raise ValueError(f"Unknown API provider: {provider}") from exc
    env_key = os.environ.get(global_name, "").strip()
    if env_key:
        return env_key
    return str(state.config.get(decoded_field, "") or getattr(state, global_name, "") or "").strip()


def get_google_cse_id() -> str:
    """Return the Custom Search Engine ID with the same env-first policy."""
    load_environment()
    return os.environ.get("GOOGLE_CSE_ID", "").strip() or str(
        state.config.get("google_cse_id", "") or ""
    ).strip()


def set_api_key(provider: str, value: str) -> None:
    """Update the live and decoded config value used by API integrations."""
    try:
        _field, decoded_field, global_name = _API_KEY_SPECS[provider]
    except KeyError as exc:
        raise ValueError(f"Unknown API provider: {provider}") from exc
    key = str(value or "").strip()
    setattr(state, global_name, key)
    state.config[decoded_field] = key


def _safe_domain_filename(raw: str) -> str:
    """Sanitiza domínio/URL para uso seguro em nomes de arquivo.

    Aceita tanto 'exemplo.com' quanto 'https://exemplo.com/path'.
    Remove protocolo, path e caracteres inválidos.
    """
    # Remove protocolo
    s = re.sub(r"^https?://", "", raw.strip(), flags=re.IGNORECASE)
    # Pega só o host (antes de '/' ou '?')
    s = s.split("/")[0].split("?")[0].split("#")[0]
    # Remove porta (ex: :8080)
    s = s.split(":")[0]
    # Substitui qualquer char fora de [a-zA-Z0-9._-] por underscore
    s = re.sub(r"[^a-zA-Z0-9._\-]", "_", s)
    # Troca pontos por underscore para nome de arquivo limpo
    s = s.replace(".", "_")
    # Remove underscores consecutivos e trailing
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "alvo"


def _sanitize_domain_input(raw: str) -> str:
    """Normaliza input de domínio digitado pelo usuário.

    Aceita 'https://exemplo.com', 'exemplo.com', etc.
    Retorna apenas o hostname limpo (ex: 'exemplo.com').
    """
    s = re.sub(r"^https?://", "", raw.strip(), flags=re.IGNORECASE)
    s = s.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
    return s.strip().lower() or raw.strip()


# ==================================================================
# FUNÇÕES — configuração
# ==================================================================
def load_config() -> dict:
    """Carrega configuração do JSON com validação de schema e tipos."""
    base = DEFAULT_CONFIG.copy()
    config_path = Path(CONFIG_FILE)
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            for key, value in loaded.items():
                if key in DEFAULT_CONFIG and not isinstance(value, type(DEFAULT_CONFIG[key])):
                    # BUG FIX: config editada a mao com tipo errado (ex: max_pages="cem")
                    # nao deve quebrar o programa no meio de um scan — cai no default
                    print(Fore.YELLOW + f"[!] Config: '{key}' com tipo invalido, usando default." + Style.RESET_ALL)
                    continue
                base[key] = value
        except (json.JSONDecodeError, IOError) as e:
            print(f"[WARN] Config corrompida, usando defaults: {e}", file=sys.stderr)
    raw = base.get("shodan_api_key", "")
    # Authentication audit guardrails were added in v6.6.6. Clamp old config
    # files that may still contain the previous 50k attempt setting.
    try:
        base["bf_attempts"] = min(100, max(1, int(base.get("bf_attempts", 100))))
    except (TypeError, ValueError):
        base["bf_attempts"] = 100
    try:
        base["bf_attempts_per_user"] = min(100, max(1, int(base.get("bf_attempts_per_user", 5))))
    except (TypeError, ValueError):
        base["bf_attempts_per_user"] = 5
    try:
        base["bf_delay"] = min(60.0, max(1.0, float(base.get("bf_delay", 1.0))))
    except (TypeError, ValueError):
        base["bf_delay"] = 1.0
    try:
        base["_shodan_decoded"] = _decode_secret(raw)
    except Exception:
        base["_shodan_decoded"] = raw
    raw_vt = base.get("virustotal_api_key", "")
    try:
        base["_vt_decoded"] = _decode_secret(raw_vt)
    except Exception:
        base["_vt_decoded"] = raw_vt
    raw_cse = base.get("google_cse_api_key", "")
    try:
        base["_google_cse_decoded"] = _decode_secret(raw_cse)
    except Exception:
        base["_google_cse_decoded"] = raw_cse
    for provider in ("censys", "netlas", "leakix"):
        field, decoded_field, _global_name = _API_KEY_SPECS[provider]
        base[decoded_field] = _decode_secret(str(base.get(field, "") or ""))
    return base


def save_config(cfg: dict) -> None:
    """Salva configuração no JSON com API keys ofuscadas."""
    out = {k: v for k, v in cfg.items() if not k.startswith("_")}
    for provider, (field, decoded_field, global_name) in _API_KEY_SPECS.items():
        value = str(state.config.get(decoded_field, "") or getattr(state, global_name, "") or "")
        out[field] = base64.b64encode(value.encode()).decode() if value else ""
    out["verbose"] = state.VERBOSE_LEVEL
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        # As API keys ficam apenas ofuscadas em base64 (nao criptografadas de
        # verdade), entao restringimos o arquivo a leitura/escrita do dono
        # para reduzir exposicao a outros usuarios locais na mesma maquina.
        try:
            os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except OSError as e:
            print(f"[WARN] save_config: nao foi possivel restringir permissoes: {e}", file=sys.stderr)
    except (IOError, PermissionError) as e:
        print(f"[WARN] save_config: {e}", file=sys.stderr)
