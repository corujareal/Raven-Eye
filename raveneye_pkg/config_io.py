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
    try:
        base["_shodan_decoded"] = base64.b64decode(raw).decode() if raw else ""
    except Exception:
        base["_shodan_decoded"] = raw
    raw_vt = base.get("virustotal_api_key", "")
    try:
        base["_vt_decoded"] = base64.b64decode(raw_vt).decode() if raw_vt else ""
    except Exception:
        base["_vt_decoded"] = raw_vt
    raw_cse = base.get("google_cse_api_key", "")
    try:
        base["_google_cse_decoded"] = base64.b64decode(raw_cse).decode() if raw_cse else ""
    except Exception:
        base["_google_cse_decoded"] = raw_cse
    return base


def save_config(cfg: dict) -> None:
    """Salva configuração no JSON com API keys ofuscadas."""
    out = {k: v for k, v in cfg.items() if not k.startswith("_")}
    out["shodan_api_key"] = (
        base64.b64encode(state.SHODAN_API_KEY.encode()).decode() if state.SHODAN_API_KEY else ""
    )
    out["virustotal_api_key"] = (
        base64.b64encode(state.VIRUSTOTAL_API_KEY.encode()).decode() if state.VIRUSTOTAL_API_KEY else ""
    )
    out["google_cse_api_key"] = (
        base64.b64encode(state.GOOGLE_CSE_API_KEY.encode()).decode() if state.GOOGLE_CSE_API_KEY else ""
    )
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
