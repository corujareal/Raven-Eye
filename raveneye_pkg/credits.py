"""Créditos oficiais do RavenEye — TandaiSec.

Este módulo concentra a identidade/autoria da ferramenta (logo + créditos).
A integridade do texto de créditos é validada em múltiplos pontos de
execução (inicialização do programa e a cada iteração do menu principal).
Se o conteúdo de `_CREDITS_TEXT` for alterado sem que o hash de referência
`_EXPECTED_HASH` seja atualizado de forma correspondente, a ferramenta se
recusa a continuar executando. Isso torna a remoção/edição casual dos
créditos impraticável sem quebrar o programa.
"""
from __future__ import annotations

import hashlib
import sys

from raveneye_pkg.terminal import Fore, Style

# ==================================================================
# LOGO TANDAISEC
# ==================================================================
TANDAISEC_LOGO = r"""
                   .:                        .:
                   .-     .....    .....     :-
                   .=.                       +:
                    -+.     .        .      =*.
                     ==.   +@+      :@#.   =*.
                .    .-=:  =@@..... %@#..:+*:     .
               .       :-:.:@@= .. :@@-.:--.       .
              .         .:.:@@:    .@@-.:.         .
             .     :       +@= .:-. :@*       :     .
             .     :+.....:%@-  .:. :%#:...  =-
                    -- .=#*#%*  :-. =%#+*=. :=       .
                    .=.  -*%%#+.  .=*#%*-   -.
             .      :.:   .:=+#+  =#+=-.   .::.
             .      ...-:     ::  .:  .. .-.:.      .
                       -+=::.  .=-.. ..:==:.        .
              .        :: .. :=-+=-=- .. ..        .
               .         ..  ..:=+:..   :         .
                        -=              =-
                       .:  .. ... .   .  :.
                           ::..::.:  ..
                           .:
"""

_CREDITS_TEXT = "Propriedade de TandaiSec — Pedro — Thiago"
_EXPECTED_HASH = "1c3a53340bad531ab53dee6c3625c52f6b100e5b9e8433b74fd57ad93f91f81c"


def _current_hash() -> str:
    return hashlib.sha256(_CREDITS_TEXT.encode("utf-8")).hexdigest()


def verify_integrity() -> None:
    """Aborta a execução caso os créditos tenham sido adulterados.

    Chamada automaticamente na inicialização e a cada laço do menu
    principal, então remover a chamada em um único lugar não basta para
    burlar a checagem.
    """
    if _current_hash() != _EXPECTED_HASH:
        print(Fore.RED + "\n[ERRO] Integridade dos créditos do RavenEye foi violada." + Style.RESET_ALL)
        print(Fore.RED + "Este build foi modificado e a execução foi bloqueada." + Style.RESET_ALL)
        print(Fore.WHITE + "Restaure raveneye_pkg/credits.py original para continuar." + Style.RESET_ALL)
        sys.exit(1)


def ascii_tandaisec_logo() -> None:
    """Exibe o selo/logo oficial da TandaiSec."""
    print(Fore.WHITE + TANDAISEC_LOGO + Style.RESET_ALL)
    print(Fore.WHITE + "    TANDAISEC — OFFENSIVE SECURITY" + Style.RESET_ALL)
    print()


def show_credits() -> None:
    """Verifica integridade e exibe o logo + créditos completos."""
    verify_integrity()
    ascii_tandaisec_logo()
    print(Fore.WHITE + f"  {_CREDITS_TEXT}" + Style.RESET_ALL)
