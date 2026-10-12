"""Required terminal styling supplied by the full RavenEye runtime."""
from __future__ import annotations

from colorama import Fore, Style, init as _colorama_init


def init(*args, **kwargs) -> None:
    _colorama_init(*args, **kwargs)
