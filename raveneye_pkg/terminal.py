"""Terminal styling compatibility layer.

Colorama is optional for core/bootstrap operation. When unavailable, ANSI/style
attributes resolve to empty strings so the legacy CLI remains importable.
"""
from __future__ import annotations

try:
    from colorama import Fore, Style, init as _colorama_init
except ImportError:  # bootstrap/diagnostic environments
    class _NoColor:
        def __getattr__(self, _name: str) -> str:
            return ""
    Fore = _NoColor()
    Style = _NoColor()

    def _colorama_init(*_args, **_kwargs) -> None:
        return None


def init(*args, **kwargs) -> None:
    _colorama_init(*args, **kwargs)
