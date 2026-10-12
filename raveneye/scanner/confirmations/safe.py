from __future__ import annotations
from .sqli import ConfirmationResult

def safe_confirm(*args, **kwargs) -> ConfirmationResult:
    return ConfirmationResult()
