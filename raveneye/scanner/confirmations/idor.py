"""Safe confirmation interface for idor.

Active exploit payloads and out-of-band callbacks are intentionally not executed
by the safe RavenEye distribution. Findings returned here are advisory only.
"""
from dataclasses import dataclass
@dataclass(frozen=True,slots=True)
class ConfirmationResult:
    confirmed: bool=False
    confidence: str='LOW'
    reason: str='Active exploit confirmation is disabled; manual authorized validation is required.'
def confirm(*args, **kwargs) -> ConfirmationResult:
    return ConfirmationResult()
