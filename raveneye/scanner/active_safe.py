"""Non-destructive security validation helpers.

These checks deliberately avoid exploit payloads and credential attacks. They are
intended for authorized assessment pipelines and CI environments.
"""
from __future__ import annotations
from dataclasses import dataclass
from urllib.parse import urlparse

@dataclass(slots=True)
class ValidationResult:
    check: str
    passed: bool
    detail: str

def validate_https(url: str) -> ValidationResult:
    scheme = urlparse(url).scheme.lower()
    return ValidationResult("https", scheme == "https", f"scheme={scheme or 'unknown'}")

def validate_cookie_flags(set_cookie: list[str]) -> list[ValidationResult]:
    out=[]
    for cookie in set_cookie:
        low=cookie.lower()
        name=cookie.split('=',1)[0].strip() or '<unnamed>'
        out.append(ValidationResult(f"cookie:{name}:secure", 'secure' in low, 'Secure flag present' if 'secure' in low else 'Secure flag missing'))
        out.append(ValidationResult(f"cookie:{name}:httponly", 'httponly' in low, 'HttpOnly flag present' if 'httponly' in low else 'HttpOnly flag missing'))
    return out
