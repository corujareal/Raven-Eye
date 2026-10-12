from __future__ import annotations

from dataclasses import dataclass, field
import re
from pathlib import Path

from .evidence import score_finding, stage_for_finding


@dataclass
class Finding:
    template_id: str
    name: str
    severity: str
    confidence: str
    url: str
    evidence: str = ''
    remediation: str = ''
    tags: list[str] = field(default_factory=list)
    cwe: str = ''
    cve: str = ''
    stage: str = ''
    confidence_score: int = 0
    score_factors: dict[str, int] = field(default_factory=dict)
    evidence_metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        self.stage = stage_for_finding(self.template_id, default=self.stage or 'POSSIBLE')
        if not self.confidence_score:
            self.confidence_score, self.score_factors = score_finding(
                self.stage, {'direct_observation': self.stage == 'CONFIRMED'}
            )

    @property
    def id(self):
        return self.template_id


class TemplateEngine:
    """Backward-compatible façade for the validated passive template engine."""

    def __init__(self, directory='raveneye/scanner/templates'):
        self.directory = Path(directory)
        self.errors = []

    def load(self):
        from .template_engine import TemplateEngine as ValidatedTemplateEngine
        engine = ValidatedTemplateEngine(self.directory)
        templates = engine.load()
        self.errors = list(engine.errors)
        return templates

    def match(self, *args, **kwargs):
        from .template_engine import TemplateEngine as ValidatedTemplateEngine
        return ValidatedTemplateEngine(self.directory).match(*args, **kwargs)


class PassiveScanner:
    """Checks that are safe by default: headers and response disclosure."""

    SECURITY_HEADERS = ('content-security-policy', 'strict-transport-security',
                        'x-content-type-options', 'referrer-policy')

    def scan_response(self, url, status, headers, body=''):
        findings = []
        h = {str(k).lower(): str(v) for k, v in headers.items()}
        missing = [x for x in self.SECURITY_HEADERS if x not in h]
        if missing:
            findings.append(Finding('headers-security', 'Security Headers', 'LOW', 'HIGH',
                                    url, ', '.join(missing),
                                    'Configure the missing response security headers.'))
        if 'server' in h and re.search(r'\d', h['server']):
            findings.append(Finding('server-disclosure', 'Server Version Disclosure', 'INFO', 'MEDIUM',
                                    url, 'Version-bearing Server header observed',
                                    'Minimize unnecessary version disclosure.'))
        cookie_values = (headers.getall('Set-Cookie', [])
                         if callable(getattr(headers, 'getall', None))
                         else ([h['set-cookie']] if h.get('set-cookie') else []))
        for index, cookie in enumerate(cookie_values, 1):
            low = str(cookie).lower()
            if url.lower().startswith('https://') and 'secure' not in low:
                findings.append(Finding('cookie-secure', 'Cookie Missing Secure', 'LOW', 'HIGH', url,
                                        f'Set-Cookie #{index} lacks Secure attribute',
                                        'Set Secure on cookies delivered over HTTPS.'))
            if 'httponly' not in low:
                findings.append(Finding('cookie-httponly', 'Cookie Missing HttpOnly', 'LOW', 'HIGH', url,
                                        f'Set-Cookie #{index} lacks HttpOnly attribute',
                                        'Set HttpOnly where client-side JavaScript does not need the cookie.'))
        if (h.get('access-control-allow-origin', '').strip() == '*'
                and h.get('access-control-allow-credentials', '').lower() == 'true'):
            findings.append(Finding('cors-credentials-wildcard',
                                    'Potential CORS Credential Misconfiguration', 'MEDIUM', 'MEDIUM',
                                    url, 'Wildcard ACAO combined with credentials',
                                    'Use an explicit allowlist of trusted origins.'))
        if any(x in body.lower() for x in ('index of /', 'directory listing for')):
            findings.append(Finding('directory-listing', 'Possible Directory Listing', 'LOW', 'MEDIUM',
                                    url, 'Directory listing marker observed',
                                    'Disable directory indexing where unintended.'))
        if 'traceback (most recent call last)' in body.lower():
            findings.append(Finding('server-error-detail-confirmed', 'Stack Trace Disclosure', 'MEDIUM',
                                    'HIGH', url, 'Python stack trace marker observed',
                                    'Return generic errors and log details server-side.', cwe='CWE-209'))
        return findings
