from __future__ import annotations
import re
from urllib.parse import urlparse

SENSITIVE_NAMES = {
    'id','user_id','userid','account_id','accountid','uid','uuid','tenant_id','tenantid',
    'order_id','invoice_id','file_id','document_id','resource_id','object_id'
}


def inspect_endpoint(url: str, *, method: str = 'GET', parameters: list[str] | None = None,
                     authenticated: bool = False) -> list[dict]:
    """Return non-destructive endpoint hygiene observations.

    This is deliberately advisory: it never mutates the target or attempts
    authorization bypasses. Sensitive-looking object identifiers are flagged
    for manual authorization testing inside an approved assessment.
    """
    findings: list[dict] = []
    params = parameters or []
    sensitive = [p for p in params if str(p).lower() in SENSITIVE_NAMES or
                 re.search(r'(?:^|_)(?:id|uuid|uid)$', str(p), re.I)]
    if sensitive and not authenticated:
        findings.append({
            'id': 'api-object-reference-review',
            'name': 'API Object Reference Requires Authorization Review',
            'severity': 'INFO', 'confidence': 'MEDIUM', 'url': url,
            'evidence': ', '.join(sensitive)[:500],
            'remediation': 'Verify server-side authorization for every object reference; test with separate authorized accounts.',
            'tags': ['api', 'authorization'], 'cwe': 'CWE-639'
        })
    parsed = urlparse(url)
    if parsed.scheme == 'http':
        findings.append({
            'id': 'api-cleartext-transport', 'name': 'API Uses Cleartext HTTP',
            'severity': 'MEDIUM', 'confidence': 'HIGH', 'url': url,
            'evidence': url[:500],
            'remediation': 'Serve authenticated or sensitive API traffic exclusively over HTTPS.',
            'tags': ['api','transport'], 'cwe': 'CWE-319'
        })
    if method.upper() in {'PUT','PATCH','DELETE'} and not authenticated:
        findings.append({
            'id': 'api-state-change-auth-review', 'name': 'State-Changing API Requires Authorization Review',
            'severity': 'INFO', 'confidence': 'MEDIUM', 'url': url,
            'evidence': method.upper(),
            'remediation': 'Verify authentication and authorization are enforced server-side for state-changing operations.',
            'tags': ['api','authorization']
        })
    return findings
