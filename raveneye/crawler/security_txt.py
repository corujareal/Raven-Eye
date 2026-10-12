from __future__ import annotations

KNOWN = {'contact','expires','encryption','acknowledgments','policy','hiring','canonical','preferred-languages'}

def parse_security_txt(text: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or ':' not in line:
            continue
        key, value = line.split(':', 1)
        key = key.strip().lower(); value = value.strip()
        if key in KNOWN or key:
            result.setdefault(key, []).append(value)
    return result

def validate_security_txt(text: str) -> list[dict]:
    data = parse_security_txt(text)
    findings=[]
    if not data.get('contact'):
        findings.append({'id':'security-txt-no-contact','name':'security.txt Missing Contact','severity':'INFO','confidence':'HIGH','evidence':'No Contact field','remediation':'Publish a monitored security contact in /.well-known/security.txt.'})
    if not data.get('policy'):
        findings.append({'id':'security-txt-no-policy','name':'security.txt Missing Policy','severity':'INFO','confidence':'HIGH','evidence':'No Policy field','remediation':'Publish the vulnerability disclosure policy URL when applicable.'})
    return findings
