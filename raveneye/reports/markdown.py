from __future__ import annotations
from ..scanner.evidence import sanitize_url
def render(target, findings):
    target = sanitize_url(target) or target
    fs=list(findings); lines=[f"# RavenEye v6.6.6 — Security Report","","**Target:** `"+str(target)+"`","", "| Severity | Confidence | Finding | URL | CWE | CVE |","|---|---|---|---|---|---|"]
    for f in fs:
        vals=[f.get('severity','INFO')+' / '+f.get('stage','POSSIBLE'),f.get('confidence','MEDIUM')+' / '+str(f.get('confidence_score',0)),f.get('name',''),sanitize_url(f.get('url','')),f.get('cwe',''),f.get('cve','')]
        lines.append('| '+' | '.join(str(v).replace('|','\\|') for v in vals)+' |')
    return '\n'.join(lines)+'\n'
