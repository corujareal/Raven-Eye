from __future__ import annotations
def render(target, findings):
    fs=list(findings); lines=[f"# RavenEye v6.6.6 — Security Report","","**Target:** `"+str(target)+"`","", "| Severity | Confidence | Finding | URL | CWE | CVE |","|---|---|---|---|---|---|"]
    for f in fs:
        vals=[f.get('severity','INFO'),f.get('confidence','MEDIUM'),f.get('name',''),f.get('url',''),f.get('cwe',''),f.get('cve','')]
        lines.append('| '+' | '.join(str(v).replace('|','\\|') for v in vals)+' |')
    return '\n'.join(lines)+'\n'
