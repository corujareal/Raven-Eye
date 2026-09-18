from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path
try:
    import yaml
except ImportError:
    yaml = None
@dataclass
class Finding:
    template_id:str; name:str; severity:str; confidence:str; url:str; evidence:str=''; remediation:str=''; tags:list[str]=field(default_factory=list); cwe:str=''; cve:str=''
    @property
    def id(self): return self.template_id
class TemplateEngine:
    def __init__(self, directory='raveneye/scanner/templates'): self.directory=Path(directory)
    def load(self):
        if yaml is None:
            return []
        out=[]
        if not self.directory.exists(): return out
        for p in self.directory.glob('*.yaml'):
            try: out.append(yaml.safe_load(p.read_text(encoding='utf-8')))
            except Exception: continue
        return out
class PassiveScanner:
    """Checks that are safe by default: headers, TLS metadata, exposed files and information disclosure."""
    SECURITY_HEADERS=('content-security-policy','strict-transport-security','x-content-type-options','referrer-policy')
    def scan_response(self,url,status,headers,body=''):
        findings=[]; h={k.lower():v for k,v in headers.items()}
        missing=[x for x in self.SECURITY_HEADERS if x not in h]
        if missing: findings.append(Finding('headers-security','Security Headers','LOW','HIGH',url,', '.join(missing),'Configure the missing response security headers.'))
        if 'server' in h and re.search(r'\d',h['server']): findings.append(Finding('server-disclosure','Server Version Disclosure','INFO','HIGH',url,h['server'],'Minimize unnecessary version disclosure.'))
        c=h.get('set-cookie','')
        if c and 'secure' not in c.lower(): findings.append(Finding('cookie-secure','Cookie Missing Secure','LOW','HIGH',url,'Set-Cookie missing Secure attribute','Set Secure on cookies delivered over HTTPS.'))
        if c and 'httponly' not in c.lower(): findings.append(Finding('cookie-httponly','Cookie Missing HttpOnly','LOW','HIGH',url,'Set-Cookie missing HttpOnly attribute','Set HttpOnly where client-side JavaScript does not need the cookie.'))
        if h.get('access-control-allow-origin','').strip()=='*' and h.get('access-control-allow-credentials','').lower()=='true': findings.append(Finding('cors-credentials-wildcard','Potential CORS Credential Misconfiguration','MEDIUM','MEDIUM',url,'Wildcard ACAO combined with credentials','Use an explicit allowlist of trusted origins.'))
        return findings
