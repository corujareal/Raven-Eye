"""Non-destructive vulnerability-category checks.

These checks identify evidence that warrants manual/authorized validation. They do
not inject exploit payloads, brute-force credentials, or attempt destructive actions.
"""
from __future__ import annotations
import re
from .engine import Finding

SQL_ERRORS = re.compile(r"(?i)(sql syntax|sqlite exception|mysql|postgresql|ora-\d+|odbc sql|jdbc exception|syntax error at or near)")
LDAP_ERRORS = re.compile(r"(?i)(ldap error|invalid dn syntax|ldapexception|javax\.naming)")
CMD_ERRORS = re.compile(r"(?i)(command not found|/bin/(?:sh|bash)|powershell|win32 process|child_process)")
TRAVERSAL_ERRORS = re.compile(r"(?i)(no such file or directory|root:x:0:0|windows\\system32|directory traversal)")
XXE_ERRORS = re.compile(r"(?i)(doctype|external entity|xml parse error|entity reference)")

MANDATORY_CATEGORIES = ('sql_injection','command_injection','directory_traversal','xxe','xss','ssl_tls','open_ports','ldap_injection','csrf','headers_security','information_disclosure')

def _f(id_,name,sev,conf,url,evidence,remediation,tags):
    return Finding(id_,name,sev,conf,url,evidence,remediation,tags=list(tags))

def inspect_categories(url: str, status: int, headers: dict, body: str = '') -> list[Finding]:
    out=[]; h={str(k).lower():str(v) for k,v in headers.items()}; text=body[:100000]
    if SQL_ERRORS.search(text): out.append(_f('sqli.error-indicator','SQL Injection — error indicator','MEDIUM','LOW',url,'Database/parser error signature observed in response.','Review parameterized query usage and validate inputs; manually reproduce only in an authorized test environment.',['sql_injection']))
    if CMD_ERRORS.search(text): out.append(_f('cmdi.execution-indicator','Command Injection — execution indicator','MEDIUM','LOW',url,'Response contains a command/runtime signature.','Review OS command construction and replace shell invocation with safe APIs/allowlists.',['command_injection']))
    if TRAVERSAL_ERRORS.search(text): out.append(_f('directory-traversal.file-indicator','Directory Traversal — file/path indicator','LOW','LOW',url,'Response contains a filesystem/path signature.','Normalize and constrain file paths to an approved base directory.',['directory_traversal']))
    if XXE_ERRORS.search(text) and ('xml' in h.get('content-type','').lower() or '<!doctype' in text.lower()): out.append(_f('xxe.xml-indicator','XXE — XML parser indicator','LOW','LOW',url,'XML/DOCTYPE parsing signature observed.','Disable external entity resolution and use hardened XML parser settings.',['xxe']))
    if '<script' in text.lower() or 'onerror=' in text.lower() or 'onload=' in text.lower():
        out.append(_f('xss.html-sink-indicator','XSS — HTML sink indicator','INFO','LOW',url,'Response contains executable HTML sink patterns; no payload was injected.','Contextually encode untrusted output and apply an appropriate CSP.',['xss']))
    if url.lower().startswith('http://'):
        out.append(_f('ssl-tls.http-only','SSL/TLS — plaintext transport','MEDIUM','HIGH',url,'Target URL uses HTTP instead of HTTPS.','Require HTTPS and redirect HTTP to HTTPS.',['ssl_tls']))
    if h.get('server') and re.search(r'\d',h['server']):
        out.append(_f('information-disclosure.server','Information Disclosure — server version','INFO','HIGH',url,h['server'],'Minimize unnecessary software/version disclosure.',['information_disclosure']))
    if 'www-authenticate' in h and h.get('www-authenticate','').lower().startswith('basic '):
        out.append(_f('csrf.auth-basic-review','CSRF — state-changing Basic Auth review','INFO','LOW',url,'Basic authentication is advertised; state-changing endpoints require CSRF review.','Use CSRF protections for browser-mediated state changes and prefer modern session controls.',['csrf']))
    if LDAP_ERRORS.search(text): out.append(_f('ldap.error-indicator','LDAP Injection — error indicator','LOW','LOW',url,'LDAP parser/error signature observed.','Use parameterized LDAP APIs and validate identifier syntax.',['ldap_injection']))
    if not h.get('x-content-type-options'): out.append(_f('headers-security.xcto','Headers Security — X-Content-Type-Options missing','LOW','HIGH',url,'Header missing','Set X-Content-Type-Options: nosniff.',['headers_security']))
    return out
