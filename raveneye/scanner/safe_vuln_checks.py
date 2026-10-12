"""Non-destructive vulnerability-category checks.

These checks identify evidence that warrants manual/authorized validation. They do
not inject exploit payloads, brute-force credentials, or attempt destructive actions.
"""
from __future__ import annotations
import re
from .engine import Finding

SQL_ERRORS = re.compile(
    r"(?i)(SQL syntax error|error in your SQL syntax|SQLite(?:3)?(?:::SQL)?(?:Exception| error)|"
    r"MySQL(?: server)? (?:error|syntax error)|MariaDB.{0,40}(?:error|syntax)|"
    r"PostgreSQL\s+(?:error|syntax error)|ORA-\d{4,5}|"
    r"ODBC.{0,40}(?:SQLSTATE|SQL error)|JDBC.{0,40}(?:Exception|error)|"
    r"syntax error at or near|unclosed quotation mark)"
)
LDAP_ERRORS = re.compile(
    r"(?i)(invalid DN syntax|LDAPException|LDAP:\s*error code\s+\d+|"
    r"javax\.naming\.(?:NamingException|InvalidNameException))"
)
CMD_ERRORS = re.compile(
    r"(?i)(?:\b(?:sh|bash):\s*[^:\r\n]{1,80}:\s*command not found\b|"
    r"\bcommand not found\b|cannot execute (?:binary file|command)|"
    r"syntax error near unexpected token|"
    r"is not recognized as an internal or external command)"
)
TRAVERSAL_ERRORS = re.compile(r"(?i)(?:root:x:0:0|[A-Z]:\\Windows\\System32(?:\\|\b))")
XXE_ERRORS = re.compile(
    r"(?i)(?:XML parser error|SAXParseException|failed to load external entity|"
    r"external entity (?:resolution|processing) failed)"
)
DOM_XSS_SOURCE = re.compile(
    r"(?i)(?:location\.(?:search|hash)|document\.(?:URL|documentURI|referrer)|window\.name)"
)
DOM_XSS_SINK = re.compile(
    r"(?i)(?:\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|"
    r"insertAdjacentHTML\s*\()"
)

MANDATORY_CATEGORIES = ('sql_injection','command_injection','directory_traversal','xxe','xss','ssl_tls','open_ports','ldap_injection','csrf','headers_security','information_disclosure')

def _f(id_,name,sev,conf,url,evidence,remediation,tags):
    return Finding(id_,name,sev,conf,url,evidence,remediation,tags=list(tags))

def inspect_categories(url: str, status: int, headers: dict, body: str = '') -> list[Finding]:
    del status  # Reserved for future status-aware checks; current signatures are body-evidence only.
    out = []
    h = {str(k).lower(): str(v) for k, v in headers.items()}
    text = body[:100000]
    if SQL_ERRORS.search(text):
        out.append(_f(
            'sqli.error-indicator', 'SQL Injection — error indicator', 'MEDIUM', 'LOW', url,
            'Specific database/parser error signature observed; input causality is unverified.',
            'Review parameterized query usage and validate inputs; manually reproduce only in an authorized test environment.',
            ['sql_injection'],
        ))
    if CMD_ERRORS.search(text):
        out.append(_f(
            'cmdi.execution-indicator', 'Command Injection — execution indicator', 'MEDIUM', 'LOW', url,
            'Specific shell/runtime error signature observed; input causality is unverified.',
            'Review OS command construction and replace shell invocation with safe APIs/allowlists.',
            ['command_injection'],
        ))
    if TRAVERSAL_ERRORS.search(text):
        out.append(_f(
            'directory-traversal.file-indicator', 'Directory Traversal — file/path indicator', 'LOW', 'LOW', url,
            'Response contains a specific system-file/path signature.',
            'Normalize and constrain file paths to an approved base directory.',
            ['directory_traversal'],
        ))
    if XXE_ERRORS.search(text) and 'xml' in h.get('content-type', '').lower():
        out.append(_f(
            'xxe.xml-indicator', 'XXE — XML parser indicator', 'LOW', 'LOW', url,
            'XML response contains a specific external-entity/parser error; exploitability is unverified.',
            'Disable external entity resolution and use hardened XML parser settings.',
            ['xxe'],
        ))
    if DOM_XSS_SOURCE.search(text) and DOM_XSS_SINK.search(text):
        out.append(_f(
            'xss.dom-source-sink-indicator', 'Potential DOM XSS source/sink pattern', 'INFO', 'LOW', url,
            'Client-side source and HTML sink patterns occur in the response; data flow and execution were not verified.',
            'Trace untrusted values to the sink and use safe DOM APIs or context-aware encoding.',
            ['xss'],
        ))
    if url.lower().startswith('http://'):
        out.append(_f('ssl-tls.http-only','SSL/TLS — plaintext transport','MEDIUM','HIGH',url,'Target URL uses HTTP instead of HTTPS.','Require HTTPS and redirect HTTP to HTTPS.',['ssl_tls']))
    if h.get('server') and re.search(r'\d', h['server']):
        out.append(_f('information-disclosure.server','Information Disclosure — server version','INFO','HIGH',url,h['server'],'Minimize unnecessary software/version disclosure.',['information_disclosure']))
    if 'www-authenticate' in h and h.get('www-authenticate','').lower().startswith('basic '):
        out.append(_f('csrf.auth-basic-review','CSRF — state-changing Basic Auth review','INFO','LOW',url,'Basic authentication is advertised; state-changing endpoints require CSRF review.','Use CSRF protections for browser-mediated state changes and prefer modern session controls.',['csrf']))
    if LDAP_ERRORS.search(text): out.append(_f('ldap.error-indicator','LDAP Injection — error indicator','LOW','LOW',url,'LDAP parser/error signature observed.','Use parameterized LDAP APIs and validate identifier syntax.',['ldap_injection']))
    if not h.get('x-content-type-options'): out.append(_f('headers-security.xcto','Headers Security — X-Content-Type-Options missing','LOW','HIGH',url,'Header missing','Set X-Content-Type-Options: nosniff.',['headers_security']))
    return out
