from __future__ import annotations
import re
from urllib.parse import urlparse
from .engine import Finding

SECURITY_HEADERS=(
    ('content-security-policy','headers.csp','CSP'),
    ('x-content-type-options','headers.xcto','X-Content-Type-Options'),
    ('strict-transport-security','tls.hsts','HSTS'),
    ('referrer-policy','headers.referrer-policy','Referrer-Policy'),
)
SECRET_RE=re.compile(r'(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{8,})')
DEBUG_RE=re.compile(r'(?i)(traceback \(most recent call last\)|stack trace|debug=true|development mode|laravel|django debug|spring boot error)')
PRIVATE_IP_RE=re.compile(r'(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})(?!\d)')


def _finding(fid,name,sev,conf,url,evidence,remediation):
    return Finding(fid,name,sev,conf,url,evidence[:500],remediation)


def _header_values(headers, name: str) -> list[str]:
    """Return all values for a header when the mapping supports getall()."""
    key = name.lower()
    try:
        getter = getattr(headers, 'getall', None)
        if callable(getter):
            vals = getter(name, [])
            return [str(v) for v in vals]
    except Exception:
        pass
    value = headers.get(name) if hasattr(headers, 'get') else None
    if value is None and hasattr(headers, 'get'):
        value = headers.get(key)
    return [] if value is None else [str(value)]


def scan_headers(url,headers,body=''):
    h={str(k).lower():str(v) for k,v in headers.items()}; out=[]
    for header,fid,label in SECURITY_HEADERS:
        if header not in h:
            # HSTS is only meaningful for HTTPS responses.
            if header == 'strict-transport-security' and not url.lower().startswith('https://'):
                continue
            out.append(_finding(fid,label,'LOW','HIGH',url,f'Missing {header}','Configure the missing security header.'))
    if url.lower().startswith('https://') and re.search(r'(?i)(?:src|href)=["\']http://',body):
        out.append(_finding('mixed-content-reference','Potential Mixed Content','LOW','MEDIUM',url,'HTTPS page references an HTTP resource','Serve resources over HTTPS and review CSP upgrade policies.'))
    if 'server' in h and re.search(r'\d',h['server']):
        out.append(_finding('server-disclosure','Server Version Disclosure','INFO','HIGH',url,h['server'],'Minimize unnecessary software/version disclosure.'))
    if 'x-powered-by' in h:
        out.append(_finding('x-powered-by-disclosure','Technology Header Disclosure','INFO','HIGH',url,h['x-powered-by'],'Remove unnecessary X-Powered-By disclosure in production.'))
    cookie_values = _header_values(headers, 'Set-Cookie') if 'set-cookie' in h else []
    for idx, cookie in enumerate(cookie_values, 1):
        c=cookie.lower()
        if url.lower().startswith('https://') and 'secure' not in c:
            out.append(_finding('cookie-secure','Cookie Missing Secure','LOW','HIGH',url,f'Set-Cookie #{idx} lacks Secure attribute','Set Secure on cookies transported over HTTPS.'))
        if 'httponly' not in c:
            out.append(_finding('cookie-httponly','Cookie Missing HttpOnly','LOW','HIGH',url,f'Set-Cookie #{idx} lacks HttpOnly attribute','Set HttpOnly for session cookies where client-side JavaScript does not need the cookie.'))
        if 'samesite' not in c:
            out.append(_finding('cookie-samesite','Cookie Missing SameSite','LOW','MEDIUM',url,f'Set-Cookie #{idx} lacks SameSite attribute','Set an appropriate SameSite policy for browser session cookies.'))
    if h.get('access-control-allow-origin','').strip()=='*' and h.get('access-control-allow-credentials','').lower()=='true':
        out.append(_finding('cors-credentials-wildcard','Potential CORS Credential Misconfiguration','MEDIUM','HIGH',url,'Wildcard ACAO combined with credentials','Use an explicit allowlist of trusted origins.'))
    if re.search(r'(?i)(?:index of /|parent directory)',body[:20000]):
        out.append(_finding('directory-listing','Possible Directory Listing','LOW','MEDIUM',url,'Directory listing marker observed in response','Disable directory indexing unless intentionally exposed.'))
    if re.search(r'(?i)sourceMappingURL=.*\.map(?:\b|$)',body):
        out.append(_finding('source-map-reference','Source Map Reference Exposed','INFO','MEDIUM',url,'JavaScript references a source map','Review whether production source maps should be publicly accessible.'))
    secret=SECRET_RE.search(body)
    if secret:
        out.append(_finding('possible-secret-disclosure','Possible Secret Disclosure','MEDIUM','MEDIUM',url,f'{secret.group(1)}=<redacted>','Remove secrets from responses and rotate exposed credentials.'))
    if DEBUG_RE.search(body[:100000]):
        out.append(_finding('debug-information-disclosure','Debug/Error Information Disclosure','MEDIUM','MEDIUM',url,'Response contains a development/debug error signature','Disable debug mode and return generic production error pages.'))
    private=PRIVATE_IP_RE.search(body[:100000])
    if private:
        out.append(_finding('private-address-disclosure','Private Network Address Disclosure','LOW','MEDIUM',url,f'Private address pattern: {private.group(0)}','Avoid exposing internal network topology unless intentionally required.'))
    return out


def check_response(url,status,headers,body=''):
    return scan_headers(url,headers,body)

# Extended passive checks: evidence-only, no payload injection.
def check_extended_response(url, status, headers, body=''):
    findings=[]
    h={str(k).lower():str(v) for k,v in headers.items()}
    text=(body or '')[:150000]
    csp=h.get('content-security-policy','')
    if csp:
        low=csp.lower()
        if "'unsafe-inline'" in low:
            findings.append(Finding('csp-unsafe-inline','CSP Allows unsafe-inline','MEDIUM','HIGH',url,"Content-Security-Policy contains 'unsafe-inline'",'Prefer nonces/hashes and remove unsafe-inline where feasible.',tags=['headers','csp']))
        if "'unsafe-eval'" in low:
            findings.append(Finding('csp-unsafe-eval','CSP Allows unsafe-eval','MEDIUM','HIGH',url,"Content-Security-Policy contains 'unsafe-eval'",'Remove unsafe-eval and avoid string-to-code execution.',tags=['headers','csp']))
    ref=h.get('referrer-policy','')
    if ref.lower() in {'unsafe-url','no-referrer-when-downgrade'}:
        findings.append(Finding('referrer-policy-weak','Weak Referrer-Policy','LOW','HIGH',url,ref,'Use a restrictive policy such as strict-origin-when-cross-origin or stricter.',tags=['headers']))
    if 'permissions-policy' not in h:
        findings.append(Finding('permissions-policy-missing','Permissions-Policy Missing','INFO','HIGH',url,'Permissions-Policy header absent','Define a least-privilege Permissions-Policy for browser capabilities.',tags=['headers']))
    if 'content-security-policy' not in h and ('text/html' in h.get('content-type','').lower() or '<html' in text.lower()):
        findings.append(Finding('csp-missing','Content-Security-Policy Missing','LOW','HIGH',url,'HTML response without CSP header','Deploy a CSP appropriate to the application and test for compatibility.',tags=['headers','csp']))
    if 'directory listing' in text.lower() or re.search(r'<title>\s*index of\s+', text, re.I):
        findings.append(Finding('directory-listing','Directory Listing Evidence','LOW','HIGH',url,'Response resembles a generated directory index','Disable directory indexing where it is not intentionally exposed.',tags=['information_disclosure']))
    if re.search(r'(?i)sourceMappingURL\s*=\s*[^\s<]+\.map', text):
        findings.append(Finding('source-map-reference','JavaScript Source Map Reference Exposed','INFO','HIGH',url,'JavaScript references a .map source map','Avoid exposing production source maps unless intentionally required; restrict access if needed.',tags=['information_disclosure']))
    if re.search(r'(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*["\'][^"\']{8,}["\']', text):
        findings.append(Finding('potential-secret-disclosure','Potential Secret Disclosure','HIGH','LOW',url,'Potential secret-like value detected; value intentionally redacted','Remove secrets from client-visible responses and rotate any confirmed exposed credentials.',tags=['information_disclosure','secrets']))
    acao=h.get('access-control-allow-origin','')
    if acao == '*' and 'access-control-allow-credentials' not in h:
        findings.append(Finding('cors-wildcard','CORS Wildcard Origin','LOW','MEDIUM',url,'Access-Control-Allow-Origin: *','Restrict origins for sensitive APIs; wildcard may be acceptable for genuinely public resources.',tags=['cors']))
    if h.get('access-control-allow-credentials','').lower() == 'true' and acao and acao != '*':
        findings.append(Finding('cors-credentialed-origin-review','Credentialed CORS Requires Origin Review','INFO','MEDIUM',url,'Credentialed CORS is enabled for an explicit origin','Ensure the allowlist is strict and does not trust arbitrary Origin values.',tags=['cors']))
    allow = h.get('allow', '').upper()
    if 'TRACE' in {x.strip() for x in allow.split(',')}:
        findings.append(Finding('http-trace-advertised','HTTP TRACE Advertised','LOW','HIGH',url,'Allow header advertises TRACE','Disable TRACE unless there is a documented operational need.',tags=['http-methods'],cwe='CWE-200'))
    cache = h.get('cache-control', '').lower()
    sensitive_path = re.search(r'(?i)(?:/account|/profile|/dashboard|/admin|/settings|/api/)', url)
    if sensitive_path and cache and 'public' in cache:
        findings.append(Finding('sensitive-response-public-cache','Sensitive-Looking Response Marked Publicly Cacheable','LOW','MEDIUM',url,'Cache-Control contains public on a sensitive-looking path','Use private/no-store for authenticated or user-specific responses.',tags=['cache'],cwe='CWE-525'))
    if 'cross-origin-resource-policy' not in h and ('text/html' in h.get('content-type','').lower() or 'javascript' in h.get('content-type','').lower()):
        findings.append(Finding('corp-missing','Cross-Origin-Resource-Policy Missing','INFO','MEDIUM',url,'Cross-Origin-Resource-Policy header absent','Set a policy appropriate to the resource sensitivity and embedding requirements.',tags=['headers']))
    if status >= 500 and re.search(r'(?i)(exception|traceback|stack trace|line \d+)', text):
        findings.append(Finding('server-error-detail-confirmed','Server Error Detail Disclosure','MEDIUM','HIGH',url,'HTTP 5xx response contains a stack/exception detail','Return generic error pages externally and retain diagnostic detail only in protected logs.',tags=['information_disclosure'],cwe='CWE-209'))
    return findings
