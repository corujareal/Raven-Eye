from __future__ import annotations
from ipaddress import IPv4Address, ip_address, ip_network
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
DEBUG_RE=re.compile(
    r'(?i)(traceback \(most recent call last\)|stack trace|'
    r'debug\s*[=:]\s*(?:true|1|on)\b|django debug page|whitelabel error page)'
)
PHPINFO_TITLE_RE = re.compile(r'(?is)<title\s*>\s*phpinfo\(\)\s*</title\s*>')
_DIRECTORY_HEADING_RE = re.compile(
    r'(?is)<(?:title|h1)\b[^>]*>\s*(?:index\s+of\b|directory\s+listing\s+for\b)'
)
_DIRECTORY_PARENT_LINK_RE = re.compile(
    r'''(?is)<a\b[^>]*href\s*=\s*["'](?:\.\./|/\.\.)["'][^>]*>\s*(?:\.\./|parent\s+directory\b)'''
)
PRIVATE_IP_RE=re.compile(
    r'(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})'
    r'(?!\d)(?!\.\d)'
)
SESSION_COOKIE_NAME = re.compile(
    r"(?i)(?:^|[._-])(?:session|sessionid|sess|sessid|auth|token|jwt|sid)(?:$|[._-])"
)
KNOWN_SESSION_COOKIE_NAMES = frozenset({
    "phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid",
})
_PRIVATE_NETWORKS = tuple(ip_network(value) for value in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
))


def _private_ip_in_text(text: str) -> str | None:
    """Return a syntactically valid RFC1918 address found in a response."""
    for match in PRIVATE_IP_RE.finditer(text):
        try:
            address = IPv4Address(match.group(0))
        except ValueError:
            continue
        if any(address in network for network in _PRIVATE_NETWORKS):
            return str(address)
    return None


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


def _cookie_flags(value: str) -> tuple[str, set[str]]:
    """Parse cookie name and attribute tokens without mistaking values for flags."""
    name, attributes = _cookie_attributes(value)
    return name.lower(), set(attributes)


def _cookie_attributes(value: str) -> tuple[str, dict[str, str | None]]:
    """Parse names and attribute values while keeping cookie contents private."""
    parts = [part.strip() for part in str(value).split(";")]
    name = parts[0].partition("=")[0].strip() if parts else ""
    attributes: dict[str, str | None] = {}
    for part in parts[1:]:
        if not part:
            continue
        key, separator, attribute_value = part.partition("=")
        attributes[key.strip().lower()] = attribute_value.strip() if separator else None
    return name, attributes


def _looks_like_directory_listing(body: str) -> bool:
    """Require a generated index heading and its parent-directory link."""
    sample = str(body or "")[:20_000]
    return bool(
        _DIRECTORY_HEADING_RE.search(sample)
        and _DIRECTORY_PARENT_LINK_RE.search(sample)
    )


def _is_secure_cookie_context(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme.lower() == 'https':
        return True
    host = (parsed.hostname or '').lower().rstrip('.')
    if host == 'localhost' or host.endswith('.localhost'):
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


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
    secure_cookie_context = _is_secure_cookie_context(url)
    for idx, cookie in enumerate(cookie_values, 1):
        raw_cookie_name, parsed_attributes = _cookie_attributes(cookie)
        cookie_name = raw_cookie_name.lower()
        attributes = set(parsed_attributes)
        likely_session = (
            cookie_name in KNOWN_SESSION_COOKIE_NAMES
            or bool(SESSION_COOKIE_NAME.search(cookie_name))
        )
        severity = 'LOW' if likely_session else 'INFO'
        confidence = 'MEDIUM' if likely_session else 'LOW'
        session_note = 'nome sugere sessão' if likely_session else 'nome não indica sessão'
        if url.lower().startswith('https://') and 'secure' not in attributes:
            out.append(_finding(
                'cookie-secure', 'Cookie Missing Secure', severity, confidence, url,
                f'Set-Cookie #{idx} não declara Secure; {session_note}.',
                'Set Secure em cookies de sessão ou outros cookies sensíveis.',
            ))
        if 'httponly' not in attributes:
            out.append(_finding(
                'cookie-httponly', 'Cookie Missing HttpOnly', severity, confidence, url,
                f'Set-Cookie #{idx} não declara HttpOnly; {session_note}.',
                'Set HttpOnly em cookies de sessão que não precisam ser lidos por JavaScript.',
            ))
        if 'samesite' not in attributes:
            out.append(_finding(
                'cookie-samesite', 'Cookie Missing SameSite', severity, confidence, url,
                f'Set-Cookie #{idx} não declara SameSite; {session_note}.',
                'Defina SameSite conforme o fluxo legítimo da aplicação.',
            ))
        # Cookie prefixes are case-sensitive browser contracts. Record only the
        # ordinal and failed rule; cookie names and values can contain secrets.
        if raw_cookie_name.startswith('__Secure-') and (
            'secure' not in attributes or not secure_cookie_context
        ):
            out.append(_finding(
                'cookie.prefix-secure', 'Invalid __Secure- Cookie Configuration',
                'INFO', 'HIGH', url,
                f'Set-Cookie #{idx} uses __Secure- without a valid Secure cookie context.',
                'Use HTTPS and Secure, or remove the prefix if the cookie is intentionally not secure.',
            ))
        if raw_cookie_name.startswith('__Host-') and (
            'secure' not in attributes
            or not secure_cookie_context
            or parsed_attributes.get('path') != '/'
            or 'domain' in attributes
        ):
            out.append(_finding(
                'cookie.prefix-host', 'Invalid __Host- Cookie Configuration',
                'INFO', 'HIGH', url,
                f'Set-Cookie #{idx} violates one or more __Host- attribute requirements.',
                'Use Secure; Path=/ and omit Domain, or choose a different cookie prefix.',
            ))
        if (str(parsed_attributes.get('samesite') or '').lower() == 'none'
                and ('secure' not in attributes or not secure_cookie_context)):
            out.append(_finding(
                'cookie.samesite-none-secure', 'SameSite=None Cookie Has Invalid Secure Context',
                'INFO', 'HIGH', url,
                f'Set-Cookie #{idx} declares SameSite=None without a valid Secure context.',
                'Use HTTPS with Secure or choose a SameSite policy compatible with its intended use.',
            ))
    if h.get('access-control-allow-origin','').strip()=='*' and h.get('access-control-allow-credentials','').lower()=='true':
        out.append(_finding(
            'cors.invalid-credentialed-wildcard',
            'Credentialed CORS Wildcard Is Rejected by Browsers',
            'INFO', 'HIGH', url,
            'ACAO is * while ACAC is true; browsers reject credentialed access for this combination.',
            'Use an explicit trusted origin if credentialed cross-origin access is intended.',
        ))
    if _looks_like_directory_listing(body):
        out.append(_finding('directory-listing','Possible Directory Listing','LOW','MEDIUM',url,'Directory listing marker observed in response','Disable directory indexing unless intentionally exposed.'))
    if re.search(r'(?i)sourceMappingURL=.*\.map(?:\b|$)',body):
        out.append(_finding('source-map-reference','Source Map Reference Exposed','INFO','MEDIUM',url,'JavaScript references a source map','Review whether production source maps should be publicly accessible.'))
    secret=SECRET_RE.search(body)
    if secret:
        out.append(_finding('possible-secret-disclosure','Possible Secret Disclosure','MEDIUM','MEDIUM',url,f'{secret.group(1)}=<redacted>','Remove secrets from responses and rotate exposed credentials.'))
    if DEBUG_RE.search(body[:100000]):
        out.append(_finding('debug-information-disclosure','Debug/Error Information Disclosure','MEDIUM','MEDIUM',url,'Response contains a development/debug error signature','Disable debug mode and return generic production error pages.'))
    phpinfo_body = body[:100000]
    if (
        PHPINFO_TITLE_RE.search(phpinfo_body)
        and 'php version' in phpinfo_body.lower()
        and 'loaded configuration file' in phpinfo_body.lower()
    ):
        out.append(_finding(
            'phpinfo-page-exposed', 'PHP Configuration Page Exposed', 'LOW', 'MEDIUM', url,
            'Response matches the PHP phpinfo() page title and configuration-table markers.',
            'Remove public access to phpinfo() output and rotate any secrets confirmed in the page.',
        ))
    private=_private_ip_in_text(body[:100000])
    if private:
        out.append(_finding('private-address-disclosure','Private Network Address Disclosure','LOW','MEDIUM',url,f'Private address pattern: {private}','Avoid exposing internal network topology unless intentionally required.'))
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
    if _looks_like_directory_listing(text):
        findings.append(Finding('directory-listing','Directory Listing Evidence','LOW','HIGH',url,'Response resembles a generated directory index','Disable directory indexing where it is not intentionally exposed.',tags=['information_disclosure']))
    if re.search(r'(?i)sourceMappingURL\s*=\s*[^\s<]+\.map', text):
        findings.append(Finding('source-map-reference','JavaScript Source Map Reference Exposed','INFO','HIGH',url,'JavaScript references a .map source map','Avoid exposing production source maps unless intentionally required; restrict access if needed.',tags=['information_disclosure']))
    if re.search(r'(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*["\'][^"\']{8,}["\']', text):
        findings.append(Finding('potential-secret-disclosure','Potential Secret Disclosure','HIGH','LOW',url,'Potential secret-like value detected; value intentionally redacted','Remove secrets from client-visible responses and rotate any confirmed exposed credentials.',tags=['information_disclosure','secrets']))
    acao=h.get('access-control-allow-origin','')
    if acao == '*' and 'access-control-allow-credentials' not in h:
        findings.append(Finding('cors-wildcard','Public CORS Wildcard — Review Resource Sensitivity','INFO','LOW',url,'Access-Control-Allow-Origin: * without credentialed access','Use an explicit allowlist for private resources; a wildcard can be appropriate for public resources.',tags=['cors'],stage='POSSIBLE'))
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
