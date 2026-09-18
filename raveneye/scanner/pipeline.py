from __future__ import annotations
import asyncio
import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..network.session import AsyncSession
from ..core.logger import redact
from ..network.scope_guard import ScopeGuard
from .passive_checks import check_response, check_extended_response
from .fingerprint import fingerprint
from .api_security import parse_openapi, analyze_openapi, analyze_graphql, inspect_operations
from .safe_vuln_checks import inspect_categories
from .cve_correlator import load_local_records, correlate_technologies
from .template_engine import TemplateEngine

_SQL_ERRORS = re.compile(r"(?i)(sql syntax|sqlite exception|mysql(?: server)? error|postgres(?:ql)?|ora-\d+|odbc sql|jdbc exception|syntax error at or near)")


def _dedupe_findings(findings):
    seen = set(); out = []
    for f in findings:
        key = (str(f.get('id', f.get('template_id', f.get('name', '')))),
               str(f.get('url', '')), str(f.get('parameter', '')))
        if key in seen:
            continue
        seen.add(key); out.append(f)
    return out


def _replace_query(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    replaced = False; out = []
    for key, old in pairs:
        if key == param and not replaced:
            out.append((key, value)); replaced = True
        else:
            out.append((key, old))
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(out), p.fragment))


def _query_params(url: str) -> list[str]:
    return list(dict.fromkeys(k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True) if k))[:24]


async def _safe_active_findings(url: str, baseline_body: str, response, request_fn) -> list[dict]:
    """Low-impact differential checks: unique reflection and parser error evidence.

    No command execution, time delays, authentication guessing, file access or OOB
    callbacks are attempted. A reflection is explicitly reported as reflection,
    never as confirmed XSS.
    """
    findings = []
    for param in _query_params(url):
        marker = 'RAVENEYE_' + hashlib.sha256(f'{url}|{param}'.encode()).hexdigest()[:12]
        body = await request_fn(_replace_query(url, param, marker))
        if body is None:
            continue
        if marker in body:
            findings.append({
                'id': 'xss.reflection', 'name': 'User Input Reflected',
                'severity': 'INFO', 'confidence': 'HIGH', 'url': url, 'parameter': param,
                'evidence': f'Unique benign marker {marker} was reflected in the response.',
                'remediation': 'Apply context-aware output encoding and validate the sink before treating the reflection as executable.',
                'cwe': 'CWE-79', 'tags': ['xss', 'active-safe']
            })
        # A single quote is a parser-error probe, not an exploit payload.
        quote_body = await request_fn(_replace_query(url, param, "'"))
        if quote_body is None:
            continue
        match = _SQL_ERRORS.search(quote_body[:150000])
        # Differential evidence is required: a pre-existing error page is not a SQLi finding.
        if match and not _SQL_ERRORS.search(baseline_body[:150000]):
            findings.append({
                'id': 'sqli.error-differential', 'name': 'SQL Parser Error After Benign Differential Probe',
                'severity': 'MEDIUM', 'confidence': 'MEDIUM', 'url': url, 'parameter': param,
                'evidence': f'Parser error signature observed after a single-quote differential probe: {match.group(0)[:120]}',
                'remediation': 'Use parameterized queries/prepared statements and validate input types.',
                'cwe': 'CWE-89', 'tags': ['sql_injection', 'active-safe']
            })
    return findings


async def scan_url(url: str, cfg, *, scope=None, active_safe: bool = True):
    host = urlparse(url).hostname or ''
    allowed = set(scope or cfg.scope.include_domains or [host])
    guard = ScopeGuard(domains=allowed, excludes=tuple(getattr(cfg.scope, 'exclude', ()) or ()))
    async with AsyncSession(user_agent=cfg.user_agent, timeout=cfg.timeout_seconds,
                            verify_tls=cfg.verify_tls, allowed_domains=allowed,
                            requests_per_second=cfg.requests_per_second, scope_guard=guard) as session:
        async with await session.request('GET', url, allow_redirects=False) as response:
            body = await response.text(errors='replace')
            headers = {str(k): redact(v) for k, v in response.headers.items()}
            findings = check_response(url, response.status, headers, body)
            findings.extend(check_extended_response(url, response.status, headers, body))
            findings.extend(inspect_categories(url, response.status, headers, body))
            # Local templates operate only on this already collected response.
            templates = TemplateEngine().load()
            for template in templates:
                findings.extend(TemplateEngine().match(template, body, headers, url, response.status))
            if active_safe and _query_params(url):
                async def _probe(probe_url: str):
                    async with await session.request('GET', probe_url, allow_redirects=False) as probe_response:
                        return await probe_response.text(errors='replace')
                findings.extend(await _safe_active_findings(url, body, response, _probe))
            api_findings = []
            ctype = headers.get('content-type', '').lower()
            if 'json' in ctype or any(token in url.lower() for token in ('openapi', 'swagger', 'api-docs')):
                try:
                    spec = parse_openapi(body)
                    api_findings.extend(analyze_openapi(spec, base_url=url))
                    api_findings.extend(inspect_operations(spec, base_url=url))
                except (ValueError, TypeError, UnicodeError):
                    pass
            api_findings.extend(analyze_graphql(url, body, ctype))
            technologies = fingerprint(headers, body)
            cve_path = getattr(cfg, 'cve_records_path', None)
            if cve_path:
                try:
                    api_findings.extend(correlate_technologies(technologies, load_local_records(cve_path), url=url))
                except (OSError, ValueError, TypeError):
                    # A malformed local feed must not make a scan fail or create guesses.
                    pass
            serial = [f.__dict__ if hasattr(f, '__dict__') else f for f in findings] + api_findings
            return {'url': url, 'status': response.status, 'headers': headers,
                    'body_length': len(body), 'findings': _dedupe_findings(serial),
                    'technologies': technologies}


async def scan_urls(urls, cfg, *, scope=None, concurrency=None, active_safe: bool = True):
    limit = max(1, min(concurrency or cfg.concurrency, 64)); sem = asyncio.Semaphore(limit)
    async def one(url):
        async with sem:
            try:
                return await scan_url(url, cfg, scope=scope, active_safe=active_safe)
            except Exception as exc:
                return {'url': url, 'status': None, 'findings': [], 'technologies': [], 'error': str(exc)}
    return await asyncio.gather(*(one(u) for u in urls))
