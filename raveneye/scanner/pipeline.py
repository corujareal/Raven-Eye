from __future__ import annotations
import asyncio
from dataclasses import asdict, is_dataclass
import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..network.session import AsyncSession
from ..core.logger import redact
from ..network.scope_guard import ScopeGuard
from ..core.targets import normalize_target
from .passive_checks import check_response, check_extended_response
from .fingerprint import fingerprint
from .api_security import parse_openapi, analyze_openapi, analyze_graphql, inspect_operations
from .safe_vuln_checks import inspect_categories
from .cve_correlator import load_local_snapshot, correlate_technologies
from .template_engine import TemplateEngine
from .evidence import make_evidence, sanitize_url, stage_for_finding, score_finding

_SQL_ERRORS = re.compile(
    r"(?i)(sql syntax|sqlite exception|mysql(?: server)? error|"
    r"postgres(?:ql)?\s+(?:error|syntax error)|ora-\d{4,5}|odbc sql|"
    r"jdbc exception|syntax error at or near|unclosed quotation mark)"
)
_DEDUPE_ID_ALIASES = {
    'csp-missing': 'headers.csp',
    'headers-security.xcto': 'headers.xcto',
    'potential-secret-disclosure': 'possible-secret-disclosure',
    'information-disclosure.server': 'server-disclosure',
}


def _dedupe_findings(findings):
    seen = set(); out = []
    for f in findings:
        finding_id = str(f.get('id', f.get('template_id', f.get('name', ''))))
        canonical_id = _DEDUPE_ID_ALIASES.get(finding_id, finding_id)
        key = (canonical_id,
               str(f.get('url', '')), str(f.get('parameter', '')),
               str((f.get('evidence_metadata') or {}).get('response', {}).get('sha256', '')),
               str(f.get('cve', '')))
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


async def _read_response_limited(response, limit: int) -> tuple[bytes, bool]:
    """Read through EOF or the configured byte cap without buffering unbounded bodies."""
    limit = max(1024, int(limit))
    content = getattr(response, 'content', None)
    iterator = getattr(content, 'iter_chunked', None)
    if callable(iterator):
        chunks = []
        total = 0
        async for chunk in iterator(min(65536, limit + 1)):
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                break
        data = b''.join(chunks)
        return data[:limit], total > limit
    data = await content.read(limit + 1)
    return data[:limit], len(data) > limit


async def _safe_active_findings(url: str, baseline_body: str, response, request_fn) -> list[dict]:
    """Low-impact differential checks: unique reflection and parser error evidence.

    No command execution, time delays, authentication guessing, file access or OOB
    callbacks are attempted. A reflection is explicitly reported as reflection,
    never as confirmed XSS.
    """
    findings = []
    baseline = {
        'status': getattr(response, 'status', None),
        'headers': dict(getattr(response, 'headers', {}) or {}),
        'body': baseline_body,
    }
    for param in _query_params(url):
        marker = 'RAVENEYE_' + hashlib.sha256(f'{url}|{param}'.encode()).hexdigest()[:12]
        probe_url = _replace_query(url, param, marker)
        observation = await request_fn(probe_url)
        if observation is None:
            continue
        observed = observation if isinstance(observation, dict) else {'body': str(observation)}
        body = str(observed.get('body', ''))
        if marker in body:
            evidence = make_evidence(
                method='GET', url=probe_url, status=observed.get('status'),
                headers=observed.get('headers', {}), body=body, source='active-safe:reflection',
                stage='POSSIBLE', factors={'unique_marker': True, 'heuristic_only': True},
                baseline=baseline, truncated=observed.get('truncated', False),
            )
            findings.append({
                'id': 'xss.reflection', 'name': 'User Input Reflected',
                'severity': 'INFO', 'confidence': 'MEDIUM', 'url': sanitize_url(url), 'parameter': param,
                'evidence': 'Unique benign marker reflected; output context and execution were not verified.',
                'remediation': 'Apply context-aware output encoding and validate the sink before treating the reflection as executable.',
                'cwe': 'CWE-79', 'tags': ['xss', 'active-safe'],
                'stage': 'POSSIBLE', 'evidence_metadata': evidence,
            })
        # A single quote is a parser-error probe, not an exploit payload.
        quote_url = _replace_query(url, param, "'")
        quote_observation = await request_fn(quote_url)
        if quote_observation is None:
            continue
        quoted = quote_observation if isinstance(quote_observation, dict) else {'body': str(quote_observation)}
        quote_body = str(quoted.get('body', ''))
        match = _SQL_ERRORS.search(quote_body[:150000])
        # Differential evidence is required: a pre-existing error page is not a SQLi finding.
        quote_status = quoted.get('status')
        baseline_has_sql_error = _SQL_ERRORS.search(baseline_body[:150000]) is not None
        if match and not baseline_has_sql_error:
            repeat_observation = await request_fn(quote_url)
            if repeat_observation is None:
                continue
            repeated = repeat_observation if isinstance(repeat_observation, dict) else {'body': str(repeat_observation)}
            repeated_body = str(repeated.get('body', ''))
            repeated_match = _SQL_ERRORS.search(repeated_body[:150000])
            repeated_status = repeated.get('status')
            repeatable = (
                repeated_match is not None
                and repeated_status == quote_status
                and repeated_match.group(0).casefold() == match.group(0).casefold()
                and abs(len(repeated_body) - len(quote_body))
                <= max(64, int(max(len(repeated_body), len(quote_body)) * 0.10))
            )
            if not repeatable:
                continue
            evidence = make_evidence(
                method='GET', url=quote_url, status=repeated.get('status'),
                headers=repeated.get('headers', {}), body=repeated_body,
                source='active-safe:sql-parser-differential', stage='PROBABLE',
                factors={'baseline_compared': True, 'differential_signal': True, 'repeatable': True},
                baseline=baseline, truncated=repeated.get('truncated', False),
            )
            findings.append({
                'id': 'sqli.error-differential', 'name': 'SQL Parser Error After Benign Differential Probe',
                'severity': 'MEDIUM', 'confidence': 'MEDIUM', 'url': sanitize_url(url), 'parameter': param,
                'evidence': 'A database/parser error signature appeared only after a repeated quote probe.',
                'remediation': 'Use parameterized queries/prepared statements and validate input types.',
                'cwe': 'CWE-89', 'tags': ['sql_injection', 'active-safe'],
                'stage': 'PROBABLE', 'evidence_metadata': evidence,
            })
    return findings


async def scan_url(url: str, cfg, *, scope=None, active_safe: bool = True):
    url = normalize_target(url)
    if not url:
        raise ValueError('URL HTTP(S) inválida para o scanner.')
    host = urlparse(url).hostname or ''
    allowed = set(scope or cfg.scope.include_domains or [host])
    guard = ScopeGuard(domains=allowed, excludes=tuple(getattr(cfg.scope, 'exclude', ()) or ()))
    async with AsyncSession(user_agent=cfg.user_agent, timeout=cfg.timeout_seconds,
                            verify_tls=cfg.verify_tls, allowed_domains=allowed,
                            requests_per_second=cfg.requests_per_second, scope_guard=guard) as session:
        async with await session.request('GET', url, allow_redirects=False) as response:
            body_limit = max(1024, int(getattr(cfg, 'max_response_bytes', 2_000_000)))
            raw_body, truncated = await _read_response_limited(response, body_limit)
            encoding = getattr(response, 'charset', None) or 'utf-8'
            try:
                body = raw_body.decode(encoding, errors='replace')
            except LookupError:
                body = raw_body.decode('utf-8', errors='replace')
            raw_headers = {str(k): str(v) for k, v in response.headers.items()}
            headers = {str(k): redact(v) for k, v in response.headers.items()}
            findings = check_response(url, response.status, headers, body)
            findings.extend(check_extended_response(url, response.status, headers, body))
            findings.extend(inspect_categories(url, response.status, headers, body))
            # Local templates operate only on this already collected response.
            template_engine = TemplateEngine()
            templates = template_engine.load()
            for template in templates:
                findings.extend(template_engine.match(template, body, headers, url, response.status))
            if active_safe and _query_params(url):
                async def _probe(probe_url: str):
                    async with await session.request('GET', probe_url, allow_redirects=False) as probe_response:
                        probe_raw, probe_truncated = await _read_response_limited(probe_response, body_limit)
                        probe_encoding = getattr(probe_response, 'charset', None) or 'utf-8'
                        try:
                            probe_body = probe_raw.decode(probe_encoding, errors='replace')
                        except LookupError:
                            probe_body = probe_raw.decode('utf-8', errors='replace')
                        return {
                            'body': probe_body,
                            'status': probe_response.status,
                            'headers': {str(k): str(v) for k, v in probe_response.headers.items()},
                            'truncated': probe_truncated,
                        }
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
            observed_at = make_evidence(
                method='GET', url=url, status=response.status, headers=raw_headers, body=body,
                source='http-response', stage='POSSIBLE',
                factors={'direct_observation': True}, truncated=truncated,
            )
            for tech in technologies:
                tech['observed_at'] = observed_at['observed_at']
                tech['response_sha256'] = observed_at['response']['sha256']
            cve_path = getattr(cfg, 'cve_records_path', None)
            if cve_path:
                try:
                    records, cve_metadata = load_local_snapshot(cve_path)
                    api_findings.extend(correlate_technologies(
                        technologies, records, url=url, source_metadata=cve_metadata
                    ))
                except (OSError, ValueError, TypeError):
                    # A malformed local feed must not make a scan fail or create guesses.
                    pass
            serial = [asdict(f) if is_dataclass(f) else dict(f) for f in findings] + api_findings
            response_evidence = make_evidence(
                method='GET', url=url, status=response.status, headers=raw_headers, body=body,
                source='http-response', stage='POSSIBLE',
                factors={'direct_observation': True}, truncated=truncated,
            )
            normalized = []
            for item in serial:
                finding_id = str(item.get('id', item.get('template_id', item.get('name', ''))))
                stage = str(item.get('stage') or stage_for_finding(finding_id)).upper()
                if stage not in {'POSSIBLE', 'PROBABLE', 'CONFIRMED'}:
                    stage = 'POSSIBLE'
                factors = {}
                if item.get('evidence_metadata'):
                    evidence_record = item['evidence_metadata']
                else:
                    factors['direct_observation'] = True
                    if stage == 'POSSIBLE':
                        factors['heuristic_only'] = True
                    if finding_id.startswith('cve.'):
                        factors['high_quality_fingerprint'] = any(
                            t.get('confidence') == 'HIGH' for t in technologies
                        )
                    evidence_record = make_evidence(
                        method='GET', url=url, status=response.status, headers=raw_headers,
                        body=body, source=finding_id or 'passive-check', stage=stage,
                        factors=factors, truncated=truncated,
                    )
                item['url'] = sanitize_url(item.get('url') or url)
                item['evidence'] = redact(item.get('evidence', ''))
                item['stage'] = stage
                item['confidence_score'] = int(evidence_record.get('confidence_score', score_finding(stage, factors)[0]))
                item['score_factors'] = dict(evidence_record.get('score_factors', {}))
                item['observed_at'] = evidence_record.get('observed_at', response_evidence['observed_at'])
                item['evidence_metadata'] = evidence_record
                normalized.append(item)
            return {'url': sanitize_url(url), 'status': response.status, 'headers': headers,
                    'body_length': len(raw_body), 'body_truncated': truncated,
                    'findings': _dedupe_findings(normalized), 'technologies': technologies,
                    'template_errors': template_engine.errors}


async def scan_urls(urls, cfg, *, scope=None, concurrency=None, active_safe: bool = True):
    limit = max(1, min(concurrency or cfg.concurrency, 64)); sem = asyncio.Semaphore(limit)
    async def one(url):
        async with sem:
            try:
                return await scan_url(url, cfg, scope=scope, active_safe=active_safe)
            except Exception as exc:
                return {
                    'url': sanitize_url(url), 'status': None, 'findings': [],
                    'technologies': [], 'error': type(exc).__name__,
                }
    return await asyncio.gather(*(one(u) for u in urls))
