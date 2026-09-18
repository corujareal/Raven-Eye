from __future__ import annotations
import json
import re
from urllib.parse import urljoin
_METHODS={'get','post','put','patch','delete','options','head','trace'}
_ID_NAMES={'id','user_id','account_id','resource_id','object_id','item_id'}

def analyze_openapi(spec: dict, *, base_url: str = ''):
    findings=[]; global_security=spec.get('security'); servers=spec.get('servers') or []
    for path, methods in (spec.get('paths') or {}).items():
        if not isinstance(methods, dict): continue
        for method, op in methods.items():
            if method.lower() not in _METHODS or not isinstance(op, dict): continue
            url=urljoin(base_url.rstrip('/')+'/', str(path).lstrip('/')) if base_url else str(path)
            security=op.get('security', global_security)
            if security == []:
                findings.append({'name':'API endpoint explicitly disables declared security','severity':'MEDIUM','confidence':'HIGH','url':url,'evidence':f'{method.upper()} {path} has security: []','remediation':'Require authentication and authorization for protected resources.'})
            elif security is None:
                findings.append({'name':'API endpoint without declared security','severity':'INFO','confidence':'MEDIUM','url':url,'evidence':f'{method.upper()} {path}','remediation':'Document and enforce authentication/authorization where required.'})
            for p in op.get('parameters') or []:
                if isinstance(p,dict) and p.get('in') in {'query','path'} and str(p.get('name','')).lower() in _ID_NAMES:
                    findings.append({'name':'Potential object-reference parameter requires authorization review','severity':'INFO','confidence':'LOW','url':url,'evidence':f"{method.upper()} {path} parameter {p.get('name')}",'remediation':'Verify server-side object-level authorization for every referenced resource.'})
    for server in servers:
        if isinstance(server,dict) and str(server.get('url','')).startswith('http://'):
            findings.append({'name':'OpenAPI server uses HTTP','severity':'LOW','confidence':'HIGH','url':str(server.get('url')),'evidence':str(server.get('url'))[:500],'remediation':'Use HTTPS for API transport.'})
    return findings

def parse_openapi(text: str):
    doc=json.loads(text)
    if not isinstance(doc,dict) or not (doc.get('openapi') or doc.get('swagger')): raise ValueError('Not an OpenAPI/Swagger document')
    return doc

def analyze_graphql(url: str, body: str, content_type: str = ''):
    """Passive GraphQL indicators only; never sends introspection or fuzzing queries."""
    hay=(body or '')[:100000]
    if 'graphql' not in url.lower() and not re.search(r'(?i)\b(query|mutation|subscription)\s+[A-Za-z_]',hay):
        return []
    findings=[]
    if re.search(r'(?i)__schema|__type',hay):
        findings.append({'name':'GraphQL introspection data exposed','severity':'MEDIUM','confidence':'HIGH','url':url,'evidence':'GraphQL response contains introspection fields','remediation':'Disable or restrict introspection in production where it is not required.'})
    if re.search(r'(?i)errors?\s*[:\[]',hay) and re.search(r'(?i)stack|traceback|exception',hay):
        findings.append({'name':'GraphQL error detail disclosure','severity':'LOW','confidence':'MEDIUM','url':url,'evidence':'Response appears to expose stack/exception details','remediation':'Return generic production errors and keep diagnostic traces server-side.'})
    return findings


def inspect_operations(spec: dict, base_url: str = '') -> list[dict]:
    """Advisory checks over OpenAPI operations; no active requests are made."""
    from .endpoint_checks import inspect_endpoint
    findings=[]
    servers=spec.get('servers') or []
    if servers and any(str(s.get('url','')).startswith('http://') for s in servers if isinstance(s,dict)):
        findings.append({'id':'openapi-cleartext-server','name':'OpenAPI Server Uses HTTP','severity':'MEDIUM','confidence':'HIGH','url':base_url,'evidence':'http:// server declared in OpenAPI','remediation':'Use HTTPS for API servers.'})
    for path, item in (spec.get('paths') or {}).items():
        if not isinstance(item,dict): continue
        for method, operation in item.items():
            if method.lower() not in {'get','post','put','patch','delete','options','head','trace'} or not isinstance(operation,dict): continue
            url=(base_url.rstrip('/') + '/' + str(path).lstrip('/')) if base_url else str(path)
            params=[]
            for p in operation.get('parameters') or []:
                if isinstance(p,dict) and p.get('name'): params.append(str(p['name']))
            findings.extend(inspect_endpoint(url,method=method,parameters=params,authenticated=bool(operation.get('security', spec.get('security')))))
            if operation.get('security') == []:
                findings.append({'id':'openapi-operation-security-empty','name':'OpenAPI Operation Disables Declared Security','severity':'MEDIUM','confidence':'HIGH','url':url,'evidence':f'{method.upper()} {path} has security: []','remediation':'Require an explicit security scheme unless the endpoint is intentionally public.'})
    return findings
