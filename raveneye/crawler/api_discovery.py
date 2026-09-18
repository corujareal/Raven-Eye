from __future__ import annotations
import json, re
from urllib.parse import urljoin
API_HINTS=("/openapi.json","/swagger.json","/swagger/v1/swagger.json","/api-docs","/graphql")
WS_RE=re.compile(r'wss?://[^"\'\s<>\\]+', re.I)

def discover_api_urls(base_url: str, body: str):
    out=[urljoin(base_url,x) for x in API_HINTS]
    out += re.findall(r'(?:wss?|https?)://[^"\'\s<>\\]+', body)
    out += [urljoin(base_url, x) for x in re.findall(r'["\'](\/[^"\']{1,200})["\']', body) if any(k in x.lower() for k in ('/api/','/graphql','/swagger','/openapi'))]
    try:
        doc=json.loads(body)
        if isinstance(doc,dict):
            out += [urljoin(base_url,p) for p in (doc.get('paths') or {})]
            out += [urljoin(base_url,s.get('url','')) for s in (doc.get('servers') or []) if isinstance(s,dict) and s.get('url')]
    except Exception: pass
    return list(dict.fromkeys(x for x in out if x))

def parse_openapi(text: str):
    doc=json.loads(text)
    if not isinstance(doc,dict) or not (doc.get('openapi') or doc.get('swagger')): raise ValueError('Not an OpenAPI/Swagger document')
    endpoints=[]
    for path,item in (doc.get('paths') or {}).items():
        if isinstance(item,dict):
            for method,operation in item.items():
                if method.lower() in {'get','post','put','patch','delete','head','options','trace'}:
                    endpoints.append({'path':path,'method':method.upper(),'operation_id':(operation or {}).get('operationId') if isinstance(operation,dict) else None})
    return {'version':doc.get('openapi') or doc.get('swagger'),'endpoints':endpoints,'servers':doc.get('servers') or []}

def graphql_indicators(body: str):
    b=body.lower();
    return {'detected': bool(re.search(r'\bgraphql\b|__schema|__typename|query\s*\{', b)),
            'introspection_enabled_indicator':'__schema' in b or '__typename' in b}
