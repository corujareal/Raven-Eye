from __future__ import annotations
import json,re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from .js_analysis import analyze_javascript
ABS_URL_RE=re.compile(r'https?://[^"\'\s<>\\]+')
WS_URL_RE=re.compile(r'wss?://[^"\'\s<>\\]+')

def extract_html(base_url:str, html:str):
    soup=BeautifulSoup(html,'lxml'); urls=[]; forms=[]; scripts=[]; js_endpoints=set(); route_templates=set()
    apis=set(ABS_URL_RE.findall(html)); websockets=set(WS_URL_RE.findall(html))
    for a in soup.find_all('a',href=True): urls.append(urljoin(base_url,a['href']))
    inline_budget=1_000_000
    executable_js_types={'','module','application/javascript','text/javascript','application/ecmascript','text/ecmascript'}
    for tag in soup.find_all(['script','link','img','iframe']):
        attr='src' if tag.name in {'script','img','iframe'} else 'href'
        if tag.get(attr):
            u=urljoin(base_url,tag[attr]); urls.append(u)
            if tag.name=='script': scripts.append(u)
        elif tag.name=='script' and not tag.find_parent('template'):
            script_type=(tag.get('type') or '').split(';',1)[0].strip().lower()
            if script_type not in executable_js_types:
                continue
            source=tag.string if tag.string is not None else tag.get_text()
            if not source or len(source)>inline_budget:
                continue
            encoded_size=len(source.encode('utf-8',errors='ignore'))
            if encoded_size>inline_budget:
                continue
            inline_budget-=encoded_size
            found=analyze_javascript(base_url,source,max_results=256)
            js_endpoints.update(found['urls'])
            urls.extend(found['urls']+found['source_maps']+found['scripts'])
            scripts.extend(found['scripts'])
            websockets.update(found['websockets'])
            route_templates.update(found['route_templates'])
    for form in soup.find_all('form'):
        fields=[]; csrf=[]
        for inp in form.find_all(['input','textarea','select']):
            name=inp.get('name'); item={'name':name,'type':inp.get('type','text'),'value':inp.get('value','')}
            fields.append(item)
            if name and re.search(r'csrf|xsrf|token',name,re.I): csrf.append(name)
        forms.append({'action':urljoin(base_url,form.get('action') or base_url),'method':(form.get('method') or 'GET').upper(),
                      'fields':fields,'csrf_fields':csrf})
    return {'urls':sorted(set(urls)|js_endpoints),'forms':forms,'apis':sorted(apis),'websockets':sorted(websockets),'scripts':list(dict.fromkeys(scripts)),'js_endpoints':sorted(js_endpoints),'route_templates':sorted(route_templates)}

def extract_openapi(text:str):
    try: data=json.loads(text)
    except Exception: return []
    if not isinstance(data,dict): return []
    return sorted((data.get('paths') or {}).keys())
