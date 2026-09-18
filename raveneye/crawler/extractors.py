from __future__ import annotations
import json,re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
ABS_URL_RE=re.compile(r'https?://[^"\'\s<>\\]+')
WS_URL_RE=re.compile(r'wss?://[^"\'\s<>\\]+')
JS_PATH_RE=re.compile(r"(?:fetch|axios\.(?:get|post|put|patch|delete)|XMLHttpRequest|\.open)\s*\(\s*[\"']([^\"']+)",re.I)

def extract_html(base_url:str, html:str):
    soup=BeautifulSoup(html,'lxml'); urls=[]; forms=[]; scripts=[]
    for a in soup.find_all('a',href=True): urls.append(urljoin(base_url,a['href']))
    for tag in soup.find_all(['script','link','img','iframe']):
        attr='src' if tag.name in {'script','img','iframe'} else 'href'
        if tag.get(attr):
            u=urljoin(base_url,tag[attr]); urls.append(u)
            if tag.name=='script': scripts.append(u)
    for form in soup.find_all('form'):
        fields=[]; csrf=[]
        for inp in form.find_all(['input','textarea','select']):
            name=inp.get('name'); item={'name':name,'type':inp.get('type','text'),'value':inp.get('value','')}
            fields.append(item)
            if name and re.search(r'csrf|xsrf|token',name,re.I): csrf.append(name)
        forms.append({'action':urljoin(base_url,form.get('action') or base_url),'method':(form.get('method') or 'GET').upper(),
                      'fields':fields,'csrf_fields':csrf})
    apis=set(ABS_URL_RE.findall(html)); websockets=set(WS_URL_RE.findall(html))
    js_endpoints={urljoin(base_url,x) for x in JS_PATH_RE.findall(html) if x.startswith(('/','./','../'))}
    return {'urls':sorted(set(urls)|js_endpoints),'forms':forms,'apis':sorted(apis),'websockets':sorted(websockets),'scripts':scripts,'js_endpoints':sorted(js_endpoints)}

def extract_openapi(text:str):
    try: data=json.loads(text)
    except Exception: return []
    if not isinstance(data,dict): return []
    return sorted((data.get('paths') or {}).keys())
