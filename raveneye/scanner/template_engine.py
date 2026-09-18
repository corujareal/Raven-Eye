from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import re
try:
    import yaml
except ImportError:
    yaml = None

@dataclass
class Finding:
    template_id: str
    name: str
    severity: str
    confidence: str
    url: str = ''
    evidence: str = ''
    remediation: str = ''
    tags: list[str] = field(default_factory=list)
    cwe: str = ''
    cve: str = ''

class TemplateEngine:
    """Nuclei-like matcher for already collected responses.

    This engine intentionally does not execute template requests or payloads.
    It supports word/regex/status matchers, matcher conditions, negative
    matchers and simple extractors over response evidence.
    """
    def __init__(self, directory='raveneye/scanner/templates'):
        self.directory = Path(directory)

    def load(self):
        if yaml is None:
            return []
        templates=[]
        if not self.directory.exists():
            return templates
        for p in sorted(self.directory.glob('*.y*ml')):
            try:
                data=yaml.safe_load(p.read_text(encoding='utf-8'))
                if isinstance(data, dict) and data.get('id') and isinstance(data.get('info'), dict):
                    templates.append(data)
            except (OSError, yaml.YAMLError):
                continue
        return templates

    @staticmethod
    def _match(m, text, status=None):
        typ=str(m.get('type','word')).lower()
        negative=bool(m.get('negative',False))
        if typ == 'word':
            values=[str(x) for x in m.get('words',[])]; matched=any(x.lower() in text.lower() for x in values)
            evidence=', '.join(values)
        elif typ == 'regex':
            values=[str(x) for x in m.get('regex',[])]; matched=any(re.search(x,text,re.I|re.M) for x in values)
            evidence=', '.join(values)
        elif typ == 'status':
            values={str(x) for x in m.get('status',[])}; matched=str(status) in values
            evidence=str(status)
        else:
            return False, ''
        return ((not matched) if negative else matched), evidence

    @staticmethod
    def _extract(extractor, text):
        typ=str(extractor.get('type','regex')).lower()
        if typ == 'regex':
            return [m.group(1) if m.groups() else m.group(0)
                    for pattern in extractor.get('regex',[])
                    for m in re.finditer(str(pattern), text, re.I|re.M)]
        if typ == 'kval':
            out=[]
            for key in extractor.get('keys',[]):
                m=re.search(rf'(?im)^\s*{re.escape(str(key))}\s*[:=]\s*(.+?)\s*$', text)
                if m: out.append(m.group(1))
            return out
        return []

    def match(self, template, response_text='', headers=None, url='', status=None):
        headers=headers or {}
        hay=response_text+'\n'+'\n'.join(f'{k}: {v}' for k,v in headers.items())
        info=template.get('info') or {}
        matchers=template.get('matchers') or []
        if isinstance(matchers, dict): matchers=[matchers]
        condition=str(template.get('matchers-condition','or')).lower()
        matched=[]
        for m in matchers:
            ok,evidence=self._match(m,hay,status)
            matched.append((ok,evidence))
        selected=[x for x in matched if x[0]]
        overall=all(x[0] for x in matched) if condition == 'and' else any(x[0] for x in matched)
        if not overall:
            return []
        evidence='; '.join(x[1] for x in selected)[:500]
        extracts=[]
        for ex in template.get('extractors') or []:
            extracts.extend(self._extract(ex,hay))
        if extracts:
            evidence=(evidence+' | extracted: '+', '.join(extracts))[:500]
        return [Finding(
            template.get('id','unknown'), info.get('name','template'),
            str(info.get('severity','info')).upper(), str(info.get('confidence','HIGH')).upper(),
            url, evidence,
            str(info.get('remediation','Review the finding and apply vendor guidance.')),
            list(info.get('tags',[]) or []), str(info.get('cwe','')), str(info.get('cve',''))
        )]
