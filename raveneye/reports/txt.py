from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone
import re
WEIGHTS={'CRITICAL':10,'HIGH':7,'MEDIUM':4,'LOW':1,'INFO':0}
_SECRET=re.compile(r'(?i)(authorization|cookie|set-cookie|api[-_]?key|token|password|secret)\s*[:=]\s*[^\s,;]+')
def risk_score(findings):
    fs=[f for f in findings if str(f.get('severity','INFO')).upper() != 'INFO']
    if not fs:
        return 0.0
    # Relatório: média ponderada das severidades observadas, ignorando INFO.
    # Mantém 10.0 para um CRITICAL isolado e evita diluição por ruído INFO.
    return round(min(10.0, sum(WEIGHTS.get(str(f.get('severity','INFO')).upper(),0) for f in fs)/len(fs)),1)
def _clip(v,n=500): return _SECRET.sub(lambda m:f'{m.group(1)}=<redacted>',str(v or '')[:n])
def render(target,findings,*,ip='unknown',duration='unknown',mode='Scan',endpoints=None,technologies=None,nmap_output=None):
    fs=list(findings); c=Counter(str(f.get('severity','INFO')).upper() for f in fs)
    lines=['='*80,'RAVENEYE v6.6.6 — RELATÓRIO DE SEGURANÇA OFENSIVA','='*80,
      f'ALVO: {target} | IP: {ip} | DATA: {datetime.now(timezone.utc).isoformat()}',
      f'DURAÇÃO: {duration} | MODO: {mode} | RISK SCORE: {risk_score(fs):.1f}/10','='*80,'','[RESUMO EXECUTIVO]',
      f"- CRÍTICO: {c['CRITICAL']} | ALTO: {c['HIGH']} | MÉDIO: {c['MEDIUM']} | BAIXO: {c['LOW']} | INFO: {c['INFO']}",
      f'- Superfície analisada: {len(endpoints or [])} endpoints','- Evidências limitadas a 500 caracteres e segredos são redigidos.','']
    for i,f in enumerate(fs,1):
        sev=str(f.get('severity','INFO')).upper(); conf=str(f.get('confidence','MEDIUM')).upper()
        lines += [f"[{i}] {f.get('name',f.get('id','Unnamed'))} — {sev} — CONFIDENCE: {conf}",f"    URL: {f.get('url','')}"]
        if f.get('parameter'): lines.append(f"    Parâmetro: {f['parameter']}")
        lines += ['    Evidência:',f"      {_clip(f.get('evidence'))}",f"    Impacto: {_clip(f.get('impact') or 'Requer validação contextual do impacto.')}",f"    Remediação: {_clip(f.get('remediation'))}",f"    CWE: {f.get('cwe','')} | CVE: {f.get('cve','')}",'']
    lines += ['[ANEXO A] ENDPOINTS DISCOVERED']+[f'  - {e}' for e in (endpoints or [])[:500]]
    lines += ['','[ANEXO B] TECHNOLOGIES DETECTED']+[f'  - {t}' for t in (technologies or [])[:200]]
    if nmap_output: lines += ['','[ANEXO C] RAW NMAP OUTPUT',_clip(nmap_output,500)]
    return '\n'.join(lines)+'\n'
