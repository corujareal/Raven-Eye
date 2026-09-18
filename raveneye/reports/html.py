from __future__ import annotations
import html
import json
from collections import Counter

_SEV=('CRITICAL','HIGH','MEDIUM','LOW','INFO')

def render(target, findings):
    findings=list(findings); c=Counter(str(f.get('severity','INFO')).upper() for f in findings)
    rows=[]
    for idx,f in enumerate(findings,1):
        sev=str(f.get('severity','INFO')).upper()
        rows.append(
            '<tr data-severity="%s" data-index="%d">'
            '<td><span class="badge %s">%s</span></td>'
            '<td><strong>%s</strong><small>%s</small></td>'
            '<td><code>%s</code></td><td>%s</td></tr>' % (
                html.escape(sev), idx, html.escape(sev.lower()), html.escape(sev),
                html.escape(str(f.get('name', f.get('id','Finding')))),
                html.escape(str(f.get('category',''))),
                html.escape(str(f.get('url',''))),
                html.escape(str(f.get('confidence','MEDIUM')))))
    cards=''.join('<div class="card"><span>%s</span><strong>%d</strong></div>'%(s,c[s]) for s in _SEV)
    total=max(1,len(findings)); segments=[]; start=0.0
    for s in _SEV:
        pct=c[s]/total*100
        if pct:
            segments.append(f'var(--{s.lower()}) {start:.2f}% {start+pct:.2f}%'); start += pct
    gradient=', '.join(segments) or 'transparent 0 100%'
    target_json=json.dumps(str(target), ensure_ascii=False)
    return f'''<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RavenEye 6.6.6 — Security Report</title>
<style>
:root{{--critical:#ff4d4d;--high:#ff9f43;--medium:#ffd166;--low:#5dade2;--info:#9b9b9b;--bg:#0b0f14;--panel:#111821;--line:#263241;--text:#e8edf2;--muted:#9aa7b5}}
*{{box-sizing:border-box}}body{{background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;margin:0;padding:28px}}
main{{max-width:1250px;margin:auto}}header,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px;margin-bottom:18px}}
h1{{margin:0 0 6px;font-size:28px}}h2{{margin-top:0}}.muted,small{{color:var(--muted)}}code{{color:#c8d6e5;word-break:break-all}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:18px 0}}.card{{background:#0e141c;border:1px solid var(--line);border-radius:12px;padding:14px}}.card span{{display:block;color:var(--muted);font-size:12px}}.card strong{{font-size:25px}}.summary{{display:flex;gap:24px;align-items:center;flex-wrap:wrap}}.donut{{width:150px;height:150px;border-radius:50%;background:conic-gradient({gradient});position:relative;flex:none}}.donut:after{{content:"";position:absolute;inset:30px;background:var(--panel);border-radius:50%}}.toolbar{{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}}button{{padding:8px 12px;background:#18212c;color:var(--text);border:1px solid #3a4756;border-radius:8px;cursor:pointer}}button.active{{outline:2px solid #7aa2f7}}table{{width:100%;border-collapse:collapse}}th,td{{padding:11px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}}th{{cursor:pointer;color:#cdd7e2}}td small{{display:block;margin-top:3px}}.badge{{display:inline-block;padding:3px 8px;border-radius:999px;font-size:11px;font-weight:700;background:#29323d}}.badge.critical{{background:#6d2028}}.badge.high{{background:#704319}}.badge.medium{{background:#66520d}}.badge.low{{background:#174565}}.badge.info{{background:#3a4149}}.empty{{padding:20px;text-align:center;color:var(--muted)}}
@media(max-width:700px){{body{{padding:12px}}th:nth-child(3),td:nth-child(3){{max-width:260px}}}}
</style></head><body><main>
<header><h1>RavenEye v6.6.6 — I see you</h1><div class="muted">Relatório de segurança · resultados do scan · self-contained report</div><p>Alvo: <code>{html.escape(str(target))}</code></p></header>
<section class="panel"><div class="summary"><div class="donut" aria-label="Distribuição de severidade"></div><div><h2>Resumo</h2><p>{len(findings)} finding(s) registrado(s).</p><p class="muted">Este documento contém resultados, evidências redigidas e recomendações — não código-fonte ou notas internas de implementação.</p></div></div><div class="cards">{cards}</div></section>
<section class="panel"><h2>Findings</h2><div class="toolbar"><button class="active" data-filter="ALL">Todos</button>{''.join(f'<button data-filter="{s}">{s}</button>' for s in _SEV)}</div>
<table id="findings"><thead><tr><th>Severity</th><th>Finding</th><th>URL</th><th>Confidence</th></tr></thead><tbody>{''.join(rows) if rows else '<tr><td colspan="4" class="empty">Nenhum finding.</td></tr>'}</tbody></table></section>
<footer class="muted">RavenEye v6.6.6 · I see you · generated report</footer>
</main>
<script>
const buttons=[...document.querySelectorAll('[data-filter]')], rows=[...document.querySelectorAll('#findings tbody tr[data-severity]')];
buttons.forEach(b=>b.addEventListener('click',()=>{{buttons.forEach(x=>x.classList.remove('active'));b.classList.add('active');const f=b.dataset.filter;rows.forEach(r=>r.style.display=(f==='ALL'||r.dataset.severity===f)?'':'none')}}));
document.querySelectorAll('th[data-sort]').forEach(h=>h.addEventListener('click',()=>{{const i=Number(h.dataset.sort),t=h.closest('table').querySelector('tbody');rows.sort((a,b)=>a.cells[i].innerText.localeCompare(b.cells[i].innerText));rows.forEach(r=>t.appendChild(r))}}));
</script></body></html>'''
