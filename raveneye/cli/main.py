from __future__ import annotations
import asyncio, json, pathlib, time
import click
from rich.console import Console
from ..core.config import load_config
from ..crawler.engine import Crawler
from ..crawler.filters import Scope
from ..scanner.pipeline import scan_url, scan_urls
from ..core.orchestrator import RavenOrchestrator
from ..core.targets import normalize_targets
from ..reports.txt import render as render_txt
from ..reports.json import render as render_json
from ..reports.html import render as render_html
from ..reports.csv import render as render_csv
from ..reports.markdown import render as render_markdown
from ..database.repository import ScanRepository
from .log_viewer import watch as watch_log, safe_delete, export_category

console=Console()

@click.group()
def main():
    """RavenEye 6.6.6 — I see you."""

@main.command()
@click.argument('urls', nargs=-1, required=True)
@click.option('--output',default='output/crawl.jsonl')
@click.option('--max-pages',default=1000,type=int)
@click.option('--scope',multiple=True,help='Allowed domain/wildcard, e.g. example.com or *.example.com')
@click.option('--exclude',multiple=True,help='Excluded URL/domain patterns')
def crawler(urls,output,max_pages,scope,exclude):
    cfg=load_config(); cfg.max_pages=max_pages
    batch=normalize_targets(urls, enabled=cfg.multi_target_enabled, max_targets=cfg.max_targets)
    if not batch.urls: raise click.ClickException('Nenhum URL válido informado.')
    if not cfg.multi_target_enabled and len(urls) > 1: raise click.ClickException('Múltiplos alvos estão desativados nas configurações.')
    s=Scope(domains=set(scope) if scope else None, excludes=set(exclude))
    rows=[]
    for target in batch.urls:
        rows.extend(asyncio.run(Crawler(cfg,scope=s).crawl([target],output)))
    console.print(f'[green]Crawl concluído:[/green] {len(rows)} URLs em {len(batch.urls)} alvo(s)')

@main.command('scan')
@click.argument('urls', nargs=-1, required=True)
@click.option('--crawl-file',default=None,help='JSONL produced by crawler')
@click.option('--report',type=click.Choice(['txt','json','html','csv','markdown','pdf']),default='txt')
@click.option('--output',default='output/report.txt')
def scan(urls,crawl_file,report,output):
    """Run bounded, non-destructive passive checks against explicit target(s)."""
    cfg=load_config(); started=time.monotonic()
    batch=normalize_targets(urls, enabled=cfg.multi_target_enabled, max_targets=cfg.max_targets)
    if not batch.urls: raise click.ClickException('Nenhum URL válido informado.')
    if not cfg.multi_target_enabled and len(urls) > 1: raise click.ClickException('Múltiplos alvos estão desativados nas configurações.')
    target=batch.urls[0]
    urls=list(batch.urls)
    if crawl_file and pathlib.Path(crawl_file).exists():
        for line in pathlib.Path(crawl_file).read_text(encoding='utf-8').splitlines():
            try:
                row=json.loads(line); candidate=row.get('url')
                if candidate and candidate not in urls: urls.append(candidate)
            except Exception: pass
    urls=urls[:max(1,cfg.max_pages)]
    results=asyncio.run(scan_urls(urls,cfg))
    findings=[]; technologies=[]
    for result in results:
        findings.extend(result.get('findings', []))
        technologies.extend(result.get('technologies', []))
    text=render_txt(url,findings,duration=f'{time.monotonic()-started:.2f}s',mode='Passive Scan')
    pathlib.Path(output).parent.mkdir(parents=True,exist_ok=True)
    if report=='txt': pathlib.Path(output).write_text(text,encoding='utf-8')
    elif report=='json': pathlib.Path(output).write_text(render_json(url,findings),encoding='utf-8')
    elif report=='html': pathlib.Path(output).write_text(render_html(url,findings),encoding='utf-8')
    elif report=='csv': pathlib.Path(output).write_text(render_csv(url,findings),encoding='utf-8')
    elif report=='markdown': pathlib.Path(output).write_text(render_markdown(url,findings),encoding='utf-8')
    else:
        from ..reports.pdf import render_pdf
        render_pdf({'target': {'domain': url}, 'findings': findings}, output)
    repo=ScanRepository(cfg.database_path); repo.save_scan(url,findings,0.0,mode='passive')
    console.print(f'[green]Scan concluído:[/green] {len(urls)} URLs, {len(findings)} findings')

@main.command('inspect')
@click.argument('urls', nargs=-1, required=True)
@click.option('--output', default='output/inspect.json')
def inspect(urls, output):
    """Inspect explicitly supplied URL(s) using bounded passive checks."""
    cfg=load_config(); batch=normalize_targets(urls, enabled=cfg.multi_target_enabled, max_targets=cfg.max_targets)
    if not batch.urls: raise click.ClickException('Nenhum URL válido informado.')
    if not cfg.multi_target_enabled and len(urls) > 1: raise click.ClickException('Múltiplos alvos estão desativados nas configurações.')
    results=[asyncio.run(scan_url(url, cfg)) for url in batch.urls]
    pathlib.Path(output).parent.mkdir(parents=True, exist_ok=True)
    payload=results[0] if len(results)==1 else {'targets':results}
    pathlib.Path(output).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
    console.print(f'[green]Inspeção salva:[/green] {output} ({len(batch.urls)} alvo(s))')

@main.command('full-scan')
@click.argument('urls', nargs=-1, required=True)
@click.option('--output-dir',default='output/full-scan')
@click.option('--max-pages',default=100,type=int)
@click.option('--scope',multiple=True)
@click.option('--exclude',multiple=True)
def full_scan(urls, output_dir, max_pages, scope, exclude):
    """Crawl then run bounded passive inspection, persistence and reports."""
    cfg=load_config(); cfg.max_pages=max_pages
    batch=normalize_targets(urls, enabled=cfg.multi_target_enabled, max_targets=cfg.max_targets)
    if not batch.urls: raise click.ClickException('Nenhum URL válido informado.')
    if not cfg.multi_target_enabled and len(urls) > 1: raise click.ClickException('Múltiplos alvos estão desativados nas configurações.')
    s=Scope(domains=set(scope) if scope else None, excludes=set(exclude))
    runs=asyncio.run(RavenOrchestrator(cfg).full_passive_many(batch.urls, output_dir=output_dir, scope=s))
    console.print(f'[green]Full scan concluído:[/green] {len(runs)} alvo(s), {sum(len(r.urls) for r in runs)} URLs, {sum(len(r.findings) for r in runs)} findings')


@main.command('log-watch')
@click.argument('path')
def log_watch(path):
    """Tail a RavenEye log until interrupted."""
    try: asyncio.run(watch_log(path))
    except KeyboardInterrupt: pass

@main.command('log-delete')
@click.argument('path')
@click.option('--confirm', prompt='Digite SIM para confirmar')
def log_delete(path, confirm):
    """Move a log to .raveneye_trash instead of permanently deleting it."""
    dest=safe_delete(path, confirmation=confirm)
    console.print(f'[yellow]Movido para:[/yellow] {dest}')

@main.command('log-export')
@click.argument('path')
@click.argument('category')
@click.option('--output', required=True)
def log_export(path, category, output):
    """Export findings from one JSONL category to CSV, JSONL or PDF."""
    dest=export_category(path, category, output)
    console.print(f'[green]Exportado:[/green] {dest}')

@main.command('version')
def version(): console.print('RavenEye 6.6.6 — I see you')

if __name__=='__main__': main()
