from __future__ import annotations
import asyncio, json, pathlib, time
from urllib.parse import urlsplit
import click
from rich.console import Console
from ..core.config import load_config
from ..crawler.engine import Crawler
from ..crawler.filters import Scope
from ..scanner.pipeline import scan_url, scan_urls
from ..core.orchestrator import RavenOrchestrator
from ..core.targets import normalize_target, normalize_targets
from ..network.domains import host_matches_rule
from ..reports.txt import render as render_txt
from ..reports.json import render as render_json
from ..reports.html import render as render_html
from ..reports.csv import render as render_csv
from ..reports.markdown import render as render_markdown
from ..database.repository import ScanRepository
from .log_viewer import watch as watch_log, safe_delete, export_category

console=Console()

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def main():
    """RavenEye 6.6.6 — reconhecimento e auditoria autorizada."""

@main.command()
@click.argument('urls', nargs=-1, required=True)
@click.option('--output',default='output/crawl.jsonl')
@click.option('--max-pages',default=1000,type=int)
@click.option('--scope',multiple=True,help='Domínio ou curinga permitido; ex.: example.com ou *.example.com')
@click.option('--exclude',multiple=True,help='Padrões de URL ou domínio excluídos')
@click.option('--headless/--no-headless', default=None,
              help='Renderiza shells SPA com Playwright e registra XHR/fetch em escopo; desativado por padrão.')
def crawler(urls,output,max_pages,scope,exclude,headless):
    cfg=load_config(); cfg.max_pages=max_pages
    if headless is not None:
        cfg.headless_rendering = headless
    batch=normalize_targets(urls, enabled=cfg.multi_target_enabled, max_targets=cfg.max_targets)
    if not batch.urls: raise click.ClickException('Nenhum URL válido informado.')
    if not cfg.multi_target_enabled and len(urls) > 1: raise click.ClickException('Múltiplos alvos estão desativados nas configurações.')
    s=Scope(domains=set(scope) if scope else None, excludes=set(exclude))
    for index, target in enumerate(batch.urls):
        crawler_run = Crawler(cfg,scope=s)
        asyncio.run(crawler_run.crawl(
            [target], output, append_output=index > 0,
            retain_results=False, retain_forms=False,
        ))
        crawled = crawler_run.telemetry.counts.get('urls_crawled', 0)
        console.print(f'[green]Alvo concluído:[/green] {crawled} URLs ({target})')
    console.print(f'[green]Rastreamento concluído:[/green] {len(batch.urls)} alvo(s)')

@main.command('scan')
@click.argument('urls', nargs=-1, required=True)
@click.option('--crawl-file',default=None,help='JSONL; só são verificadas URLs do host informado ou de seus subdomínios')
@click.option('--report',type=click.Choice(['txt','json','html','csv','markdown','pdf']),default='txt',help='Formato do relatório')
@click.option('--output',default='output/report.txt')
def scan(urls,crawl_file,report,output):
    """Executa verificações passivas, limitadas e não destrutivas nos alvos informados."""
    cfg=load_config(); started=time.monotonic()
    batch=normalize_targets(urls, enabled=cfg.multi_target_enabled, max_targets=cfg.max_targets)
    if not batch.urls: raise click.ClickException('Nenhum URL válido informado.')
    if not cfg.multi_target_enabled and len(urls) > 1: raise click.ClickException('Múltiplos alvos estão desativados nas configurações.')
    if not click.confirm('Confirmo que tenho autorização para executar o scanner nestes alvos?', default=False):
        raise click.Abort()
    target=batch.urls[0]
    urls=list(batch.urls)
    seed_hosts = {
        (urlsplit(seed).hostname or "").lower().rstrip(".")
        for seed in batch.urls
    }
    ignored_crawl_rows = 0
    if crawl_file:
        crawl_path = pathlib.Path(crawl_file)
        if not crawl_path.is_file():
            raise click.ClickException(f'Arquivo de crawl não encontrado: {crawl_file}')
        for line_number, line in enumerate(crawl_path.read_text(encoding='utf-8').splitlines(), 1):
            if not line.strip():
                continue
            try:
                row=json.loads(line)
            except json.JSONDecodeError as exc:
                raise click.ClickException(f'JSONL inválido em {crawl_file}:{line_number}: {exc.msg}') from None
            if not isinstance(row, dict):
                raise click.ClickException(f'Registro de crawl em {crawl_file}:{line_number} precisa ser um objeto JSON.')
            candidate=row.get('url')
            if candidate:
                normalized = normalize_target(candidate) if isinstance(candidate, str) else ""
                candidate_host = (urlsplit(normalized).hostname or "").lower().rstrip(".") if normalized else ""
                if not normalized or not any(host_matches_rule(candidate_host, seed_host) for seed_host in seed_hosts):
                    ignored_crawl_rows += 1
                    continue
                if normalized not in urls:
                    urls.append(normalized)
    if ignored_crawl_rows:
        console.print(f'[yellow]Entradas de crawl inválidas ou fora do escopo ignoradas: {ignored_crawl_rows}[/yellow]')
    urls=urls[:max(1,cfg.max_pages)]
    results=asyncio.run(scan_urls(urls,cfg))
    findings=[]; technologies=[]
    for result in results:
        findings.extend(result.get('findings', []))
        technologies.extend(result.get('technologies', []))
    text=render_txt(target,findings,duration=f'{time.monotonic()-started:.2f}s',mode='Passive Scan')
    pathlib.Path(output).parent.mkdir(parents=True,exist_ok=True)
    if report=='txt': pathlib.Path(output).write_text(text,encoding='utf-8')
    elif report=='json': pathlib.Path(output).write_text(render_json(target,findings),encoding='utf-8')
    elif report=='html': pathlib.Path(output).write_text(render_html(target,findings),encoding='utf-8')
    elif report=='csv': pathlib.Path(output).write_text(render_csv(target,findings),encoding='utf-8')
    elif report=='markdown': pathlib.Path(output).write_text(render_markdown(target,findings),encoding='utf-8')
    else:
        from ..reports.pdf import render_pdf
        render_pdf({'target': {'domain': target}, 'findings': findings}, output)
    repo=ScanRepository(cfg.database_path); repo.save_scan(target,findings,0.0,mode='passive')
    console.print(f'[green]Verificação concluída:[/green] {len(urls)} URLs, {len(findings)} achados')

@main.command('inspect')
@click.argument('urls', nargs=-1, required=True)
@click.option('--output', default='output/inspect.json')
def inspect(urls, output):
    """Inspeciona as URLs informadas com verificações passivas e limitadas."""
    cfg=load_config(); batch=normalize_targets(urls, enabled=cfg.multi_target_enabled, max_targets=cfg.max_targets)
    if not batch.urls: raise click.ClickException('Nenhum URL válido informado.')
    if not cfg.multi_target_enabled and len(urls) > 1: raise click.ClickException('Múltiplos alvos estão desativados nas configurações.')
    if not click.confirm('Confirmo que tenho autorização para inspecionar estes alvos?', default=False):
        raise click.Abort()
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
    """Rastreia os alvos e executa inspeção passiva, persistência e geração de relatórios."""
    cfg=load_config(); cfg.max_pages=max_pages
    batch=normalize_targets(urls, enabled=cfg.multi_target_enabled, max_targets=cfg.max_targets)
    if not batch.urls: raise click.ClickException('Nenhum URL válido informado.')
    if not cfg.multi_target_enabled and len(urls) > 1: raise click.ClickException('Múltiplos alvos estão desativados nas configurações.')
    if not click.confirm('Confirmo que tenho autorização para executar crawler e scanner nestes alvos?', default=False):
        raise click.Abort()
    s=Scope(domains=set(scope) if scope else None, excludes=set(exclude))
    runs=asyncio.run(RavenOrchestrator(cfg).full_passive_many(batch.urls, output_dir=output_dir, scope=s))
    console.print(f'[green]Verificação completa concluída:[/green] {len(runs)} alvo(s), {sum(len(r.urls) for r in runs)} URLs, {sum(len(r.findings) for r in runs)} achados')


@main.command('log-watch')
@click.argument('path')
def log_watch(path):
    """Acompanha um arquivo de log do RavenEye até ser interrompido."""
    try: asyncio.run(watch_log(path))
    except KeyboardInterrupt: pass

@main.command('log-delete')
@click.argument('path')
@click.option('--confirm', prompt='Digite SIM para confirmar')
def log_delete(path, confirm):
    """Move um log para .raveneye_trash sem apagá-lo permanentemente."""
    dest=safe_delete(path, confirmation=confirm)
    console.print(f'[yellow]Movido para:[/yellow] {dest}')

@main.command('log-export')
@click.argument('path')
@click.argument('category')
@click.option('--output', required=True)
def log_export(path, category, output):
    """Exporta achados de uma categoria JSONL para CSV, JSONL ou PDF."""
    dest=export_category(path, category, output)
    console.print(f'[green]Exportado:[/green] {dest}')

@main.command('version')
def version(): console.print('RavenEye 6.6.6 — eu vejo você')

if __name__=='__main__': main()
