from __future__ import annotations
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse
from ..core.targets import normalize_target
from typing import Any
from ..crawler.engine import Crawler
from ..crawler.filters import Scope
from ..database.async_repository import AsyncScanRepository
from ..reports.txt import render as render_txt
from ..reports.json import render as render_json
from ..reports.html import render as render_html
from ..scanner.pipeline import scan_urls
from .events import Event, EventBus

@dataclass(slots=True)
class ScanRun:
    target: str
    crawl_rows: list[dict[str, Any]] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    scan_id: int | None = None
    risk_score: float = 0.0
    @property
    def urls(self): return [str(r['url']) for r in self.crawl_rows if r.get('url') and not r.get('error')]

class RavenOrchestrator:
    """Single async execution path for discovery, inspection, persistence and reports."""
    def __init__(self, config, *, event_bus: EventBus | None = None):
        self.config=config; self.repo=AsyncScanRepository(config.database_path); self.events=event_bus or EventBus()

    async def _emit(self, topic, **data): await self.events.publish(Event(topic,data))

    async def full_passive(self, target: str, *, output_dir: str|Path, scope: Scope|None=None) -> ScanRun:
        started=time.monotonic(); out=Path(output_dir); out.mkdir(parents=True,exist_ok=True)
        active_scope=scope or Scope()
        await self._emit('scan.started', target=target, mode='full-passive')
        crawl_rows=await Crawler(self.config,scope=active_scope).crawl([target],str(out/'crawl.jsonl'))
        await self._emit('crawl.completed', target=target, urls=len(crawl_rows))
        urls=[r['url'] for r in crawl_rows if r.get('url') and not r.get('error')]
        results=await scan_urls(urls,self.config,scope=active_scope.domains or None)
        findings=[]; technologies=[]
        for result in results: findings.extend(result.get('findings',[])); technologies.extend(result.get('technologies',[]))
        findings=_dedupe(findings); technologies=sorted(set(map(str,technologies)))
        score=_risk_score(findings); duration=time.monotonic()-started
        run=ScanRun(target,crawl_rows,results,findings,technologies,duration,None,score)
        run.scan_id=await self.repo.save_scan(target,findings,score,mode='full-passive')
        (out/'report.txt').write_text(render_txt(target,findings,duration=f'{duration:.2f}s',mode='Full Passive Scan',endpoints=urls,technologies=technologies),encoding='utf-8')
        (out/'report.json').write_text(render_json(target,findings),encoding='utf-8')
        (out/'report.html').write_text(render_html(target,findings),encoding='utf-8')
        await self._emit('scan.completed',target=target,scan_id=run.scan_id,findings=len(findings),risk_score=score,duration=duration)
        return run

    async def full_passive_many(self, targets, *, output_dir: str|Path, scope: Scope|None=None) -> list[ScanRun]:
        """Run isolated passive scans for multiple explicit targets."""
        target_list=[]
        seen=set()
        for target in targets or []:
            value = normalize_target(str(target).strip())
            if value and value not in seen:
                seen.add(value); target_list.append(value)
            if len(target_list) >= int(getattr(self.config, 'max_targets', 50)):
                break
        base=Path(output_dir)
        results=[]
        for index,target in enumerate(target_list,1):
            target_host = (urlparse(target).hostname or f'target_{index}').replace(':', '_')
            target_out=base / f'{index:02d}_{target_host}' if len(target_list)>1 else base
            results.append(await self.full_passive(target, output_dir=target_out, scope=scope))
        return results

def _dedupe(findings):
    seen=set(); out=[]
    for f in findings:
        k=(f.get('id',f.get('name','')),f.get('url',''),f.get('parameter',''))
        if k not in seen: seen.add(k); out.append(f)
    return out

def _risk_score(findings):
    # Severity-weighted saturation: one confirmed critical issue is never diluted by INFO noise.
    weights={'CRITICAL':10,'HIGH':7,'MEDIUM':4,'LOW':1,'INFO':0}
    fs=[f for f in findings if str(f.get('severity','INFO')).upper()!='INFO']
    if not fs: return 0.0
    score=sum(weights.get(str(f.get('severity','INFO')).upper(),0) for f in fs)
    return round(min(10.0,score/2.0),1)
