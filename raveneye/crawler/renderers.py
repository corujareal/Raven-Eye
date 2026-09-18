from __future__ import annotations
from typing import Any
SPA_MARKERS=('id="root"','id="app"','id="__next"','id="__nuxt"','data-reactroot','ng-version=','vite','webpackJsonp')
def looks_like_spa(html:str)->bool:
    h=html.lower(); return sum(m in h for m in SPA_MARKERS)>=1 and len(html)<200_000
async def render(url:str,*,timeout_ms:int=5000,wait_until:str='domcontentloaded')->dict[str,Any]:
    try: from playwright.async_api import async_playwright
    except ImportError as exc: raise RuntimeError('Playwright is not installed; install the optional browser dependency') from exc
    async with async_playwright() as pw:
        browser=await pw.chromium.launch(headless=True)
        try:
            page=await browser.new_page(); await page.goto(url,wait_until=wait_until,timeout=timeout_ms)
            return {'url':page.url,'status':None,'content_type':'text/html','body':await page.content()}
        finally: await browser.close()
