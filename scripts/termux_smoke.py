#!/usr/bin/env python3
"""Local smoke test for a Termux installation. No network requests."""
from __future__ import annotations
import importlib.util, platform, sys

CORE = ["aiohttp", "httpx", "aiosqlite", "rich", "click", "bs4", "dotenv", "colorama"]
OPTIONAL = ["pydantic", "yaml", "lxml", "sqlalchemy", "reportlab", "PIL", "playwright"]

print(f"Python: {platform.python_version()} | platform={platform.platform()}")
missing=[]
for name in CORE:
    ok=importlib.util.find_spec(name) is not None
    print(f"CORE   {'OK' if ok else 'MISS'} {name}")
    if not ok: missing.append(name)
for name in OPTIONAL:
    ok=importlib.util.find_spec(name) is not None
    print(f"OPT    {'OK' if ok else 'SKIP'} {name}")
print(f"Core status: {'PASS' if not missing else 'FAIL: ' + ', '.join(missing)}")
sys.exit(0 if not missing else 1)
