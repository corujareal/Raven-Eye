from __future__ import annotations
import inspect, json
from pathlib import Path


def write_jsonl(rows, path=None):
    """Write sync or async iterables to JSONL; preserves legacy (rows, path) API."""
    if path is not None and isinstance(rows, (str, Path)) and not isinstance(path, (str, Path)):
        rows, path = path, rows
    elif path is None:
        path, rows = rows, []
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(rows, '__aiter__'):
        async def _write():
            count=0
            with p.open('w', encoding='utf-8') as fh:
                async for row in rows:
                    fh.write(json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n'); count += 1
            return count
        return _write()
    with p.open('w', encoding='utf-8') as fh:
        count=0
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n'); count += 1
    return count


def iter_jsonl(path: str | Path):
    with Path(path).open('r', encoding='utf-8') as fh:
        for line in fh:
            line=line.strip()
            if not line: continue
            try: yield json.loads(line)
            except json.JSONDecodeError: continue
