from __future__ import annotations
import json, logging, re
from pathlib import Path
from typing import Any

_SECRET = re.compile(r'(?i)(authorization|cookie|set-cookie|api[-_]?key|token|password|secret)\s*[:=]\s*[^,;\s]+(?:\s+[^,;\s]+)?')

def redact(value: Any) -> str:
    text = str(value)
    return _SECRET.sub(lambda m: f'{m.group(1)}=<redacted>', text)

class JsonlHandler(logging.Handler):
    def __init__(self, path: str | Path):
        super().__init__(); self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True)
    def emit(self, record: logging.LogRecord) -> None:
        payload={'ts':record.created,'level':record.levelname,'logger':record.name,'message':redact(record.getMessage())}
        with self.path.open('a',encoding='utf-8') as f: f.write(json.dumps(payload,ensure_ascii=False)+'\n')

def get_logger(path: str='output/raveneye.jsonl') -> logging.Logger:
    log=logging.getLogger('raveneye')
    log.setLevel(logging.INFO)
    marker=str(Path(path).resolve())
    if not any(getattr(h,'raveneye_path',None)==marker for h in log.handlers):
        h=JsonlHandler(path); h.raveneye_path=marker; log.addHandler(h)
    return log
