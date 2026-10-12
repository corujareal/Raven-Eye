from __future__ import annotations
import sqlite3
from pathlib import Path
class MigrationError(RuntimeError): pass
def migrate(path:str,migrations_dir:str|None=None)->int:
    db_path=Path(path); db_path.parent.mkdir(parents=True,exist_ok=True); mdir=Path(migrations_dir) if migrations_dir else Path(__file__).with_name('migrations'); files=sorted(mdir.glob('*.sql')); conn=sqlite3.connect(db_path)
    try:
        conn.execute('CREATE TABLE IF NOT EXISTS schema_migrations(version TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)'); applied={r[0] for r in conn.execute('SELECT version FROM schema_migrations')}; count=0
        for f in files:
            version=f.name.split('_',1)[0]
            if version in applied: continue
            try:
                with conn:
                    conn.executescript(f.read_text(encoding='utf-8')); conn.execute('INSERT INTO schema_migrations(version) VALUES (?)',(version,))
            except sqlite3.Error as exc: raise MigrationError(f'Migration {f.name} failed: {exc}') from exc
            count+=1
        return count
    finally: conn.close()
