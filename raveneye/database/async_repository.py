from __future__ import annotations
import datetime as dt
import hashlib
import json
import sqlite3
import os
from pathlib import Path
from typing import Iterable, Mapping, Any

try:
    import aiosqlite
except ImportError:  # pragma: no cover
    aiosqlite = None

# The stdlib fallback uses short synchronous operations. In Python 3.14 on the
# supported runtime, sqlite work dispatched through asyncio.to_thread completed
# in its worker but did not wake the awaiting coroutine. aiosqlite remains an
# explicit opt-in for environments where its worker lifecycle has been verified.
USE_AIOSQLITE = os.getenv("RAVENEYE_ASYNC_DB_DRIVER", "stdlib").lower() == "aiosqlite"

_SCHEMA = '''
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    created_at TEXT NOT NULL,
    mode TEXT NOT NULL,
    risk_score REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    name TEXT,
    severity TEXT,
    confidence TEXT,
    url TEXT,
    evidence TEXT,
    remediation TEXT,
    cwe TEXT,
    cve TEXT,
    stage TEXT NOT NULL DEFAULT 'POSSIBLE',
    confidence_score INTEGER NOT NULL DEFAULT 0,
    observed_at TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    request_sha256 TEXT NOT NULL DEFAULT '',
    response_sha256 TEXT NOT NULL DEFAULT '',
    baseline_sha256 TEXT NOT NULL DEFAULT '',
    evidence_metadata TEXT NOT NULL DEFAULT '{}',
    cve_source TEXT NOT NULL DEFAULT '',
    cve_schema_version TEXT NOT NULL DEFAULT '',
    cve_retrieved_at TEXT NOT NULL DEFAULT '',
    cve_dataset_sha256 TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_url ON findings(url);
CREATE TABLE IF NOT EXISTS finding_history (
    fingerprint TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    occurrences INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_finding_history_target ON finding_history(target);
CREATE INDEX IF NOT EXISTS idx_finding_history_last_seen ON finding_history(last_seen);
'''

class AsyncScanRepository:
    """Async API for SQLite storage with persistent finding history.

    The default stdlib driver performs short local operations synchronously;
    set RAVENEYE_ASYNC_DB_DRIVER=aiosqlite to opt into the asynchronous driver.
    """
    def __init__(self, path: str | Path):
        self.path = Path(path)

    async def init(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if aiosqlite and USE_AIOSQLITE:
            async with aiosqlite.connect(self.path) as db:
                await db.executescript(_SCHEMA)
                cursor = await db.execute("PRAGMA table_info(findings)")
                present = {row[1] for row in await cursor.fetchall()}
                for name, declaration in self._evidence_columns().items():
                    if name not in present:
                        await db.execute(f"ALTER TABLE findings ADD COLUMN {name} {declaration}")
                await db.commit()
        else:
            self._init_sync()

    def _init_sync(self) -> None:
        with sqlite3.connect(self.path) as db:
            db.executescript(_SCHEMA)
            self._ensure_evidence_columns(db)
            db.commit()

    @staticmethod
    def _evidence_columns():
        return {
            "stage": "TEXT NOT NULL DEFAULT 'POSSIBLE'",
            "confidence_score": "INTEGER NOT NULL DEFAULT 0",
            "observed_at": "TEXT NOT NULL DEFAULT ''",
            "source": "TEXT NOT NULL DEFAULT ''",
            "request_sha256": "TEXT NOT NULL DEFAULT ''",
            "response_sha256": "TEXT NOT NULL DEFAULT ''",
            "baseline_sha256": "TEXT NOT NULL DEFAULT ''",
            "evidence_metadata": "TEXT NOT NULL DEFAULT '{}'",
            "cve_source": "TEXT NOT NULL DEFAULT ''",
            "cve_schema_version": "TEXT NOT NULL DEFAULT ''",
            "cve_retrieved_at": "TEXT NOT NULL DEFAULT ''",
            "cve_dataset_sha256": "TEXT NOT NULL DEFAULT ''",
        }

    @classmethod
    def _ensure_evidence_columns(cls, db):
        present = {row[1] for row in db.execute("PRAGMA table_info(findings)")}
        for name, declaration in cls._evidence_columns().items():
            if name not in present:
                db.execute(f"ALTER TABLE findings ADD COLUMN {name} {declaration}")

    @staticmethod
    def _fingerprint(target: str, finding: Mapping[str, Any]) -> str:
        raw = '|'.join(str(finding.get(k, '')) for k in ('id', 'template_id', 'name', 'url', 'parameter', 'cwe', 'cve'))
        return hashlib.sha256(f'{target}|{raw}'.encode('utf-8', 'replace')).hexdigest()

    @staticmethod
    def _row(f: Mapping[str, Any], scan_id: int):
        metadata = f.get("evidence_metadata") or {}
        return (scan_id, f.get('name', f.get('id', '')), f.get('severity', 'INFO'),
                f.get('confidence', 'MEDIUM'), f.get('url', ''), str(f.get('evidence', ''))[:500],
                f.get('remediation', ''), f.get('cwe', ''), f.get('cve', ''),
                f.get('stage', 'POSSIBLE'), int(f.get('confidence_score', 0)),
                f.get('observed_at', metadata.get('observed_at', '')), metadata.get('source', ''),
                (metadata.get('request') or {}).get('sha256', ''),
                (metadata.get('response') or {}).get('sha256', ''),
                (metadata.get('baseline') or {}).get('sha256', ''),
                json.dumps(metadata, ensure_ascii=False, sort_keys=True),
                f.get('cve_source', ''), f.get('cve_schema_version', ''),
                f.get('cve_retrieved_at', ''), f.get('cve_dataset_sha256', ''))

    async def save_scan(self, target: str, findings: Iterable[Mapping[str, Any]], risk_score: float,
                        *, mode: str = 'scan', created_at: str | None = None) -> int:
        await self.init()
        rows = list(findings)
        created_at = created_at or dt.datetime.now(dt.timezone.utc).isoformat()
        if aiosqlite and USE_AIOSQLITE:
            async with aiosqlite.connect(self.path) as db:
                cur = await db.execute(
                    'INSERT INTO scans(target,created_at,mode,risk_score) VALUES(?,?,?,?)',
                    (target, created_at, mode, float(risk_score)))
                scan_id = int(cur.lastrowid)
                await db.executemany(
                    '''INSERT INTO findings(scan_id,name,severity,confidence,url,evidence,remediation,cwe,cve,
                       stage,confidence_score,observed_at,source,request_sha256,response_sha256,
                       baseline_sha256,evidence_metadata,cve_source,cve_schema_version,
                       cve_retrieved_at,cve_dataset_sha256)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', [self._row(f, scan_id) for f in rows])
                for f in rows:
                    await self._history_upsert(db, target, f, created_at)
                await db.commit()
                return scan_id
        return self._save_sync(target, rows, risk_score, mode, created_at)

    async def _history_upsert(self, db, target: str, f: Mapping[str, Any], seen_at: str) -> None:
        fp = self._fingerprint(target, f)
        await db.execute('''INSERT INTO finding_history
            (fingerprint,target,name,severity,confidence,first_seen,last_seen,occurrences)
            VALUES(?,?,?,?,?,?,?,1)
            ON CONFLICT(fingerprint) DO UPDATE SET
              last_seen=excluded.last_seen,
              occurrences=finding_history.occurrences+1,
              severity=excluded.severity,
              confidence=excluded.confidence''',
            (fp, target, str(f.get('name', f.get('id', 'Finding'))),
             str(f.get('severity', 'INFO')), str(f.get('confidence', 'MEDIUM')), seen_at, seen_at))

    def _save_sync(self, target, rows, risk_score, mode, created_at) -> int:
        with sqlite3.connect(self.path) as db:
            cur = db.execute('INSERT INTO scans(target,created_at,mode,risk_score) VALUES(?,?,?,?)',
                             (target, created_at, mode, float(risk_score)))
            scan_id = int(cur.lastrowid)
            db.executemany('''INSERT INTO findings(scan_id,name,severity,confidence,url,evidence,remediation,cwe,cve,
                              stage,confidence_score,observed_at,source,request_sha256,response_sha256,
                              baseline_sha256,evidence_metadata,cve_source,cve_schema_version,
                              cve_retrieved_at,cve_dataset_sha256)
                              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', [self._row(f, scan_id) for f in rows])
            for f in rows:
                fp = self._fingerprint(target, f)
                db.execute('''INSERT INTO finding_history
                    (fingerprint,target,name,severity,confidence,first_seen,last_seen,occurrences)
                    VALUES(?,?,?,?,?,?,?,1)
                    ON CONFLICT(fingerprint) DO UPDATE SET
                      last_seen=excluded.last_seen,
                      occurrences=finding_history.occurrences+1,
                      severity=excluded.severity,
                      confidence=excluded.confidence''',
                    (fp, target, str(f.get('name', f.get('id', 'Finding'))),
                     str(f.get('severity', 'INFO')), str(f.get('confidence', 'MEDIUM')), created_at, created_at))
            db.commit()
            return scan_id

    async def recent_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        await self.init(); limit = max(1, min(int(limit), 200))
        if aiosqlite and USE_AIOSQLITE:
            async with aiosqlite.connect(self.path) as db:
                db.row_factory = sqlite3.Row
                cur = await db.execute('SELECT id,target,created_at,mode,risk_score FROM scans ORDER BY id DESC LIMIT ?', (limit,))
                return [dict(r) for r in await cur.fetchall()]
        return self._recent_sync(limit)

    def _recent_sync(self, limit: int) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            return [dict(r) for r in db.execute(
                'SELECT id,target,created_at,mode,risk_score FROM scans ORDER BY id DESC LIMIT ?', (limit,)).fetchall()]

    async def finding_history(self, target: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        await self.init(); limit = max(1, min(int(limit), 500))
        query = 'SELECT fingerprint,target,name,severity,confidence,first_seen,last_seen,occurrences FROM finding_history'
        params: tuple[Any, ...] = ()
        if target:
            query += ' WHERE target=?'; params = (target,)
        query += ' ORDER BY last_seen DESC LIMIT ?'; params += (limit,)
        if aiosqlite and USE_AIOSQLITE:
            async with aiosqlite.connect(self.path) as db:
                db.row_factory = sqlite3.Row
                cur = await db.execute(query, params)
                return [dict(r) for r in await cur.fetchall()]
        return self._history_sync(query, params)

    def _history_sync(self, query, params):
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            return [dict(r) for r in db.execute(query, params).fetchall()]
