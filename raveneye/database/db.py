from __future__ import annotations
from pathlib import Path
import asyncio, sqlite3
try:
    import aiosqlite
except ImportError:  # compatibility for minimal source checkouts
    aiosqlite=None
SCHEMA='''
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT,target TEXT NOT NULL,started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,finished_at TEXT,mode TEXT NOT NULL DEFAULT 'passive',risk_score REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS endpoints(id INTEGER PRIMARY KEY AUTOINCREMENT,scan_id INTEGER NOT NULL,url TEXT NOT NULL,status INTEGER,content_type TEXT,FOREIGN KEY(scan_id) REFERENCES scans(id));
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY AUTOINCREMENT,scan_id INTEGER NOT NULL,target TEXT NOT NULL,severity TEXT NOT NULL,name TEXT NOT NULL,url TEXT NOT NULL,evidence TEXT,remediation TEXT,confidence TEXT,cwe TEXT,cve TEXT,FOREIGN KEY(scan_id) REFERENCES scans(id));
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);
CREATE TABLE IF NOT EXISTS finding_history(fingerprint TEXT PRIMARY KEY,target TEXT NOT NULL,name TEXT NOT NULL,severity TEXT NOT NULL,confidence TEXT NOT NULL,first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,occurrences INTEGER NOT NULL DEFAULT 1);
CREATE INDEX IF NOT EXISTS idx_finding_history_target ON finding_history(target);
CREATE INDEX IF NOT EXISTS idx_finding_history_last_seen ON finding_history(last_seen);
'''
class _FallbackCursor:
    def __init__(self, cur): self.cur=cur; self.lastrowid=cur.lastrowid
    async def fetchone(self): return await asyncio.to_thread(self.cur.fetchone)
    async def fetchall(self): return await asyncio.to_thread(self.cur.fetchall)
class _FallbackDB:
    def __init__(self,path): self.conn=sqlite3.connect(path, check_same_thread=False)
    async def executescript(self,sql): await asyncio.to_thread(self.conn.executescript,sql)
    async def execute(self,sql,params=()): return _FallbackCursor(await asyncio.to_thread(self.conn.execute,sql,params))
    async def commit(self): await asyncio.to_thread(self.conn.commit)
    async def close(self): await asyncio.to_thread(self.conn.close)
async def init_db(path='data/raveneye.db'):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    db=await aiosqlite.connect(path) if aiosqlite else _FallbackDB(path)
    await db.executescript(SCHEMA); await db.commit(); return db
async def create_scan(db,target,mode='passive'):
    cur=await db.execute('INSERT INTO scans(target,mode) VALUES (?,?)',(target,mode)); await db.commit(); return cur.lastrowid
async def add_endpoint(db,scan_id,url,status=None,content_type=None):
    await db.execute('INSERT INTO endpoints(scan_id,url,status,content_type) VALUES (?,?,?,?)',(scan_id,url,status,content_type)); await db.commit()
async def add_finding(db,scan_id,target,finding):
    await db.execute('INSERT INTO findings(scan_id,target,severity,name,url,evidence,remediation,confidence,cwe,cve) VALUES (?,?,?,?,?,?,?,?,?,?)',
        (scan_id,target,finding.get('severity','INFO'),finding.get('name','Finding'),finding.get('url',target),str(finding.get('evidence',''))[:500],finding.get('remediation',''),finding.get('confidence','MEDIUM'),finding.get('cwe'),finding.get('cve'))); await db.commit()
async def finish_scan(db,scan_id,risk_score=0.0):
    await db.execute('UPDATE scans SET finished_at=CURRENT_TIMESTAMP,risk_score=? WHERE id=?',(risk_score,scan_id)); await db.commit()
