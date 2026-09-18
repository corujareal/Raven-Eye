from __future__ import annotations
import json
from pathlib import Path

class ScanRepository:
    def __init__(self, path='raveneye.db'):
        self.path=Path(path)
    def init(self):
        import sqlite3
        with sqlite3.connect(self.path) as db:
            db.executescript("CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT,target TEXT NOT NULL,created_at TEXT NOT NULL,mode TEXT,risk_score REAL);CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY AUTOINCREMENT,scan_id INTEGER,name TEXT,severity TEXT,confidence TEXT,url TEXT,evidence TEXT,remediation TEXT,cwe TEXT,cve TEXT,FOREIGN KEY(scan_id) REFERENCES scans(id));")
    def save_scan(self,target,findings,risk_score,mode='scan',created_at=''):
        import sqlite3, datetime
        self.init(); created_at=created_at or datetime.datetime.now(datetime.timezone.utc).isoformat()
        with sqlite3.connect(self.path) as db:
            cur=db.execute('INSERT INTO scans(target,created_at,mode,risk_score) VALUES(?,?,?,?)',(target,created_at,mode,risk_score)); sid=cur.lastrowid
            for f in findings: db.execute('INSERT INTO findings(scan_id,name,severity,confidence,url,evidence,remediation,cwe,cve) VALUES(?,?,?,?,?,?,?,?,?)',(sid,f.get('name',''),f.get('severity','INFO'),f.get('confidence','MEDIUM'),f.get('url',''),str(f.get('evidence',''))[:500],f.get('remediation',''),f.get('cwe',''),f.get('cve','')))
        return sid
