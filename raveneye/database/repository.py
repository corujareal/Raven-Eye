from __future__ import annotations
import json
from pathlib import Path

_EVIDENCE_COLUMNS = {
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

class ScanRepository:
    def __init__(self, path='raveneye.db'):
        self.path=Path(path)
    def init(self):
        import sqlite3
        with sqlite3.connect(self.path) as db:
            db.executescript("CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT,target TEXT NOT NULL,created_at TEXT NOT NULL,mode TEXT,risk_score REAL);CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY AUTOINCREMENT,scan_id INTEGER,name TEXT,severity TEXT,confidence TEXT,url TEXT,evidence TEXT,remediation TEXT,cwe TEXT,cve TEXT,FOREIGN KEY(scan_id) REFERENCES scans(id));")
            present = {row[1] for row in db.execute("PRAGMA table_info(findings)")}
            for name, declaration in _EVIDENCE_COLUMNS.items():
                if name not in present:
                    db.execute(f"ALTER TABLE findings ADD COLUMN {name} {declaration}")
    def save_scan(self,target,findings,risk_score,mode='scan',created_at=''):
        import sqlite3, datetime
        self.init(); created_at=created_at or datetime.datetime.now(datetime.timezone.utc).isoformat()
        with sqlite3.connect(self.path) as db:
            cur=db.execute('INSERT INTO scans(target,created_at,mode,risk_score) VALUES(?,?,?,?)',(target,created_at,mode,risk_score)); sid=cur.lastrowid
            for f in findings:
                metadata = f.get("evidence_metadata") or {}
                db.execute('''INSERT INTO findings(
                    scan_id,name,severity,confidence,url,evidence,remediation,cwe,cve,
                    stage,confidence_score,observed_at,source,request_sha256,response_sha256,
                    baseline_sha256,evidence_metadata,cve_source,cve_schema_version,
                    cve_retrieved_at,cve_dataset_sha256
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(
                    sid,f.get('name',''),f.get('severity','INFO'),f.get('confidence','MEDIUM'),
                    f.get('url',''),str(f.get('evidence',''))[:500],f.get('remediation',''),
                    f.get('cwe',''),f.get('cve',''),f.get('stage','POSSIBLE'),
                    int(f.get('confidence_score',0)),f.get('observed_at',metadata.get('observed_at','')),
                    metadata.get('source',''),(metadata.get('request') or {}).get('sha256',''),
                    (metadata.get('response') or {}).get('sha256',''),
                    (metadata.get('baseline') or {}).get('sha256',''),
                    json.dumps(metadata,ensure_ascii=False,sort_keys=True),
                    f.get('cve_source',''),f.get('cve_schema_version',''),
                    f.get('cve_retrieved_at',''),f.get('cve_dataset_sha256','')
                ))
        return sid
