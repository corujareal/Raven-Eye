CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY,
  target TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,
  risk_score REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS endpoints (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  method TEXT,
  status INTEGER,
  kind TEXT,
  UNIQUE(scan_id,url,method)
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  endpoint_id INTEGER REFERENCES endpoints(id) ON DELETE SET NULL,
  template_id TEXT,
  name TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence TEXT NOT NULL,
  evidence TEXT,
  remediation TEXT,
  cwe TEXT,
  cve TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan_severity ON findings(scan_id,severity);
CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);
