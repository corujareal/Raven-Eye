CREATE INDEX IF NOT EXISTS idx_endpoints_url ON endpoints(url);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve);
