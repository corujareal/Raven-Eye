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
