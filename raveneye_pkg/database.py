from __future__ import annotations

"""Persistência leve e cache local da RavenEye 6.6.6.

O módulo usa somente a biblioteca padrão. O banco é criado/migrado no startup
e guarda apenas metadados/cache, nunca credenciais em claro.
"""

import json
import hashlib
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

LOGGER = logging.getLogger("RavenEye.database")
SCHEMA_VERSION = 2
_DEFAULT_DB = Path("data") / "raveneye.db"

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS fingerprint_cache (
    fingerprint TEXT PRIMARY KEY,
    product TEXT NOT NULL,
    version TEXT,
    payload TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_cache (
    cache_key TEXT PRIMARY KEY,
    product TEXT,
    version TEXT,
    payload TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS exploitdb_cache (
    cache_key TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_cache (
    cache_key TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    mode TEXT NOT NULL,
    started_at REAL NOT NULL,
    elapsed REAL NOT NULL,
    risk_score REAL NOT NULL DEFAULT 0,
    summary TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    category TEXT NOT NULL,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    target TEXT NOT NULL,
    url TEXT,
    parameter TEXT,
    evidence TEXT,
    remediation TEXT,
    cwe TEXT,
    cve TEXT,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    UNIQUE(scan_id, fingerprint),
    FOREIGN KEY(scan_id) REFERENCES scan_runs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);

CREATE INDEX IF NOT EXISTS idx_cve_product_version
    ON cve_cache(product, version);

CREATE INDEX IF NOT EXISTS idx_scan_expires
    ON scan_cache(expires_at);
"""

_CONN: sqlite3.Connection | None = None
_LOCK = threading.RLock()


def _db_path(config: dict[str, Any] | None = None) -> Path:
    cfg = config or {}
    raw = cfg.get("database_path", str(_DEFAULT_DB))
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return path


def initialize(config: dict[str, Any] | None = None) -> Path:
    """Cria/verifica o banco e executa migrações idempotentes."""
    global _CONN
    path = _db_path(config)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        if _CONN is None:
            _CONN = sqlite3.connect(str(path), timeout=10, check_same_thread=False)
            _CONN.row_factory = sqlite3.Row
        conn = _CONN
        conn.executescript(_SCHEMA)
        current = conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()
        if current is None:
            conn.execute(
                "INSERT INTO meta(key,value) VALUES('schema_version',?)",
                (str(SCHEMA_VERSION),),
            )
        elif int(current["value"]) < SCHEMA_VERSION:
            # Mantemos migrações incrementais aqui para futuras versões.
            conn.execute(
                "UPDATE meta SET value=? WHERE key='schema_version'",
                (str(SCHEMA_VERSION),),
            )
        conn.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES('last_startup',?)",
            (str(int(time.time())),),
        )
        conn.commit()
    return path


def integrity_check() -> bool:
    with _LOCK:
        if _CONN is None:
            raise RuntimeError("Banco ainda não inicializado")
        row = _CONN.execute("PRAGMA integrity_check").fetchone()
        return bool(row and row[0] == "ok")


def close() -> None:
    global _CONN
    with _LOCK:
        if _CONN is not None:
            _CONN.close()
            _CONN = None


def _require() -> sqlite3.Connection:
    if _CONN is None:
        initialize()
    assert _CONN is not None
    return _CONN


def _put(table: str, key: str, payload: Any, **extra: Any) -> None:
    now = int(time.time())
    conn = _require()
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    with _LOCK:
        if table == "fingerprint_cache":
            conn.execute(
                """INSERT OR REPLACE INTO fingerprint_cache
                   (fingerprint,product,version,payload,updated_at)
                   VALUES(?,?,?,?,?)""",
                (key, extra.get("product", ""), extra.get("version"), data, now),
            )
        elif table == "cve_cache":
            conn.execute(
                """INSERT OR REPLACE INTO cve_cache
                   (cache_key,product,version,payload,updated_at)
                   VALUES(?,?,?,?,?)""",
                (key, extra.get("product", ""), extra.get("version"), data, now),
            )
        elif table == "exploitdb_cache":
            conn.execute(
                """INSERT OR REPLACE INTO exploitdb_cache
                   (cache_key,payload,updated_at) VALUES(?,?,?)""",
                (key, data, now),
            )
        elif table == "scan_cache":
            conn.execute(
                """INSERT OR REPLACE INTO scan_cache
                   (cache_key,payload,expires_at) VALUES(?,?,?)""",
                (key, data, int(extra.get("expires_at", now + 3600))),
            )
        else:
            raise ValueError(table)
        conn.commit()


def _get(table: str, key: str) -> Any | None:
    conn = _require()
    with _LOCK:
        if table == "fingerprint_cache":
            row = conn.execute(
                "SELECT payload FROM fingerprint_cache WHERE fingerprint=?", (key,)
            ).fetchone()
        elif table == "cve_cache":
            row = conn.execute(
                "SELECT payload FROM cve_cache WHERE cache_key=?", (key,)
            ).fetchone()
        elif table == "exploitdb_cache":
            row = conn.execute(
                "SELECT payload FROM exploitdb_cache WHERE cache_key=?", (key,)
            ).fetchone()
        elif table == "scan_cache":
            row = conn.execute(
                "SELECT payload,expires_at FROM scan_cache WHERE cache_key=?", (key,)
            ).fetchone()
            if row and int(row["expires_at"]) < int(time.time()):
                conn.execute("DELETE FROM scan_cache WHERE cache_key=?", (key,))
                conn.commit()
                return None
        else:
            raise ValueError(table)
        return json.loads(row["payload"]) if row else None


def put_fingerprint(key: str, payload: Any, product: str = "", version: str | None = None) -> None:
    _put("fingerprint_cache", key, payload, product=product, version=version)


def get_fingerprint(key: str) -> Any | None:
    return _get("fingerprint_cache", key)


def put_cve(key: str, payload: Any, product: str = "", version: str | None = None) -> None:
    _put("cve_cache", key, payload, product=product, version=version)


def get_cve(key: str) -> Any | None:
    return _get("cve_cache", key)


def put_exploitdb(key: str, payload: Any) -> None:
    _put("exploitdb_cache", key, payload)


def get_exploitdb(key: str) -> Any | None:
    return _get("exploitdb_cache", key)


def put_scan(key: str, payload: Any, ttl: int = 3600) -> None:
    _put("scan_cache", key, payload, expires_at=int(time.time()) + max(1, ttl))


def get_scan(key: str) -> Any | None:
    return _get("scan_cache", key)


def save_scan_with_findings(result: dict[str, Any]) -> int:
    """Persiste uma execução e suas findings; não grava segredos em claro."""
    conn = _require(); now = int(time.time())
    summary = json.dumps(result.get("summary", {}), ensure_ascii=False, sort_keys=True)
    with _LOCK:
        cur = conn.execute(
            "INSERT INTO scan_runs(target,mode,started_at,elapsed,risk_score,summary,created_at) VALUES(?,?,?,?,?,?,?)",
            (str(result.get("target", "")), str(result.get("mode", "solo")), float(result.get("started_at", now)),
             float(result.get("elapsed", 0)), float(result.get("risk_score", 0)), summary, now),
        )
        scan_id = int(cur.lastrowid)
        for item in result.get("findings", []):
            evidence = str(item.get("evidence", ""))[:500]
            fp = hashlib.sha256((str(item.get("category",""))+"|"+str(item.get("url",""))+"|"+str(item.get("parameter",""))+"|"+evidence).encode()).hexdigest()
            conn.execute(
                """INSERT OR IGNORE INTO findings
                (scan_id,fingerprint,category,name,severity,confidence,target,url,parameter,evidence,remediation,cwe,cve,first_seen,last_seen)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (scan_id, fp, str(item.get("category","")), str(item.get("name","")), str(item.get("severity","INFO")),
                 str(item.get("confidence","LOW")), str(item.get("target", result.get("target",""))), str(item.get("url","")),
                 str(item.get("parameter","")), evidence, str(item.get("recommendation",""))[:500], str(item.get("cwe","")),
                 str(item.get("cve","")), now, now),
            )
        conn.commit()
    return scan_id

def list_findings(target: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
    conn = _require()
    with _LOCK:
        if target:
            rows = conn.execute("SELECT * FROM findings WHERE target=? ORDER BY last_seen DESC LIMIT ?", (target, int(limit))).fetchall()
        else:
            rows = conn.execute("SELECT * FROM findings ORDER BY last_seen DESC LIMIT ?", (int(limit),)).fetchall()
        return [dict(r) for r in rows]
