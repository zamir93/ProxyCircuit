# ProxyCircuit v0.2.3 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
"""SQLite schema and connection helpers."""
import sqlite3
import time
from .settings import DB, BASE, CERTS, DEPLOY, ACME

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS admins (
 username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin', active INTEGER NOT NULL DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES admins(username) ON DELETE CASCADE,
 csrf TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS certificates (
 id TEXT PRIMARY KEY, label TEXT NOT NULL, domain TEXT NOT NULL, kind TEXT NOT NULL,
 fullchain_path TEXT, privkey_path TEXT, expires_at TEXT, status TEXT NOT NULL,
 error TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS hosts (
 id TEXT PRIMARY KEY, domain TEXT UNIQUE NOT NULL, upstream_scheme TEXT NOT NULL,
 upstream_host TEXT NOT NULL, upstream_port INTEGER NOT NULL, upstream_tls_name TEXT,
 websocket INTEGER DEFAULT 1, force_https INTEGER DEFAULT 0,
 certificate_id TEXT REFERENCES certificates(id) ON DELETE SET NULL, category TEXT NOT NULL DEFAULT '',
 upstream_host_header TEXT,
 enabled INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS streams (
 id TEXT PRIMARY KEY, label TEXT NOT NULL, protocol TEXT NOT NULL,
 listen_port INTEGER NOT NULL, target_host TEXT NOT NULL, target_port INTEGER NOT NULL,
 timeout_seconds INTEGER DEFAULT 300, enabled INTEGER DEFAULT 1,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(protocol, listen_port)
);
CREATE TABLE IF NOT EXISTS certificate_jobs (
 id TEXT PRIMARY KEY, cert_id TEXT NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
 domain TEXT NOT NULL, email TEXT NOT NULL,
 operation TEXT NOT NULL DEFAULT 'issue', status TEXT DEFAULT 'pending', error TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS certificate_cleanup (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL, fullchain_path TEXT, privkey_path TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS site_settings (
 id INTEGER PRIMARY KEY CHECK(id=1), fallback_html TEXT NOT NULL, updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, action TEXT NOT NULL,
 description TEXT NOT NULL DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""

def connect():
    BASE.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(DB), timeout=10)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    con.execute('PRAGMA busy_timeout=5000')
    return con

def init_db():
    for folder in (BASE, CERTS, DEPLOY, ACME):
        folder.mkdir(parents=True, exist_ok=True)
    con = connect()
    con.executescript(SCHEMA)
    # Idempotent migration for existing 0.1.3 SQLite installations.
    columns = {r[1] for r in con.execute('PRAGMA table_info(hosts)')}
    if 'upstream_tls_name' not in columns:
        con.execute('ALTER TABLE hosts ADD COLUMN upstream_tls_name TEXT')
    for table, name, ddl in (
        ('admins', 'role', "TEXT NOT NULL DEFAULT 'admin'"),
        ('admins', 'active', 'INTEGER NOT NULL DEFAULT 1'),
        ('hosts', 'category', "TEXT NOT NULL DEFAULT ''"),
        ('hosts', 'upstream_host_header', 'TEXT'),
        ('certificate_jobs', 'operation', "TEXT NOT NULL DEFAULT 'issue'"),
    ):
        columns = {r[1] for r in con.execute(f'PRAGMA table_info({table})')}
        if name not in columns:
            con.execute(f'ALTER TABLE {table} ADD COLUMN {name} {ddl}')
    con.execute('CREATE INDEX IF NOT EXISTS idx_hosts_category ON hosts(category)')
    con.execute('CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username)')
    con.execute('DELETE FROM sessions WHERE expires < ?', (int(time.time()),))
    con.commit()
    con.close()

def asdicts(rows):
    return [dict(x) for x in rows]

def audit(con, actor, action, description=''):
    con.execute('INSERT INTO audit(username,action,description) VALUES(?,?,?)',
                (actor, action, str(description)[:500]))
