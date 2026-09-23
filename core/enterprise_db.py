"""Tables locales des modules entreprise. Les secrets n'y figurent que chiffrés."""

from __future__ import annotations

import sqlite3

from core.store import default_db_path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    host TEXT NOT NULL,
    username TEXT NOT NULL,
    kind TEXT NOT NULL,
    nonce BLOB NOT NULL,
    cipher BLOB NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_reports (
    id INTEGER PRIMARY KEY,
    credential_id INTEGER,
    host TEXT NOT NULL,
    created_at TEXT NOT NULL,
    packages_json TEXT NOT NULL DEFAULT '[]',
    compliance_json TEXT NOT NULL DEFAULT '[]',
    findings_json TEXT NOT NULL DEFAULT '[]',
    detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS agents (
    hostname TEXT PRIMARY KEY,
    os_name TEXT NOT NULL DEFAULT '',
    last_seen TEXT NOT NULL,
    package_count INTEGER NOT NULL DEFAULT 0,
    report_json TEXT NOT NULL DEFAULT '{}'
);
"""


def connect() -> sqlite3.Connection:
    path = default_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn
