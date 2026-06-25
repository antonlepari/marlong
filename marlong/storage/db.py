"""SQLite persistence.

A single portable file (marlong.db by default). Easy to swap for
PostgreSQL later by reimplementing this module against the same calls.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List

from ..core.schema import Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    targets     TEXT NOT NULL,
    collectors  TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finding_count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    id          TEXT NOT NULL,
    scan_id     TEXT NOT NULL,
    source      TEXT,
    type        TEXT,
    target      TEXT,
    title       TEXT,
    url         TEXT,
    snippet     TEXT,
    severity    TEXT,
    tags        TEXT,
    entities    TEXT,
    metadata    TEXT,
    discovered_at TEXT,
    PRIMARY KEY (id, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev  ON findings(severity);
"""


class Store:
    def __init__(self, path: str = "marlong.db"):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def new_scan(self, scan_id: str, targets: List[str], collectors: List[str]) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO scans (id, targets, collectors, started_at) VALUES (?,?,?,?)",
            (scan_id, json.dumps(targets), json.dumps(collectors),
             datetime.now(timezone.utc).isoformat()),
        )
        self.conn.commit()

    def save_findings(self, scan_id: str, findings: Iterable[Finding]) -> int:
        rows = [
            (f.id, scan_id, f.source, f.type, f.target, f.title, f.url, f.snippet,
             f.severity, json.dumps(f.tags), json.dumps(f.entities),
             json.dumps(f.metadata), f.discovered_at)
            for f in findings
        ]
        self.conn.executemany(
            "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows
        )
        self.conn.execute("UPDATE scans SET finding_count=? WHERE id=?", (len(rows), scan_id))
        self.conn.commit()
        return len(rows)

    def close(self) -> None:
        self.conn.close()
