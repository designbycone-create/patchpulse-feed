"""SQLite storage. One file, safe for concurrent threads."""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT 'unsure',
  check_token TEXT NOT NULL,
  dismissed TEXT NOT NULL DEFAULT '[]',
  added_at REAL NOT NULL,
  last_scan_at REAL,
  last_status TEXT NOT NULL DEFAULT 'pending',
  scanning INTEGER NOT NULL DEFAULT 0,
  alerted_keys TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  at REAL NOT NULL,
  status TEXT NOT NULL,
  result TEXT NOT NULL,
  rules_version TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS scans_site ON scans(site_id, at DESC);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at REAL NOT NULL,
  site_id INTEGER,
  kind TEXT NOT NULL,
  message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, expires REAL NOT NULL);
"""

KEEP_SCANS_PER_SITE = 60
KEEP_EVENTS = 1000


class Store:
    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript(SCHEMA)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def q(self, sql: str, args=()):
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def x(self, sql: str, args=()):
        with self._lock:
            cur = self._db.execute(sql, args)
            return cur.lastrowid

    # --- settings ---
    def get(self, key: str, default=None):
        rows = self.q("SELECT value FROM settings WHERE key=?", (key,))
        return json.loads(rows[0]["value"]) if rows else default

    def set(self, key: str, value):
        self.x("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
               (key, json.dumps(value)))

    def all_settings(self) -> dict:
        return {r["key"]: json.loads(r["value"]) for r in self.q("SELECT key,value FROM settings")}

    # --- sites ---
    def add_site(self, url: str, label: str, provider: str) -> int:
        return self.x("INSERT INTO sites(url,label,provider,check_token,added_at) VALUES(?,?,?,?,?)",
                      (url, label, provider, secrets.token_urlsafe(24), time.time()))

    def site(self, site_id: int):
        rows = self.q("SELECT * FROM sites WHERE id=?", (site_id,))
        return _site(rows[0]) if rows else None

    def sites(self):
        return [_site(r) for r in self.q("SELECT * FROM sites ORDER BY label COLLATE NOCASE, url")]

    def update_site(self, site_id: int, **fields):
        allowed = {"label", "provider", "dismissed", "last_scan_at", "last_status", "scanning",
                   "alerted_keys", "check_token"}
        sets, args = [], []
        for k, v in fields.items():
            if k not in allowed:
                raise ValueError(k)
            if isinstance(v, (list, dict)):
                v = json.dumps(v)
            sets.append(f"{k}=?")
            args.append(v)
        if sets:
            self.x(f"UPDATE sites SET {', '.join(sets)} WHERE id=?", (*args, site_id))

    def delete_site(self, site_id: int):
        self.x("DELETE FROM sites WHERE id=?", (site_id,))

    # --- scans ---
    def add_scan(self, site_id: int, status: str, result: dict, rules_version: str):
        sid = self.x("INSERT INTO scans(site_id,at,status,result,rules_version) VALUES(?,?,?,?,?)",
                     (site_id, time.time(), status, json.dumps(result), rules_version))
        self.x("""DELETE FROM scans WHERE site_id=? AND id NOT IN
                  (SELECT id FROM scans WHERE site_id=? ORDER BY at DESC LIMIT ?)""",
               (site_id, site_id, KEEP_SCANS_PER_SITE))
        return sid

    def latest_scan(self, site_id: int):
        rows = self.q("SELECT * FROM scans WHERE site_id=? ORDER BY at DESC LIMIT 1", (site_id,))
        if not rows:
            return None
        r = rows[0]
        return {"id": r["id"], "at": r["at"], "status": r["status"], "rules_version": r["rules_version"],
                **json.loads(r["result"])}

    def scan_history(self, site_id: int, limit: int = 30):
        return [{"at": r["at"], "status": r["status"]} for r in
                self.q("SELECT at,status FROM scans WHERE site_id=? ORDER BY at DESC LIMIT ?", (site_id, limit))]

    # --- events ---
    def event(self, kind: str, message: str, site_id: int | None = None):
        self.x("INSERT INTO events(at,site_id,kind,message) VALUES(?,?,?,?)", (time.time(), site_id, kind, message))
        self.x("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)", (KEEP_EVENTS,))

    def events(self, limit: int = 50):
        return [dict(r) for r in self.q("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))]

    # --- sessions ---
    def add_session(self, token_hash: str, ttl: float):
        self.x("INSERT INTO sessions(token_hash,expires) VALUES(?,?)", (token_hash, time.time() + ttl))
        self.x("DELETE FROM sessions WHERE expires < ?", (time.time(),))

    def session_valid(self, token_hash: str) -> bool:
        return bool(self.q("SELECT 1 FROM sessions WHERE token_hash=? AND expires > ?", (token_hash, time.time())))

    def drop_session(self, token_hash: str):
        self.x("DELETE FROM sessions WHERE token_hash=?", (token_hash,))

    def drop_all_sessions(self):
        self.x("DELETE FROM sessions")


def _site(r) -> dict:
    d = dict(r)
    d["dismissed"] = json.loads(d.get("dismissed") or "[]")
    d["alerted_keys"] = json.loads(d.get("alerted_keys") or "[]")
    d["scanning"] = bool(d.get("scanning"))
    return d
