from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .settings import settings

_LOCK = threading.RLock()
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS account (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    email TEXT NOT NULL,
    uid TEXT,
    id_token TEXT,
    refresh_token TEXT,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS cameras (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dsn TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'native',
    tutk_uid TEXT,
    password TEXT,
    auth_key TEXT,
    lan_ip TEXT,
    lan_port INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    sort INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    created_at REAL NOT NULL
);
"""


def db_path() -> Path:
    return settings.data_dir / "owlet-rtsp.db"


def conn() -> sqlite3.Connection:
    global _conn
    with _LOCK:
        if _conn is None:
            settings.data_dir.mkdir(parents=True, exist_ok=True)
            _conn = sqlite3.connect(db_path(), check_same_thread=False)
            _conn.row_factory = sqlite3.Row
            _conn.execute("PRAGMA journal_mode=WAL")
        return _conn


def init() -> None:
    with _LOCK, conn() as c:
        c.executescript(SCHEMA)
        c.execute("BEGIN")
        columns = {r["name"] for r in c.execute("PRAGMA table_info(account)")}
        for column in ("uid", "id_token", "refresh_token"):
            if column not in columns:
                c.execute(f"ALTER TABLE account ADD COLUMN {column} TEXT")
        if "refresh_token" not in columns:
            # Earlier password logins stored the Firebase refresh token here.
            if "ayla_refresh" in columns:
                c.execute("UPDATE account SET refresh_token = ayla_refresh WHERE uid IS NOT NULL")
            c.execute("DELETE FROM sessions")
        columns = {r["name"] for r in c.execute("PRAGMA table_info(cameras)")}
        for column, kind in (("lan_ip", "TEXT"), ("lan_port", "INTEGER"), ("seen_port", "INTEGER")):
            if column not in columns:
                c.execute(f"ALTER TABLE cameras ADD COLUMN {column} {kind}")
        c.execute("DELETE FROM cameras WHERE source = 'demo'")
        c.execute("UPDATE cameras SET source = 'native' WHERE source IS NOT 'native'")


def close() -> None:
    global _conn
    with _LOCK:
        if _conn is not None:
            _conn.close()
            _conn = None


def get_account() -> dict[str, Any] | None:
    with _LOCK:
        row = conn().execute(
            "SELECT email, uid, id_token, refresh_token FROM account WHERE id = 1"
        ).fetchone()
        return dict(row) if row else None


def set_account(email: str, uid: str, id_token: str, refresh_token: str | None) -> None:
    with _LOCK, conn() as c:
        c.execute("""
            INSERT INTO account (id, email, uid, id_token, refresh_token, updated_at)
            VALUES (1, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET email = excluded.email, uid = excluded.uid,
                id_token = excluded.id_token,
                refresh_token = COALESCE(excluded.refresh_token, account.refresh_token),
                updated_at = excluded.updated_at
        """, (email, uid, id_token, refresh_token, time.time()))


def unlink_account() -> None:
    with _LOCK, conn() as c:
        c.execute("DELETE FROM sessions")
        c.execute("DELETE FROM cameras")
        c.execute("DELETE FROM account")
        if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='discoveries'").fetchone():
            c.execute("DELETE FROM discoveries")


def list_cameras() -> list[dict[str, Any]]:
    with _LOCK:
        return [dict(r) for r in conn().execute("SELECT * FROM cameras ORDER BY sort, id")]


def get_camera(cam_id: int) -> dict[str, Any] | None:
    with _LOCK:
        row = conn().execute("SELECT * FROM cameras WHERE id = ?", (cam_id,)).fetchone()
        return dict(row) if row else None


def sync_camera(cam: dict[str, Any]) -> int:
    """Keep local settings when the account returns an existing camera."""
    with _LOCK, conn() as c:
        row = c.execute("""
            INSERT INTO cameras (dsn, name, source, tutk_uid, password, auth_key, created_at)
            VALUES (?, ?, 'native', ?, ?, ?, ?)
            ON CONFLICT(dsn) DO UPDATE SET
                tutk_uid = COALESCE(excluded.tutk_uid, cameras.tutk_uid),
                password = COALESCE(excluded.password, cameras.password),
                auth_key = COALESCE(excluded.auth_key, cameras.auth_key)
            RETURNING id
        """, (cam["dsn"], cam["name"], cam.get("tutk_uid"), cam.get("password"),
              cam.get("auth_key"), time.time())).fetchone()
        return row["id"]


def edit_camera(cam_id: int, fields: dict[str, Any]) -> None:
    changes = {k: fields[k] for k in ("name", "enabled", "lan_ip", "lan_port") if k in fields}
    if changes:
        assignments = ", ".join(f"{k} = ?" for k in changes)
        with _LOCK, conn() as c:
            c.execute(f"UPDATE cameras SET {assignments} WHERE id = ?", (*changes.values(), cam_id))


def remember_port(cam_id: int, port: int) -> None:
    """Store the UDP port the camera answered on. The next start tries it first."""
    with _LOCK, conn() as c:
        c.execute("UPDATE cameras SET seen_port = ? WHERE id = ?", (port, cam_id))


def delete_camera(cam_id: int) -> None:
    with _LOCK, conn() as c:
        c.execute("DELETE FROM cameras WHERE id = ?", (cam_id,))


def add_session(token: str) -> None:
    with _LOCK, conn() as c:
        c.execute("INSERT INTO sessions VALUES (?, ?)", (token, time.time()))


SESSION_AGE = 30 * 24 * 60 * 60


def has_session(token: str) -> bool:
    with _LOCK:
        return conn().execute(
            "SELECT 1 FROM sessions WHERE token = ? AND created_at > ?", (token, time.time() - SESSION_AGE)
        ).fetchone() is not None


def drop_session(token: str) -> None:
    with _LOCK, conn() as c:
        c.execute("DELETE FROM sessions WHERE token = ?", (token,))
