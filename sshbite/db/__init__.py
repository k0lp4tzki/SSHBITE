"""SQLite access: connection setup (WAL, foreign keys, 0600/0700), migrations, small helpers."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path

from .. import __version__


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def migrations() -> list[tuple[int, str, str]]:
    out = []
    for entry in resources.files(__package__).joinpath("migrations").iterdir():
        m = re.match(r"^(\d{3})_.*\.sql$", entry.name)
        if m:
            out.append((int(m.group(1)), entry.name, entry.read_text(encoding="utf-8")))
    return sorted(out)


def latest_version() -> int:
    m = migrations()
    return m[-1][0] if m else 0


def _prepare_path(path: str) -> None:
    p = Path(path)
    d = p.parent
    if not d.exists():
        d.mkdir(parents=True, mode=0o700)
        os.chmod(d, 0o700)
    if not p.exists():
        fd = os.open(p, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
    try:
        if os.stat(p).st_mode & 0o077:
            os.chmod(p, 0o600)
    except PermissionError:
        pass


def connect(path: str, migrate: bool = True, create: bool = True) -> sqlite3.Connection:
    if path != ":memory:":
        if not create and not os.path.exists(path):
            raise FileNotFoundError(path)
        _prepare_path(path)
    conn = sqlite3.connect(path, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    if migrate:
        migrate_db(conn, path)
    return conn


def user_version(conn: sqlite3.Connection) -> int:
    return conn.execute("PRAGMA user_version").fetchone()[0]


def backup(conn: sqlite3.Connection, dest: str) -> None:
    """SQLite online backup; safe while the DB is in use. Destination gets mode 0600."""
    d = Path(dest)
    if d.exists():
        raise FileExistsError(dest)
    fd = os.open(d, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    target = sqlite3.connect(dest)
    try:
        conn.backup(target)
    finally:
        target.close()
    os.chmod(dest, 0o600)


def migrate_db(conn: sqlite3.Connection, path: str) -> int:
    cur = user_version(conn)
    pending = [m for m in migrations() if m[0] > cur]
    if not pending:
        return cur
    if cur > 0 and path != ":memory:":
        dest = f"{path}.pre-{__version__}"
        n = 1
        while os.path.exists(dest):
            dest = f"{path}.pre-{__version__}.{n}"
            n += 1
        backup(conn, dest)
    for num, _name, sql in pending:
        conn.execute("BEGIN IMMEDIATE")
        try:
            # executescript would COMMIT implicitly; run statements one by one inside the transaction
            for stmt in _split_sql(sql):
                conn.execute(stmt)
            conn.execute(f"PRAGMA user_version = {num}")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    return user_version(conn)


def _split_sql(sql: str) -> list[str]:
    lines = [ln for ln in sql.split("\n") if not ln.strip().startswith("--")]
    text = "\n".join(lines)
    return [s.strip() for s in text.split(";") if s.strip()]


def j(value) -> str:
    """Compact, deterministic JSON for storage."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, sort_keys=False)


def unj(value, default=None):
    if value is None:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


class Tx:
    """with Tx(conn): ... - BEGIN IMMEDIATE / COMMIT / ROLLBACK."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def __enter__(self):
        self.conn.execute("BEGIN IMMEDIATE")
        return self.conn

    def __exit__(self, exc_type, exc, tb):
        self.conn.execute("ROLLBACK" if exc_type else "COMMIT")
        return False
