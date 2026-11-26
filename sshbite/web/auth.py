"""Login, sessions, CSRF, user lockout and per-IP rate limit (spec 8.1).

- Passwords: argon2id (sshbite.users).
- User lockout: 5 failures within 15 min lock the user for 15 min (app_user.failed_logins / locked_until).
  The 6th attempt is answered with error.code = "account_locked" and locked_until.
- Unknown user names behave like existing ones: same argon2 work, same "bad_credentials", and they "lock"
  after 5 failures too (in memory), so the answer never reveals whether a user exists.
- Per IP: 20 failures within 15 min -> 429 for every further login attempt from that address.
- Session token: 32 random bytes, stored only as SHA-256; cookie sshbite_session (HttpOnly, SameSite=Strict,
  Secure under TLS); every session has its own CSRF token.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone

from ..users import hasher, verify_password

COOKIE = "sshbite_session"
WINDOW_S = 15 * 60
USER_MAX_FAILURES = 5
IP_MAX_FAILURES = 20
LOCK_S = 15 * 60

# a valid argon2id hash of a random password: unknown users cost the same verify time
_DUMMY_HASH = hasher().hash(secrets.token_hex(16))


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii", "replace")).hexdigest()


class LoginResult:
    def __init__(self, ok: bool, code: str = "", user_id: int | None = None, locked_until: str | None = None):
        self.ok = ok
        self.code = code
        self.user_id = user_id
        self.locked_until = locked_until


class Guard:
    """In-process failure windows (the lock itself is persisted in app_user.locked_until)."""

    def __init__(self, clock=time.time):
        self.clock = clock
        self._lock = threading.Lock()
        self._ip: dict[str, deque] = {}
        self._user: dict[str, deque] = {}
        self._ghost_locked: dict[str, float] = {}

    def _prune(self, d: deque, now: float) -> None:
        while d and now - d[0] > WINDOW_S:
            d.popleft()

    def ip_blocked(self, ip: str) -> bool:
        with self._lock:
            now = self.clock()
            d = self._ip.get(ip)
            if not d:
                return False
            self._prune(d, now)
            return len(d) >= IP_MAX_FAILURES

    def ip_failure(self, ip: str) -> None:
        with self._lock:
            self._ip.setdefault(ip, deque()).append(self.clock())

    def user_failure(self, name: str) -> int:
        """Record a failure; return the number of failures in the window."""
        with self._lock:
            now = self.clock()
            d = self._user.setdefault(name, deque())
            self._prune(d, now)
            d.append(now)
            return len(d)

    def user_reset(self, name: str) -> None:
        with self._lock:
            self._user.pop(name, None)
            self._ghost_locked.pop(name, None)

    def ghost_lock(self, name: str, until: float) -> None:
        with self._lock:
            self._ghost_locked[name] = until

    def ghost_locked_until(self, name: str) -> float | None:
        with self._lock:
            u = self._ghost_locked.get(name)
            if u is not None and u <= self.clock():
                self._ghost_locked.pop(name, None)
                return None
            return u


def check_login(conn: sqlite3.Connection, guard: Guard, username: str, password: str) -> LoginResult:
    now = datetime.fromtimestamp(guard.clock(), timezone.utc)
    key = username.strip()
    row = conn.execute("SELECT id, pw_hash, failed_logins, locked_until FROM app_user WHERE username=?",
                       (key,)).fetchone()
    if row is None:
        until = guard.ghost_locked_until(key)
        if until is not None:
            return LoginResult(False, "account_locked",
                               locked_until=_iso(datetime.fromtimestamp(until, timezone.utc)))
        verify_password(_DUMMY_HASH, password)  # same cost as a real check
        n = guard.user_failure(key)
        if n >= USER_MAX_FAILURES:
            guard.ghost_lock(key, guard.clock() + LOCK_S)
        return LoginResult(False, "bad_credentials")
    locked = _parse(row["locked_until"])
    if locked is not None and locked > now:
        return LoginResult(False, "account_locked", locked_until=row["locked_until"])
    if verify_password(row["pw_hash"], password):
        conn.execute("UPDATE app_user SET failed_logins=0, locked_until=NULL WHERE id=?", (row["id"],))
        guard.user_reset(key)
        return LoginResult(True, user_id=row["id"])
    n = guard.user_failure(key)
    if n >= USER_MAX_FAILURES:
        until = _iso(now + timedelta(seconds=LOCK_S))
        conn.execute("UPDATE app_user SET failed_logins=?, locked_until=? WHERE id=?", (n, until, row["id"]))
        guard.user_reset(key)
    else:
        conn.execute("UPDATE app_user SET failed_logins=?, locked_until=NULL WHERE id=?", (n, row["id"]))
    return LoginResult(False, "bad_credentials")


def create_session(conn: sqlite3.Connection, user_id: int, hours: float) -> tuple[str, str, str]:
    """Return (token, csrf_token, expires_at). Only the token's SHA-256 is stored."""
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires = _iso(now + timedelta(hours=hours))
    conn.execute("DELETE FROM session WHERE expires_at < ?", (_iso(now),))
    conn.execute("INSERT INTO session(token_sha256, user_id, csrf_token, created_at, expires_at) VALUES (?,?,?,?,?)",
                 (token_hash(token), user_id, csrf, _iso(now), expires))
    return token, csrf, expires


def load_session(conn: sqlite3.Connection, token: str | None) -> sqlite3.Row | None:
    if not token or len(token) > 256:
        return None
    row = conn.execute(
        "SELECT s.token_sha256, s.user_id, s.csrf_token, s.expires_at, u.username FROM session s"
        " JOIN app_user u ON u.id = s.user_id WHERE s.token_sha256=?", (token_hash(token),)).fetchone()
    if row is None:
        return None
    if row["expires_at"] < _iso(datetime.now(timezone.utc)):
        conn.execute("DELETE FROM session WHERE token_sha256=?", (row["token_sha256"],))
        return None
    return row


def csrf_ok(session: sqlite3.Row, header: str | None) -> bool:
    return bool(header) and hmac.compare_digest(session["csrf_token"].encode(), header.encode("utf-8", "replace"))


def delete_session(conn: sqlite3.Connection, token: str | None) -> None:
    if token:
        conn.execute("DELETE FROM session WHERE token_sha256=?", (token_hash(token),))
