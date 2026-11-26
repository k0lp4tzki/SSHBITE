"""UI logins in app_user (argon2id). The web package (P2) verifies with verify_password()."""

from __future__ import annotations

import re
import sqlite3

import click
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .db import utcnow

_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MIN_PASSWORD = 12


def hasher() -> PasswordHasher:
    return PasswordHasher()  # argon2id with the library's current recommended parameters


def validate_username(name: str) -> None:
    if not _USER_RE.match(name):
        raise click.UsageError("user names may contain letters, digits, '.', '_' and '-' (max 64)")


def add_user(conn: sqlite3.Connection, name: str, password: str) -> int:
    if len(password) < MIN_PASSWORD:
        raise ValueError("password too short")
    cur = conn.execute("INSERT INTO app_user(username, pw_hash, created_at, failed_logins) VALUES (?,?,?,0)",
                       (name, hasher().hash(password), utcnow()))
    return cur.lastrowid


def set_password(conn: sqlite3.Connection, name: str, password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise ValueError("password too short")
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("UPDATE app_user SET pw_hash=?, failed_logins=0, locked_until=NULL WHERE username=?",
                     (hasher().hash(password), name))
        conn.execute("DELETE FROM session WHERE user_id=(SELECT id FROM app_user WHERE username=?)", (name,))
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


def verify_password(pw_hash: str, password: str) -> bool:
    try:
        return hasher().verify(pw_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
