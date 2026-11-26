"""known_hosts lines: markers, patterns, negation, [host]:port, hashed entries."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from dataclasses import dataclass, field

from . import cap
from .keys import PublicKey, parse_key_fields


@dataclass
class KnownHostEntry:
    line_no: int
    raw: str
    marker: str | None = None          # cert-authority | revoked
    hashed: bool = False
    patterns: list[str] = field(default_factory=list)
    salt: bytes | None = None
    digest: bytes | None = None
    key: PublicKey | None = None
    error: str | None = None


_HASH_RE = re.compile(r"^\|1\|([A-Za-z0-9+/=]+)\|([A-Za-z0-9+/=]+)$")


def parse_line(line: str, line_no: int) -> KnownHostEntry | None:
    raw = cap(line.rstrip("\r\n"))
    s = raw.strip()
    if not s or s.startswith("#"):
        return None
    e = KnownHostEntry(line_no=line_no, raw=raw)
    parts = s.split(None)
    if parts[0].startswith("@"):
        m = parts[0][1:].lower()
        if m not in ("cert-authority", "revoked"):
            e.error = f"unknown marker {parts[0]}"
            return e
        e.marker = m
        parts = parts[1:]
    if len(parts) < 3:
        e.error = "too few fields"
        return e
    hosts, alg, b64 = parts[0], parts[1], parts[2]
    comment = " ".join(parts[3:])
    hm = _HASH_RE.match(hosts)
    if hm:
        try:
            e.salt = base64.b64decode(hm.group(1), validate=True)
            e.digest = base64.b64decode(hm.group(2), validate=True)
        except (binascii.Error, ValueError):
            e.error = "bad hashed host"
            return e
        e.hashed = True
        e.patterns = [hosts]
    else:
        e.patterns = [p for p in hosts.split(",") if p]
    e.key = parse_key_fields(alg, b64, comment)
    if e.key is None:
        e.error = "invalid key"
    return e


def parse(text: str) -> list[KnownHostEntry]:
    out = []
    for no, line in enumerate(text.split("\n"), start=1):
        e = parse_line(line, no)
        if e is not None:
            out.append(e)
    return out


def split_host_port(pattern: str, default_port: int = 22) -> tuple[str, int]:
    """'[h]:p' -> (h, p); 'h' -> (h, default)."""
    m = re.match(r"^\[([^\]]+)\]:(\d{1,5})$", pattern)
    if m:
        return m.group(1), int(m.group(2))
    return pattern, default_port


def is_plain_pattern(pattern: str) -> bool:
    return not pattern.startswith("!") and not any(c in pattern for c in "*?")


def hash_candidate(name: str, port: int) -> str:
    return name if port == 22 else f"[{name}]:{port}"


def hash_matches(entry: KnownHostEntry, candidate: str) -> bool:
    if not entry.hashed or entry.salt is None or entry.digest is None:
        return False
    mac = hmac.new(entry.salt, candidate.encode(), hashlib.sha1).digest()
    return hmac.compare_digest(mac, entry.digest)


def hash_host(name: str, salt: bytes) -> str:
    mac = hmac.new(salt, name.encode(), hashlib.sha1).digest()
    return "|1|" + base64.b64encode(salt).decode() + "|" + base64.b64encode(mac).decode()


def entry_matches_host(entry: KnownHostEntry, names: list[str], port: int = 22) -> bool:
    """OpenSSH host matching for strict mode: any positive pattern match, no negated match."""
    import fnmatch

    cands = [hash_candidate(n, port) for n in names]
    if entry.hashed:
        return any(hash_matches(entry, c) for c in cands)
    pos = False
    for p in entry.patterns:
        neg = p.startswith("!")
        pat = p[1:] if neg else p
        for c in cands:
            if fnmatch.fnmatchcase(c.lower(), pat.lower()):
                if neg:
                    return False
                pos = True
    return pos
