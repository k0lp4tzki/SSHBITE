"""ssh_config: Host blocks with HostName, User, Port, IdentityFile, ProxyJump; Match/Include recorded."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import cap


@dataclass
class SshConfigEntry:
    file: str
    line_no: int                # the Host line
    host_pattern: str
    hostname: str | None = None
    hostname_line: int | None = None
    user: str | None = None
    port: int | None = None
    identity_files: list[str] = field(default_factory=list)
    proxyjump: str | None = None
    proxyjump_line: int | None = None
    is_match: bool = False


def _split(line: str) -> tuple[str, str] | None:
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    m = re.match(r"^([A-Za-z][A-Za-z0-9]*)\s*(?:=\s*|\s+)(.*)$", s)
    if not m:
        m2 = re.match(r"^([A-Za-z][A-Za-z0-9]*)$", s)
        return (m2.group(1).lower(), "") if m2 else None
    val = m.group(2).strip()
    if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
        val = val[1:-1]
    return m.group(1).lower(), val


def parse(text: str, file: str) -> tuple[list[SshConfigEntry], list[tuple[int, str]]]:
    """Return (entries, includes). Settings before the first Host are a '*' block (line 0)."""
    entries: list[SshConfigEntry] = []
    includes: list[tuple[int, str]] = []
    cur = SshConfigEntry(file=file, line_no=0, host_pattern="*")
    pre = cur
    for no, line in enumerate(text.split("\n"), start=1):
        kv = _split(cap(line))
        if kv is None:
            continue
        k, v = kv
        if k == "host":
            cur = SshConfigEntry(file=file, line_no=no, host_pattern=v)
            entries.append(cur)
            continue
        if k == "match":
            cur = SshConfigEntry(file=file, line_no=no, host_pattern="match " + v, is_match=True)
            entries.append(cur)
            continue
        if k == "include":
            includes.extend((no, p) for p in v.split())
            continue
        # first obtained value wins
        if k == "hostname" and cur.hostname is None:
            cur.hostname, cur.hostname_line = v, no
        elif k == "user" and cur.user is None:
            cur.user = v
        elif k == "port" and cur.port is None:
            if v.isascii() and v.isdigit() and 0 < int(v) < 65536:
                cur.port = int(v)
        elif k == "identityfile":
            cur.identity_files.append(v)
        elif k == "proxyjump" and cur.proxyjump is None:
            cur.proxyjump, cur.proxyjump_line = v, no
    if pre.hostname or pre.user or pre.port or pre.identity_files or pre.proxyjump:
        entries.insert(0, pre)
    return entries, includes


def has_wildcard(pattern: str) -> bool:
    return any(c in pattern for c in "*?!") or "%" in pattern


def proxyjump_hops(value: str) -> list[tuple[str, int | None]]:
    """'[user@]host[:port],...' -> [(host, port)]; 'none' -> []."""
    if not value or value.lower() == "none":
        return []
    hops = []
    for hop in value.split(","):
        hop = hop.strip()
        if not hop:
            continue
        if hop.startswith("ssh://"):
            hop = hop[6:]
        if "@" in hop:
            hop = hop.rsplit("@", 1)[1]
        port = None
        m = re.match(r"^\[([^\]]+)\](?::([0-9]{1,5}))?$", hop, re.ASCII)
        if m:
            hop, port = m.group(1), int(m.group(2)) if m.group(2) else None
        elif hop.count(":") == 1:
            h, p = hop.split(":")
            if p.isascii() and p.isdigit() and len(p) <= 5:
                hop, port = h, int(p)
        if port is not None and not 0 < port < 65536:
            continue
        hops.append((hop, port))
    return hops
