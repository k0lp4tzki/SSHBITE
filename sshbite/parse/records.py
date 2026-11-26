"""Parser for collector output records (spec 3.5). Robust against truncated or garbage input."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import cap


@dataclass
class FileRec:
    path: str
    uid: int | None
    owner: str | None
    mode: int | None
    mtime: int | None
    size: int | None
    account: str
    section: str
    lines: list[str] = field(default_factory=list)
    has_content: bool = False
    akf_for: str | None = None   # authorized keys file of this user


@dataclass
class Collected:
    version: str | None = None
    sha_short: str | None = None
    values: dict[str, list[str]] = field(default_factory=dict)
    cmds: dict[str, list[str]] = field(default_factory=dict)
    files: list[FileRec] = field(default_factory=list)
    private_headers: dict[str, str] = field(default_factory=dict)
    keygen: dict[str, dict[str, tuple[int | None, list[str]]]] = field(default_factory=dict)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)
    end_count: int | None = None
    garbage: int = 0
    truncated: bool = False

    @property
    def complete(self) -> bool:
        return self.end_count is not None

    def value(self, key: str, default: str = "") -> str:
        v = self.values.get(key)
        return v[0] if v else default

    def file(self, path: str) -> FileRec | None:
        for f in self.files:
            if f.path == path:
                return f
        return None


_SYM_RE = re.compile(r"^[-dlcbps][-rwxsStT]{9}[.+@]?$")


def parse_mode(s: str) -> int | None:
    if re.fullmatch(r"[0-7]{1,4}", s):
        return int(s, 8)
    if _SYM_RE.match(s):
        bits = 0
        perms = s[1:10]
        for i, c in enumerate(perms):
            if c in "rwxst":
                bits |= 1 << (8 - i)
        if perms[2] in "sS":
            bits |= 0o4000
        if perms[5] in "sS":
            bits |= 0o2000
        if perms[8] in "tT":
            bits |= 0o1000
        return bits
    return None


def _int(s: str) -> int | None:
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def parse(text: str, truncated: bool = False) -> Collected:
    c = Collected(truncated=truncated)
    section = ""
    sink: list[str] | None = None
    sink_file: FileRec | None = None
    user = ""
    pending_akf: str | None = None
    for raw in text.split("\n"):
        line = cap(raw.rstrip("\r"))
        if line.startswith("|"):
            if sink is not None:
                sink.append(line[1:])
                if sink_file is not None:
                    sink_file.has_content = True
            else:
                c.garbage += 1
            continue
        if not line:
            continue
        if line.startswith("#SSHBITE "):
            parts = line.split()
            c.version = parts[1] if len(parts) > 1 else None
            c.sha_short = parts[2] if len(parts) > 2 else None
            continue
        tag, _, rest = line.partition(" ")
        if tag == "#S":
            section = rest.strip()
            c.sections.append(section)
            sink, sink_file = None, None
            continue
        if tag == "#V":
            key, _, value = rest.partition("\t")
            sink, sink_file = None, None
            if key == "cmd":
                sink = c.cmds.setdefault(value, [])
            elif key == "user":
                user = value
                c.users.append(value)
            elif key == "akf":
                pending_akf = value
            else:
                c.values.setdefault(key, []).append(value)
            continue
        if tag == "#F":
            f = rest.split("\t")
            if len(f) < 7:
                c.garbage += 1
                sink, sink_file = None, None
                continue
            path = f[0]
            rec = FileRec(path=path, uid=_int(f[1]), owner=None if f[2] in ("?", "") else f[2],
                          mode=parse_mode(f[3]), mtime=_int(f[4]), size=_int(f[5]), account=f[6],
                          section=section)
            if pending_akf is not None and pending_akf == path:
                rec.akf_for = user
            pending_akf = None if pending_akf == path else pending_akf
            c.files.append(rec)
            sink, sink_file = rec.lines, rec
            continue
        if tag == "#H":
            path, _, first = rest.partition("\t")
            c.private_headers[path] = first
            sink, sink_file = None, None
            continue
        if tag == "#K":
            f = rest.split("\t", 3)
            if len(f) == 4 and f[1] in ("y", "l"):
                d = c.keygen.setdefault(f[0], {})
                rc, lines = d.get(f[1], (_int(f[2]), []))
                lines.append(f[3])
                d[f[1]] = (rc, lines)
            else:
                c.garbage += 1
            sink, sink_file = None, None
            continue
        if tag == "#X":
            path, _, reason = rest.partition("\t")
            c.skipped.append((path, reason))
            sink, sink_file = None, None
            continue
        if tag == "#END":
            c.end_count = _int(rest.strip()) if rest.strip() else 0
            sink, sink_file = None, None
            continue
        c.garbage += 1
        sink, sink_file = None, None
    return c


def ip_addresses(c: Collected) -> list[str]:
    """Interface addresses from `ip -o addr` / `hostname -I` / `ifconfig -a`, without loopback/link-local."""
    import ipaddress

    out: list[str] = []
    for line in c.cmds.get("ip-addr", []):
        toks = line.split()
        cands: list[str] = []
        if " inet " in f" {line} " or " inet6 " in f" {line} ":
            for i, t in enumerate(toks):
                if t in ("inet", "inet6") and i + 1 < len(toks):
                    cands.append(toks[i + 1].split("/")[0])
                elif t.startswith("addr:"):
                    cands.append(t[5:])
        else:
            cands = toks
        for cand in cands:
            try:
                ip = ipaddress.ip_address(cand.split("%")[0])
            except ValueError:
                continue
            if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
                continue
            s = str(ip)
            if s not in out:
                out.append(s)
    return out
