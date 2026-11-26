"""authorized_keys lines per sshd(8): options with quotes and escapes, from= matching."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from . import cap, ssh_pattern_match
from .keys import PublicKey, looks_like_alg, parse_key_fields

FLAG_OPTIONS = {
    "restrict", "cert-authority", "agent-forwarding", "no-agent-forwarding", "port-forwarding",
    "no-port-forwarding", "pty", "no-pty", "user-rc", "no-user-rc", "x11-forwarding",
    "no-x11-forwarding", "touch-required", "no-touch-required", "verify-required",
}
VALUE_OPTIONS = {"from", "command", "permitopen", "permitlisten", "principals", "expiry-time", "environment", "tunnel"}


@dataclass
class AuthorizedEntry:
    line_no: int
    raw: str
    key: PublicKey | None = None
    options: list[tuple[str, str | None]] = field(default_factory=list)
    error: str | None = None

    def opt(self, name: str) -> str | None:
        for k, v in self.options:
            if k == name:
                return v
        return None

    def has(self, name: str) -> bool:
        return any(k == name for k, _ in self.options)

    @property
    def from_patterns(self) -> list[str]:
        v = self.opt("from")
        return [p.strip() for p in v.split(",") if p.strip()] if v else []

    @property
    def command(self) -> str | None:
        return self.opt("command")

    @property
    def restrict(self) -> bool:
        return self.has("restrict")

    @property
    def cert_authority(self) -> bool:
        return self.has("cert-authority")

    @property
    def principals(self) -> str | None:
        return self.opt("principals")

    @property
    def expiry_time(self) -> str | None:
        return self.opt("expiry-time")

    def options_json(self) -> list[list]:
        return [[k, v] for k, v in self.options]


class _OptError(ValueError):
    pass


def _parse_options(s: str) -> tuple[list[tuple[str, str | None]], str]:
    """Parse the leading option string; return (options, rest of line)."""
    opts: list[tuple[str, str | None]] = []
    i, n = 0, len(s)
    while i < n:
        j = i
        while j < n and s[j] not in ',= \t':
            j += 1
        name = s[i:j].lower()
        if not name:
            raise _OptError("empty option")
        value: str | None = None
        if j < n and s[j] == "=":
            j += 1
            if j >= n or s[j] != '"':
                raise _OptError(f"option {name}: value must be quoted")
            j += 1
            buf = []
            while True:
                if j >= n:
                    raise _OptError(f"option {name}: missing end quote")
                c = s[j]
                if c == "\\" and j + 1 < n and s[j + 1] == '"':
                    buf.append('"')
                    j += 2
                    continue
                if c == '"':
                    j += 1
                    break
                buf.append(c)
                j += 1
            value = "".join(buf)
        opts.append((name, value))
        if j >= n:
            return opts, ""
        if s[j] == ",":
            i = j + 1
            continue
        if s[j] in " \t":
            return opts, s[j:].lstrip(" \t")
        raise _OptError(f"unexpected character after option {name}")
    return opts, ""


def parse_line(line: str, line_no: int) -> AuthorizedEntry | None:
    """Parse one line. None for blank/comment lines; an entry with error for malformed ones."""
    raw = cap(line.rstrip("\r\n"))
    s = raw.strip()
    if not s or s.startswith("#"):
        return None
    entry = AuthorizedEntry(line_no=line_no, raw=raw)
    first = s.split(None, 1)[0]
    rest = s
    if not looks_like_alg(first):
        try:
            entry.options, rest = _parse_options(s)
        except _OptError as exc:
            entry.error = str(exc)
            return entry
    parts = rest.split(None, 2)
    if len(parts) < 2:
        entry.error = "missing key"
        return entry
    key = parse_key_fields(parts[0], parts[1], parts[2].strip() if len(parts) > 2 else "")
    if key is None:
        entry.error = "invalid key"
        return entry
    entry.key = key
    return entry


def parse(text: str) -> list[AuthorizedEntry]:
    out = []
    for no, line in enumerate(text.split("\n"), start=1):
        e = parse_line(line, no)
        if e is not None:
            out.append(e)
    return out


# ---- from= ----------------------------------------------------------------------

def _pattern_matches(pat: str, names: list[str], ips: list[str]) -> bool:
    if "/" in pat:
        try:
            net = ipaddress.ip_network(pat, strict=False)
        except ValueError:
            return False
        for ip in ips:
            try:
                if ipaddress.ip_address(ip) in net:
                    return True
            except ValueError:
                pass
        return False
    return any(ssh_pattern_match(v, pat) for v in list(ips) + list(names))


def from_matches(patterns: list[str], names: list[str], ips: list[str]) -> bool:
    """sshd semantics: a negated match rejects; otherwise any positive match accepts."""
    positive = False
    for raw in patterns:
        neg = raw.startswith("!")
        pat = raw[1:] if neg else raw
        if not pat:
            continue
        if _pattern_matches(pat, names, ips):
            if neg:
                return False
            positive = True
    return positive


def literal_from_targets(patterns: list[str]) -> list[str]:
    """Literal names/IPs only: no wildcards, CIDRs or negations (crawl references)."""
    out = []
    for p in patterns:
        if p.startswith("!") or "/" in p or any(c in p for c in "*?[]"):
            continue
        out.append(p)
    return out
