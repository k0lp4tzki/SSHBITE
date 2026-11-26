"""sshd: `sshd -T` output and sshd_config files (with Include and Match)."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

from . import cap

DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "pubkeyauthentication": "yes",
    "authorizedkeysfile": ".ssh/authorized_keys .ssh/authorized_keys2",
    "authorizedkeyscommand": "none",
    "trustedusercakeys": "none",
}
MULTI = {"allowusers", "denyusers", "allowgroups", "denygroups", "hostkey", "subsystem", "acceptenv",
         "listenaddress", "port", "include", "setenv", "hostcertificate", "permitopen", "permitlisten"}


@dataclass
class Setting:
    source: str      # sshd-T | parsed
    name: str
    value: str
    file: str | None = None
    line: int | None = None


def parse_sshd_t(lines: list[str]) -> list[Setting]:
    out = []
    for line in lines:
        s = cap(line).strip()
        if not s:
            continue
        parts = s.split(None, 1)
        out.append(Setting("sshd-T", parts[0].lower(), parts[1] if len(parts) > 1 else ""))
    return out


def parse_config(files: dict[str, list[str]], main: str = "/etc/ssh/sshd_config") -> list[Setting]:
    """Parse the main config and Include-d files that are present in `files`.
    Match blocks are stored as one setting 'match' with the raw block."""
    out: list[Setting] = []
    seen: set[str] = set()

    def do_file(path: str, depth: int) -> None:
        if path in seen or depth > 8 or path not in files:
            return
        seen.add(path)
        lines = files[path]
        i = 0
        while i < len(lines):
            line = cap(lines[i])
            s = line.strip()
            no = i + 1
            i += 1
            if not s or s.startswith("#"):
                continue
            m = re.match(r"^(\S+?)\s*(?:=\s*|\s+)(.*)$", s)
            name, value = (m.group(1).lower(), m.group(2).strip()) if m else (s.lower(), "")
            if name == "match":
                block = [s]
                while i < len(lines):
                    nxt = lines[i].strip()
                    if re.match(r"^match\b", nxt, re.I):
                        break
                    block.append(cap(lines[i]).rstrip())
                    i += 1
                out.append(Setting("parsed", "match", "\n".join(block).rstrip(), path, no))
                continue
            if name == "include":
                out.append(Setting("parsed", name, value, path, no))
                for pat in value.split():
                    if not pat.startswith("/"):
                        pat = "/etc/ssh/" + pat
                    for f in sorted(files):
                        if fnmatch.fnmatchcase(f, pat):
                            do_file(f, depth + 1)
                continue
            out.append(Setting("parsed", name, value, path, no))

    do_file(main, 0)
    return out


def effective(settings: list[Setting], name: str) -> str:
    """Global effective value: sshd -T if present, else first parsed value, else the default."""
    t = [s for s in settings if s.source == "sshd-T"]
    if t:
        for s in t:
            if s.name == name:
                return s.value
        return DEFAULTS.get(name, "")
    for s in settings:
        if s.source == "parsed" and s.name == name:
            return s.value
    return DEFAULTS.get(name, "")


def effective_multi(settings: list[Setting], name: str) -> list[str]:
    t = [s for s in settings if s.source == "sshd-T"]
    src = t if t else [s for s in settings if s.source == "parsed"]
    vals: list[str] = []
    for s in src:
        if s.name == name:
            vals.extend(s.value.split())
    return vals
