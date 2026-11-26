"""Turn the collector records of one host into structured facts (accounts, keys, files, settings)."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import authorized_keys as ak
from . import known_hosts as kh
from . import ssh_config as sc
from . import sshd as sshd_mod
from .keys import PublicKey, parse_public_key_line
from .records import Collected, ip_addresses

NOLOGIN_SHELLS = {"", "/bin/false", "/usr/bin/false", "/sbin/nologin", "/usr/sbin/nologin", "/bin/nologin"}


@dataclass
class Account:
    username: str
    uid: int | None
    gid: int | None
    home: str
    shell: str
    login_shell: bool
    pw_state: str = "unknown"
    expiry: str | None = None


@dataclass
class AuthorizedRec:
    username: str
    file: str
    entry: ak.AuthorizedEntry
    user_exists: bool = True


@dataclass
class PrivateKeyRec:
    username: str
    path: str
    fp: str | None
    alg: str | None
    bits: int | None
    encrypted: str
    mode: int | None
    owner: str | None
    mtime: str | None
    has_pub: bool
    header: str = ""


@dataclass
class PubFileRec:
    username: str
    path: str
    key: PublicKey


@dataclass
class KnownHostsRec:
    username: str          # '' = system file
    file: str
    entry: kh.KnownHostEntry


@dataclass
class SshConfigRec:
    username: str
    file: str
    entry: sc.SshConfigEntry


@dataclass
class HostKeyRec:
    alg: str
    fp: str
    bits: int | None


@dataclass
class HostData:
    hostname: str = ""
    os: str = ""
    kernel: str = ""
    uid: str = ""
    ips: list[str] = field(default_factory=list)
    host_keys: list[HostKeyRec] = field(default_factory=list)
    sshd: list[sshd_mod.Setting] = field(default_factory=list)
    accounts: dict[str, Account] = field(default_factory=dict)
    authorized: list[AuthorizedRec] = field(default_factory=list)
    private_keys: list[PrivateKeyRec] = field(default_factory=list)
    pub_files: list[PubFileRec] = field(default_factory=list)
    known_hosts: list[KnownHostsRec] = field(default_factory=list)
    ssh_configs: list[SshConfigRec] = field(default_factory=list)
    unreadable: list[tuple[str, str]] = field(default_factory=list)
    shadow_available: bool = False

    def preferred_host_key(self) -> HostKeyRec | None:
        def pref(k: HostKeyRec) -> int:
            if k.alg == "ssh-ed25519":
                return 0
            if k.alg.startswith("ecdsa-"):
                return 1
            if k.alg == "ssh-rsa":
                return 2
            return 3
        ks = sorted(self.host_keys, key=lambda k: (pref(k), k.fp))
        return ks[0] if ks else None


_L_TYPES = {
    "ED25519": "ssh-ed25519", "RSA": "ssh-rsa", "DSA": "ssh-dss",
    "ED25519-SK": "sk-ssh-ed25519@openssh.com", "ECDSA-SK": "sk-ecdsa-sha2-nistp256@openssh.com",
}
_L_RE = re.compile(r"^(\d+)\s+(SHA256:[A-Za-z0-9+/]+)\s.*\(([A-Z0-9-]+)\)\s*$")


def _parse_l_output(lines: list[str]) -> tuple[str, str | None, int | None] | None:
    for line in lines:
        m = _L_RE.match(line.strip())
        if m:
            bits = int(m.group(1))
            t = m.group(3)
            if t == "ECDSA":
                alg = {256: "ecdsa-sha2-nistp256", 384: "ecdsa-sha2-nistp384", 521: "ecdsa-sha2-nistp521"}.get(bits)
            else:
                alg = _L_TYPES.get(t)
            return m.group(2), alg, bits
    return None


def _guess_alg_from_header(h: str) -> str | None:
    if "BEGIN DSA" in h:
        return "ssh-dss"
    if "BEGIN RSA" in h:
        return "ssh-rsa"
    if "BEGIN EC" in h:
        return "ecdsa-sha2-nistp256"
    return None


def _iso(epoch: int | None) -> str | None:
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _parse_os(lines: list[str]) -> str:
    vals = {}
    for line in lines:
        if "=" in line:
            k, v = line.split("=", 1)
            vals[k.strip()] = v.strip().strip('"')
    return vals.get("PRETTY_NAME") or " ".join(x for x in (vals.get("NAME"), vals.get("VERSION_ID")) if x)


def build(c: Collected, audit_fp: str | None = None) -> HostData:
    d = HostData()
    d.hostname = c.value("hostname").strip()
    d.kernel = c.value("uname").strip()
    d.uid = c.value("uid").strip()
    d.os = _parse_os(c.cmds.get("os-release", []))
    d.ips = ip_addresses(c)
    d.unreadable = list(c.skipped)

    # host keys
    for f in c.files:
        if f.section == "HOSTKEYS":
            for line in f.lines:
                k = parse_public_key_line(line)
                if k is not None:
                    d.host_keys.append(HostKeyRec(k.alg, k.fp, k.bits))
                    break

    # sshd
    t_lines = [ln for ln in c.cmds.get("sshd-T", []) if ln.strip()]
    if t_lines:
        d.sshd.extend(sshd_mod.parse_sshd_t(t_lines))
    cfg_files = {f.path: f.lines for f in c.files if f.section == "SSHD" and f.has_content}
    d.sshd.extend(sshd_mod.parse_config(cfg_files))

    # accounts + shadow
    shadow: dict[str, tuple[str, str]] = {}
    if "shadow" in c.cmds:
        d.shadow_available = True
        for line in c.cmds["shadow"]:
            parts = line.split(":")
            if len(parts) >= 3:
                shadow[parts[0]] = (parts[1], parts[2])
    for line in c.cmds.get("passwd", []):
        p = line.split(":")
        if len(p) < 7 or not p[0]:
            continue
        shell = p[6].strip()
        acc = Account(username=p[0], uid=_int(p[2]), gid=_int(p[3]), home=p[5], shell=shell,
                      login_shell=not (shell in NOLOGIN_SHELLS or shell.endswith("/nologin")))
        if p[0] in shadow:
            first, exp = shadow[p[0]]
            acc.pw_state = "locked" if first in ("!", "*") else "hash" if first == "$" else "none" if first == "" \
                else "hash"
            if exp.strip().isascii() and exp.strip().isdigit():
                try:
                    acc.expiry = (datetime(1970, 1, 1, tzinfo=timezone.utc)
                                  + timedelta(days=int(exp))).strftime("%Y-%m-%d")
                except (OverflowError, ValueError):
                    acc.expiry = None
        if acc.username not in d.accounts:
            d.accounts[acc.username] = acc

    files_by_path = {f.path: f for f in c.files}

    for f in c.files:
        if f.section == "USERS":
            name = posixpath.basename(f.path)
            user = f.account
            if f.akf_for is not None:
                for e in ak.parse("\n".join(f.lines)):
                    if e.key is not None and audit_fp and e.key.fp == audit_fp:
                        continue
                    d.authorized.append(AuthorizedRec(f.akf_for, f.path, e, f.akf_for in d.accounts))
                continue
            if not f.has_content:
                continue
            if name.startswith("known_hosts"):
                for e in kh.parse("\n".join(f.lines)):
                    d.known_hosts.append(KnownHostsRec(user, f.path, e))
            elif name == "config":
                entries, _inc = sc.parse("\n".join(f.lines), f.path)
                for e in entries:
                    d.ssh_configs.append(SshConfigRec(user, f.path, e))
            elif name.endswith(".pub"):
                for line in f.lines:
                    k = parse_public_key_line(line)
                    if k is not None:
                        d.pub_files.append(PubFileRec(user, f.path, k))
                        break
        elif f.section == "SYSTEM" and f.has_content:
            if f.path == "/etc/ssh/ssh_known_hosts":
                for e in kh.parse("\n".join(f.lines)):
                    d.known_hosts.append(KnownHostsRec("", f.path, e))
            else:
                entries, _inc = sc.parse("\n".join(f.lines), f.path)
                for e in entries:
                    d.ssh_configs.append(SshConfigRec("", f.path, e))

    # private keys
    pubs = {p.path: p for p in d.pub_files}
    for path, header in c.private_headers.items():
        f = files_by_path.get(path)
        kg = c.keygen.get(path, {})
        fp = alg = None
        bits = None
        encrypted = "unknown"
        y_rc, y_lines = kg.get("y", (None, []))
        if y_rc == 0:
            for line in y_lines:
                k = parse_public_key_line(line)
                if k is not None:
                    fp, alg, bits = k.fp, k.alg, k.bits
                    encrypted = "no"
                    break
        if any("incorrect passphrase" in ln or "passphrase" in ln.lower() and "incorrect" in ln.lower() for ln in y_lines):
            encrypted = "yes"
        pub = pubs.get(path + ".pub")
        if fp is None and pub is not None:
            fp, alg, bits = pub.key.fp, pub.key.alg, pub.key.bits
        if fp is None:
            l_rc, l_lines = kg.get("l", (None, []))
            parsed = _parse_l_output(l_lines) if l_rc == 0 else None
            if parsed:
                fp, alg, bits = parsed
        if alg is None:
            alg = _guess_alg_from_header(header)
        d.private_keys.append(PrivateKeyRec(
            username=f.account if f else "", path=path, fp=fp, alg=alg, bits=bits, encrypted=encrypted,
            mode=f.mode if f else None, owner=f.owner if f else None, mtime=_iso(f.mtime) if f else None,
            has_pub=(path + ".pub") in files_by_path, header=header))
    return d


def _int(s: str) -> int | None:
    """An integer that fits SQLite's 64-bit column, else None (untrusted input)."""
    try:
        v = int(s)
    except (TypeError, ValueError):
        return None
    return v if -(1 << 63) <= v < (1 << 63) else None
