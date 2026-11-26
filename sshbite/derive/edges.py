"""Access and evidence edges (spec 4.3) and known-host pairs."""

from __future__ import annotations

import fnmatch
import re
from datetime import datetime, timezone

from ..db import j, unj
from ..parse.authorized_keys import from_matches
from . import HostInfo, ScanData


def expiry_passed(value: str | None, now: datetime | None = None) -> bool:
    """authorized_keys expiry-time: YYYYMMDD[HHMM[SS]][Z]."""
    if not value:
        return False
    m = re.fullmatch(r"(\d{8})(\d{4})?(\d{2})?(Z)?", value.strip())
    if not m:
        return False
    s = m.group(1) + (m.group(2) or "0000") + (m.group(3) or "00")
    try:
        t = datetime.strptime(s, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return t < (now or datetime.now(timezone.utc))


def sshd_denies(h: HostInfo, user: str) -> bool:
    """AllowUsers / DenyUsers / AllowGroups evaluated on the user name only (spec 4.3)."""
    if not h.settings:
        return False

    def pats(name: str) -> list[str]:
        return [p.split("@", 1)[0] for p in h.multi(name)]

    deny = pats("denyusers")
    if any(fnmatch.fnmatchcase(user, p) for p in deny):
        return True
    allow = pats("allowusers")
    if allow and not any(fnmatch.fnmatchcase(user, p) for p in allow):
        return True
    groups = h.multi("allowgroups")
    if groups and not any(fnmatch.fnmatchcase(user, p) for p in groups):
        return True
    return False


def dst_flags(h: HostInfo, entry) -> tuple[list[str], bool]:
    """Return (flags, sshd_denied)."""
    user = entry["username"]
    flags: list[str] = []
    acc = h.accounts.get(user)
    if (acc is not None and acc["uid"] == 0) or (acc is None and user == "root"):
        flags.append("dst_root")
    if acc is not None and not acc["login_shell"]:
        flags.append("dst_nologin")
    if h.accounts and acc is None:
        flags.append("dst_user_missing")
    if entry["command"]:
        flags.append("forced_command")
    if expiry_passed(entry["expiry_time"]):
        flags.append("expired")
    denied = sshd_denies(h, user)
    if denied:
        flags.append("sshd_denied")
    return flags, denied


def derive_edges(data: ScanData, audit_fp: str | None = None) -> None:
    db, sid = data.db, data.scan_id
    rows = []
    for e in data.entries:
        fp = e["fp"]
        if not fp or e["cert_authority"]:
            continue
        if audit_fp and fp == audit_fp:
            continue
        dst = data.hosts.get(e["host_id"])
        if dst is None:
            continue
        flags, denied = dst_flags(dst, e)
        pubkey_off = dst.effective("pubkeyauthentication") == "no"
        patterns = unj(e["from_patterns"], []) or []
        holders = data.priv_by_fp.get(fp, [])
        if not holders:
            rows.append((sid, "access", None, None, dst.id, e["username"], fp, "unknown_origin",
                         int(not pubkey_off and not denied), j(flags), e["id"], None, None))
            continue
        for pk in holders:
            src = data.hosts.get(pk["host_id"])
            if patterns:
                ok = src is not None and from_matches(patterns, src.names, src.ips)
                status = "restricted_ok" if ok else "restricted_blocked"
            else:
                status = "confirmed"
            effective = status != "restricted_blocked" and not pubkey_off and not denied
            rows.append((sid, "access", pk["host_id"], pk["username"], dst.id, e["username"], fp, status,
                         int(effective), j(flags), e["id"], pk["id"], None))
    # evidence edges: references (not from=) whose target is resolved
    kh_fp: dict[tuple, str] = {}
    for r in db.execute("SELECT host_id, username, file, line_no, key_fp FROM known_host_entry WHERE scan_id=?",
                        (sid,)):
        kh_fp[(r[0], r[1], r[2], r[3])] = r[4]
    for r in data.refs:
        if r["source"] == "from_option" or r["target_host_id"] is None or r["outcome"] == "unresolvable":
            continue
        status = "known_hosts" if r["source"].endswith("known_hosts") or r["source"] == "known_hosts_hashed" \
            else "ssh_config"
        fp = kh_fp.get((r["from_host_id"], r["username"], r["file"], r["line_no"])) if status == "known_hosts" else None
        rows.append((sid, "evidence", r["from_host_id"], r["username"], r["target_host_id"], None, fp, status, 0,
                     j([r["source"]]), None, None, r["id"]))
    db.executemany(
        "INSERT INTO edge(scan_id, kind, src_host_id, src_user, dst_host_id, dst_user, fp, status, effective, flags,"
        " authorized_entry_id, private_key_id, reference_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)


def derive_known_host_pairs(data: ScanData) -> None:
    db, sid = data.db, data.scan_id
    updates = []
    for r in db.execute("SELECT id, target_host_id, key_fp FROM known_host_entry WHERE scan_id=?", (sid,)):
        tgt = data.hosts.get(r[1]) if r[1] is not None else None
        if tgt is None or not r[2] or not tgt.host_keys:
            val = "unknown"
        else:
            val = "yes" if r[2] in tgt.host_keys else "no"
        updates.append((val, r[0]))
    db.executemany("UPDATE known_host_entry SET matches_actual=? WHERE id=?", updates)
