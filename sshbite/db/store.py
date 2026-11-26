"""Write the in-memory result of a crawl into the per-scan tables (spec 4.1)."""

from __future__ import annotations

import ipaddress
import sqlite3
from typing import TYPE_CHECKING

from ..config import scope_match
from ..parse.keys import classify_strength
from . import j

if TYPE_CHECKING:  # pragma: no cover
    from ..crawl import Ref, Scanner, Target

CONNECTED = ("ok", "partial", "unreachable", "timeout", "auth_failed", "hostkey_mismatch", "hostkey_unknown",
             "collector_error", "output_limit", "alias")


def subnet_of(addr: str | None) -> str | None:
    if not addr:
        return None
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return None
    net = ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 64}", strict=False)
    return str(net)


def addr_identity(addr: str, port: int) -> str:
    try:
        ipaddress.ip_address(addr)
        return f"addr:{addr}" if port == 22 else f"addr:{addr}:{port}"
    except ValueError:
        return f"name:{addr.lower()}" if port == 22 else f"name:{addr.lower()}:{port}"


def upsert_host(db: sqlite3.Connection, identity: str, display: str, scan_id: int, synthetic: int = 0,
                merge_from: list[str] | None = None, keep_name: bool = False) -> int:
    """Find or create the host row. keep_name: an uncollected host keeps the name it is known by."""
    row = db.execute("SELECT id FROM host WHERE identity=?", (identity,)).fetchone()
    if row is None and merge_from:
        for old in merge_from:
            r2 = db.execute("SELECT id FROM host WHERE identity=?", (old,)).fetchone()
            if r2 is not None:
                db.execute("UPDATE host SET identity=? WHERE id=?", (identity, r2[0]))
                row = r2
                break
    if row is None:
        cur = db.execute("INSERT INTO host(identity, display_name, synthetic, first_seen_scan, last_seen_scan)"
                         " VALUES (?,?,?,?,?)", (identity, display, synthetic, scan_id, scan_id))
        return cur.lastrowid
    if keep_name:
        db.execute("UPDATE host SET last_seen_scan=max(coalesce(last_seen_scan,0), ?) WHERE id=?", (scan_id, row[0]))
    else:
        db.execute("UPDATE host SET display_name=?, last_seen_scan=max(coalesce(last_seen_scan,0), ?) WHERE id=?",
                   (display, scan_id, row[0]))
    return row[0]


def _identity_for(s: "Scanner", t: "Target") -> tuple[str, list[str]]:
    """Return (identity, identities to merge from)."""
    db = s.db
    if t.has_data and t.data.preferred_host_key() is not None:
        ident = "hk:" + t.data.preferred_host_key().fp
        merge = [addr_identity(t.addr, t.port)]
        if db.execute("SELECT 1 FROM host WHERE identity=?", (ident,)).fetchone() is None:
            # a host whose key was changed and then accepted keeps its history
            row = db.execute(
                "SELECT h.identity FROM host_scan hs JOIN host h ON h.id = hs.host_id"
                " WHERE hs.connect_addr=? AND hs.connect_port=? AND h.identity LIKE 'hk:%'"
                " ORDER BY hs.scan_id DESC LIMIT 1", (t.addr, t.port)).fetchone()
            if row is not None:
                last = db.execute(
                    "SELECT hs.status FROM host_scan hs JOIN host h ON h.id=hs.host_id WHERE h.identity=?"
                    " ORDER BY hs.scan_id DESC LIMIT 1", (row[0],)).fetchone()
                if last is not None and last[0] == "hostkey_mismatch":
                    merge.insert(0, row[0])
        return ident, merge
    # not collected: known host keys of this address point at the collected identity
    if t.status in CONNECTED and t.status != "alias":
        old = []
        if t.hostkey_detail and t.hostkey_detail.get("old"):
            old = [o["fp"] for o in t.hostkey_detail["old"]]
        else:
            old = [r[0] for r in db.execute("SELECT fp FROM trusted_hostkey WHERE addr=? AND port=?", (t.addr, t.port))]
        for fp in old:
            if db.execute("SELECT 1 FROM host WHERE identity=?", ("hk:" + fp,)).fetchone():
                return "hk:" + fp, []
        # the address was collected before under a host key identity
        row = db.execute(
            "SELECT h.identity FROM host_scan hs JOIN host h ON h.id = hs.host_id"
            " WHERE hs.connect_addr=? AND hs.connect_port=? AND h.identity LIKE 'hk:%'"
            " ORDER BY hs.scan_id DESC LIMIT 1", (t.addr, t.port)).fetchone()
        if row is not None:
            return row[0], []
    return addr_identity(t.addr, t.port), []


def _groups(s: "Scanner", t: "Target") -> list[tuple[str, str]]:
    out = []
    addr = t.connect_ip or t.addr
    sn = subnet_of(addr)
    if sn:
        out.append(("subnet", sn))
    names = list(t.names) + ([t.data.hostname] if t.data and t.data.hostname else [])
    ips = [a for a in [addr] + (t.data.ips if t.data else []) if a]
    tag = "untagged"
    for tg in s.cfg.grouping.tags:
        if scope_match(tg.match, names, ips):
            tag = tg.name
            break
    out.append(("tag", tag))
    ans = [g for k, g in t.groups if k == "ansible"]
    out.append(("ansible", ans[0] if ans else "ungrouped"))
    return out


def persist_scan(s: "Scanner") -> None:
    db = s.db
    sid = s.scan_id
    assert sid is not None
    db.execute("BEGIN IMMEDIATE")
    try:
        _persist(s, db, sid)
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise


def _persist(s: "Scanner", db: sqlite3.Connection, sid: int) -> None:
    rules = s.cfg.rules.strength
    all_targets: list[Target] = list(s.targets) + list(s.seen.values())
    # hosts
    used_ids: set[int] = set()
    for t in sorted(all_targets, key=lambda x: (x.status not in ("ok", "partial", "output_limit", "collector_error"), x.order)):
        ident, merge = _identity_for(s, t)
        hid = upsert_host(db, ident, t.display, sid, merge_from=merge, keep_name=not t.has_data)
        if hid in used_ids:
            # two targets ended up with one identity (e.g. an alias): keep the first, mark this one
            ident = addr_identity(t.addr, t.port) + ("" if t.status == "alias" else f"#{t.order}")
            hid = upsert_host(db, ident, t.display, sid)
        used_ids.add(hid)
        t.host_id = hid

    # references
    for r in s.refs:
        cur = db.execute(
            "INSERT INTO reference(scan_id, from_host_id, username, source, file, line_no, value, resolved_ips,"
            " target_host_id, outcome) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (sid, r.from_t.host_id, r.username, r.source, r.file, r.line_no, r.value, j(r.resolved_ips),
             r.target.host_id if r.target else None, r.outcome))
        r.db_id = cur.lastrowid

    for t in all_targets:
        _persist_target(s, db, sid, t, rules)


def _route_names(route) -> list[str] | None:
    return [h.display for h in route] if route else None


def _persist_target(s: "Scanner", db: sqlite3.Connection, sid: int, t: "Target", rules) -> None:
    hid = t.host_id
    d = t.data if t.has_data else None
    attempts = [{"route": _route_names(r), "error": err} for r, err in t.attempts]
    seed_source = t.seed_source
    db.execute(
        "INSERT INTO host_scan(scan_id, host_id, status, privilege, depth, discovered_via_ref, seed_source, route,"
        " route_attempts, connect_addr, connect_port, hostname, os, kernel, ips, partial_reasons, error,"
        " alias_of_host_id, unresolved_hashed, duration_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (sid, hid, t.status, t.privilege, t.depth, t.via.db_id if t.via else None, seed_source,
         j(_route_names(t.route)) if t.route else None, j(attempts),
         t.connect_ip or t.addr, t.port, d.hostname if d else None, d.os if d else None, d.kernel if d else None,
         j(d.ips if d else []), j(t.partial_reasons), s.secret.redact(t.error) if t.error else None,
         t.alias_of.host_id if t.alias_of else None, t.unresolved_hashed, t.duration_ms))

    names = []
    for n in ([d.hostname] if d and d.hostname else []) + list(t.names):
        if n and n not in names:
            names.append(n)
    for n in names:
        kind = "ip" if _is_ip(n) else "name"
        db.execute("INSERT OR IGNORE INTO host_name(scan_id, host_id, kind, value) VALUES (?,?,?,?)",
                   (sid, hid, kind, n.lower() if kind == "name" else n))
    for ip in (d.ips if d else []) + ([t.connect_ip] if t.connect_ip and _is_ip(t.connect_ip) else []):
        db.execute("INSERT OR IGNORE INTO host_name(scan_id, host_id, kind, value) VALUES (?,?,?,?)",
                   (sid, hid, "ip", ip))
    for kind, name in _groups(s, t):
        db.execute("INSERT INTO host_group(scan_id, host_id, kind, name) VALUES (?,?,?,?)", (sid, hid, kind, name))

    if d is None:
        return
    for k in d.host_keys:
        db.execute("INSERT INTO host_key(scan_id, host_id, alg, fp, bits) VALUES (?,?,?,?,?)",
                   (sid, hid, k.alg, k.fp, k.bits))
    for st in d.sshd:
        db.execute("INSERT INTO sshd_setting(scan_id, host_id, source, name, value, file, line) VALUES (?,?,?,?,?,?,?)",
                   (sid, hid, st.source, st.name, st.value, st.file, st.line))
    for a in d.accounts.values():
        db.execute("INSERT OR IGNORE INTO account(scan_id, host_id, username, uid, gid, home, shell, login_shell,"
                   " pw_state, expiry) VALUES (?,?,?,?,?,?,?,?,?,?)",
                   (sid, hid, a.username, a.uid, a.gid, a.home, a.shell, int(a.login_shell), a.pw_state, a.expiry))
    for a in d.authorized:
        e = a.entry
        key = e.key
        db.execute(
            "INSERT INTO authorized_entry(scan_id, host_id, username, file, line_no, fp, alg, comment, options,"
            " from_patterns, command, restrict, cert_authority, principals, expiry_time, user_exists, raw)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sid, hid, a.username, a.file, e.line_no, key.fp if key else None, key.alg if key else None,
             key.comment if key else None, j(e.options_json()), j(e.from_patterns), e.command, int(e.restrict),
             int(e.cert_authority), e.principals, e.expiry_time, int(a.user_exists), e.raw))
        if key is not None:
            upsert_key(db, key.fp, key.alg, key.bits, classify_strength(key.alg, key.bits, rules), sid)
    for p in d.private_keys:
        db.execute(
            "INSERT INTO private_key(scan_id, host_id, username, path, fp, alg, bits, encrypted, mode, owner, mtime,"
            " has_pub) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (sid, hid, p.username, p.path, p.fp, p.alg, p.bits, p.encrypted, p.mode, p.owner, p.mtime,
             int(p.has_pub)))
        if p.fp:
            upsert_key(db, p.fp, p.alg, p.bits, classify_strength(p.alg or "", p.bits, rules), sid)
    for pf in d.pub_files:
        db.execute("INSERT INTO pub_file(scan_id, host_id, username, path, fp, comment) VALUES (?,?,?,?,?,?)",
                   (sid, hid, pf.username, pf.path, pf.key.fp, pf.key.comment))
    # known_hosts: link to the target of the reference made from this line
    kh_target: dict[int, tuple[str, int | None]] = {}
    for r in s.refs:
        if r.kh_rec is not None and r.from_t is t:
            if id(r.kh_rec) not in kh_target:
                kh_target[id(r.kh_rec)] = (r.value, r.target.host_id if r.target else None)
    for rec in d.known_hosts:
        e = rec.entry
        rv, tgt = kh_target.get(id(rec), (None, None))
        db.execute(
            "INSERT INTO known_host_entry(scan_id, host_id, username, file, line_no, marker, hashed, patterns,"
            " resolved_value, target_host_id, key_alg, key_fp, matches_actual) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sid, hid, rec.username, rec.file, e.line_no, e.marker, int(e.hashed), j(e.patterns), rv, tgt,
             e.key.alg if e.key else None, e.key.fp if e.key else None, "unknown"))
    for rec in d.ssh_configs:
        e = rec.entry
        db.execute(
            "INSERT INTO ssh_config_entry(scan_id, host_id, username, file, line_no, host_pattern, hostname, user,"
            " port, identity_files, proxyjump) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (sid, hid, rec.username, rec.file, e.line_no, e.host_pattern, e.hostname, e.user, e.port,
             j(e.identity_files), e.proxyjump))


def upsert_key(db: sqlite3.Connection, fp: str, alg: str | None, bits: int | None, strength: str, sid: int) -> None:
    db.execute(
        "INSERT INTO key(fp, alg, bits, strength, first_seen_scan, last_seen_scan) VALUES (?,?,?,?,?,?)"
        " ON CONFLICT(fp) DO UPDATE SET last_seen_scan=max(coalesce(last_seen_scan,0), excluded.last_seen_scan),"
        " alg=coalesce(key.alg, excluded.alg), bits=coalesce(key.bits, excluded.bits),"
        " strength=CASE WHEN key.strength='unknown' THEN excluded.strength ELSE key.strength END",
        (fp, alg, bits, strength, sid, sid))


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False
