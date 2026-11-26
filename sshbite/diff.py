"""Compare two scans per identity (spec 4.2): added, removed and changed per category."""

from __future__ import annotations

import sqlite3

from .db import unj

CATEGORIES = ("hosts", "keys", "placements", "edges", "findings")


def _hosts(conn, sid):
    out = {}
    for r in conn.execute("SELECT h.identity, h.display_name, hs.status, hs.privilege, hs.route FROM host_scan hs"
                          " JOIN host h ON h.id=hs.host_id WHERE hs.scan_id=?", (sid,)):
        out[r[0]] = {"identity": r[0], "host": r[1], "status": r[2], "privilege": r[3], "route": unj(r[4])}
    return out


def _keys(conn, sid):
    out = {}
    for r in conn.execute(
            "SELECT k.fp, k.alg, k.bits, k.strength FROM key k WHERE k.fp IN ("
            " SELECT fp FROM authorized_entry WHERE scan_id=? AND fp IS NOT NULL"
            " UNION SELECT fp FROM private_key WHERE scan_id=? AND fp IS NOT NULL)", (sid, sid)):
        out[r[0]] = {"fp": r[0], "alg": r[1], "bits": r[2], "strength": r[3]}
    lab = {r[0]: r[1] for r in conn.execute("SELECT fp, label FROM key_label")}
    comments = {}
    for r in conn.execute("SELECT fp, comment FROM authorized_entry WHERE scan_id=? AND comment IS NOT NULL", (sid,)):
        comments.setdefault(r[0], r[1])
    for fp, v in out.items():
        v["label"] = lab.get(fp)
        v["comment"] = comments.get(fp)
    return out


def _placements(conn, sid):
    out = {}
    for r in conn.execute("SELECT h.identity, h.display_name, a.username, a.fp, a.file, a.line_no FROM authorized_entry a"
                          " JOIN host h ON h.id=a.host_id WHERE a.scan_id=? AND a.fp IS NOT NULL", (sid,)):
        key = ("authorized", r[0], r[2], r[3])
        out.setdefault(key, {"kind": "authorized", "host": r[1], "user": r[2], "fp": r[3], "file": r[4], "line": r[5]})
    for r in conn.execute("SELECT h.identity, h.display_name, p.username, p.fp, p.path FROM private_key p"
                          " JOIN host h ON h.id=p.host_id WHERE p.scan_id=? AND p.fp IS NOT NULL", (sid,)):
        key = ("private", r[0], r[2], r[3])
        out.setdefault(key, {"kind": "private", "host": r[1], "user": r[2], "fp": r[3], "file": r[4], "line": None})
    return out


def _edges(conn, sid):
    out = {}
    for r in conn.execute(
            "SELECT e.kind, hs.identity, hs.display_name, e.src_user, hd.identity, hd.display_name, e.dst_user, e.fp,"
            " e.status, e.effective FROM edge e LEFT JOIN host hs ON hs.id=e.src_host_id"
            " JOIN host hd ON hd.id=e.dst_host_id WHERE e.scan_id=?", (sid,)):
        key = (r[0], r[1] or "unknown", r[3] or "", r[4], r[6] or "", r[7] or "")
        out.setdefault(key, {"kind": r[0], "src": r[2] or "unknown", "src_user": r[3], "dst": r[5], "dst_user": r[6],
                             "fp": r[7], "status": r[8], "effective": bool(r[9])})
    return out


def _findings(conn, sid):
    out = {}
    for r in conn.execute("SELECT f.ident, f.rule, f.severity, h.display_name, f.username, f.fp, f.file, f.line_no"
                          " FROM finding f LEFT JOIN host h ON h.id=f.host_id WHERE f.scan_id=?", (sid,)):
        out.setdefault(r[0], {"ident": r[0], "rule": r[1], "severity": r[2], "host": r[3], "user": r[4], "fp": r[5],
                              "file": r[6], "line": r[7]})
    return out


def _cmp(a: dict, b: dict, changed_fields: tuple = ()):
    added = [b[k] for k in b if k not in a]
    removed = [a[k] for k in a if k not in b]
    changed = []
    for k in a:
        if k in b and changed_fields:
            diffs = {f: {"a": a[k].get(f), "b": b[k].get(f)} for f in changed_fields if a[k].get(f) != b[k].get(f)}
            if diffs:
                changed.append({**b[k], "changes": diffs})
    return {"added": added, "removed": removed, "changed": changed}


def diff_scans(conn: sqlite3.Connection, a: int, b: int) -> dict:
    meta = {}
    for sid in (a, b):
        r = conn.execute("SELECT id, started_at, label, synthetic FROM scan WHERE id=?", (sid,)).fetchone()
        meta[sid] = {"id": r[0], "started_at": r[1], "label": r[2], "synthetic": bool(r[3])}
    return {
        "a": meta[a], "b": meta[b],
        "hosts": _cmp(_hosts(conn, a), _hosts(conn, b), ("status", "privilege", "route")),
        "keys": _cmp(_keys(conn, a), _keys(conn, b)),
        "placements": _cmp(_placements(conn, a), _placements(conn, b)),
        "edges": _cmp(_edges(conn, a), _edges(conn, b), ("status", "effective")),
        "findings": _cmp(_findings(conn, a), _findings(conn, b), ("severity",)),
    }


def _fmt(cat: str, x: dict) -> str:
    if cat == "hosts":
        return f"{x['host']} ({x['status']}{', ' + x['privilege'] if x.get('privilege') else ''})"
    if cat == "keys":
        return f"{x['fp']} {x['alg']} {x['bits'] or ''} {x['strength']} {x.get('label') or x.get('comment') or ''}".rstrip()
    if cat == "placements":
        where = f"{x['file']}:{x['line']}" if x.get("line") else x["file"]
        return f"{x['kind']} {x['host']}:{x['user']} {x['fp']} ({where})"
    if cat == "edges":
        src = "unknown" if x["src"] == "unknown" else f"{x['src']}:{x['src_user'] or ''}"
        dst = f"{x['dst']}:{x['dst_user']}" if x["dst_user"] else x["dst"]
        return f"{x['kind']} {src} -> {dst} {x['fp'] or ''} [{x['status']}]"
    loc = ":".join(str(v) for v in (x.get("host"), x.get("user")) if v)
    return f"{x['severity']} {x['rule']} {loc} {x['fp'] or ''} {x['file'] or ''}{':' + str(x['line']) if x.get('line') else ''}".rstrip()


def render_text(d: dict) -> str:
    lines = [f"diff scan {d['a']['id']} -> scan {d['b']['id']}"]
    for cat in CATEGORIES:
        c = d[cat]
        lines.append("")
        lines.append(f"{cat}: {len(c['added'])} added, {len(c['removed'])} removed, {len(c['changed'])} changed")
        for x in c["added"]:
            lines.append(f"  + {_fmt(cat, x)}")
        for x in c["removed"]:
            lines.append(f"  - {_fmt(cat, x)}")
        for x in c["changed"]:
            ch = ", ".join(f"{f}: {v['a']} -> {v['b']}" if f != "route" else
                           f"route: {' -> '.join(v['a'] or []) or '-'} => {' -> '.join(v['b'] or []) or '-'}"
                           for f, v in x["changes"].items())
            lines.append(f"  ~ {_fmt(cat, x)}: {ch}")
    return "\n".join(lines)
