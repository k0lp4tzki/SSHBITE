"""Scan listings for the CLI (and reusable by the web API): list, show, delete."""

from __future__ import annotations

import sqlite3

from .db import unj

SEVERITIES = ("critical", "high", "medium", "low", "info")


def scans_list_data(conn: sqlite3.Connection) -> list[dict]:
    out = []
    for r in conn.execute("SELECT id, label, started_at, finished_at, status, synthetic, counts FROM scan ORDER BY id"):
        out.append({"id": r["id"], "label": r["label"], "started_at": r["started_at"],
                    "finished_at": r["finished_at"], "status": r["status"], "synthetic": bool(r["synthetic"]),
                    "counts": unj(r["counts"], {})})
    return out


def discovered_via(conn: sqlite3.Connection, ref_id: int | None) -> dict | None:
    if ref_id is None:
        return None
    r = conn.execute("SELECT r.source, r.file, r.line_no, r.value, h.display_name FROM reference r"
                     " LEFT JOIN host h ON h.id = r.from_host_id WHERE r.id=?", (ref_id,)).fetchone()
    if r is None:
        return None
    return {"parent": r["display_name"], "source": r["source"], "file": r["file"], "line": r["line_no"],
            "value": r["value"]}


def scan_show_data(conn: sqlite3.Connection, sid: int) -> dict:
    s = conn.execute("SELECT * FROM scan WHERE id=?", (sid,)).fetchone()
    scan = {k: s[k] for k in s.keys() if k not in ("params", "counts", "progress")}
    scan["synthetic"] = bool(s["synthetic"])
    scan["params"] = unj(s["params"], {})
    scan["counts"] = unj(s["counts"], {})
    scan["progress"] = unj(s["progress"], {})
    metrics = {r["host_id"]: {k: r[k] for k in r.keys() if k not in ("scan_id", "host_id")}
               for r in conn.execute("SELECT * FROM host_metric WHERE scan_id=?", (sid,))}
    fsev: dict[int, dict[str, int]] = {}
    for r in conn.execute("SELECT host_id, severity, count(*) n FROM finding WHERE scan_id=? AND host_id IS NOT NULL"
                          " GROUP BY host_id, severity", (sid,)):
        fsev.setdefault(r["host_id"], {})[r["severity"]] = r["n"]
    hosts = []
    for r in conn.execute(
            "SELECT hs.*, h.display_name, h.identity FROM host_scan hs JOIN host h ON h.id = hs.host_id"
            " WHERE hs.scan_id=? ORDER BY hs.depth, h.display_name", (sid,)):
        hosts.append({
            "host_id": r["host_id"], "display_name": r["display_name"], "identity": r["identity"],
            "status": r["status"], "privilege": r["privilege"], "depth": r["depth"],
            "discovered_via": discovered_via(conn, r["discovered_via_ref"]) or (
                {"parent": None, "source": r["seed_source"], "file": None, "line": None} if r["seed_source"] else None),
            "route": unj(r["route"]), "route_attempts": unj(r["route_attempts"], []),
            "connect_addr": r["connect_addr"], "connect_port": r["connect_port"], "hostname": r["hostname"],
            "os": r["os"], "kernel": r["kernel"], "ips": unj(r["ips"], []),
            "partial_reasons": unj(r["partial_reasons"], []), "error": r["error"],
            "unresolved_hashed": r["unresolved_hashed"], "duration_ms": r["duration_ms"],
            "metrics": metrics.get(r["host_id"], {}),
            "findings_by_severity": fsev.get(r["host_id"], {}),
        })
    unresolved = sum(h["unresolved_hashed"] or 0 for h in hosts)
    return {"scan": scan, "hosts": hosts, "unresolved_hashed_total": unresolved}


def _via_text(v: dict | None) -> str:
    if not v:
        return "-"
    if v.get("parent") is None:
        return v.get("source") or "-"
    src = v.get("source") or ""
    tag = " (hashed)" if src == "known_hosts_hashed" else ""
    return f"{v['parent']} {v['file']}:{v['line']}{tag}"


def render_scan_text(d: dict) -> str:
    s = d["scan"]
    c = s["counts"] or {}
    lines = [
        f"scan {s['id']}{' [SYNTHETIC DATA]' if s['synthetic'] else ''}  {s['status']}  label: {s['label'] or '-'}",
        f"started {s['started_at']}  finished {s['finished_at'] or '-'}  entry {s['entry_host']}",
        f"tool {s['tool_version']}  collector sha256 {s['collector_sha256']}",
        f"hosts: " + ", ".join(f"{v} {k}" for k, v in sorted((c.get('hosts') or {}).items())),
        f"findings: " + ", ".join(f"{(c.get('findings') or {}).get(k, 0)} {k}" for k in SEVERITIES),
        f"access edges: {c.get('access_edges', 0)} ({c.get('effective_edges', 0)} effective, "
        f"{c.get('unknown_origin_edges', 0)} unknown origin); unresolved hashed known_hosts entries: "
        f"{d['unresolved_hashed_total']}",
        "",
        f"{'host':18} {'status':17} {'privilege':13} {'depth':>5}  {'discovered via':44} route",
    ]
    for h in d["hosts"]:
        route = " -> ".join(h["route"]) if h["route"] else "-"
        lines.append(f"{h['display_name'][:18]:18} {h['status']:17} {h['privilege'] or '-':13} "
                     f"{h['depth'] if h['depth'] is not None else '-':>5}  {_via_text(h['discovered_via'])[:44]:44} {route}")
        if h["status"] not in ("ok",) and h["route_attempts"] and (h["status"] != "partial"):
            for a in h["route_attempts"]:
                r = " -> ".join(a["route"] or [])
                lines.append(f"{'':20}tried {r}: {a['error'] or 'ok'}")
        elif any(a.get("error") for a in h["route_attempts"]):
            for a in h["route_attempts"]:
                if a.get("error"):
                    lines.append(f"{'':20}tried {' -> '.join(a['route'] or [])}: {a['error']}")
        for reason in h["partial_reasons"]:
            lines.append(f"{'':20}reason: {reason}")
        if h["error"] and h["status"] not in ("unreachable",):
            lines.append(f"{'':20}error: {h['error']}")
    return "\n".join(lines)


def delete_scan(conn: sqlite3.Connection, sid: int) -> dict:
    st = conn.execute("SELECT status FROM scan WHERE id=?", (sid,)).fetchone()
    if st is not None and st[0] == "running":
        lock = conn.execute("SELECT pid FROM scan_lock WHERE scan_id=?", (sid,)).fetchone()
        if lock is not None:
            from .errors import ScanLocked

            raise ScanLocked(f"scan {sid} is running (pid {lock[0]})")
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM scan WHERE id=?", (sid,))
        hosts = conn.execute(
            "DELETE FROM host WHERE id NOT IN (SELECT host_id FROM host_scan)"
            " AND id NOT IN (SELECT host_id FROM host_name) AND id NOT IN (SELECT dst_host_id FROM edge)").rowcount
        keys = conn.execute(
            "DELETE FROM key WHERE fp NOT IN (SELECT fp FROM authorized_entry WHERE fp IS NOT NULL)"
            " AND fp NOT IN (SELECT fp FROM private_key WHERE fp IS NOT NULL)").rowcount
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return {"deleted": sid, "hosts_pruned": hosts, "keys_pruned": keys}
