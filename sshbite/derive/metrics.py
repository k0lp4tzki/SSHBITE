"""Heatmap metrics per host (spec 4.5): effective access edges with src != dst, and evidence edges."""

from __future__ import annotations

from . import ScanData


def derive_metrics(data: ScanData) -> None:
    db, sid = data.db, data.scan_id
    m = {hid: {"in_hosts": set(), "in_users": set(), "in_keys": set(), "in_unknown_keys": set(),
               "out_hosts": set(), "out_users": set(), "out_keys": set(), "ev_in_hosts": set(),
               "ev_out_hosts": set()} for hid in data.hosts}
    for src, src_user, dst, dst_user, fp, status in db.execute(
            "SELECT src_host_id, src_user, dst_host_id, dst_user, fp, status FROM edge"
            " WHERE scan_id=? AND kind='access' AND effective=1", (sid,)):
        if src is not None and src == dst:
            continue
        d = m.get(dst)
        if d is not None:
            if src is not None:
                d["in_hosts"].add(src)
                d["in_users"].add((src, src_user))
            d["in_keys"].add(fp)
            if status == "unknown_origin":
                d["in_unknown_keys"].add(fp)
        s = m.get(src) if src is not None else None
        if s is not None:
            s["out_hosts"].add(dst)
            s["out_users"].add((dst, dst_user))
            s["out_keys"].add(fp)
    for src, dst in db.execute("SELECT src_host_id, dst_host_id FROM edge WHERE scan_id=? AND kind='evidence'", (sid,)):
        if src is None or src == dst:
            continue
        if dst in m:
            m[dst]["ev_in_hosts"].add(src)
        if src in m:
            m[src]["ev_out_hosts"].add(dst)
    cols = ("in_hosts", "in_users", "in_keys", "in_unknown_keys", "out_hosts", "out_users", "out_keys",
            "ev_in_hosts", "ev_out_hosts")
    db.executemany(
        f"INSERT INTO host_metric(scan_id, host_id, {', '.join(cols)}) VALUES (?, ?, {', '.join('?' * len(cols))})",
        [(sid, hid, *[len(v[c]) for c in cols]) for hid, v in m.items()])
