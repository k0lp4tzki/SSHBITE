"""`sshbite hostkey accept`: trust the changed host key that the last scan saw for an address."""

from __future__ import annotations

import sqlite3

from .db import utcnow
from .derive.findings import hostkey_change_detail


def accept(conn: sqlite3.Connection, addr: str, port: int | None) -> list[str]:
    q = ("SELECT hs.connect_port, hs.error, hs.scan_id FROM host_scan hs WHERE hs.connect_addr=? AND hs.status='hostkey_mismatch'"
         + (" AND hs.connect_port=?" if port is not None else "") + " ORDER BY hs.scan_id DESC LIMIT 1")
    row = conn.execute(q, (addr, port) if port is not None else (addr,)).fetchone()
    out: list[str] = []
    conn.execute("BEGIN IMMEDIATE")
    try:
        if row is not None:
            p = row[0]
            d = hostkey_change_detail(row[1], addr)
            new = d.get("new")
            old = [(r[0], r[1]) for r in conn.execute("SELECT alg, fp FROM trusted_hostkey WHERE addr=? AND port=?", (addr, p))]
            conn.execute("DELETE FROM trusted_hostkey WHERE addr=? AND port=?", (addr, p))
            if new:
                conn.execute("INSERT INTO trusted_hostkey(addr, port, alg, fp, first_seen_scan, accepted_at)"
                             " VALUES (?,?,?,?,?,?)", (addr, p, new["alg"], new["fp"], row[2], utcnow()))
                for a, f in old:
                    out.append(f"{addr}:{p}  {a} {f}  -> no longer trusted")
                out.append(f"{addr}:{p}  {new['alg']} {new['fp']}  -> trusted (seen in scan {row[2]})")
            else:
                out.append(f"{addr}:{p}  stored keys removed; the next scan trusts the key it sees")
        else:
            q2 = "DELETE FROM trusted_hostkey WHERE addr=?" + (" AND port=?" if port is not None else "")
            n = conn.execute(q2, (addr, port) if port is not None else (addr,)).rowcount
            if n:
                out.append(f"{addr}: no recorded key change; {n} stored key(s) removed, the next scan trusts the key it sees")
            else:
                out.append(f"{addr}: no stored host key and no recorded key change - nothing to accept")
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return out
