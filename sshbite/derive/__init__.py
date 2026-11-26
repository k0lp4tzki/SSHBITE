"""Derivation of edges, known-host pairs, findings and metrics for one scan (spec 4.3-4.5)."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

from ..db import unj
from ..parse import sshd as sshd_mod


@dataclass
class HostInfo:
    id: int
    identity: str
    display: str
    status: str
    names: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    settings: list[sshd_mod.Setting] = field(default_factory=list)
    accounts: dict[str, sqlite3.Row] = field(default_factory=dict)
    host_keys: set[str] = field(default_factory=set)
    collected: bool = False

    def effective(self, name: str) -> str:
        return sshd_mod.effective(self.settings, name).strip().lower() if self.settings else \
            sshd_mod.DEFAULTS.get(name, "")

    def multi(self, name: str) -> list[str]:
        return sshd_mod.effective_multi(self.settings, name)


class ScanData:
    """Everything derivation needs, loaded once per scan."""

    def __init__(self, db: sqlite3.Connection, scan_id: int):
        self.db = db
        self.scan_id = scan_id
        self.hosts: dict[int, HostInfo] = {}
        for r in db.execute(
                "SELECT hs.host_id, h.identity, h.display_name, hs.status, hs.hostname FROM host_scan hs"
                " JOIN host h ON h.id = hs.host_id WHERE hs.scan_id=?", (scan_id,)):
            self.hosts[r[0]] = HostInfo(r[0], r[1], r[4] or r[2], r[3])
        for r in db.execute("SELECT host_id, kind, value FROM host_name WHERE scan_id=?", (scan_id,)):
            h = self.hosts.get(r[0])
            if h:
                (h.ips if r[1] == "ip" else h.names).append(r[2])
        for r in db.execute("SELECT host_id, source, name, value, file, line FROM sshd_setting WHERE scan_id=?",
                            (scan_id,)):
            h = self.hosts.get(r[0])
            if h:
                h.settings.append(sshd_mod.Setting(r[1], r[2], r[3] or "", r[4], r[5]))
        for r in db.execute("SELECT * FROM account WHERE scan_id=?", (scan_id,)):
            h = self.hosts.get(r["host_id"])
            if h:
                h.accounts[r["username"]] = r
                h.collected = True
        for r in db.execute("SELECT host_id, fp FROM host_key WHERE scan_id=?", (scan_id,)):
            h = self.hosts.get(r[0])
            if h:
                h.host_keys.add(r[1])
                h.collected = True
        self.entries = db.execute("SELECT * FROM authorized_entry WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
        self.privs = db.execute("SELECT * FROM private_key WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
        self.refs = db.execute("SELECT * FROM reference WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
        self.priv_by_fp: dict[str, list[sqlite3.Row]] = {}
        for p in self.privs:
            if p["fp"]:
                self.priv_by_fp.setdefault(p["fp"], []).append(p)


def derive_scan(db: sqlite3.Connection, scan_id: int, cfg=None, audit_fp: str | None = None) -> None:
    """(Re)compute edge, known-host pairs, finding and host_metric rows for the scan. Idempotent."""
    from .edges import derive_edges, derive_known_host_pairs
    from .findings import derive_findings
    from .metrics import derive_metrics

    rules = cfg.rules if cfg is not None else None
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute("DELETE FROM edge WHERE scan_id=?", (scan_id,))
        db.execute("DELETE FROM finding WHERE scan_id=?", (scan_id,))
        db.execute("DELETE FROM host_metric WHERE scan_id=?", (scan_id,))
        data = ScanData(db, scan_id)
        derive_known_host_pairs(data)
        derive_edges(data, audit_fp)
        derive_findings(data, rules)
        derive_metrics(data)
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise


__all__ = ["derive_scan", "ScanData", "HostInfo", "unj"]
