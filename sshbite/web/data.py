"""Per-scan views for the API: heatmap matrix and cells (spec 4.5), ranking, graph neighbourhood.

A completed scan never changes, so its edges and host groups are loaded once and cached in memory
(keyed by scan id, status and finish time). At 2,000 synthetic hosts / 15,000 edges a heatmap is a few
tens of milliseconds of set arithmetic.
"""

from __future__ import annotations

import ipaddress
import re
import sqlite3
import threading
from collections import OrderedDict
from dataclasses import dataclass, field

from ..db import unj

# hosts that were connected to; they are the rows and columns of the matrix (alias rows are not)
MATRIX_STATUSES = ("ok", "partial", "unreachable", "timeout", "auth_failed", "hostkey_mismatch", "hostkey_unknown",
                   "collector_error", "output_limit")
GROUP_KINDS = ("host", "subnet", "ansible", "tag", "depth")
METRICS = ("hosts", "users", "keys")
MAX_GROUPS = 60
DRILL_MAX = 100
OTHER = "~other"
UNKNOWN = "~unknown"
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
STRENGTH_RANK = {"critical": 0, "weak": 1, "unknown": 2, "ok": 3, "good": 4}


def natural_key(s: str):
    """Natural order; IPs and subnets numerically."""
    try:
        net = ipaddress.ip_network(s, strict=False)
        return (0, net.version, int(net.network_address), net.prefixlen, "")
    except ValueError:
        pass
    parts = re.split(r"(\d+)", s.lower())
    return (1, 0, 0, 0, tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in parts if p != ""))


@dataclass
class HostInfo:
    id: int
    name: str
    status: str
    privilege: str | None
    depth: int | None
    groups: dict = field(default_factory=dict)
    sev: str | None = None      # worst finding severity


@dataclass
class Edge:
    id: int
    kind: str
    src: int | None
    src_user: str | None
    dst: int
    dst_user: str | None
    fp: str | None
    status: str
    effective: int
    flags: list


class ScanView:
    def __init__(self, conn: sqlite3.Connection, sid: int):
        self.sid = sid
        self.hosts: dict[int, HostInfo] = {}
        for r in conn.execute("SELECT hs.host_id, h.display_name, hs.status, hs.privilege, hs.depth FROM host_scan hs"
                              " JOIN host h ON h.id=hs.host_id WHERE hs.scan_id=?", (sid,)):
            self.hosts[r[0]] = HostInfo(r[0], r[1], r[2], r[3], r[4])
        for hid, kind, name in conn.execute("SELECT host_id, kind, name FROM host_group WHERE scan_id=?", (sid,)):
            h = self.hosts.get(hid)
            if h is not None and kind not in h.groups:
                h.groups[kind] = name
        for hid, sev in conn.execute("SELECT host_id, severity FROM finding WHERE scan_id=? AND host_id IS NOT NULL",
                                     (sid,)):
            h = self.hosts.get(hid)
            if h is not None and (h.sev is None or SEV_RANK[sev] < SEV_RANK[h.sev]):
                h.sev = sev
        self.matrix_hosts = sorted((h.id for h in self.hosts.values() if h.status in MATRIX_STATUSES),
                                   key=lambda i: natural_key(self.hosts[i].name))
        self.edges: list[Edge] = []
        for r in conn.execute("SELECT id, kind, src_host_id, src_user, dst_host_id, dst_user, fp, status, effective,"
                              " flags FROM edge WHERE scan_id=? ORDER BY id", (sid,)):
            self.edges.append(Edge(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], unj(r[9], []) or []))
        self.keys = {r[0]: (r[1], r[2], r[3]) for r in conn.execute(
            "SELECT fp, alg, bits, strength FROM key WHERE fp IN (SELECT fp FROM edge WHERE scan_id=?)", (sid,))}
        self.metrics = {r["host_id"]: dict(r) for r in conn.execute("SELECT * FROM host_metric WHERE scan_id=?", (sid,))}

    # ------------------------------------------------------------ helpers
    def layer_edges(self, layer: str, include_unknown: bool = True) -> list[Edge]:
        if layer == "evidence":
            return [e for e in self.edges if e.kind == "evidence" and e.src is not None and e.src != e.dst]
        out = []
        for e in self.edges:
            if e.kind != "access" or not e.effective:
                continue
            if e.src is None:
                if include_unknown:
                    out.append(e)
            elif e.src != e.dst:
                out.append(e)
        return out

    def group_of(self, hid: int, group_by: str) -> str:
        if group_by == "host":
            return str(hid)
        h = self.hosts[hid]
        if group_by == "depth":
            return str(h.depth) if h.depth is not None else "?"
        return h.groups.get(group_by) or ("ungrouped" if group_by == "ansible" else "untagged" if group_by == "tag"
                                          else "none")

    def group_label(self, gid: str, group_by: str) -> str:
        if gid == OTHER:
            return "Other"
        if gid == UNKNOWN:
            return "Unknown origin"
        if group_by == "host":
            if gid.startswith("unknown:"):
                return "? " + gid[len("unknown:"):]
            return self.hosts[int(gid)].name
        if group_by == "depth":
            return f"Depth {gid}"
        return gid

    def edge_dict(self, e: Edge) -> dict:
        k = self.keys.get(e.fp) if e.fp else None
        return {"id": e.id, "kind": e.kind, "src_host_id": e.src, "src": self.hosts[e.src].name if e.src is not None
                and e.src in self.hosts else None, "src_user": e.src_user, "dst_host_id": e.dst,
                "dst": self.hosts[e.dst].name if e.dst in self.hosts else None, "dst_user": e.dst_user, "fp": e.fp,
                "status": e.status, "effective": bool(e.effective), "flags": e.flags,
                "alg": k[0] if k else None, "bits": k[1] if k else None, "strength": k[2] if k else None}


def _pair_item(metric: str, e: Edge):
    src = e.src if e.src is not None else "u:" + (e.fp or "")
    if metric == "hosts":
        return (src, e.dst)
    if metric == "users":
        return (src, e.src_user, e.dst, e.dst_user)
    return e.fp if e.fp is not None else (src, e.dst)


class Views:
    """LRU cache of ScanViews."""

    def __init__(self, size: int = 6):
        self.size = size
        self._lock = threading.Lock()
        self._cache: OrderedDict = OrderedDict()

    def get(self, conn: sqlite3.Connection, sid: int) -> ScanView:
        st = conn.execute("SELECT status, finished_at FROM scan WHERE id=?", (sid,)).fetchone()
        key = (sid, st[0] if st else None, st[1] if st else None)
        with self._lock:
            v = self._cache.get(key)
            if v is not None:
                self._cache.move_to_end(key)
                return v
        v = ScanView(conn, sid)
        with self._lock:
            for k in [k for k in self._cache if k[0] == sid]:
                del self._cache[k]
            self._cache[key] = v
            while len(self._cache) > self.size:
                self._cache.popitem(last=False)
        return v


# ------------------------------------------------------------------ heatmap

def _fold(totals: dict[str, int], groups: list[str], limit: int) -> tuple[list[str], set[str]]:
    """Keep the limit-1 largest groups when there are more than limit; return (kept, folded)."""
    if len(groups) <= limit:
        return groups, set()
    ranked = sorted(groups, key=lambda g: (-totals.get(g, 0), natural_key(g)))
    keep = set(ranked[:limit - 1])
    return [g for g in groups if g in keep], set(ranked[limit - 1:])


def _matrix_groups(v: ScanView, group_by: str) -> list[str]:
    gs = {v.group_of(h, group_by) for h in v.matrix_hosts}
    if group_by == "host":
        return [str(h) for h in v.matrix_hosts]
    return sorted(gs, key=natural_key)


def _group_folding(v: ScanView, group_by: str, metric: str, edges: list[Edge]):
    groups = _matrix_groups(v, group_by)
    row_sets: dict[str, set] = {}
    col_sets: dict[str, set] = {}
    for e in edges:
        it = _pair_item(metric, e)
        if e.src is not None:
            row_sets.setdefault(v.group_of(e.src, group_by), set()).add(it)
        col_sets.setdefault(v.group_of(e.dst, group_by), set()).add(it)
    rows, rfold = _fold({g: len(s) for g, s in row_sets.items()}, groups, MAX_GROUPS)
    cols, cfold = _fold({g: len(s) for g, s in col_sets.items()}, groups, MAX_GROUPS)
    return groups, rows, rfold, cols, cfold


def heatmap(v: ScanView, group_by: str, metric: str, layer: str, include_unknown: bool,
            src_group: str | None, dst_group: str | None) -> dict:
    unknown_on = include_unknown and layer == "access"
    edges = v.layer_edges(layer, unknown_on)
    if layer == "evidence" and metric == "keys":
        metric = "hosts"
    if src_group is None and dst_group is None:
        return _heatmap_groups(v, group_by, metric, layer, unknown_on, edges)
    return _heatmap_drill(v, group_by, metric, layer, unknown_on, edges, src_group or "*", dst_group or "*")


def _heatmap_groups(v, group_by, metric, layer, unknown_on, edges) -> dict:
    groups, rows, rfold, cols, cfold = _group_folding(v, group_by, metric, edges)
    rmap = {g: g for g in rows}
    rmap.update({g: OTHER for g in rfold})
    cmap = {g: g for g in cols}
    cmap.update({g: OTHER for g in cfold})
    row_ids = rows + ([OTHER] if rfold else [])
    col_ids = cols + ([OTHER] if cfold else [])
    sets: dict[tuple[str, str], set] = {}
    has_unknown = False
    for e in edges:
        if e.src is None:
            rg = UNKNOWN
            has_unknown = True
        else:
            rg = rmap.get(v.group_of(e.src, group_by))
        cg = cmap.get(v.group_of(e.dst, group_by))
        if rg is None or cg is None:
            continue
        sets.setdefault((rg, cg), set()).add(_pair_item(metric, e))
    if unknown_on and has_unknown:
        row_ids.append(UNKNOWN)
    size = {}
    for h in v.matrix_hosts:
        g = v.group_of(h, group_by)
        size[g] = size.get(g, 0) + 1
    rix = {g: i for i, g in enumerate(row_ids)}
    cix = {g: i for i, g in enumerate(col_ids)}
    cells = [[rix[r], cix[c], len(s)] for (r, c), s in sets.items() if r in rix and c in cix]
    cells.sort()

    def node(g: str, folded: set) -> dict:
        d = {"id": g, "label": v.group_label(g, group_by), "kind": "group", "size": size.get(g, 0)}
        if g == OTHER:
            d.update(kind="other", size=sum(size.get(x, 0) for x in folded), groups=len(folded))
        elif g == UNKNOWN:
            d.update(kind="unknown", size=len({e.fp for e in edges if e.src is None}))
        elif group_by == "host":
            h = v.hosts[int(g)]
            d.update(kind="host", host_id=h.id, status=h.status, size=1)
        return d

    return {"level": "groups", "group_by": group_by, "metric": metric, "layer": layer,
            "include_unknown": unknown_on, "rows": [node(g, rfold) for g in row_ids],
            "cols": [node(g, cfold) for g in col_ids], "cells": cells,
            "max": max((c[2] for c in cells), default=0), "hidden": 0, "src_group": None, "dst_group": None,
            "hosts_total": len(v.matrix_hosts), "edges_total": len(edges)}


def _members(v: ScanView, group_by: str, gid: str, metric: str, edges: list[Edge], side: str) -> set[int] | None:
    """Host ids of a group (None = all matrix hosts)."""
    if gid == "*":
        return set(v.matrix_hosts)
    if gid == OTHER:
        _g, _r, rfold, _c, cfold = _group_folding(v, group_by, metric, edges)
        folded = rfold if side == "src" else cfold
        return {h for h in v.matrix_hosts if v.group_of(h, group_by) in folded}
    return {h for h in v.matrix_hosts if v.group_of(h, group_by) == gid}


def _heatmap_drill(v, group_by, metric, layer, unknown_on, edges, src_group, dst_group) -> dict:
    dst_m = _members(v, group_by, dst_group, metric, edges, "dst")
    unknown_rows = src_group == UNKNOWN
    src_m = set() if unknown_rows else _members(v, group_by, src_group, metric, edges, "src")
    sets: dict[tuple, set] = {}
    for e in edges:
        if e.dst not in dst_m:
            continue
        if unknown_rows:
            if e.src is not None:
                continue
            r = "unknown:" + (e.fp or "")
        else:
            if e.src is None or e.src not in src_m:
                continue
            r = e.src
        sets.setdefault((r, e.dst), set()).add(_pair_item(metric, e))
    rtot: dict = {}
    ctot: dict = {}
    for (r, c), s in sets.items():
        rtot[r] = rtot.get(r, 0) + len(s)
        ctot[c] = ctot.get(c, 0) + len(s)

    def name_of(x):
        return x if isinstance(x, str) else v.hosts[x].name

    all_rows = list(rtot) if unknown_rows else list(src_m)
    all_cols = list(dst_m)
    rows = sorted(all_rows, key=lambda x: (-rtot.get(x, 0), natural_key(name_of(x))))[:DRILL_MAX]
    cols = sorted(all_cols, key=lambda x: (-ctot.get(x, 0), natural_key(name_of(x))))[:DRILL_MAX]
    rows.sort(key=lambda x: natural_key(name_of(x)))
    cols.sort(key=lambda x: natural_key(name_of(x)))
    hidden = (len(all_rows) - len(rows)) + (len(all_cols) - len(cols))
    rix = {x: i for i, x in enumerate(rows)}
    cix = {x: i for i, x in enumerate(cols)}
    cells = sorted([rix[r], cix[c], len(s)] for (r, c), s in sets.items() if r in rix and c in cix)

    def hnode(x) -> dict:
        if isinstance(x, str):
            return {"id": x, "label": "? " + x[len("unknown:"):], "kind": "unknown_key", "fp": x[len("unknown:"):],
                    "size": 1}
        h = v.hosts[x]
        return {"id": str(x), "label": h.name, "kind": "host", "host_id": h.id, "status": h.status, "size": 1}

    def glabel(g):
        if g == "*":
            return "all"
        if g == OTHER:
            return "Other"
        return v.group_label(g, group_by)

    return {"level": "hosts", "group_by": group_by, "metric": metric, "layer": layer, "include_unknown": unknown_on,
            "rows": [hnode(x) for x in rows], "cols": [hnode(x) for x in cols], "cells": cells,
            "max": max((c[2] for c in cells), default=0), "hidden": hidden,
            "rows_total": len(all_rows), "cols_total": len(all_cols),
            "src_group": src_group, "dst_group": dst_group, "src_label": glabel(src_group),
            "dst_label": glabel(dst_group), "hosts_total": len(v.matrix_hosts), "edges_total": len(edges)}


def _match_src(v: ScanView, group_by: str, gid: str, e: Edge, members) -> bool:
    if gid.startswith("unknown:"):
        return e.src is None and e.fp == gid[len("unknown:"):]
    if gid == UNKNOWN:
        return e.src is None
    if e.src is None:
        return False
    if members is not None:
        return e.src in members
    return v.group_of(e.src, group_by) == gid


def heatmap_cell(v: ScanView, group_by: str, metric: str, layer: str, src_group: str, dst_group: str,
                 limit: int = 5) -> dict:
    edges = v.layer_edges(layer, True)
    if layer == "evidence" and metric == "keys":
        metric = "hosts"
    src_m = _members(v, group_by, src_group, metric, edges, "src") if src_group in (OTHER, "*") else None
    dst_m = _members(v, group_by, dst_group, metric, edges, "dst") if dst_group in (OTHER, "*") else None
    pairs: dict[tuple, dict] = {}
    value_set: set = set()
    for e in edges:
        if not _match_src(v, group_by, src_group, e, src_m):
            continue
        if dst_m is not None:
            if e.dst not in dst_m:
                continue
        elif v.group_of(e.dst, group_by) != dst_group:
            continue
        value_set.add(_pair_item(metric, e))
        key = (e.src if e.src is not None else "unknown:" + (e.fp or ""), e.dst)
        p = pairs.setdefault(key, {"users": set(), "keys": set()})
        p["users"].add((e.src_user, e.dst_user))
        if e.fp:
            p["keys"].add(e.fp)
    out = []
    for (s, d), p in pairs.items():
        users, keys = len(p["users"]), len(p["keys"])
        unknown = isinstance(s, str)
        dst_users = sorted({u[1] for u in p["users"] if u[1]})
        out.append({"src_host_id": None if unknown else s, "src": s if unknown else v.hosts[s].name,
                    "dst_host_id": d, "dst": v.hosts[d].name, "users": users, "keys": keys,
                    "dst_users": dst_users[:5],
                    "value": keys if metric == "keys" else users})
    out.sort(key=lambda x: (-x["value"], -x["users"], natural_key(x["src"]), natural_key(x["dst"])))
    return {"value": len(value_set), "pairs_total": len(out), "pairs": out[:limit]}


# ------------------------------------------------------------------ ranking

RANK_COLS = {("in", "hosts"): "in_hosts", ("in", "users"): "in_users", ("in", "keys"): "in_keys",
             ("in", "unknown_keys"): "in_unknown_keys", ("out", "hosts"): "out_hosts", ("out", "users"): "out_users",
             ("out", "keys"): "out_keys", ("out", "unknown_keys"): "in_unknown_keys"}
METRIC_KEYS = ("in_hosts", "in_users", "in_keys", "in_unknown_keys", "out_hosts", "out_users", "out_keys",
               "ev_in_hosts", "ev_out_hosts")


def ranking(v: ScanView, direction: str, metric: str, limit: int) -> list[dict]:
    col = RANK_COLS[(direction, metric)]
    rows = []
    for hid, m in v.metrics.items():
        h = v.hosts.get(hid)
        if h is None or m[col] <= 0:
            continue
        rows.append({"host_id": hid, "display_name": h.name, "status": h.status, "value": m[col],
                     "metrics": {k: m[k] for k in METRIC_KEYS}})
    rows.sort(key=lambda r: (-r["value"], natural_key(r["display_name"])))
    return rows[:limit]


# ------------------------------------------------------------------ graph

def graph(v: ScanView, center_host: int | None, center_key: str | None, hops: int, layer: str,
          max_nodes: int) -> dict:
    def ok(e: Edge) -> bool:
        if layer == "access" and e.kind != "access":
            return False
        if layer == "evidence" and e.kind != "evidence":
            return False
        return e.src != e.dst

    edges = [e for e in v.edges if ok(e)]

    def nid(e: Edge, side: str) -> str:
        if side == "src":
            return str(e.src) if e.src is not None else "unknown:" + (e.fp or "")
        return str(e.dst)

    adj: dict[str, list[Edge]] = {}
    for e in edges:
        adj.setdefault(nid(e, "src"), []).append(e)
        adj.setdefault(nid(e, "dst"), []).append(e)
    dist: dict[str, int] = {}
    frontier: list[str] = []
    if center_host is not None:
        dist[str(center_host)] = 0
        frontier = [str(center_host)]
        start_depth = 0
    else:
        for e in edges:
            if e.fp == center_key:
                for n in (nid(e, "src"), nid(e, "dst")):
                    if n not in dist:
                        dist[n] = 1
                        frontier.append(n)
        start_depth = 1
    d = start_depth
    while frontier and d < hops:
        nxt = []
        for n in frontier:
            for e in adj.get(n, []):
                for m in (nid(e, "src"), nid(e, "dst")):
                    if m not in dist:
                        dist[m] = d + 1
                        nxt.append(m)
        frontier = nxt
        d += 1
    degree = {n: len(adj.get(n, [])) for n in dist}

    def nname(n: str) -> str:
        if n.startswith("unknown:"):
            return n
        return v.hosts[int(n)].name if int(n) in v.hosts else n

    ordered = sorted(dist, key=lambda n: (dist[n], -degree[n], natural_key(nname(n))))
    total = len(ordered)
    keep = ordered[:max_nodes]
    keep_set = set(keep)
    nodes = []
    for n in keep:
        if n.startswith("unknown:"):
            fp = n[len("unknown:"):]
            k = v.keys.get(fp)
            nodes.append({"id": n, "kind": "unknown", "label": n, "fp": fp, "status": None, "dist": dist[n],
                          "degree": degree[n], "strength": k[2] if k else None})
        else:
            h = v.hosts[int(n)]
            nodes.append({"id": n, "kind": "host", "label": h.name, "host_id": h.id, "status": h.status,
                          "dist": dist[n], "degree": degree[n], "sev": h.sev if h.sev in ("critical", "high") else None})
    links: dict[tuple, dict] = {}
    for e in edges:
        s, t = nid(e, "src"), nid(e, "dst")
        if s not in keep_set or t not in keep_set:
            continue
        if center_key is not None and hops == 1 and e.fp != center_key:
            continue
        key = (s, t, e.kind, e.fp, e.status, e.effective)
        k = v.keys.get(e.fp) if e.fp else None
        lk = links.setdefault(key, {"source": s, "target": t, "kind": e.kind, "status": e.status,
                                     "effective": bool(e.effective), "fp": e.fp, "strength": k[2] if k else None,
                                     "alg": k[0] if k else None, "bits": k[1] if k else None,
                                     "users": [], "flags": [], "edge_ids": []})
        u = f"{e.src_user or ''}→{e.dst_user or ''}"
        if u not in lk["users"]:
            lk["users"].append(u)
        for f in e.flags:
            if f not in lk["flags"]:
                lk["flags"].append(f)
        lk["edge_ids"].append(e.id)
    return {"nodes": nodes, "links": list(links.values()), "truncated": total > max_nodes, "total_nodes": total,
            "center": str(center_host) if center_host is not None else None, "center_key": center_key}
