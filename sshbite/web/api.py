"""The HTTP API (spec 5, with the additions of the P2 brief).

General rules: JSON under /api, a session for everything but login, URL-safe fingerprints in paths
(+ -> -, / -> _), lists with page/page_size -> {items, total, page}, errors {"error": {code, message}},
and X-CSRF-Token on POST/PUT/DELETE.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterator
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .. import __version__
from .. import db as dbm
from ..db import unj
from ..diff import diff_scans
from ..export import COLUMNS, ROWS, ExportFilter, to_csv, to_json
from ..report import discovered_via
from . import auth
from . import data as D
from .app import ApiError

router = APIRouter()

SEVERITIES = ("critical", "high", "medium", "low", "info")
STRENGTHS = ("critical", "weak", "ok", "good", "unknown")
NOT_SCANNED = ("excluded", "out_of_scope", "max_depth", "max_hosts", "unresolvable", "alias", "already", "no_ssh")


# ------------------------------------------------------------------ plumbing

def open_db(path: str) -> sqlite3.Connection:
    """A request's connection; FastAPI may run a dependency and its endpoint on different threads."""
    if not __import__("os").path.exists(path):
        raise ApiError(503, "database_unavailable", f"database {path} does not exist")
    conn = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def get_db(request: Request) -> Iterator[sqlite3.Connection]:
    conn = open_db(request.app.state.database)
    try:
        yield conn
    finally:
        conn.close()


def session(request: Request, conn: sqlite3.Connection = Depends(get_db)) -> sqlite3.Row:
    s = auth.load_session(conn, request.cookies.get(auth.COOKIE))
    if s is None:
        raise ApiError(401, "unauthenticated", "Your session has ended. Log in again.")
    if request.method in ("POST", "PUT", "DELETE", "PATCH") and not auth.csrf_ok(
            s, request.headers.get("X-CSRF-Token")):
        raise ApiError(403, "csrf", "missing or wrong X-CSRF-Token")
    return s


def fp_from_url(s: str) -> str:
    return s.replace("-", "+").replace("_", "/")


def fp_to_url(fp: str) -> str:
    return fp.replace("+", "-").replace("/", "_")


def _scan_row(conn, sid: int) -> sqlite3.Row:
    r = conn.execute("SELECT * FROM scan WHERE id=?", (sid,)).fetchone()
    if r is None:
        raise ApiError(404, "scan_not_found", f"Scan #{sid} does not exist.")
    return r


def _page(items: list, page: int, page_size: int) -> dict:
    total = len(items)
    start = (page - 1) * page_size
    return {"items": items[start:start + page_size], "total": total, "page": page, "page_size": page_size}


Page = Query(1, ge=1)
PageSize = Query(100, ge=1, le=1000)


def _csv_list(v: str | None) -> list[str]:
    return [x for x in (v or "").split(",") if x]


def _host_names(conn, sid: int) -> dict[int, str]:
    return {r[0]: r[1] for r in conn.execute(
        "SELECT hs.host_id, h.display_name FROM host_scan hs JOIN host h ON h.id=hs.host_id WHERE hs.scan_id=?",
        (sid,))}


def _labels(conn) -> dict[str, sqlite3.Row]:
    return {r["fp"]: r for r in conn.execute("SELECT * FROM key_label")}


# ------------------------------------------------------------------ auth

class LoginBody(BaseModel):
    username: str = ""
    password: str = ""


@router.post("/login", status_code=204)
def login(body: LoginBody, request: Request, conn: sqlite3.Connection = Depends(get_db)):
    guard: auth.Guard = request.app.state.guard
    ip = request.client.host if request.client else "?"
    if guard.ip_blocked(ip):
        raise ApiError(429, "rate_limited", "Too many attempts from this address. Wait 15 minutes and try again.")
    if len(body.username) > 64 or len(body.password) > 1024:
        guard.ip_failure(ip)
        raise ApiError(401, "bad_credentials", "Wrong username or password.")
    res = auth.check_login(conn, guard, body.username, body.password)
    if not res.ok:
        guard.ip_failure(ip)
        if res.code == "account_locked":
            raise ApiError(401, "account_locked", "This account is locked after 5 failed attempts.",
                           locked_until=res.locked_until)
        raise ApiError(401, "bad_credentials", "Wrong username or password.")
    token, _csrf, _exp = auth.create_session(conn, res.user_id, request.app.state.session_hours)
    response = Response(status_code=204)
    response.set_cookie(auth.COOKIE, token, max_age=int(request.app.state.session_hours * 3600), path="/",
                        httponly=True, samesite="strict", secure=bool(request.app.state.tls))
    return response


@router.post("/logout", status_code=204)
def logout(request: Request, s=Depends(session), conn: sqlite3.Connection = Depends(get_db)):
    auth.delete_session(conn, request.cookies.get(auth.COOKIE))
    response = Response(status_code=204)
    response.delete_cookie(auth.COOKIE, path="/", httponly=True, samesite="strict",
                           secure=bool(request.app.state.tls))
    return response


@router.get("/session")
def get_session(s=Depends(session)):
    return {"username": s["username"], "csrf_token": s["csrf_token"], "expires_at": s["expires_at"],
            "version": __version__}


# ------------------------------------------------------------------ scans

def _scan_item(r: sqlite3.Row) -> dict:
    return {"id": r["id"], "label": r["label"], "started_at": r["started_at"], "finished_at": r["finished_at"],
            "status": r["status"], "synthetic": bool(r["synthetic"]), "counts": unj(r["counts"], {}) or {},
            "entry_host": r["entry_host"], "running": r["status"] == "running"}


@router.get("/scans")
def list_scans(page: int = Page, page_size: int = PageSize, s=Depends(session),
               conn: sqlite3.Connection = Depends(get_db)):
    items = [_scan_item(r) for r in conn.execute("SELECT * FROM scan ORDER BY id DESC")]
    return _page(items, page, page_size)


@router.get("/scans/{sid}")
def get_scan(sid: int, s=Depends(session), conn: sqlite3.Connection = Depends(get_db)):
    r = _scan_row(conn, sid)
    d = _scan_item(r)
    d["params"] = unj(r["params"], {}) or {}
    d["progress"] = unj(r["progress"], {}) or {}
    d["tool_version"] = r["tool_version"]
    d["collector_sha256"] = r["collector_sha256"]
    d["error"] = (d["counts"] or {}).get("error")
    d["unresolved_hashed_total"] = conn.execute(
        "SELECT coalesce(sum(unresolved_hashed),0) FROM host_scan WHERE scan_id=?", (sid,)).fetchone()[0]
    prev = conn.execute("SELECT id FROM scan WHERE status='completed' AND id<? ORDER BY id DESC LIMIT 1",
                        (sid,)).fetchone()
    d["previous_completed"] = prev[0] if prev else None
    if r["status"] == "running":
        d["progress"]["partial"] = (d["progress"].get("by_status") or {}).get("partial", 0)
        d["progress"]["unreachable"] = sum((d["progress"].get("by_status") or {}).get(k, 0)
                                           for k in ("unreachable", "timeout", "auth_failed"))
    return d


@router.get("/scans/{sid}/crawl")
def crawl_tree(sid: int, s=Depends(session), conn: sqlite3.Connection = Depends(get_db)):
    """The crawl tree (design 4.4): hosts with their parent, and references that led to no new host."""
    _scan_row(conn, sid)
    names = _host_names(conn, sid)
    refs = {r["id"]: r for r in conn.execute("SELECT * FROM reference WHERE scan_id=?", (sid,))}
    hosts = []
    for r in conn.execute("SELECT hs.*, h.display_name FROM host_scan hs JOIN host h ON h.id=hs.host_id"
                          " WHERE hs.scan_id=?", (sid,)):
        ref = refs.get(r["discovered_via_ref"])
        hosts.append({
            "host_id": r["host_id"], "display_name": r["display_name"], "status": r["status"],
            "privilege": r["privilege"], "depth": r["depth"], "route": unj(r["route"]),
            "route_attempts": unj(r["route_attempts"], []) or [], "parent_host_id": ref["from_host_id"] if ref else None,
            "via": ({"parent": names.get(ref["from_host_id"]), "source": ref["source"], "file": ref["file"],
                     "line": ref["line_no"], "value": ref["value"], "username": ref["username"]} if ref else
                    {"parent": None, "source": r["seed_source"], "file": None, "line": None}),
            "unresolved_hashed": r["unresolved_hashed"], "alias_of_host_id": r["alias_of_host_id"],
            "error": r["error"],
        })
    via_ids = {r["discovered_via_ref"] for r in conn.execute(
        "SELECT discovered_via_ref FROM host_scan WHERE scan_id=? AND discovered_via_ref IS NOT NULL", (sid,))}
    references = []
    for rid, r in refs.items():
        if rid in via_ids or r["outcome"] == "queued":
            continue
        references.append({"id": rid, "from_host_id": r["from_host_id"], "username": r["username"],
                           "source": r["source"], "file": r["file"], "line": r["line_no"], "value": r["value"],
                           "outcome": r["outcome"], "target_host_id": r["target_host_id"],
                           "target": names.get(r["target_host_id"])})
    return {"hosts": hosts, "references": references,
            "unresolved_hashed_total": sum(h["unresolved_hashed"] or 0 for h in hosts)}


# ------------------------------------------------------------------ hosts

def _host_list(conn, sid: int) -> list[dict]:
    refs = {r["id"]: r for r in conn.execute("SELECT id, from_host_id, source, file, line_no, value FROM reference"
                                             " WHERE scan_id=?", (sid,))}
    names = _host_names(conn, sid)
    metrics = {r["host_id"]: {k: r[k] for k in D.METRIC_KEYS} for r in conn.execute(
        "SELECT * FROM host_metric WHERE scan_id=?", (sid,))}
    fsev: dict[int, dict] = {}
    for hid, sev, n in conn.execute("SELECT host_id, severity, count(*) FROM finding WHERE scan_id=? AND host_id IS"
                                    " NOT NULL GROUP BY host_id, severity", (sid,)):
        fsev.setdefault(hid, {})[sev] = n
    groups: dict[int, dict] = {}
    for hid, kind, name in conn.execute("SELECT host_id, kind, name FROM host_group WHERE scan_id=?", (sid,)):
        groups.setdefault(hid, {}).setdefault(kind, name)
    ips: dict[int, list] = {}
    for hid, val in conn.execute("SELECT host_id, value FROM host_name WHERE scan_id=? AND kind='ip' ORDER BY rowid",
                                 (sid,)):
        ips.setdefault(hid, []).append(val)
    out = []
    for r in conn.execute("SELECT hs.*, h.display_name FROM host_scan hs JOIN host h ON h.id=hs.host_id"
                          " WHERE hs.scan_id=?", (sid,)):
        hid = r["host_id"]
        ref = refs.get(r["discovered_via_ref"])
        hip = list(unj(r["ips"], []) or [])
        if r["connect_addr"] and r["connect_addr"] not in hip and _is_ip(r["connect_addr"]):
            hip.insert(0, r["connect_addr"])
        elif r["connect_addr"] in hip:
            hip.remove(r["connect_addr"])
            hip.insert(0, r["connect_addr"])
        for x in ips.get(hid, []):
            if x not in hip:
                hip.append(x)
        fs = fsev.get(hid, {})
        out.append({
            "host_id": hid, "display_name": r["display_name"], "ips": hip, "status": r["status"],
            "privilege": r["privilege"], "depth": r["depth"], "route": unj(r["route"]),
            "discovered_via": ({"parent": names.get(ref["from_host_id"]), "parent_host_id": ref["from_host_id"],
                                "source": ref["source"], "file": ref["file"], "line": ref["line_no"]} if ref else
                               {"parent": None, "parent_host_id": None, "source": r["seed_source"], "file": None,
                                "line": None}),
            "metrics": metrics.get(hid, {k: 0 for k in D.METRIC_KEYS}), "findings_by_severity": fs,
            "findings_total": sum(fs.values()), "groups": groups.get(hid, {}),
            "unresolved_hashed": r["unresolved_hashed"], "os": r["os"],
        })
    return out


def _is_ip(v: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _filter_hosts(items: list[dict], status: str | None, privilege: str | None, q: str | None,
                  group_kind: str | None, group: str | None) -> list[dict]:
    st = set(_csv_list(status))
    pv = set(_csv_list(privilege))
    out = []
    ql = (q or "").strip().lower()
    for h in items:
        if st and h["status"] not in st:
            continue
        if not st and h["status"] == "no_ssh":  # silent CIDR-seed addresses are hidden by default (spec 3.3)
            continue
        if pv and (h["privilege"] or "none") not in pv:
            continue
        if ql and ql not in h["display_name"].lower() and not any(ql in ip for ip in h["ips"]):
            continue
        if group_kind and group:
            if group_kind == "depth":
                if str(h["depth"]) != group:
                    continue
            elif (h["groups"].get(group_kind) or "") != group:
                continue
        out.append(h)
    return out


HOST_SORTS = {
    "name": lambda h: D.natural_key(h["display_name"]),
    "in_hosts": lambda h: (-h["metrics"]["in_hosts"], D.natural_key(h["display_name"])),
    "out_hosts": lambda h: (-h["metrics"]["out_hosts"], D.natural_key(h["display_name"])),
    "in_unknown_keys": lambda h: (-h["metrics"]["in_unknown_keys"], D.natural_key(h["display_name"])),
    "findings": lambda h: (tuple(-h["findings_by_severity"].get(s, 0) for s in SEVERITIES),
                           D.natural_key(h["display_name"])),
    "depth": lambda h: (h["depth"] if h["depth"] is not None else 999, D.natural_key(h["display_name"])),
    "unresolved_hashed": lambda h: (-(h["unresolved_hashed"] or 0), D.natural_key(h["display_name"])),
}


@router.get("/scans/{sid}/hosts")
def list_hosts(sid: int, status: str | None = None, privilege: str | None = None, q: str | None = None,
               group_kind: str | None = Query(None, pattern="^(subnet|ansible|tag|depth)$"),
               group: str | None = None,
               sort: str = Query("name", pattern="^(name|in_hosts|out_hosts|in_unknown_keys|findings|depth|"
                                                 "unresolved_hashed)$"),
               order: str = Query("default", pattern="^(default|asc|desc)$"),
               page: int = Page, page_size: int = PageSize, s=Depends(session),
               conn: sqlite3.Connection = Depends(get_db)):
    _scan_row(conn, sid)
    allh = _host_list(conn, sid)
    items = _filter_hosts(allh, status, privilege, q, group_kind, group)
    items.sort(key=HOST_SORTS[sort])
    if order == "desc" and sort in ("name", "depth") or order == "asc" and sort not in ("name", "depth"):
        items.reverse()
    res = _page(items, page, page_size)
    res["status_counts"] = {}
    for h in allh:
        res["status_counts"][h["status"]] = res["status_counts"].get(h["status"], 0) + 1
    res["unresolved_hashed_total"] = sum(h["unresolved_hashed"] or 0 for h in allh)
    facets: dict[str, set] = {"subnet": set(), "ansible": set(), "tag": set(), "depth": set()}
    for h in allh:
        for k, v in h["groups"].items():
            facets.setdefault(k, set()).add(v)
        if h["depth"] is not None:
            facets["depth"].add(str(h["depth"]))
    res["groups"] = {k: sorted(v, key=D.natural_key) for k, v in facets.items()}
    return res


def _edge_query(conn, sid: int, where: str = "", args: tuple = ()) -> list[dict]:
    names = _host_names(conn, sid)
    keys = {}
    rows = conn.execute(
        "SELECT e.*, a.file AS a_file, a.line_no AS a_line, a.from_patterns AS a_from, a.options AS a_opts,"
        " p.path AS p_path, r.source AS r_source, r.file AS r_file, r.line_no AS r_line, r.value AS r_value,"
        " k.alg AS k_alg, k.bits AS k_bits, k.strength AS k_strength FROM edge e"
        " LEFT JOIN authorized_entry a ON a.id = e.authorized_entry_id"
        " LEFT JOIN private_key p ON p.id = e.private_key_id"
        " LEFT JOIN reference r ON r.id = e.reference_id"
        " LEFT JOIN key k ON k.fp = e.fp"
        f" WHERE e.scan_id=? {where} ORDER BY e.id", (sid, *args)).fetchall()
    out = []
    for r in rows:
        out.append({
            "id": r["id"], "kind": r["kind"], "status": r["status"], "effective": bool(r["effective"]),
            "flags": unj(r["flags"], []) or [], "src_host_id": r["src_host_id"],
            "src": names.get(r["src_host_id"]) if r["src_host_id"] is not None else None,
            "src_user": r["src_user"], "dst_host_id": r["dst_host_id"], "dst": names.get(r["dst_host_id"]),
            "dst_user": r["dst_user"], "fp": r["fp"], "alg": r["k_alg"], "bits": r["k_bits"],
            "strength": r["k_strength"], "from_patterns": unj(r["a_from"], []) or [],
            "options": unj(r["a_opts"], []) or [],
            "authorized_file": r["a_file"], "authorized_line": r["a_line"], "private_key_path": r["p_path"],
            "evidence_source": r["r_source"], "evidence_file": r["r_file"], "evidence_line": r["r_line"],
            "evidence_value": r["r_value"],
        })
    del keys
    return out


def _known_hosts_rows(conn, sid: int, where: str, args: tuple, names: dict) -> list[dict]:
    out = []
    for r in conn.execute(f"SELECT * FROM known_host_entry WHERE scan_id=? AND {where} ORDER BY host_id, username,"
                          " file, line_no", (sid, *args)):
        out.append({"id": r["id"], "host_id": r["host_id"], "host": names.get(r["host_id"]), "username": r["username"],
                    "file": r["file"], "line": r["line_no"], "marker": r["marker"], "hashed": bool(r["hashed"]),
                    "patterns": unj(r["patterns"], []) or [], "resolved_value": r["resolved_value"],
                    "target_host_id": r["target_host_id"], "target": names.get(r["target_host_id"]),
                    "key_alg": r["key_alg"], "key_fp": r["key_fp"], "matches_actual": r["matches_actual"]})
    return out


def _finding_items(conn, sid: int, where: str = "", args: tuple = ()) -> list[dict]:
    labels = _labels(conn)
    out = []
    for r in conn.execute(
            "SELECT f.*, h.display_name AS host, k.alg AS k_alg, k.bits AS k_bits, k.strength AS k_strength"
            " FROM finding f LEFT JOIN host h ON h.id=f.host_id LEFT JOIN key k ON k.fp=f.fp"
            f" WHERE f.scan_id=? {where}", (sid, *args)):
        lab = labels.get(r["fp"]) if r["fp"] else None
        out.append({"id": r["id"], "rule": r["rule"], "severity": r["severity"], "host_id": r["host_id"],
                    "host": r["host"], "username": r["username"], "fp": r["fp"], "alg": r["k_alg"],
                    "bits": r["k_bits"], "strength": r["k_strength"], "label": lab["label"] if lab else None,
                    "file": r["file"], "line": r["line_no"], "detail": unj(r["detail"], {}) or {},
                    "recommendation": r["recommendation"], "ident": r["ident"]})
    return out


def _sort_findings(items: list[dict], sort: str = "severity") -> list[dict]:
    def k(f):
        base = (D.SEV_RANK[f["severity"]], f["rule"], D.natural_key(f["host"] or ""), f["username"] or "",
                f["file"] or "", f["line"] or 0, f["id"])
        if sort == "rule":
            return (f["rule"],) + base
        if sort == "host":
            return (D.natural_key(f["host"] or "~"),) + base
        return base

    return sorted(items, key=k)


@router.get("/scans/{sid}/hosts/{hid}")
def host_detail(sid: int, hid: int, s=Depends(session), conn: sqlite3.Connection = Depends(get_db)):
    _scan_row(conn, sid)
    r = conn.execute("SELECT hs.*, h.display_name, h.identity FROM host_scan hs JOIN host h ON h.id=hs.host_id"
                     " WHERE hs.scan_id=? AND hs.host_id=?", (sid, hid)).fetchone()
    if r is None:
        raise ApiError(404, "host_not_found", f"Host {hid} does not occur in scan #{sid}.")
    names = _host_names(conn, sid)
    hs = {k: r[k] for k in r.keys()}
    for k in ("route", "route_attempts", "ips", "partial_reasons"):
        hs[k] = unj(hs[k], [] if k != "route" else None)
    via = discovered_via(conn, r["discovered_via_ref"])
    if via is not None:
        ref = conn.execute("SELECT from_host_id, username FROM reference WHERE id=?", (r["discovered_via_ref"],)).fetchone()
        via["parent_host_id"] = ref[0] if ref else None
        via["username"] = ref[1] if ref else None
    else:
        via = {"parent": None, "parent_host_id": None, "source": r["seed_source"], "file": None, "line": None}
    hs["discovered_via"] = via
    hs["alias_of"] = names.get(r["alias_of_host_id"]) if r["alias_of_host_id"] else None
    host_names = [dict(x) for x in conn.execute("SELECT kind, value FROM host_name WHERE scan_id=? AND host_id=?"
                                                " ORDER BY kind, rowid", (sid, hid))]
    host_keys = [dict(x) for x in conn.execute("SELECT alg, fp, bits FROM host_key WHERE scan_id=? AND host_id=?",
                                               (sid, hid))]
    groups = {x[0]: x[1] for x in conn.execute("SELECT kind, name FROM host_group WHERE scan_id=? AND host_id=?",
                                                (sid, hid))}
    sshd = [dict(x) for x in conn.execute("SELECT source, name, value, file, line FROM sshd_setting WHERE scan_id=?"
                                          " AND host_id=? ORDER BY rowid", (sid, hid))]
    accounts = [dict(x) for x in conn.execute("SELECT username, uid, gid, home, shell, login_shell, pw_state, expiry"
                                              " FROM account WHERE scan_id=? AND host_id=? ORDER BY uid, username",
                                              (sid, hid))]
    priv_fps = {x[0] for x in conn.execute("SELECT DISTINCT fp FROM private_key WHERE scan_id=? AND fp IS NOT NULL",
                                           (sid,))}
    holders: dict[str, int] = {}
    for fp, n in conn.execute("SELECT fp, count(*) FROM private_key WHERE scan_id=? AND fp IS NOT NULL GROUP BY fp",
                              (sid,)):
        holders[fp] = n
    keys = {x[0]: x for x in conn.execute("SELECT fp, alg, bits, strength FROM key WHERE fp IN (SELECT fp FROM"
                                          " authorized_entry WHERE scan_id=? AND host_id=? UNION SELECT fp FROM"
                                          " private_key WHERE scan_id=? AND host_id=?)", (sid, hid, sid, hid))}
    labels = _labels(conn)
    authorized = []
    for a in conn.execute("SELECT * FROM authorized_entry WHERE scan_id=? AND host_id=? ORDER BY username, file,"
                          " line_no", (sid, hid)):
        k = keys.get(a["fp"])
        authorized.append({
            "id": a["id"], "username": a["username"], "file": a["file"], "line": a["line_no"], "fp": a["fp"],
            "alg": a["alg"], "bits": k["bits"] if k else None, "strength": k["strength"] if k else "unknown",
            "comment": a["comment"], "options": unj(a["options"], []) or [],
            "from_patterns": unj(a["from_patterns"], []) or [], "command": a["command"],
            "restrict": bool(a["restrict"]), "cert_authority": bool(a["cert_authority"]),
            "principals": a["principals"], "expiry_time": a["expiry_time"], "user_exists": bool(a["user_exists"]),
            "raw": a["raw"], "origin": ("ca" if a["cert_authority"] else "known" if a["fp"] in priv_fps else "unknown"),
            "holders": holders.get(a["fp"], 0), "label": labels[a["fp"]]["label"] if a["fp"] in labels else None,
        })
    private = []
    for p in conn.execute("SELECT * FROM private_key WHERE scan_id=? AND host_id=? ORDER BY username, path",
                          (sid, hid)):
        k = keys.get(p["fp"]) if p["fp"] else None
        private.append({"id": p["id"], "username": p["username"], "path": p["path"], "fp": p["fp"], "alg": p["alg"],
                        "bits": p["bits"], "strength": k["strength"] if k else "unknown", "encrypted": p["encrypted"],
                        "mode": f"{p['mode']:04o}" if p["mode"] is not None else None,
                        "mode_bad": bool(p["mode"] is not None and p["mode"] & 0o044),
                        "owner": p["owner"], "mtime": p["mtime"], "has_pub": bool(p["has_pub"])})
    pubs = [dict(x) for x in conn.execute("SELECT username, path, fp, comment FROM pub_file WHERE scan_id=? AND"
                                          " host_id=? ORDER BY username, path", (sid, hid))]
    known_hosts = _known_hosts_rows(conn, sid, "host_id=?", (hid,), names)
    ssh_config = []
    for c in conn.execute("SELECT * FROM ssh_config_entry WHERE scan_id=? AND host_id=? ORDER BY username, file,"
                          " line_no", (sid, hid)):
        ssh_config.append({"username": c["username"], "file": c["file"], "line": c["line_no"],
                           "host_pattern": c["host_pattern"], "hostname": c["hostname"], "user": c["user"],
                           "port": c["port"], "identity_files": unj(c["identity_files"], []) or [],
                           "proxyjump": c["proxyjump"]})
    refs_out = []
    for x in conn.execute("SELECT * FROM reference WHERE scan_id=? AND from_host_id=? ORDER BY username, file, line_no",
                          (sid, hid)):
        refs_out.append({"id": x["id"], "username": x["username"], "source": x["source"], "file": x["file"],
                         "line": x["line_no"], "value": x["value"], "outcome": x["outcome"],
                         "target_host_id": x["target_host_id"], "target": names.get(x["target_host_id"])})
    known_by = _known_hosts_rows(conn, sid, "target_host_id=? AND host_id!=?", (hid, hid), names)
    edges_in = _edge_query(conn, sid, "AND e.dst_host_id=?", (hid,))
    edges_out = _edge_query(conn, sid, "AND e.src_host_id=?", (hid,))
    findings = _sort_findings(_finding_items(conn, sid, "AND f.host_id=?", (hid,)))
    metrics = conn.execute("SELECT * FROM host_metric WHERE scan_id=? AND host_id=?", (sid, hid)).fetchone()
    # users who have SSH data on this host
    users: dict[str, dict] = {}
    for lst, kind in ((authorized, "authorized"), (private, "private"), (pubs, "pub"), (known_hosts, "known_hosts"),
                      (ssh_config, "ssh_config")):
        for x in lst:
            users.setdefault(x["username"], {"authorized": 0, "private": 0, "pub": 0, "known_hosts": 0,
                                             "ssh_config": 0})[kind] += 1
    unresolved = {}
    hashed_unmatched = r["unresolved_hashed"] or 0
    return {
        "host_scan": hs, "names": host_names, "host_keys": host_keys, "groups": groups, "sshd": sshd,
        "accounts": accounts, "authorized": authorized, "private_keys": private, "pub_files": pubs,
        "known_hosts": known_hosts, "ssh_config": ssh_config, "references_out": refs_out, "known_by": known_by,
        "edges_in": edges_in, "edges_out": edges_out, "findings": findings,
        "metrics": {k: metrics[k] for k in D.METRIC_KEYS} if metrics else {k: 0 for k in D.METRIC_KEYS},
        "users": [{"username": u, **c} for u, c in sorted(users.items(), key=lambda x: (x[0] != "root", x[0]))],
        "unresolved_hashed": hashed_unmatched, "unresolved_by_user": unresolved,
    }


# ------------------------------------------------------------------ keys

def _key_summary(conn, sid: int) -> list[dict]:
    labels = _labels(conn)
    auth_hosts: dict[str, set] = {}
    comments: dict[str, list] = {}
    for fp, hid, comment in conn.execute("SELECT fp, host_id, comment FROM authorized_entry WHERE scan_id=? AND fp IS"
                                         " NOT NULL AND cert_authority=0 ORDER BY id", (sid,)):
        auth_hosts.setdefault(fp, set()).add(hid)
        if comment and comment not in comments.setdefault(fp, []):
            comments[fp].append(comment)
    ca_fps: dict[str, set] = {}
    for fp, hid, comment in conn.execute("SELECT fp, host_id, comment FROM authorized_entry WHERE scan_id=? AND fp IS"
                                         " NOT NULL AND cert_authority=1", (sid,)):
        ca_fps.setdefault(fp, set()).add(hid)
        if comment and comment not in comments.setdefault(fp, []):
            comments[fp].append(comment)
    holders: dict[str, set] = {}
    for fp, hid, user in conn.execute("SELECT fp, host_id, username FROM private_key WHERE scan_id=? AND fp IS NOT NULL",
                                      (sid,)):
        holders.setdefault(fp, set()).add((hid, user))
    for fp, comment in conn.execute("SELECT fp, comment FROM pub_file WHERE scan_id=? AND fp IS NOT NULL", (sid,)):
        if comment and comment not in comments.setdefault(fp, []):
            comments[fp].append(comment)
    fsev: dict[str, dict] = {}
    for fp, sev, n in conn.execute("SELECT fp, severity, count(*) FROM finding WHERE scan_id=? AND fp IS NOT NULL"
                                   " GROUP BY fp, severity", (sid,)):
        fsev.setdefault(fp, {})[sev] = n
    fps = set(auth_hosts) | set(holders) | set(ca_fps)
    keys = {r[0]: r for r in conn.execute("SELECT fp, alg, bits, strength FROM key")}
    out = []
    for fp in fps:
        k = keys.get(fp)
        lab = labels.get(fp)
        out.append({"fp": fp, "fp_url": fp_to_url(fp), "alg": k["alg"] if k else None, "bits": k["bits"] if k else None,
                    "strength": k["strength"] if k else "unknown", "label": lab["label"] if lab else None,
                    "owner": lab["owner"] if lab else None, "comments": comments.get(fp, []),
                    "authorized_hosts": len(auth_hosts.get(fp, set()) | ca_fps.get(fp, set())),
                    "private_holders": len(holders.get(fp, set())),
                    "origin": "known" if fp in holders else "unknown", "cert_authority": fp in ca_fps,
                    "findings": fsev.get(fp, {})})
    return out


@router.get("/scans/{sid}/keys")
def list_keys(sid: int, q: str | None = None, strength: str | None = None,
              origin: str | None = Query(None, pattern="^(known|unknown|all)?$"),
              sort: str = Query("strength", pattern="^(strength|fp|bits|authorized_hosts|private_holders|label)$"),
              order: str = Query("default", pattern="^(default|asc|desc)$"),
              page: int = Page, page_size: int = PageSize, s=Depends(session),
              conn: sqlite3.Connection = Depends(get_db)):
    _scan_row(conn, sid)
    allk = _key_summary(conn, sid)
    st = set(_csv_list(strength))
    ql = (q or "").strip().lower()
    items = []
    for k in allk:
        if st and k["strength"] not in st:
            continue
        if origin in ("known", "unknown") and k["origin"] != origin:
            continue
        if ql and not (ql in k["fp"].lower() or ql in (k["label"] or "").lower() or ql in (k["owner"] or "").lower()
                       or any(ql in c.lower() for c in k["comments"])):
            continue
        items.append(k)
    sorts = {
        "strength": lambda k: (D.STRENGTH_RANK.get(k["strength"], 9), -k["authorized_hosts"], k["fp"]),
        "fp": lambda k: k["fp"],
        "bits": lambda k: (-(k["bits"] or 0), k["fp"]),
        "authorized_hosts": lambda k: (-k["authorized_hosts"], k["fp"]),
        "private_holders": lambda k: (-k["private_holders"], k["fp"]),
        "label": lambda k: ((k["label"] or "~").lower(), k["fp"]),
    }
    items.sort(key=sorts[sort])
    if order == "desc" and sort in ("fp", "label") or order == "asc" and sort not in ("fp", "label"):
        items.reverse()
    res = _page(items, page, page_size)
    res["strength_counts"] = {}
    for k in allk:
        res["strength_counts"][k["strength"]] = res["strength_counts"].get(k["strength"], 0) + 1
    res["total_all"] = len(allk)
    return res


def _label_dict(lab) -> dict:
    if lab is None:
        return {"label": None, "owner": None, "note": None, "updated_at": None, "updated_by": None}
    return {k: lab[k] for k in ("label", "owner", "note", "updated_at", "updated_by")}


@router.get("/scans/{sid}/keys/{fp_url}")
def key_detail(sid: int, fp_url: str, s=Depends(session), conn: sqlite3.Connection = Depends(get_db)):
    _scan_row(conn, sid)
    fp = fp_from_url(fp_url)
    names = _host_names(conn, sid)
    k = conn.execute("SELECT * FROM key WHERE fp=?", (fp,)).fetchone()
    lab = conn.execute("SELECT * FROM key_label WHERE fp=?", (fp,)).fetchone()
    eff: dict[int, bool] = {}
    for aid, e in conn.execute("SELECT authorized_entry_id, max(effective) FROM edge WHERE scan_id=? AND fp=? AND"
                               " authorized_entry_id IS NOT NULL GROUP BY authorized_entry_id", (sid, fp)):
        eff[aid] = bool(e)
    authorized = []
    comments: list[str] = []
    for a in conn.execute("SELECT * FROM authorized_entry WHERE scan_id=? AND fp=? ORDER BY host_id, username",
                          (sid, fp)):
        authorized.append({"id": a["id"], "host_id": a["host_id"], "host": names.get(a["host_id"]),
                           "username": a["username"], "file": a["file"], "line": a["line_no"],
                           "options": unj(a["options"], []) or [], "from_patterns": unj(a["from_patterns"], []) or [],
                           "cert_authority": bool(a["cert_authority"]), "comment": a["comment"],
                           "effective": eff.get(a["id"]), "raw": a["raw"]})
        if a["comment"] and a["comment"] not in comments:
            comments.append(a["comment"])
    authorized.sort(key=lambda x: (D.natural_key(x["host"] or ""), x["username"]))
    private = []
    for p in conn.execute("SELECT * FROM private_key WHERE scan_id=? AND fp=?", (sid, fp)):
        private.append({"host_id": p["host_id"], "host": names.get(p["host_id"]), "username": p["username"],
                        "path": p["path"], "encrypted": p["encrypted"],
                        "mode": f"{p['mode']:04o}" if p["mode"] is not None else None,
                        "mode_bad": bool(p["mode"] is not None and p["mode"] & 0o044), "owner": p["owner"]})
    pubs = []
    for p in conn.execute("SELECT * FROM pub_file WHERE scan_id=? AND fp=?", (sid, fp)):
        pubs.append({"host_id": p["host_id"], "host": names.get(p["host_id"]), "username": p["username"],
                     "path": p["path"], "comment": p["comment"]})
        if p["comment"] and p["comment"] not in comments:
            comments.append(p["comment"])
    if not authorized and not private and not pubs:
        raise ApiError(404, "key_not_in_scan", f"Key {fp} does not occur in scan #{sid}.",
                       fp=fp, label=_label_dict(lab))
    edges = _edge_query(conn, sid, "AND e.fp=?", (fp,))
    findings = _sort_findings(_finding_items(conn, sid, "AND f.fp=?", (fp,)))
    return {"fp": fp, "fp_url": fp_to_url(fp), "alg": k["alg"] if k else None, "bits": k["bits"] if k else None,
            "strength": k["strength"] if k else "unknown", "is_cert": any("cert" in (a.get("raw") or "").split(" ")[0]
                                                                         for a in authorized),
            "origin": "known" if private else "unknown", "comments": comments, "label": _label_dict(lab),
            "authorized_on": authorized, "private_on": private, "pub_on": pubs, "edges": edges,
            "findings": findings}


class LabelBody(BaseModel):
    label: str | None = None
    owner: str | None = None
    note: str | None = None


@router.put("/keys/{fp_url}/label")
def put_label(fp_url: str, body: LabelBody, s=Depends(session), conn: sqlite3.Connection = Depends(get_db)):
    fp = fp_from_url(fp_url)
    if not fp.startswith("SHA256:") or len(fp) > 100:
        raise ApiError(400, "bad_fingerprint", "not a SHA256 fingerprint")
    if conn.execute("SELECT 1 FROM key WHERE fp=?", (fp,)).fetchone() is None:
        raise ApiError(404, "key_not_found", f"Key {fp} is not known.")

    def clean(v, n, name):
        v = (v or "").strip()
        if len(v) > n:
            raise ApiError(400, "too_long", f"{name} is longer than {n} characters")
        return v or None

    label, owner, note = clean(body.label, 80, "label"), clean(body.owner, 80, "owner"), clean(body.note, 2000, "note")
    now = dbm.utcnow()
    conn.execute("INSERT INTO key_label(fp, label, owner, note, updated_at, updated_by) VALUES (?,?,?,?,?,?)"
                 " ON CONFLICT(fp) DO UPDATE SET label=excluded.label, owner=excluded.owner, note=excluded.note,"
                 " updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                 (fp, label, owner, note, now, s["username"]))
    return _label_dict(conn.execute("SELECT * FROM key_label WHERE fp=?", (fp,)).fetchone())


# ------------------------------------------------------------------ edges, heatmap, ranking, graph

@router.get("/scans/{sid}/edges")
def list_edges(sid: int, host_id: int | None = None, src_host_id: int | None = None, dst_host_id: int | None = None,
               fp: str | None = None, kind: str | None = Query(None, pattern="^(access|evidence)$"),
               status: str | None = None, effective: bool | None = None, unknown_origin: bool | None = None,
               page: int = Page, page_size: int = PageSize, s=Depends(session),
               conn: sqlite3.Connection = Depends(get_db)):
    _scan_row(conn, sid)
    where, args = [], []
    if host_id is not None:
        where.append("(e.src_host_id=? OR e.dst_host_id=?)")
        args += [host_id, host_id]
    if src_host_id is not None:
        where.append("e.src_host_id=?")
        args.append(src_host_id)
    if unknown_origin:
        where.append("e.src_host_id IS NULL")
    if dst_host_id is not None:
        where.append("e.dst_host_id=?")
        args.append(dst_host_id)
    if fp:
        where.append("e.fp=?")
        args.append(fp_from_url(fp) if not fp.startswith("SHA256:") or "-" in fp or "_" in fp else fp)
    if kind:
        where.append("e.kind=?")
        args.append(kind)
    st = _csv_list(status)
    if st:
        where.append(f"e.status IN ({','.join('?' * len(st))})")
        args += st
    if effective is not None:
        where.append("e.effective=?")
        args.append(int(effective))
    items = _edge_query(conn, sid, "".join(" AND " + w for w in where), tuple(args))
    return _page(items, page, page_size)


def _view(request: Request, conn, sid: int) -> D.ScanView:
    _scan_row(conn, sid)
    return request.app.state.views.get(conn, sid)


@router.get("/scans/{sid}/heatmap")
def get_heatmap(sid: int, request: Request,
                group_by: str = Query("auto", pattern="^(auto|host|subnet|ansible|tag|depth)$"),
                metric: str = Query("hosts", pattern="^(hosts|users|keys)$"),
                layer: str = Query("access", pattern="^(access|evidence)$"),
                include_unknown: bool = True, src_group: str | None = None, dst_group: str | None = None,
                s=Depends(session), conn: sqlite3.Connection = Depends(get_db)):
    v = _view(request, conn, sid)
    if group_by == "auto":
        group_by = "host" if len(v.matrix_hosts) <= 60 else "subnet"
    t0 = time.perf_counter()
    res = D.heatmap(v, group_by, metric, layer, include_unknown, src_group, dst_group)
    res["ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return res


@router.get("/scans/{sid}/heatmap/cell")
def get_heatmap_cell(sid: int, request: Request, src_group: str, dst_group: str,
                     group_by: str = Query("host", pattern="^(host|subnet|ansible|tag|depth)$"),
                     metric: str = Query("hosts", pattern="^(hosts|users|keys)$"),
                     layer: str = Query("access", pattern="^(access|evidence)$"),
                     s=Depends(session), conn: sqlite3.Connection = Depends(get_db)):
    v = _view(request, conn, sid)
    return D.heatmap_cell(v, group_by, metric, layer, src_group, dst_group)


@router.get("/scans/{sid}/ranking")
def get_ranking(sid: int, request: Request, direction: str = Query("in", pattern="^(in|out)$"),
                metric: str = Query("hosts", pattern="^(hosts|users|keys|unknown_keys)$"),
                limit: int = Query(25, ge=1, le=500), s=Depends(session),
                conn: sqlite3.Connection = Depends(get_db)):
    v = _view(request, conn, sid)
    return {"items": D.ranking(v, direction, metric, limit), "direction": direction, "metric": metric}


@router.get("/scans/{sid}/graph")
def get_graph(sid: int, request: Request, center_host: int | None = None, center_key: str | None = None,
              hops: int = Query(1, ge=1, le=2), layer: str = Query("access", pattern="^(access|evidence|both)$"),
              max_nodes: int = Query(150, ge=2, le=150), s=Depends(session),
              conn: sqlite3.Connection = Depends(get_db)):
    if (center_host is None) == (center_key is None):
        raise ApiError(400, "bad_request", "give exactly one of center_host and center_key")
    v = _view(request, conn, sid)
    fp = None
    if center_key is not None:
        fp = fp_from_url(center_key)
    elif center_host not in v.hosts:
        raise ApiError(404, "host_not_found", f"Host {center_host} does not occur in scan #{sid}.")
    return D.graph(v, center_host, fp, hops, layer, max_nodes)


# ------------------------------------------------------------------ findings

@router.get("/scans/{sid}/findings")
def list_findings(sid: int, severity_min: str | None = Query(None, pattern="^(critical|high|medium|low|info)$"),
                  severity: str | None = None, rule: str | None = None, host_id: int | None = None, fp: str | None = None, q: str | None = None,
                  sort: str = Query("severity", pattern="^(severity|rule|host)$"),
                  page: int = Page, page_size: int = PageSize, s=Depends(session),
                  conn: sqlite3.Connection = Depends(get_db)):
    _scan_row(conn, sid)
    where, args = [], []
    if severity_min:
        sev = SEVERITIES[:SEVERITIES.index(severity_min) + 1]
        where.append(f"f.severity IN ({','.join('?' * len(sev))})")
        args += list(sev)
    exact = [x for x in _csv_list(severity) if x in SEVERITIES]
    if exact:
        where.append(f"f.severity IN ({','.join('?' * len(exact))})")
        args += exact
    rules = _csv_list(rule)
    if rules:
        where.append(f"f.rule IN ({','.join('?' * len(rules))})")
        args += rules
    if host_id is not None:
        where.append("f.host_id=?")
        args.append(host_id)
    if fp:
        where.append("f.fp=?")
        args.append(fp_from_url(fp))
    items = _finding_items(conn, sid, "".join(" AND " + w for w in where), tuple(args))
    ql = (q or "").strip().lower()
    if ql:
        items = [f for f in items if ql in " ".join(str(x) for x in (
            f["host"], f["username"], f["file"], f["line"], f["fp"], json.dumps(f["detail"]), f["recommendation"],
            f["rule"], f["label"]) if x is not None).lower()]
    items = _sort_findings(items, sort)
    res = _page(items, page, page_size)
    res["severity_counts"] = {r[0]: r[1] for r in conn.execute(
        "SELECT severity, count(*) FROM finding WHERE scan_id=? GROUP BY severity", (sid,))}
    res["rule_counts"] = {r[0]: r[1] for r in conn.execute(
        "SELECT rule, count(*) FROM finding WHERE scan_id=? GROUP BY rule", (sid,))}
    return res


# ------------------------------------------------------------------ diff, export, search

@router.get("/diff")
def get_diff(a: int, b: int, download: bool = False, s=Depends(session), conn: sqlite3.Connection = Depends(get_db)):
    _scan_row(conn, a)
    _scan_row(conn, b)
    d = diff_scans(conn, a, b)
    if download:
        return Response(json.dumps(d, indent=2, ensure_ascii=False) + "\n", media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="sshbite-diff-{a}-{b}.json"'})
    return d


@router.get("/scans/{sid}/export/{name}")
def export(sid: int, name: str, request: Request, severity_min: str | None = None, severity: str | None = None,
           rule: str | None = None,
           host_id: int | None = None, fp: str | None = None, q: str | None = None, kind: str | None = None,
           status: str | None = None, privilege: str | None = None, group_kind: str | None = None,
           group: str | None = None, strength: str | None = None, origin: str | None = None,
           s=Depends(session), conn: sqlite3.Connection = Depends(get_db)):
    what, _, fmt = name.rpartition(".")
    if what not in ROWS or fmt not in ("csv", "json"):
        raise ApiError(404, "not_found", "export must be {findings|keys|edges|hosts|authorized}.{csv|json}")
    _scan_row(conn, sid)
    if severity_min and severity_min not in SEVERITIES:
        raise ApiError(400, "bad_request", "severity_min: unknown severity")
    flt = ExportFilter(min_severity=severity_min, rules=_csv_list(rule), host_id=host_id,
                       fp=fp_from_url(fp) if fp else None, q=q if what in ("findings", "keys") else None,
                       kind=kind if kind in ("access", "evidence") else None)
    rows = ROWS[what](conn, sid, flt)
    if what == "hosts" and (status or privilege or q or (group_kind and group)):
        keep = {h["display_name"] for h in _filter_hosts(_host_list(conn, sid), status, privilege, q, group_kind,
                                                          group)}
        rows = [r for r in rows if r["host"] in keep]
    if what == "keys" and (strength or origin in ("known", "unknown")):
        st = set(_csv_list(strength))
        rows = [r for r in rows if (not st or r["strength"] in st) and
                (origin not in ("known", "unknown") or r["origin"] == origin)]
    if what == "findings" and severity:
        exact = set(_csv_list(severity))
        rows = [r for r in rows if r["severity"] in exact]
    if what == "findings":
        order = {f["id"]: i for i, f in enumerate(_sort_findings(_finding_items(conn, sid)))}
        rows.sort(key=lambda r: order.get(r["finding_id"], 0))
    cols = COLUMNS[what]
    fname = f"sshbite-scan{sid}-{what}.{fmt}"
    if fmt == "csv":
        return Response(to_csv(cols, rows), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{fname}"'})
    return Response(to_json(conn, sid, cols, rows), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@router.get("/search")
def search(q: str = Query(..., min_length=1, max_length=200), scan: int | None = None, s=Depends(session),
           conn: sqlite3.Connection = Depends(get_db)):
    sid = scan
    if sid is None:
        r = conn.execute("SELECT id FROM scan WHERE status='completed' ORDER BY id DESC LIMIT 1").fetchone()
        if r is None:
            return {"hosts": [], "keys": [], "users": [], "scan": None}
        sid = r[0]
    _scan_row(conn, sid)
    like = "%" + q.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    hosts = []
    for r in conn.execute(
            "SELECT hs.host_id, h.display_name, hs.status, (SELECT group_concat(value, ',') FROM host_name n WHERE"
            " n.scan_id=hs.scan_id AND n.host_id=hs.host_id AND n.kind='ip') AS ips FROM host_scan hs"
            " JOIN host h ON h.id=hs.host_id WHERE hs.scan_id=? AND (lower(h.display_name) LIKE ? ESCAPE '\\' OR"
            " hs.host_id IN (SELECT host_id FROM host_name WHERE scan_id=? AND lower(value) LIKE ? ESCAPE '\\'))"
            " ORDER BY length(h.display_name), h.display_name LIMIT 20", (sid, like, sid, like)):
        hosts.append({"host_id": r[0], "display_name": r[1], "status": r[2], "ips": (r[3] or "").split(",")[:3]})
    keys = []
    seen = set()
    for r in conn.execute(
            "SELECT k.fp, k.alg, k.bits, k.strength, l.label,"
            " (SELECT comment FROM authorized_entry a WHERE a.scan_id=? AND a.fp=k.fp AND a.comment IS NOT NULL LIMIT 1)"
            " AS comment FROM key k LEFT JOIN key_label l ON l.fp=k.fp"
            " WHERE k.fp IN (SELECT fp FROM authorized_entry WHERE scan_id=? UNION SELECT fp FROM private_key WHERE"
            " scan_id=?) AND (lower(k.fp) LIKE ? ESCAPE '\\' OR lower(coalesce(l.label,'')) LIKE ? ESCAPE '\\' OR"
            " lower(coalesce(l.owner,'')) LIKE ? ESCAPE '\\' OR k.fp IN (SELECT fp FROM authorized_entry WHERE"
            " scan_id=? AND lower(coalesce(comment,'')) LIKE ? ESCAPE '\\' UNION SELECT fp FROM pub_file WHERE"
            " scan_id=? AND lower(coalesce(comment,'')) LIKE ? ESCAPE '\\')) LIMIT 20",
            (sid, sid, sid, like, like, like, sid, like, sid, like)):
        if r[0] in seen:
            continue
        seen.add(r[0])
        keys.append({"fp": r[0], "fp_url": fp_to_url(r[0]), "alg": r[1], "bits": r[2], "strength": r[3],
                     "label": r[4], "comment": r[5]})
    users = []
    for r in conn.execute(
            "SELECT DISTINCT u.host_id, h.display_name, u.username FROM (SELECT host_id, username FROM authorized_entry"
            " WHERE scan_id=? UNION SELECT host_id, username FROM private_key WHERE scan_id=? UNION SELECT host_id,"
            " username FROM known_host_entry WHERE scan_id=? AND username!='' UNION SELECT host_id, username FROM"
            " ssh_config_entry WHERE scan_id=? AND username!='') u JOIN host h ON h.id=u.host_id"
            " WHERE lower(u.username) LIKE ? ESCAPE '\\' ORDER BY u.username, h.display_name LIMIT 20",
            (sid, sid, sid, sid, like)):
        users.append({"host_id": r[0], "host": r[1], "username": r[2]})
    return {"hosts": hosts, "keys": keys, "users": users, "scan": sid}


@router.api_route("/{rest:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"], include_in_schema=False)
def api_not_found(rest: str):
    raise ApiError(404, "not_found", f"no such endpoint: /api/{rest}")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = ["router", "fp_to_url", "fp_from_url", "JSONResponse"]
