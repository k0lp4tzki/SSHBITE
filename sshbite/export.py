"""Cleanup worklists as CSV / JSON (spec 7). Rows are built here and reused by the web API."""

from __future__ import annotations

import csv
import fnmatch
import io
import json
import sqlite3
from dataclasses import dataclass, field

from .db import unj

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

COLUMNS = {
    "findings": ["finding_id", "scan_id", "severity", "rule", "host", "host_ips", "user", "key_fp", "key_alg",
                 "key_bits", "key_label", "file", "line_no", "detail", "recommendation", "removal_hint", "status"],
    "keys": ["key_fp", "alg", "bits", "strength", "label", "owner", "comments", "origin", "authorized_on",
             "authorized_host_count", "private_on", "finding_rules"],
    "edges": ["kind", "status", "effective", "flags", "src_host", "src_user", "dst_host", "dst_user", "key_fp",
              "key_alg", "strength", "from_patterns", "authorized_file", "authorized_line", "private_key_path",
              "evidence_source", "evidence_file", "evidence_line"],
    # 'reasons' and 'route_attempts' extend spec 7 so partial/unreachable hosts carry their reasons (J6)
    "hosts": ["host", "ips", "status", "privilege", "depth", "discovered_via", "route", "os", "in_hosts", "in_users",
              "in_keys", "in_unknown_keys", "out_hosts", "out_users", "out_keys", "findings_critical",
              "findings_high", "reasons", "route_attempts"],
    "authorized": ["host", "user", "file", "line_no", "key_fp", "alg", "bits", "strength", "options", "origin",
                   "comment"],
}


@dataclass
class ExportFilter:
    min_severity: str | None = None
    rules: list[str] = field(default_factory=list)
    host_glob: str | None = None
    kind: str | None = None
    host_id: int | None = None
    fp: str | None = None
    q: str | None = None


class _Ctx:
    def __init__(self, conn: sqlite3.Connection, sid: int):
        self.conn = conn
        self.sid = sid
        self.host_name: dict[int, str] = {}
        self.host_ips: dict[int, list[str]] = {}
        for r in conn.execute("SELECT hs.host_id, h.display_name, hs.ips FROM host_scan hs JOIN host h ON h.id=hs.host_id"
                              " WHERE hs.scan_id=?", (sid,)):
            self.host_name[r[0]] = r[1]
            self.host_ips[r[0]] = unj(r[2], []) or []
        for r in conn.execute("SELECT host_id, value FROM host_name WHERE scan_id=? AND kind='ip'", (sid,)):
            lst = self.host_ips.setdefault(r[0], [])
            if r[1] not in lst:
                lst.append(r[1])
        self.keys = {r[0]: r for r in conn.execute("SELECT fp, alg, bits, strength FROM key")}
        self.labels = {r[0]: r for r in conn.execute("SELECT fp, label, owner, note FROM key_label")}
        self.private_fps = {r[0] for r in conn.execute(
            "SELECT DISTINCT fp FROM private_key WHERE scan_id=? AND fp IS NOT NULL", (sid,))}

    def name(self, hid: int | None) -> str:
        if hid is None:
            return ""
        return self.host_name.get(hid) or self.conn.execute("SELECT display_name FROM host WHERE id=?", (hid,)).fetchone()[0]

    def host_ok(self, flt: ExportFilter, hid: int | None) -> bool:
        if flt.host_id is not None and hid != flt.host_id:
            return False
        if not flt.host_glob:
            return True
        if hid is None:
            return False
        g = flt.host_glob.lower()
        cands = [self.name(hid)] + self.host_ips.get(hid, [])
        return any(fnmatch.fnmatchcase(c.lower(), g) for c in cands if c)

    def origin(self, fp: str | None) -> str:
        if not fp:
            return ""
        return "known" if fp in self.private_fps else "unknown"


def removal_hint(rule: str, host: str, user: str | None, fp: str | None, file: str | None, line: int | None,
                 detail: dict) -> str:
    fps = f" ({fp})" if fp else ""
    if rule in ("key_strength_critical", "key_strength_weak", "root_authorized_key", "key_unknown_origin",
                "key_for_disabled_user", "cert_authority_trusted") and file and line:
        return f"delete line {line} of {file} on {host}{fps}"
    if rule in ("key_strength_critical", "key_strength_weak", "private_key_unencrypted") and file:
        return f"delete {file} on {host} once the key is replaced{fps}"
    if rule == "private_key_bad_permissions" and file:
        return f"chmod 600 {file} on {host} and replace the key{fps}"
    if rule == "known_host_stale" and file and line:
        return f"delete line {line} of {file} on {host}"
    if rule == "permit_root_login_yes":
        return f"set PermitRootLogin prohibit-password in /etc/ssh/sshd_config on {host}"
    if rule == "password_authentication_yes":
        return f"set PasswordAuthentication no in /etc/ssh/sshd_config on {host}"
    if rule == "key_on_many_hosts":
        return f"replace{fps} with per-purpose keys on {detail.get('hosts', '?')} hosts"
    if rule == "duplicate_key_across_users":
        return f"issue one key per person/purpose instead of{fps}"
    if rule == "host_key_changed":
        return f"verify the new host key of {host} out-of-band, then `sshbite hostkey accept`"
    if rule == "host_unreachable":
        return f"check whether {host} still exists"
    if rule == "partial_scan":
        return f"grant the audit account sudo on {host} or scan with --ask-sudo-password"
    return ""


def finding_rows(conn: sqlite3.Connection, sid: int, flt: ExportFilter | None = None) -> list[dict]:
    flt = flt or ExportFilter()
    ctx = _Ctx(conn, sid)
    out = []
    for r in conn.execute("SELECT * FROM finding WHERE scan_id=? ORDER BY id", (sid,)):
        if flt.min_severity and SEVERITY_RANK[r["severity"]] > SEVERITY_RANK[flt.min_severity]:
            continue
        if flt.rules and r["rule"] not in flt.rules:
            continue
        if flt.fp and r["fp"] != flt.fp:
            continue
        if (flt.host_glob or flt.host_id is not None) and not ctx.host_ok(flt, r["host_id"]):
            continue
        k = ctx.keys.get(r["fp"]) if r["fp"] else None
        lab = ctx.labels.get(r["fp"]) if r["fp"] else None
        detail = unj(r["detail"], {}) or {}
        host = ctx.name(r["host_id"])
        row = {
            "finding_id": r["id"], "scan_id": sid, "severity": r["severity"], "rule": r["rule"], "host": host,
            "host_ips": ";".join(ctx.host_ips.get(r["host_id"], [])) if r["host_id"] else "",
            "user": r["username"] or "", "key_fp": r["fp"] or "", "key_alg": k["alg"] if k else "",
            "key_bits": k["bits"] if k and k["bits"] is not None else "", "key_label": lab["label"] if lab and lab["label"] else "",
            "file": r["file"] or "", "line_no": r["line_no"] if r["line_no"] is not None else "",
            "detail": json.dumps(detail, sort_keys=True), "recommendation": r["recommendation"],
            "removal_hint": removal_hint(r["rule"], host, r["username"], r["fp"], r["file"], r["line_no"], detail),
            "status": "",
        }
        if flt.q and flt.q.lower() not in " ".join(str(v) for v in row.values()).lower():
            continue
        out.append(row)
    return out


def key_rows(conn: sqlite3.Connection, sid: int, flt: ExportFilter | None = None) -> list[dict]:
    flt = flt or ExportFilter()
    ctx = _Ctx(conn, sid)
    auth: dict[str, list] = {}
    comments: dict[str, set] = {}
    for r in conn.execute("SELECT host_id, username, fp, comment FROM authorized_entry WHERE scan_id=? AND fp IS NOT NULL"
                          " ORDER BY id", (sid,)):
        auth.setdefault(r[2], []).append((r[0], r[1]))
        if r[3]:
            comments.setdefault(r[2], set()).add(r[3])
    priv: dict[str, list] = {}
    for r in conn.execute("SELECT host_id, username, path, fp FROM private_key WHERE scan_id=? AND fp IS NOT NULL ORDER BY id",
                          (sid,)):
        priv.setdefault(r[3], []).append((r[0], r[1], r[2]))
    for r in conn.execute("SELECT fp, comment FROM pub_file WHERE scan_id=? AND fp IS NOT NULL", (sid,)):
        if r[1]:
            comments.setdefault(r[0], set()).add(r[1])
    rules: dict[str, set] = {}
    for r in conn.execute("SELECT fp, rule FROM finding WHERE scan_id=? AND fp IS NOT NULL", (sid,)):
        rules.setdefault(r[0], set()).add(r[1])
    out = []
    for fp in sorted(set(auth) | set(priv)):
        k = ctx.keys.get(fp)
        lab = ctx.labels.get(fp)
        hosts = auth.get(fp, [])
        if flt.fp and fp != flt.fp:
            continue
        if flt.host_glob and not any(ctx.host_ok(flt, h) for h, _u in hosts) and \
                not any(ctx.host_ok(flt, h) for h, _u, _p in priv.get(fp, [])):
            continue
        row = {
            "key_fp": fp, "alg": k["alg"] if k else "", "bits": k["bits"] if k and k["bits"] is not None else "",
            "strength": k["strength"] if k else "unknown", "label": lab["label"] if lab and lab["label"] else "",
            "owner": lab["owner"] if lab and lab["owner"] else "", "comments": ";".join(sorted(comments.get(fp, set()))),
            "origin": ctx.origin(fp),
            "authorized_on": ";".join(f"{ctx.name(h)}:{u}" for h, u in hosts),
            "authorized_host_count": len({h for h, _u in hosts}),
            "private_on": ";".join(f"{ctx.name(h)}:{u}:{p}" for h, u, p in priv.get(fp, [])),
            "finding_rules": ";".join(sorted(rules.get(fp, set()))),
        }
        if flt.q and flt.q.lower() not in " ".join(str(v) for v in row.values()).lower():
            continue
        out.append(row)
    return out


def edge_rows(conn: sqlite3.Connection, sid: int, flt: ExportFilter | None = None) -> list[dict]:
    flt = flt or ExportFilter()
    ctx = _Ctx(conn, sid)
    out = []
    q = ("SELECT e.*, a.file AS a_file, a.line_no AS a_line, a.from_patterns AS a_from, p.path AS p_path,"
         " r.source AS r_source, r.file AS r_file, r.line_no AS r_line FROM edge e"
         " LEFT JOIN authorized_entry a ON a.id = e.authorized_entry_id"
         " LEFT JOIN private_key p ON p.id = e.private_key_id"
         " LEFT JOIN reference r ON r.id = e.reference_id WHERE e.scan_id=? ORDER BY e.id")
    for r in conn.execute(q, (sid,)):
        if flt.kind and r["kind"] != flt.kind:
            continue
        if flt.fp and r["fp"] != flt.fp:
            continue
        if (flt.host_glob or flt.host_id is not None) and not (ctx.host_ok(flt, r["src_host_id"]) or ctx.host_ok(flt, r["dst_host_id"])):
            continue
        k = ctx.keys.get(r["fp"]) if r["fp"] else None
        out.append({
            "kind": r["kind"], "status": r["status"], "effective": r["effective"],
            "flags": ";".join(unj(r["flags"], []) or []),
            "src_host": ctx.name(r["src_host_id"]) if r["src_host_id"] is not None else "unknown",
            "src_user": r["src_user"] or "", "dst_host": ctx.name(r["dst_host_id"]), "dst_user": r["dst_user"] or "",
            "key_fp": r["fp"] or "", "key_alg": k["alg"] if k else "", "strength": k["strength"] if k else "",
            "from_patterns": ",".join(unj(r["a_from"], []) or []), "authorized_file": r["a_file"] or "",
            "authorized_line": r["a_line"] if r["a_line"] is not None else "", "private_key_path": r["p_path"] or "",
            "evidence_source": r["r_source"] or "", "evidence_file": r["r_file"] or "",
            "evidence_line": r["r_line"] if r["r_line"] is not None else "",
        })
    return out


def host_rows(conn: sqlite3.Connection, sid: int, flt: ExportFilter | None = None) -> list[dict]:
    from .report import _via_text, discovered_via

    flt = flt or ExportFilter()
    ctx = _Ctx(conn, sid)
    metrics = {r["host_id"]: r for r in conn.execute("SELECT * FROM host_metric WHERE scan_id=?", (sid,))}
    fs: dict[tuple[int, str], int] = {}
    for r in conn.execute("SELECT host_id, severity, count(*) FROM finding WHERE scan_id=? GROUP BY host_id, severity",
                          (sid,)):
        fs[(r[0], r[1])] = r[2]
    out = []
    for r in conn.execute("SELECT hs.*, h.display_name FROM host_scan hs JOIN host h ON h.id=hs.host_id"
                          " WHERE hs.scan_id=? ORDER BY hs.depth, h.display_name", (sid,)):
        if (flt.host_glob or flt.host_id is not None) and not ctx.host_ok(flt, r["host_id"]):
            continue
        m = metrics.get(r["host_id"])
        via = discovered_via(conn, r["discovered_via_ref"])
        attempts = unj(r["route_attempts"], []) or []
        row = {
            "host": r["display_name"], "ips": ";".join(ctx.host_ips.get(r["host_id"], [])), "status": r["status"],
            "privilege": r["privilege"] or "", "depth": r["depth"] if r["depth"] is not None else "",
            "discovered_via": _via_text(via) if via else (r["seed_source"] or ""),
            "route": " -> ".join(unj(r["route"], []) or []), "os": r["os"] or "",
        }
        for c in ("in_hosts", "in_users", "in_keys", "in_unknown_keys", "out_hosts", "out_users", "out_keys"):
            row[c] = m[c] if m is not None else 0
        row["findings_critical"] = fs.get((r["host_id"], "critical"), 0)
        row["findings_high"] = fs.get((r["host_id"], "high"), 0)
        reasons = list(unj(r["partial_reasons"], []) or [])
        if r["error"]:
            reasons.append(r["error"])
        row["reasons"] = "; ".join(reasons)
        row["route_attempts"] = "; ".join(f"{' -> '.join(a.get('route') or [])}: {a.get('error') or 'ok'}"
                                          for a in attempts)
        out.append(row)
    return out


def authorized_rows(conn: sqlite3.Connection, sid: int, flt: ExportFilter | None = None) -> list[dict]:
    flt = flt or ExportFilter()
    ctx = _Ctx(conn, sid)
    out = []
    for r in conn.execute("SELECT * FROM authorized_entry WHERE scan_id=? ORDER BY host_id, username, file, line_no",
                          (sid,)):
        if (flt.host_glob or flt.host_id is not None) and not ctx.host_ok(flt, r["host_id"]):
            continue
        if flt.fp and r["fp"] != flt.fp:
            continue
        k = ctx.keys.get(r["fp"]) if r["fp"] else None
        opts = unj(r["options"], []) or []
        out.append({
            "host": ctx.name(r["host_id"]), "user": r["username"], "file": r["file"], "line_no": r["line_no"],
            "key_fp": r["fp"] or "", "alg": r["alg"] or "", "bits": k["bits"] if k and k["bits"] is not None else "",
            "strength": k["strength"] if k else "unknown",
            "options": ",".join(f"{n}={json.dumps(v)}" if v is not None else n for n, v in opts),
            "origin": ctx.origin(r["fp"]), "comment": r["comment"] or "",
        })
    return out


ROWS = {"findings": finding_rows, "keys": key_rows, "edges": edge_rows, "hosts": host_rows,
        "authorized": authorized_rows}


def csv_safe(value) -> str:
    """RFC 4180 cell; cells starting with = + - @, a tab, CR or LF get a ' prefix (CSV injection)."""
    s = "" if value is None else str(value)
    if s and s[0] in "=+-@\t\r\n":
        s = "'" + s
    return s


def to_csv(columns: list[str], rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    w.writerow(columns)
    for r in rows:
        w.writerow([csv_safe(r.get(c)) for c in columns])
    return buf.getvalue()


def to_json(conn: sqlite3.Connection, sid: int, columns: list[str], rows: list[dict]) -> str:
    s = conn.execute("SELECT id, started_at, label, synthetic FROM scan WHERE id=?", (sid,)).fetchone()
    doc = {"scan": {"id": s["id"], "started_at": s["started_at"], "label": s["label"], "synthetic": bool(s["synthetic"])},
           "items": [{c: r.get(c) for c in columns} for r in rows]}
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def export(conn: sqlite3.Connection, sid: int, what: str, fmt: str, flt: ExportFilter | None = None) -> str:
    rows = ROWS[what](conn, sid, flt)
    cols = COLUMNS[what]
    return to_csv(cols, rows) if fmt == "csv" else to_json(conn, sid, cols, rows)
