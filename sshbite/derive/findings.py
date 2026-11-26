"""Findings (spec 4.4). Every finding stores its recommendation and a stable ident."""

from __future__ import annotations

import hashlib
from datetime import date

from ..db import j, unj
from ..parse.keys import classify_strength
from . import ScanData

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

RULES = {
    "key_strength_critical": ("critical", "Replace with ed25519, remove this line/file"),
    "key_strength_weak": ("medium", "Plan replacement with ed25519"),
    "root_authorized_key": ("high", "Remove, or restrict with from=; use personal accounts + sudo"),
    "key_on_many_hosts": ("medium", "Split into per-purpose keys"),
    "key_unknown_origin": ("high", "Identify the owner, else remove"),
    "private_key_unencrypted": ("medium", "Add a passphrase or use an agent/hardware key"),
    "private_key_bad_permissions": ("high", "chmod 600; treat the key as exposed"),
    "duplicate_key_across_users": ("medium", "One key per person/purpose"),
    "key_for_disabled_user": ("medium", "Remove if unused"),
    "permit_root_login_yes": ("high", "Set prohibit-password or no"),
    "password_authentication_yes": ("medium", "Disable if keys are used"),
    "host_key_changed": ("critical", "Verify out-of-band, then hostkey accept"),
    "known_host_stale": ("low", "Remove the stale line"),
    "host_unreachable": ("low", "Check whether the host still exists"),
    "partial_scan": ("medium", "Grant sudo or provide the sudo password"),
    "authorized_keys_command": ("info", "Keys from the command are not audited"),
    "cert_authority_trusted": ("info", "Review the CA trust"),
}


def finding_ident(rule: str, host_identity: str | None, user: str | None, fp: str | None, file: str | None,
                  line: int | None) -> str:
    s = "|".join([rule, host_identity or "", user or "", fp or "", file or "", "" if line is None else str(line)])
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


def _strength_rules(rules):
    if rules is None:
        from ..config import StrengthCfg

        return StrengthCfg()
    return rules.strength


def derive_findings(data: ScanData, rules=None) -> None:
    db, sid = data.db, data.scan_id
    strength_rules = _strength_rules(rules)
    many = rules.many_hosts_threshold if rules is not None else 10
    out: list[tuple] = []

    def add(rule, host_id=None, user=None, fp=None, file=None, line=None, detail=None, severity=None):
        sev, rec = RULES[rule]
        h = data.hosts.get(host_id) if host_id is not None else None
        ident = finding_ident(rule, h.identity if h else None, user, fp, file, line)
        out.append((sid, rule, severity or sev, host_id, user, fp, file, line, j(detail or {}), rec, ident))

    key_info: dict[str, tuple] = {r[0]: (r[1], r[2]) for r in db.execute("SELECT fp, alg, bits FROM key")}

    def strength(alg, bits):
        return classify_strength(alg or "", bits, strength_rules)

    # ---- authorized entries
    hosts_per_fp: dict[str, set[int]] = {}
    users_per_fp_host: dict[tuple[str, int], set[str]] = {}
    for e in data.entries:
        fp = e["fp"]
        h = data.hosts.get(e["host_id"])
        if fp is None or h is None:
            continue
        loc = dict(host_id=e["host_id"], user=e["username"], fp=fp, file=e["file"], line=e["line_no"])
        alg, bits = e["alg"], key_info.get(fp, (None, None))[1]
        st = strength(alg, bits)
        if st == "critical":
            add("key_strength_critical", detail={"alg": alg, "bits": bits, "where": "authorized"}, **loc)
        elif st == "weak":
            add("key_strength_weak", detail={"alg": alg, "bits": bits, "where": "authorized"}, **loc)
        if e["cert_authority"]:
            add("cert_authority_trusted", detail={"principals": e["principals"], "options": unj(e["options"], [])},
                **loc)
            continue
        hosts_per_fp.setdefault(fp, set()).add(e["host_id"])
        users_per_fp_host.setdefault((fp, e["host_id"]), set()).add(e["username"])
        acc = h.accounts.get(e["username"])
        is_root = (acc is not None and acc["uid"] == 0) or (acc is None and e["username"] == "root")
        if is_root:
            has_from = bool(unj(e["from_patterns"], []))
            add("root_authorized_key", severity="medium" if has_from else "high",
                detail={"from": unj(e["from_patterns"], [])}, **loc)
        if fp not in data.priv_by_fp:
            add("key_unknown_origin", detail={"comment": e["comment"]}, **loc)
        disabled = None
        if h.accounts and acc is None:
            disabled = "user does not exist"
        elif acc is not None and not acc["login_shell"]:
            disabled = f"no login shell ({acc['shell'] or 'empty'})"
        elif acc is not None and acc["pw_state"] == "locked" and acc["expiry"] and acc["expiry"] < date.today().isoformat():
            disabled = f"locked and expired on {acc['expiry']}"
        if disabled:
            add("key_for_disabled_user", detail={"reason": disabled}, **loc)

    for fp, hosts in hosts_per_fp.items():
        if len(hosts) >= many:
            names = sorted(data.hosts[h].display for h in hosts if h in data.hosts)
            add("key_on_many_hosts", fp=fp, detail={"hosts": len(hosts), "host_names": names[:200],
                                                     "threshold": many})

    # ---- private keys
    holders: dict[str, set[tuple[int, str]]] = {}
    for p in data.privs:
        loc = dict(host_id=p["host_id"], user=p["username"], fp=p["fp"], file=p["path"], line=None)
        st = strength(p["alg"], p["bits"])
        if st == "critical":
            add("key_strength_critical", detail={"alg": p["alg"], "bits": p["bits"], "where": "private"}, **loc)
        elif st == "weak":
            add("key_strength_weak", detail={"alg": p["alg"], "bits": p["bits"], "where": "private"}, **loc)
        if p["encrypted"] == "no":
            add("private_key_unencrypted", **loc)
        mode = p["mode"]
        bad = []
        if mode is not None and mode & 0o044:
            bad.append(f"mode {mode:04o}")
        if p["owner"] and p["owner"] != "?" and p["owner"] != p["username"]:
            bad.append(f"owner {p['owner']} is not {p['username']}")
        if bad:
            add("private_key_bad_permissions", detail={"problems": bad, "mode": f"{mode:04o}" if mode is not None else None},
                **loc)
        if p["fp"]:
            holders.setdefault(p["fp"], set()).add((p["host_id"], p["username"]))

    dup_fps = {fp for fp, hs in holders.items() if len(hs) >= 2}
    dup_fps |= {fp for (fp, _h), users in users_per_fp_host.items() if len(users) >= 2}
    for fp in sorted(dup_fps):
        priv = sorted(f"{data.hosts[h].display}:{u}" for h, u in holders.get(fp, set()) if h in data.hosts)
        auth = sorted(f"{data.hosts[h].display}:{','.join(sorted(us))}" for (f, h), us in users_per_fp_host.items()
                      if f == fp and len(us) >= 2 and h in data.hosts)
        add("duplicate_key_across_users", fp=fp, detail={"private_holders": priv, "authorized_for": auth})

    # ---- hosts
    for h in data.hosts.values():
        if h.settings:
            if h.effective("permitrootlogin") == "yes":
                add("permit_root_login_yes", host_id=h.id, detail={"value": "yes"})
            if h.effective("passwordauthentication") == "yes":
                add("password_authentication_yes", host_id=h.id, detail={"value": "yes"})
            akc = h.effective("authorizedkeyscommand")
            if akc and akc != "none":
                add("authorized_keys_command", host_id=h.id, detail={"command": akc})
            ca = h.effective("trustedusercakeys")
            if ca and ca != "none":
                add("cert_authority_trusted", host_id=h.id, file=ca, detail={"trustedusercakeys": ca})

    for r in db.execute("SELECT host_id, status, error, route_attempts, partial_reasons, connect_addr FROM host_scan"
                        " WHERE scan_id=?", (sid,)):
        hid, status = r[0], r[1]
        if status == "hostkey_mismatch":
            add("host_key_changed", host_id=hid, detail=hostkey_change_detail(r[2], r[5]))
        elif status in ("unreachable", "timeout", "auth_failed"):
            add("host_unreachable", host_id=hid, detail={"status": status, "error": r[2],
                                                        "attempts": unj(r[3], [])})
        elif status in ("partial", "output_limit"):
            add("partial_scan", host_id=hid, detail={"status": status, "reasons": unj(r[4], [])})

    for r in db.execute("SELECT id, username, file, line_no, host_id, target_host_id, key_fp FROM known_host_entry"
                        " WHERE scan_id=? AND matches_actual='no'", (sid,)):
        tgt = data.hosts.get(r[5])
        add("known_host_stale", host_id=r[4], user=r[1], fp=r[6], file=r[2], line=r[3],
            detail={"target": tgt.display if tgt else None, "target_host_id": r[5],
                    "actual": sorted(tgt.host_keys) if tgt else []})

    db.executemany(
        "INSERT INTO finding(scan_id, rule, severity, host_id, username, fp, file, line_no, detail, recommendation,"
        " ident) VALUES (?,?,?,?,?,?,?,?,?,?,?)", out)


def hostkey_change_detail(error: str | None, address: str | None) -> dict:
    """Old and new fingerprints from the transport's mismatch message."""
    import re

    d: dict = {"address": address, "error": error, "old": [], "new": None}
    if error:
        m = re.search(r"offered (\S+) (SHA256:\S+?);", error)
        if m:
            d["new"] = {"alg": m.group(1), "fp": m.group(2)}
        m = re.search(r"trusted (.*)$", error)
        if m:
            for part in m.group(1).split(","):
                bits = part.split()
                if len(bits) == 2:
                    d["old"].append({"alg": bits[0], "fp": bits[1]})
    return d
