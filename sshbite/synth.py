"""Synthetic scan for scale testing (spec 9.4): `sshbite synth --hosts 2000 --seed 42`.

Generates, deterministically from the seed: hosts in /24 subnets (40 at 2,000 hosts), 15,000 authorized
entries (scaled with the host count), a fleet key on 1,200 hosts, 300 unknown-origin keys and hub hosts with
more than 200 outbound edges. The scan and its hosts carry synthetic=1. Derivation is the real one.
"""

from __future__ import annotations

import base64
import hashlib
import random
import time

from . import __version__
from .db import j, utcnow
from .db.store import upsert_key
from .derive import derive_scan
from .parse.keys import classify_strength

USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "mallory", "niaj",
         "olivia", "peggy", "rupert", "sybil", "trent", "victor", "walter", "yvonne"]


def _fp(*parts) -> str:
    h = hashlib.sha256("|".join(str(p) for p in parts).encode()).digest()
    return "SHA256:" + base64.b64encode(h).decode().rstrip("=")


def synth(conn, n_hosts: int = 2000, seed: int = 42, cfg=None) -> dict:
    t0 = time.monotonic()
    rng = random.Random(seed)
    rules = cfg.rules.strength if cfg is not None else None
    if rules is None:
        from .config import StrengthCfg
        rules = StrengthCfg()
    scale = n_hosts / 2000.0
    n_subnets = max(1, min(40, round(40 * scale)) if n_hosts >= 40 else 1)
    per_subnet = -(-n_hosts // n_subnets)
    target_entries = max(n_hosts, round(15000 * scale))
    fleet_hosts = min(n_hosts, round(1200 * scale))
    n_unknown = max(1, round(300 * scale))
    n_hubs = max(1, round(5 * scale))
    hub_fanout = min(n_hosts - 1, max(201, round(250 * scale)) if n_hosts > 202 else n_hosts - 1)

    conn.execute("BEGIN IMMEDIATE")
    try:
        cur = conn.execute(
            "INSERT INTO scan(label, started_at, status, synthetic, tool_version, collector_sha256, config_sha256,"
            " entry_host, params, progress, pid) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (f"synthetic {n_hosts} hosts, seed {seed}", utcnow(), "running", 1, __version__, None, None,
             "syn-0001.synthetic.invalid:22", j({"synth": {"hosts": n_hosts, "seed": seed}}),
             j({"phase": "generate", "depth": 0, "queued": 0, "running": 0, "done": 0, "by_status": {}}), None))
        sid = cur.lastrowid

        # ---- hosts
        hosts = []  # (host_id, name, ip, subnet, depth)
        for i in range(n_hosts):
            s, k = divmod(i, per_subnet)
            name = f"syn-{i + 1:04d}.synthetic.invalid"
            ip = f"10.66.{s}.{10 + k}"
            ident = "hk:" + _fp("syn-host", seed, i)
            row = conn.execute("SELECT id FROM host WHERE identity=?", (ident,)).fetchone()
            if row is None:
                hid = conn.execute("INSERT INTO host(identity, display_name, synthetic, first_seen_scan, last_seen_scan)"
                                   " VALUES (?,?,1,?,?)", (ident, name, sid, sid)).lastrowid
            else:
                hid = row[0]
                conn.execute("UPDATE host SET last_seen_scan=? WHERE id=?", (sid, hid))
            depth = 0 if i == 0 else 1 + (s % 4) + (1 if k > per_subnet // 2 else 0)
            hosts.append((hid, name, ip, f"10.66.{s}.0/24", depth))
        by_depth: dict[int, list[int]] = {}
        for idx, h in enumerate(hosts):
            by_depth.setdefault(h[4], []).append(idx)

        statuses = []
        for idx in range(n_hosts):
            x = rng.random()
            st = "ok" if idx == 0 or x < 0.965 else "partial" if x < 0.98 else "unreachable" if x < 0.995 else "timeout"
            statuses.append(st)

        # references: each non-entry host is discovered from a host one level up
        ref_rows = []
        parents = {}
        for idx in range(1, n_hosts):
            d = hosts[idx][4]
            cands = by_depth.get(d - 1) or [0]
            p = rng.choice(cands)
            parents[idx] = p
        host_scan_rows = []
        name_rows, group_rows, key_rows, sshd_rows, acc_rows = [], [], [], [], []
        roles = ["web", "db", "app", "batch", "infra"]
        for idx, (hid, name, ip, subnet, depth) in enumerate(hosts):
            st = statuses[idx]
            collected = st in ("ok", "partial")
            route = None
            if collected:
                route = ["syn-0001.synthetic.invalid"] + ([name] if idx else [])
            attempts = [{"route": ["syn-0001.synthetic.invalid", name], "error": None if collected else
                         ("timeout" if st == "timeout" else "channel open failed: No route to host")}] if idx else \
                [{"route": [name], "error": None}]
            host_scan_rows.append([sid, hid, st, "root" if st == "ok" else "unprivileged" if st == "partial" else None,
                                   depth, None, "entry" if idx == 0 else None, j(route) if route else None, j(attempts),
                                   ip, 22, name.split(".")[0] if collected else None,
                                   "Debian GNU/Linux 12 (bookworm)" if collected else None,
                                   "Linux 6.1.0-28-amd64 x86_64" if collected else None, j([ip] if collected else []),
                                   j(["sudo: a password is required"] if st == "partial" else []),
                                   None if collected else attempts[0]["error"], None, 0, rng.randint(300, 4000)])
            name_rows += [(sid, hid, "name", name), (sid, hid, "ip", ip)]
            group_rows += [(sid, hid, "subnet", subnet),
                           (sid, hid, "tag", "dmz" if int(subnet.split(".")[2]) < 4 else "untagged"),
                           (sid, hid, "ansible", roles[idx % len(roles)])]
            if collected:
                key_rows.append((sid, hid, "ssh-ed25519", _fp("syn-hostkey", seed, idx), 256))
                prl = "yes" if rng.random() < 0.03 else "prohibit-password"
                pwa = "yes" if rng.random() < 0.05 else "no"
                for n, v in (("permitrootlogin", prl), ("passwordauthentication", pwa),
                             ("pubkeyauthentication", "yes"), ("authorizedkeysfile", ".ssh/authorized_keys"),
                             ("authorizedkeyscommand", "none")):
                    sshd_rows.append((sid, hid, "sshd-T", n, v, None, None))
                acc_rows.append((sid, hid, "root", 0, 0, "/root", "/bin/bash", 1, "locked", None))
                acc_rows.append((sid, hid, "deploy", 1001, 1001, "/home/deploy", "/bin/bash", 1, "locked", None))
                acc_rows.append((sid, hid, "backup", 34, 34, "/var/backups", "/usr/sbin/nologin", 0, "locked", None))

        # references (discovered_via + extra evidence)
        for idx, p in parents.items():
            ref_rows.append((sid, hosts[p][0], "deploy", "known_hosts", "/home/deploy/.ssh/known_hosts",
                             1 + idx % 50, hosts[idx][2], j([hosts[idx][2]]), hosts[idx][0], "queued", idx))
        for _ in range(n_hosts):
            a, b = rng.randrange(n_hosts), rng.randrange(n_hosts)
            if a != b and statuses[a] in ("ok", "partial"):
                ref_rows.append((sid, hosts[a][0], rng.choice(USERS), "ssh_config", f"/home/{rng.choice(USERS)}/.ssh/config",
                                 rng.randint(1, 40), hosts[b][2], j([hosts[b][2]]), hosts[b][0], "already", None))
        ref_ids: dict[int, int] = {}
        for r in ref_rows:
            rid = conn.execute("INSERT INTO reference(scan_id, from_host_id, username, source, file, line_no, value,"
                               " resolved_ips, target_host_id, outcome) VALUES (?,?,?,?,?,?,?,?,?,?)", r[:10]).lastrowid
            if r[10] is not None:
                ref_ids[r[10]] = rid
        for idx, row in enumerate(host_scan_rows):
            row[5] = ref_ids.get(idx)
        conn.executemany(
            "INSERT INTO host_scan(scan_id, host_id, status, privilege, depth, discovered_via_ref, seed_source, route,"
            " route_attempts, connect_addr, connect_port, hostname, os, kernel, ips, partial_reasons, error,"
            " alias_of_host_id, unresolved_hashed, duration_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            host_scan_rows)
        conn.executemany("INSERT OR IGNORE INTO host_name(scan_id, host_id, kind, value) VALUES (?,?,?,?)", name_rows)
        conn.executemany("INSERT INTO host_group(scan_id, host_id, kind, name) VALUES (?,?,?,?)", group_rows)
        conn.executemany("INSERT INTO host_key(scan_id, host_id, alg, fp, bits) VALUES (?,?,?,?,?)", key_rows)
        conn.executemany("INSERT INTO sshd_setting(scan_id, host_id, source, name, value, file, line) VALUES (?,?,?,?,?,?,?)",
                         sshd_rows)

        collected_idx = [i for i in range(n_hosts) if statuses[i] in ("ok", "partial")]
        entries = []   # (host_idx, user, fp, alg, comment, options, from)
        privs = []     # (host_idx, user, path, fp, alg, bits, encrypted, mode)
        keys: dict[str, tuple[str, int]] = {}

        def add_key(fp, alg, bits):
            keys[fp] = (alg, bits)

        # fleet key: private on the first hub, authorized for root on fleet_hosts hosts
        hubs = [round(i * n_hosts / n_hubs) for i in range(n_hubs)]
        fleet = _fp("syn-fleet", seed)
        add_key(fleet, "ssh-rsa", 3072)
        privs.append((hubs[0], "deploy", "/home/deploy/.ssh/fleet_rsa", fleet, "ssh-rsa", 3072, "no", 0o600))
        for idx in rng.sample(collected_idx, min(fleet_hosts, len(collected_idx))):
            entries.append((idx, "root", fleet, "ssh-rsa", "fleet-deploy", [], []))
        # hub keys: each hub reaches > 200 hosts
        for n, hidx in enumerate(hubs):
            fp = _fp("syn-hub", seed, n)
            add_key(fp, "ssh-ed25519", 256)
            privs.append((hidx, "deploy", "/home/deploy/.ssh/id_ed25519", fp, "ssh-ed25519", 256, "yes", 0o600))
            for idx in rng.sample([i for i in collected_idx if i != hidx], min(hub_fanout, len(collected_idx) - 1)):
                entries.append((idx, "deploy", fp, "ssh-ed25519", f"hub{n}@syn", [], []))
        # unknown-origin keys
        for n in range(n_unknown):
            alg, bits = rng.choice([("ssh-rsa", 2048), ("ssh-rsa", 1024), ("ssh-dss", 1024), ("ssh-ed25519", 256),
                                    ("ssh-rsa", 4096)])
            fp = _fp("syn-unknown", seed, n)
            add_key(fp, alg, bits)
            for idx in rng.sample(collected_idx, rng.randint(1, 6)):
                entries.append((idx, "root" if rng.random() < 0.3 else rng.choice(USERS), fp, alg,
                                f"old-{n}@legacy", [], []))
        # personal keys until the target number of entries is reached
        n = 0
        while len(entries) < target_entries:
            user = USERS[n % len(USERS)]
            alg, bits = rng.choices([("ssh-ed25519", 256), ("ssh-rsa", 4096), ("ssh-rsa", 3072), ("ssh-rsa", 2048),
                                     ("ecdsa-sha2-nistp256", 256), ("ssh-rsa", 1024)],
                                    weights=[50, 15, 12, 15, 6, 2])[0]
            fp = _fp("syn-personal", seed, n)
            add_key(fp, alg, bits)
            home = rng.choice(collected_idx)
            privs.append((home, user, f"/home/{user}/.ssh/id_{'rsa' if alg == 'ssh-rsa' else 'ed25519' if alg == 'ssh-ed25519' else 'ecdsa'}",
                          fp, alg, bits, rng.choice(["yes", "yes", "no", "unknown"]), 0o644 if rng.random() < 0.01 else 0o600))
            for idx in rng.sample(collected_idx, min(len(collected_idx), rng.randint(3, 15))):
                if len(entries) >= target_entries:
                    break
                frm = []
                if rng.random() < 0.05:
                    frm = [f"10.66.{rng.randrange(n_subnets)}.0/24"]
                entries.append((idx, user, fp, alg, f"{user}@syn", [["from", ",".join(frm)]] if frm else [], frm))
            n += 1

        # personal accounts exist where their keys are authorized, except for ~1 % left-overs
        seen_acc = set()
        for idx, user, *_rest in entries:
            if user in ("root", "deploy") or (idx, user) in seen_acc or statuses[idx] not in ("ok", "partial"):
                continue
            seen_acc.add((idx, user))
            if rng.random() < 0.01:
                continue
            u_i = USERS.index(user)
            acc_rows.append((sid, hosts[idx][0], user, 2000 + u_i, 2000 + u_i, f"/home/{user}", "/bin/bash", 1,
                             "hash", None))
        conn.executemany("INSERT INTO account(scan_id, host_id, username, uid, gid, home, shell, login_shell, pw_state,"
                         " expiry) VALUES (?,?,?,?,?,?,?,?,?,?)", acc_rows)

        line_no: dict[tuple[int, str], int] = {}
        ae_rows = []
        for idx, user, fp, alg, comment, opts, frm in entries:
            k = (idx, user)
            line_no[k] = line_no.get(k, 0) + 1
            f = "/root/.ssh/authorized_keys" if user == "root" else f"/home/{user}/.ssh/authorized_keys"
            ae_rows.append((sid, hosts[idx][0], user, f, line_no[k], fp, alg, comment, j(opts), j(frm), None, 0, 0, None,
                            None, 1, f"{alg} AAAA...synthetic {comment}"))
        conn.executemany(
            "INSERT INTO authorized_entry(scan_id, host_id, username, file, line_no, fp, alg, comment, options,"
            " from_patterns, command, restrict, cert_authority, principals, expiry_time, user_exists, raw)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ae_rows)
        conn.executemany(
            "INSERT INTO private_key(scan_id, host_id, username, path, fp, alg, bits, encrypted, mode, owner, mtime,"
            " has_pub) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [(sid, hosts[i][0], u, p, fp, a, b, e, m, u, "2024-01-01T00:00:00Z", 1) for i, u, p, fp, a, b, e, m in privs])
        for fp, (alg, bits) in keys.items():
            upsert_key(conn, fp, alg, bits, classify_strength(alg, bits, rules), sid)
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    t1 = time.monotonic()
    derive_scan(conn, sid, cfg)
    t2 = time.monotonic()
    from .crawl import scan_counts

    counts = scan_counts(conn, sid)
    conn.execute("UPDATE scan SET status='completed', finished_at=?, counts=?, progress=? WHERE id=?",
                 (utcnow(), j(counts), j({"phase": "done", "depth": max(h[4] for h in hosts), "queued": 0,
                                          "running": 0, "done": n_hosts, "by_status": counts["hosts"]}), sid))
    return {"scan_id": sid, "hosts": n_hosts, "authorized_entries": len(ae_rows), "access_edges": counts["access_edges"],
            "findings": counts["findings_total"], "generate_s": t1 - t0, "derive_s": t2 - t1}
