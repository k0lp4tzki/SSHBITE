"""A small hand-built scan for derivation/diff/export tests (no crawl involved)."""

from sshbite.db import j, utcnow
from sshbite.db.store import upsert_key

K1 = ("SHA256:k1k1k1k1k1k1k1k1k1k1k1k1k1k1k1k1k1k1k1k1k1k", "ssh-ed25519", 256, "good")
K2 = ("SHA256:k2k2k2k2k2k2k2k2k2k2k2k2k2k2k2k2k2k2k2k2k2k", "ssh-rsa", 2048, "weak")
K3 = ("SHA256:k3k3k3k3k3k3k3k3k3k3k3k3k3k3k3k3k3k3k3k3k3k", "ssh-dss", 1024, "critical")
K4 = ("SHA256:k4k4k4k4k4k4k4k4k4k4k4k4k4k4k4k4k4k4k4k4k4k", "ssh-ed25519", 256, "good")


def build(conn, variant: int = 1) -> tuple[int, dict]:
    sid = conn.execute("INSERT INTO scan(started_at, status, synthetic) VALUES (?, 'completed', 0)",
                       (utcnow(),)).lastrowid
    hosts = {}
    spec = {
        "A": ("10.0.0.1", "ok", [("prohibit-password", "no", "yes", "")]),
        "B": ("10.0.0.2", "ok", [("yes", "yes", "yes", "")]),
        "C": ("10.0.0.3", "ok", [("prohibit-password", "no", "yes", "alice")]),
        "D": ("10.0.0.4", "ok", [("prohibit-password", "no", "no", "")]),
        "E": ("10.0.0.5", "unreachable" if variant == 1 else "ok", []),
    }
    for name, (ip, status, sshd) in spec.items():
        hid = conn.execute("INSERT OR IGNORE INTO host(identity, display_name, first_seen_scan, last_seen_scan)"
                           " VALUES (?,?,?,?)", (f"hk:{name}", name, sid, sid)).lastrowid
        hid = conn.execute("SELECT id FROM host WHERE identity=?", (f"hk:{name}",)).fetchone()[0]
        hosts[name] = hid
        conn.execute("INSERT INTO host_scan(scan_id, host_id, status, privilege, depth, connect_addr, connect_port,"
                     " hostname, ips, route, route_attempts, partial_reasons) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                     (sid, hid, status, "root" if status == "ok" else None, 1, ip, 22, name.lower(), j([ip]),
                      j(["A", name]) if status == "ok" else None,
                      j([{"route": ["A", name], "error": None if status == "ok" else "timeout"}]), j([])))
        conn.execute("INSERT INTO host_name(scan_id, host_id, kind, value) VALUES (?,?,?,?)", (sid, hid, "ip", ip))
        conn.execute("INSERT INTO host_name(scan_id, host_id, kind, value) VALUES (?,?,?,?)",
                     (sid, hid, "name", name.lower()))
        if status != "ok":
            continue
        conn.execute("INSERT INTO host_key(scan_id, host_id, alg, fp, bits) VALUES (?,?,?,?,?)",
                     (sid, hid, "ssh-ed25519", f"SHA256:hostkey{name}", 256))
        for prl, pwa, pka, allow in sshd:
            for n, v in (("permitrootlogin", prl), ("passwordauthentication", pwa), ("pubkeyauthentication", pka),
                         ("authorizedkeyscommand", "none")):
                conn.execute("INSERT INTO sshd_setting(scan_id, host_id, source, name, value) VALUES (?,?,?,?,?)",
                             (sid, hid, "sshd-T", n, v))
            if allow:
                conn.execute("INSERT INTO sshd_setting(scan_id, host_id, source, name, value) VALUES (?,?,?,?,?)",
                             (sid, hid, "sshd-T", "allowusers", allow))
        for u, uid, shell in (("root", 0, "/bin/bash"), ("alice", 1000, "/bin/bash"), ("bob", 1001, "/bin/bash"),
                              ("backup", 34, "/usr/sbin/nologin"), ("svc", 1002, "/bin/sh")):
            conn.execute("INSERT INTO account(scan_id, host_id, username, uid, gid, home, shell, login_shell, pw_state)"
                         " VALUES (?,?,?,?,?,?,?,?,?)", (sid, hid, u, uid, uid, f"/home/{u}", shell,
                                                          int(not shell.endswith("nologin")), "locked"))

    def entry(host, user, key, line, frm=None, command=None, ca=False):
        opts = []
        if frm:
            opts.append(["from", ",".join(frm)])
        if command:
            opts.append(["command", command])
        if ca:
            opts.append(["cert-authority", None])
        f = "/root/.ssh/authorized_keys" if user == "root" else f"/home/{user}/.ssh/authorized_keys"
        conn.execute("INSERT INTO authorized_entry(scan_id, host_id, username, file, line_no, fp, alg, comment, options,"
                     " from_patterns, command, cert_authority, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (sid, hosts[host], user, f, line, key[0], key[1], "c", j(opts), j(frm or []), command, int(ca), "raw"))

    entry("B", "alice", K1, 1)                          # confirmed
    entry("B", "root", K1, 1, frm=["10.9.9.9"])         # restricted_blocked, root finding medium
    entry("B", "root", K3, 2)                           # unknown origin, critical, root high
    if variant == 1:
        entry("B", "bob", K4, 1)                        # unknown origin (removed in variant 2)
    entry("B", "svc", K2, 1, command="/bin/backup")     # forced command, weak
    entry("B", "backup", K1, 1)                         # nologin -> disabled user
    entry("C", "bob", K1, 1)                            # AllowUsers alice -> sshd_denied
    entry("C", "alice", K1, 1, frm=["10.0.0.0/24", "!10.0.0.9"])  # restricted_ok
    entry("D", "alice", K1, 1)                          # pubkeyauthentication no
    entry("A", "alice", K1, 1)                          # self edge
    entry("C", "root", K4, 2, ca=True)                  # cert-authority: no edge, info finding
    conn.execute("INSERT INTO private_key(scan_id, host_id, username, path, fp, alg, bits, encrypted, mode, owner, has_pub)"
                 " VALUES (?,?,?,?,?,?,?,?,?,?,?)", (sid, hosts["A"], "alice", "/home/alice/.ssh/id_ed25519", K1[0],
                                                     K1[1], K1[2], "yes", 0o600, "alice", 1))
    conn.execute("INSERT INTO private_key(scan_id, host_id, username, path, fp, alg, bits, encrypted, mode, owner, has_pub)"
                 " VALUES (?,?,?,?,?,?,?,?,?,?,?)", (sid, hosts["A"], "svc", "/home/svc/.ssh/id_rsa", K2[0], K2[1],
                                                     K2[2], "no", 0o644, "root", 0))
    for k in (K1, K2, K3, K4):
        upsert_key(conn, k[0], k[1], k[2], k[3], sid)
    # a reference A -> B from known_hosts, with a stale key
    rid = conn.execute("INSERT INTO reference(scan_id, from_host_id, username, source, file, line_no, value, resolved_ips,"
                       " target_host_id, outcome) VALUES (?,?,?,?,?,?,?,?,?,?)",
                       (sid, hosts["A"], "alice", "known_hosts", "/home/alice/.ssh/known_hosts", 1, "10.0.0.2",
                        j(["10.0.0.2"]), hosts["B"], "already")).lastrowid
    conn.execute("INSERT INTO known_host_entry(scan_id, host_id, username, file, line_no, hashed, patterns,"
                 " resolved_value, target_host_id, key_alg, key_fp) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                 (sid, hosts["A"], "alice", "/home/alice/.ssh/known_hosts", 1, 0, j(["10.0.0.2"]), "10.0.0.2",
                  hosts["B"], "ssh-ed25519", "SHA256:stale"))
    conn.execute("INSERT INTO reference(scan_id, from_host_id, username, source, file, line_no, value, resolved_ips,"
                 " target_host_id, outcome) VALUES (?,?,?,?,?,?,?,?,?,?)",
                 (sid, hosts["B"], "alice", "from_option", "/x", 1, "10.0.0.1", j(["10.0.0.1"]), hosts["A"], "alias"))
    return sid, hosts
