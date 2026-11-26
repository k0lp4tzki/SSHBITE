"""privilege.mode installed against the lab (spec 8.3, package A: i00-i05, i99).

Runs after test_lab.py. The owner's installation step (`sshbite collector export`, then the files on every
host as docs/install.md says) is done by lab/installed.sh through the lab-control sshd. Every scan is
bracketed by the read-only snapshot as in test_lab.py; i99 removes the installation again and proves with
the same snapshot that every host is byte for byte as before i01.

Set SSHBITE_EVIDENCE_DIR to keep the console transcripts, the attack matrix and the diff.
"""

from __future__ import annotations

import asyncio
import concurrent.futures as cf
import json
import os
import sqlite3
import subprocess
from pathlib import Path

import asyncssh
import pytest
import yaml

from sshbite import collector
from sshbite.privilege import commands

from . import lab as L

pytestmark = pytest.mark.e2e

EXP = L.expected()
S1 = EXP["scan1"]
P = "/usr/local/libexec/sshbite/sshbite-collect"
R = "/usr/local/libexec/sshbite/sshbite-resolve"
B = collector.declared_sha_short(collector.collect_script())

# authorized_keys variant (A/B/C of the exported template) and from= per lab host. The scanner reaches the
# lab from 172.30.0.0/16 (directly or through a Docker port mapping); every other host sees the hop before it.
AK = {
    "jump": ("A", "172.30.0.0/16"),
    **{h: ("B", "172.30.1.5") for h in ("a1", "a2", "a3", "a4", "a5")},
    **{h: ("B", "172.30.2.5") for h in ("b1", "b2", "b4", "b5")},
    "b3": ("C", "172.30.2.5"),     # c1 is reached through b3 (chain fallback)
    "c1": ("C", "172.30.3.13"),    # c2 is reached through c1: from = b3, forwarding on
    "c2": ("B", "172.30.3.21"),    # from = c1
}
if "r1" in EXP["hosts"]:           # the EL host (package B): stand-alone, published like the entry
    AK["r1"] = ("A", "172.30.0.0/16")
HOSTS = sorted(h for h in EXP["hosts"] if h in AK)


# ---------------------------------------------------------------- fixtures

@pytest.fixture(scope="module")
def entry():
    e = L.find_entry()
    if e is None:
        pytest.skip("lab unavailable: need docker, podman or root")
    return e


@pytest.fixture(scope="module")
def ctl(entry):
    return L.LabControl(EXP["hosts"])


@pytest.fixture(scope="module")
def evidence():
    d = os.environ.get("SSHBITE_EVIDENCE_DIR")
    if not d:
        return None
    p = Path(d)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _write(evidence, name: str, text: str) -> None:
    if evidence is not None:
        (evidence / name).write_text(text)


@pytest.fixture(scope="module")
def cfg(entry, tmp_path_factory):
    """One database, two configs: the unchanged lab config (mode sudo) and the same with mode installed."""
    host, port = entry
    env = dict(os.environ, LAB_NO_START="1", LAB_ENTRY_HOST=host, LAB_ENTRY_PORT=str(port))
    subprocess.run(["sh", str(L.LAB / "up.sh")], check=True, env=env, capture_output=True)
    data = yaml.safe_load((L.LAB / "sshbite.lab.yaml").read_text())
    d = tmp_path_factory.mktemp("installed")
    data["database"] = str(d / "sshbite.db")
    out = {"dir": d, "db": Path(data["database"])}
    for name, priv in (("sudo", None), ("installed", {"mode": "installed"}),
                       ("bad-path", {"mode": "installed", "collector_path": "/usr/local/libexec/sshbite/collect"})):
        x = dict(data)
        if priv:
            x["privilege"] = priv
        p = d / f"{name}.yaml"
        p.write_text(yaml.safe_dump(x))
        p.chmod(0o600)
        out[name] = p
    # i05: the entry and a few seeds, so that every broken host is reached although its parent may be broken
    seeds = d / "seeds.txt"
    seeds.write_text("".join(f"{EXP['hosts'][h][0]}\n" for h in ("a2", "a3", "a4", "a5", "b2")))
    x = dict(data, privilege={"mode": "installed"}, seeds={"hosts_file": str(seeds)})
    p = d / "failures.yaml"
    p.write_text(yaml.safe_dump(x))
    p.chmod(0o600)
    out["failures"] = p
    return out


@pytest.fixture(scope="module")
def state():
    return {}


def _db(cfg) -> sqlite3.Connection:
    c = sqlite3.connect(cfg["db"])
    c.row_factory = sqlite3.Row
    return c


def _rows(conn, sid) -> dict[str, sqlite3.Row]:
    return {r["display_name"]: r for r in conn.execute(
        "SELECT hs.*, h.display_name FROM host_scan hs JOIN host h ON h.id=hs.host_id WHERE hs.scan_id=?", (sid,))}


def _scan(ctl, cfg, key: str, label: str, evidence, *args: str, env: dict | None = None):
    """Snapshot, scan, snapshot: (process, scan id, snapshot diff)."""
    before = ctl.snapshot_all()
    proc = L.sshbite(cfg[key], "scan", "--label", label, *args, env=env)
    after = ctl.snapshot_all()
    diff = L.snapshot_diff(before, after)
    _write(evidence, f"snapshot-{label}.diff", diff)
    sid = _db(cfg).execute("SELECT max(id) FROM scan WHERE status='completed'").fetchone()[0]
    return proc, sid, diff


def _parallel(fn, hosts):
    with cf.ThreadPoolExecutor(len(hosts)) as ex:
        return dict(zip(hosts, ex.map(fn, hosts)))


def _apply(ctl, cfg, host: str) -> str:
    return ctl.run_text(host, L.installed_apply_script(cfg["dir"] / "export", L.installed_line(*AK[host])))


# ---------------------------------------------------------------- tests

def test_i00_sudo_baseline(ctl, cfg, state, evidence):
    """Mode sudo with the password, as scan 1 of test_lab.py: the reference for i03."""
    state["pristine"] = ctl.snapshot_all()        # i99 compares the hosts with this
    proc, sid, diff = _scan(ctl, cfg, "sudo", "baseline-sudo", evidence, env={"SSHBITE_SUDO_PASSWORD": "labsudo"})
    _write(evidence, "console-scan-baseline-sudo.txt",
           "$ SSHBITE_SUDO_PASSWORD=*** sshbite scan --label baseline-sudo\n" + proc.stdout + proc.stderr)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert diff == "", diff
    rows = _rows(_db(cfg), sid)
    for name, (status, priv, *_rest) in S1["hosts"].items():
        assert (rows[name]["status"], rows[name]["privilege"]) == (status, priv), name
    state["base"] = sid


def test_i01_apply(ctl, cfg, evidence):
    """sshbite collector export, sha256sum -c, then the installation on every lab host."""
    out = cfg["dir"] / "export"
    p = L.sshbite(cfg["installed"], "collector", "export", str(out))
    _write(evidence, "console-export.txt", f"$ sshbite collector export {out}\n" + p.stdout + p.stderr)
    assert p.returncode == 0, p.stderr
    assert sorted(x.name for x in out.iterdir()) == ["SHA256SUMS", "authorized_keys.sshbite", "sshbite-collect",
                                                    "sshbite-gate", "sshbite-resolve", "sudoers.d-sshbite"]
    c = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=out, capture_output=True, text=True)
    _write(evidence, "console-sha256sum-c.txt", f"$ cd {out} && sha256sum -c SHA256SUMS\n" + c.stdout + c.stderr)
    assert c.returncode == 0 and c.stdout.count(": OK") == 5, c.stdout + c.stderr
    p2 = L.sshbite(cfg["installed"], "collector", "export", str(out))
    assert p2.returncode == 2 and f"export directory is not empty: {out}" in p2.stderr
    res = _parallel(lambda h: _apply(ctl, cfg, h), HOSTS)
    _write(evidence, "console-apply.txt", "".join(f"### {h}: lab/installed.sh apply {' '.join(AK[h])}\n{res[h]}\n"
                                                  for h in HOSTS))
    for h in HOSTS:
        assert "/etc/sudoers.d/sshbite: parsed OK" in res[h], (h, res[h])


def test_i02_validate(cfg, evidence):
    p = L.sshbite(cfg["installed"], "config", "validate", "--connect")
    _write(evidence, "console-validate-ok.txt", "$ sshbite config validate --connect\n" + p.stdout + p.stderr)
    assert p.returncode == 0, p.stdout + p.stderr
    assert p.stdout.splitlines()[-1] == (f"entry OK, pinned key matches, sudo: root (installed {P}, "
                                         f"collector B={B} matches)")
    # a config whose collector_path does not match what the gate allows: exit 3 with the gate's refusal
    bad = L.sshbite(cfg["bad-path"], "config", "validate", "--connect")
    _write(evidence, "console-validate-failed.txt",
           "$ sshbite config validate --connect   # privilege.collector_path: /usr/local/libexec/sshbite/collect\n"
           + bad.stdout + bad.stderr)
    assert bad.returncode == 3, bad.stdout + bad.stderr
    assert bad.stdout.splitlines()[-1] == (
        "entry OK, pinned key matches, sudo: FAILED - privilege.mode installed: refused by sshbite-gate on this "
        "host: sshbite-gate: denied (command not allowed)")


# What differs between the sudo baseline and the installed scan, and why. Everything else must be equal.
# b5 has no sudo rule in the lab (scan 1: partial/unprivileged); the installed sudoers rule makes it root, so
# its root-only files are read now. a4 needed the sudo password before; now it is NOPASSWD for the collector.
I03_HOSTS_CHANGED = {("b5", "status", "partial", "ok"), ("b5", "privilege", "unprivileged", "root"),
                     ("a4", "privilege", "sudo_password", "root")}
I03_KEYS_ADDED = {"carol@b5"}
I03_PLACEMENTS_ADDED = {("authorized", "b5", "carol", "/home/carol/.ssh/authorized_keys")}
I03_EDGES_ADDED = {("unknown", "b5", "carol")}
I03_FINDINGS_ADDED = {("key_unknown_origin", "b5", "carol")}
I03_FINDINGS_REMOVED = {("partial_scan", "b5", None)}


def test_i03_scan_installed(ctl, cfg, state, evidence):
    proc, sid, diff = _scan(ctl, cfg, "installed", "installed", evidence)
    _write(evidence, "console-scan-installed.txt", "$ sshbite scan --label installed\n" + proc.stdout + proc.stderr)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert diff == "", "lab changed during the installed scan:\n" + diff
    state["inst"] = sid
    conn = _db(cfg)
    rows = _rows(conn, sid)
    for name, (status, *_rest) in S1["hosts"].items():
        if status in ("ok", "partial"):
            assert (rows[name]["status"], rows[name]["privilege"]) == ("ok", "root"), name
        else:
            assert rows[name]["status"] == status, name
    assert len([r for r in rows.values() if r["status"] == "ok"]) == 12
    params = json.loads(conn.execute("SELECT params FROM scan WHERE id=?", (sid,)).fetchone()[0])
    assert params["privilege_mode"] == "installed" and params["collector_path"] == P
    sha = conn.execute("SELECT collector_sha256 FROM scan WHERE id=?", (sid,)).fetchone()[0]
    assert f"{sha}  sshbite-collect\n" in (cfg["dir"] / "export" / "SHA256SUMS").read_text()
    _write(evidence, "scans-show-installed.txt", L.sshbite(cfg["installed"], "scans", "show", str(sid)).stdout)

    t = L.sshbite(cfg["installed"], "diff", str(state["base"]), str(sid))
    _write(evidence, "diff-baseline-installed.txt",
           f"$ sshbite diff {state['base']} {sid}   # baseline (mode sudo) -> installed\n" + t.stdout)
    d = json.loads(L.sshbite(cfg["installed"], "diff", str(state["base"]), str(sid), "--format", "json").stdout)
    hosts_changed = {(h["host"], k, v["a"], v["b"]) for h in d["hosts"]["changed"] for k, v in h["changes"].items()}
    assert hosts_changed == I03_HOSTS_CHANGED, hosts_changed
    assert d["hosts"]["added"] == d["hosts"]["removed"] == []
    assert {k.get("comment") for k in d["keys"]["added"]} == I03_KEYS_ADDED, d["keys"]
    assert d["keys"]["removed"] == d["keys"]["changed"] == []
    assert {(p["kind"], p["host"], p["user"], p["file"]) for p in d["placements"]["added"]} == I03_PLACEMENTS_ADDED
    assert d["placements"]["removed"] == d["placements"]["changed"] == []
    assert {(e["src"], e["dst"], e["dst_user"]) for e in d["edges"]["added"]} == I03_EDGES_ADDED, d["edges"]
    assert d["edges"]["removed"] == d["edges"]["changed"] == []
    assert {(f["rule"], f["host"], f["user"]) for f in d["findings"]["added"]} == I03_FINDINGS_ADDED
    assert {(f["rule"], f["host"], f["user"]) for f in d["findings"]["removed"]} == I03_FINDINGS_REMOVED
    assert d["findings"]["changed"] == []


# ---- i04: the attack matrix with the audit key

DENIED = "sshbite-gate: denied (command not allowed)"
SUDO_CMDS = commands("sudo")
ATTACKS = [   # (label, command, stdin); None = no command (login shell with a PTY)
    ("id", "id", None),
    ("interactive shell with PTY", "<pty>", None),
    ("interactive shell without PTY", None, "id\nexit\n"),
    ("/bin/sh -s with a script", "/bin/sh -s", "id\n"),
    ("old mode sudo: probe", SUDO_CMDS["probe"], None),
    ("old mode sudo: run with a script", SUDO_CMDS["run"], "id\n"),
    ("probe; id", f"sudo -n -l {P}; id", None),
    ("collector with an argument", f"sudo -n {P} x", None),
    ("sudo -n /bin/sh", "sudo -n /bin/sh", "id\n"),
    ("subsystem sftp", "<sftp>", None),
]


def _known(host: str):
    return ([asyncssh.read_public_key(str(L.KEYS / f"{host}_host_ed25519.pub"))], [], [])


async def _try(conn, command, stdin) -> tuple[int | None, str, str]:
    if command == "<pty>":
        try:
            proc = await conn.create_process(term_type="xterm", encoding="utf-8")
        except asyncssh.ChannelOpenError as exc:
            return None, "", f"PTY request refused by sshd: {exc.reason}"
        proc.stdin.write("id\nexit\n")
        proc.stdin.write_eof()
    elif command is None:
        proc = await conn.create_process(encoding="utf-8")
        proc.stdin.write("id\nexit\n")
        proc.stdin.write_eof()
    elif command == "<sftp>":
        proc = await conn.create_process(subsystem="sftp", encoding=None)
        proc.stdin.write_eof()
    else:
        proc = await conn.create_process(command, encoding="utf-8")
        if stdin:
            proc.stdin.write(stdin)
        proc.stdin.write_eof()
    res = await asyncio.wait_for(proc.wait(), 20)
    out, err = res.stdout or "", res.stderr or ""
    if isinstance(out, bytes):
        out, err = out.decode("utf-8", "replace"), err.decode("utf-8", "replace")
    return res.exit_status, out, err


async def _matrix(entry, targets: list[str]) -> list[dict]:
    key = asyncssh.read_private_key(str(L.KEYS / "audit_ed25519"))
    host, port = entry
    rows: list[dict] = []

    def add(target, label, command, rc, out, err, expect):
        first = (err.strip().splitlines() or [""])[0]
        rows.append({"host": target, "label": label, "command": command, "rc": rc, "stderr": first, "stdout": out,
                     "expect": expect})

    async with asyncssh.connect(host, port, username="sshbite", client_keys=[key], known_hosts=_known("jump"),
                                config=None, agent_path=None, connect_timeout=15) as jconn:
        for target in targets:
            conn_cm = None
            if target == "jump":
                conn = jconn
            else:   # through jump (B hosts), or directly for a stand-alone A host (r1)
                tunnel = {} if AK[target][0] == "A" else {"tunnel": jconn}
                conn_cm = asyncssh.connect(EXP["hosts"][target][0], 22, username="sshbite", client_keys=[key],
                                           known_hosts=_known(target), config=None, agent_path=None,
                                           connect_timeout=15, **tunnel)
                conn = await conn_cm.__aenter__()
            try:
                for label, command, stdin in ATTACKS:
                    rc, out, err = await _try(conn, command, stdin)
                    shown = {"<pty>": "(login shell, PTY requested)", None: "(login shell, no command)",
                             "<sftp>": "(subsystem sftp)"}.get(command, command)
                    if stdin:
                        shown += "   [stdin: " + stdin.strip().replace("\n", "\\n") + "]"
                    add(target, label, shown, rc, out, err, "denied-pty" if command == "<pty>" else "denied")
                rc, out, err = await _try(conn, f"sudo -n -l {P}", None)
                add(target, "probe", f"sudo -n -l {P}", rc, out, err, "allowed")
                rc, out, err = await _try(conn, f"sudo -n {P}", "id\n")
                add(target, "collector (stdin: id)", f"sudo -n {P}   [stdin: id]", rc, out, err, "allowed")
                rc, out, err = await _try(conn, R, "a1\n")
                add(target, "resolve a1", f"{R}   [stdin: a1]", rc, out, err, "allowed")
                # forwarding: jump only to port 22; everything else nowhere
                fwd = [("172.30.1.11", 2200), ("172.30.1.11", 22)] if target == "jump" else [("172.30.1.12", 22)]
                for fhost, fport in fwd:
                    try:
                        r, w = await conn.open_connection(fhost, fport)
                        w.close()
                        rc, err = 0, "forward opened"
                    except asyncssh.ChannelOpenError as exc:
                        rc, err = None, f"channel open refused: {exc.reason}"
                    ok = target == "jump" and fport == 22
                    add(target, f"port forward to {fhost}:{fport}", f"(direct-tcpip {fhost}:{fport})", rc, "", err,
                        "allowed" if ok else "denied-forward")
            finally:
                if conn_cm is not None:
                    await conn_cm.__aexit__(None, None, None)
    # login on a1 directly from the runner: from= allows only the entry host
    try:
        async with asyncssh.connect(EXP["hosts"]["a1"][0], 22, username="sshbite", client_keys=[key],
                                    known_hosts=_known("a1"), config=None, agent_path=None, connect_timeout=15):
            rc, err = 0, "login accepted"
    except asyncssh.PermissionDenied as exc:
        rc, err = None, f"permission denied: {exc.reason}"
    add("a1", "login from the runner (not from the entry host)", "(direct login, no hop)", rc, "", err,
        "denied-login")
    return rows


def test_i04_attack_matrix(entry, evidence):
    targets = [h for h in ("jump", "a1", "r1") if h in HOSTS]
    rows = asyncio.run(_matrix(entry, targets))
    lines = ["# Attack matrix (i04): the audit key against the installed gate", "",
             "Each row is one SSH request with the audit key `lab/keys/audit_ed25519`; a1 is reached through jump.",
             "", "| Host | Request | Exit | First stderr line / result |", "|---|---|---|---|"]
    for r in rows:
        rc = "-" if r["rc"] is None else str(r["rc"])
        lines.append(f"| {r['host']} | `{r['command']}` | {rc} | {r['stderr'] or '(empty)'} |")
    lines += ["", "Exit `-`: no process was started - sshd refused the PTY, the forwarding channel or the login itself.",
              "sftp: sshd does not forward a subsystem's stderr; exit 126 is the gate's refusal."]
    _write(evidence, "attack-matrix.md", "\n".join(lines) + "\n")
    for r in rows:
        what = (r["host"], r["label"], r["rc"], r["stderr"])
        if r["expect"] == "denied" and r["label"] == "subsystem sftp":
            # sshd does not pass a subsystem's stderr to the client; the exit code is the gate's
            assert r["rc"] == 126 and r["stderr"] in ("", DENIED) and r["stdout"] == "", what
        elif r["expect"] == "denied":
            assert r["rc"] == 126 and r["stderr"] == DENIED, what
            assert "uid=" not in r["stdout"], what
        elif r["expect"] == "denied-pty":   # restrict: sshd refuses the PTY before the gate runs
            assert r["rc"] is None and r["stderr"].startswith("PTY request refused by sshd"), what
        elif r["expect"] == "denied-forward":
            assert r["rc"] is None and r["stderr"].startswith("channel open refused"), what
        elif r["expect"] == "denied-login":
            assert r["rc"] is None and r["stderr"].startswith("permission denied"), what
        elif r["label"] == "probe":
            assert r["rc"] == 0 and r["stdout"].strip() == P, what
        elif r["label"].startswith("collector"):
            assert r["rc"] == 0 and r["stdout"].startswith(f"#SSHBITE 1 {B}\n"), what
            assert "uid=" not in r["stdout"] and "#END" in r["stdout"], what
        elif r["label"] == "resolve a1":
            assert r["rc"] == 0 and "a1\t172.30.1.11" in r["stdout"].splitlines(), what
        else:
            assert r["rc"] == 0, what


# ---- i05: broken installations become collector_error with the exact text, never partial

BREAK = {
    "a2": (f"rm {P}", f"privilege.mode installed: collector not installed at {P}"),
    "a3": ("sed -i 's/NOPASSWD: //' /etc/sudoers.d/sshbite",
           f"privilege.mode installed: sudo asks for a password - the sudoers rule for {P} must be NOPASSWD"),
    # Debian's sudo 1.9 answers `sudo -n -l P` without any rule for the account like a rule without NOPASSWD
    "a4": ("rm /etc/sudoers.d/sshbite",
           f"privilege.mode installed: sudo asks for a password - the sudoers rule for {P} must be NOPASSWD"),
    "a5": (f"sed -i 's/^B=[0-9a-f]*$/B=000000000000/' {P}",
           f"privilege.mode installed: installed collector version differs from this SSHBITE (expected B={B}, "
           f"host has B=000000000000) - run 'sshbite collector export' and reinstall sshbite-collect"),
    # a sudoers rule for sshbite, but not for the collector: sudo -n -l P says nothing and exits 1
    "b2": (f"sed -i 's|NOPASSWD: {P} \"\"|NOPASSWD: /bin/true|' /etc/sudoers.d/sshbite",
           f"privilege.mode installed: sudo does not allow {P} for this account (sudo -n -l exit 1: )"),
}


def test_i05_failures(ctl, cfg, state, evidence):
    for h, (cmd, _text) in BREAK.items():
        ctl.run_text(h, f"set -eu\n{cmd}\n")
    try:
        proc, sid, diff = _scan(ctl, cfg, "failures", "installed-failures", evidence, "--no-crawl")
        _write(evidence, "console-scan-failures.txt",
               "$ sshbite scan --label installed-failures --no-crawl   # entry + seeds a2 a3 a4 a5 b2\n"
               + proc.stdout + proc.stderr)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert diff == "", diff
        state["fail"] = sid
        show = L.sshbite(cfg["installed"], "scans", "show", str(sid))
        _write(evidence, "scans-show-failures.txt", show.stdout)
        conn = _db(cfg)
        by_addr = {r["connect_addr"]: r for r in conn.execute(
            "SELECT hs.*, h.display_name FROM host_scan hs JOIN host h ON h.id=hs.host_id WHERE hs.scan_id=?", (sid,))}
        for h, (_cmd, text) in BREAK.items():
            r = by_addr[EXP["hosts"][h][0]]
            assert (r["status"], r["error"]) == ("collector_error", text), (h, r["status"], r["error"])
            assert text in show.stdout, h
        assert by_addr[EXP["hosts"]["jump"][0]]["status"] == "ok"
        statuses = {r["status"] for r in by_addr.values()}
        privs = {r["privilege"] for r in by_addr.values()}
        assert "partial" not in statuses and "unprivileged" not in privs, (statuses, privs)
    finally:
        res = _parallel(lambda h: _apply(ctl, cfg, h), list(BREAK))   # J3: export once, reinstall
        for h in BREAK:
            assert "/etc/sudoers.d/sshbite: parsed OK" in res[h], (h, res[h])
    p = L.sshbite(cfg["installed"], "config", "validate", "--connect")
    assert p.returncode == 0, p.stdout + p.stderr


def test_i99_remove(ctl, state, evidence):
    """Remove the installation; every host is byte for byte as before i01, and test_00b holds again."""
    res = _parallel(lambda h: ctl.run_text(h, L.installed_remove_script()), HOSTS)
    for h in HOSTS:
        assert "restored" in res[h], (h, res[h])
    after = ctl.snapshot_all()
    diff = L.snapshot_diff(state["pristine"], after)
    _write(evidence, "snapshot-before-apply-vs-after-remove.diff", diff)
    assert diff == "", diff
    from .test_lab import test_00b_sshd_and_ssh_keygen_write_nothing

    test_00b_sshd_and_ssh_keygen_write_nothing(ctl, None)
