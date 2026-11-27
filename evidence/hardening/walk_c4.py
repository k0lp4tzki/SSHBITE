"""Walk of the four journeys of the check-4 package against the lab, as an operator would do them (walk-c4.txt).

  python3 evidence/hardening/walk_c4.py              export, install every lab host (lab/installed.sh), then
      J1 FIFO race on a5: scans of a5 until one meets the FIFO ('read timed out'), root processes afterwards;
      J2 flood on a5: full scan, a5 partial with 'output budget exceeded', zvictim's key there;
      J3 remote forward with the audit key on jump and r1: refused, -L to port 22 works;
      J4 install.md on r1 with an account sshbite that existed before (bash, wheel, authorized_keys2 with a
         key of its own): the leftover key logs in to a shell; the steps of install.md find and remove it all.
      Uninstalls every host at the end; database in WALK_DIR for the screenshots.
  python3 evidence/hardening/walk_c4.py screens OUT  with `sshbite -c $WALK_DIR/sshbite.yaml serve` running:
      screenshots desktop 1440 px and phone 390 px into OUT
Run from the repository root with the lab reachable (SSHBITE_LAB_ENTRY=jump:22).
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import asyncssh
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tests.e2e import lab as L  # noqa: E402
from tests.e2e.test_lab_installed import AK, HOSTS  # noqa: E402

W = Path(os.environ.get("WALK_DIR", "/tmp/sshbite-walk-c4"))
OUT: list[str] = []
ctl = L.LabControl(L.lab_hosts())
SB = str(Path(sys.executable).parent / "sshbite")
A5 = L.expected()["hosts"]["a5"][0]


def say(text: str) -> None:
    OUT.append(text)
    print(text, flush=True)


def sh(args: list[str], shown: str, **kw) -> subprocess.CompletedProcess:
    p = subprocess.run(args, capture_output=True, text=True, cwd=str(W), timeout=900, **kw)
    say(f"$ {shown}\n{p.stdout}{p.stderr}(exit {p.returncode})\n")
    return p


def host(h: str, text: str, what: str) -> str:
    out = ctl.run_text(h, text + "\n")
    say(f"[{h} as root] {what}\n{out}")
    return out


def config(name: str, **extra) -> Path:
    h, _, port = os.environ.get("SSHBITE_LAB_ENTRY", "jump:22").rpartition(":")
    subprocess.run(["sh", str(L.LAB / "up.sh")], check=True, capture_output=True,
                   env=dict(os.environ, LAB_NO_START="1", LAB_ENTRY_HOST=h, LAB_ENTRY_PORT=port))
    data = yaml.safe_load((L.LAB / "sshbite.lab.yaml").read_text())
    data["database"] = str(W / "sshbite.db")
    data["privilege"] = {"mode": "installed"}
    data.update(extra)
    p = W / name
    p.write_text(yaml.safe_dump(data, sort_keys=False))
    p.chmod(0o600)
    return p


def latest(db: Path) -> tuple[int, dict]:
    c = sqlite3.connect(db)
    sid = c.execute("SELECT max(id) FROM scan WHERE status='completed'").fetchone()[0]
    rows = {r[0]: (r[1], r[2], json.loads(r[3] or "[]")) for r in c.execute(
        "SELECT h.display_name, hs.status, hs.privilege, hs.partial_reasons FROM host_scan hs JOIN host h "
        "ON h.id=hs.host_id WHERE hs.scan_id=?", (sid,))}
    return sid, rows


def j1_fifo(cfg: Path, a5cfg: Path) -> None:
    say("##### J1 a local user on a5 flips ~/.ssh/known_hosts between file, symlink and FIFO during the scans")
    host("a5", (L.LAB / "race.sh").read_text().replace('case "${1:-}" in', 'set -- start fifo\ncase "${1:-}" in'),
         "lab/race.sh start fifo")
    try:
        host("a5", "set -- count 50\n" + (L.LAB / "race.sh").read_text(), "lab/race.sh count 50   # the control: "
             "head as root, each under timeout 2")
        hit = None
        for i in range(1, 41):
            p = subprocess.run([SB, "-c", str(a5cfg), "scan", "--no-crawl", "--label", f"a5 FIFO race {i}"],
                               capture_output=True, text=True, cwd=str(W), timeout=300)
            sid, rows = latest(W / "sshbite.db")
            st, priv, reasons = rows["a5"]
            timed = [r for r in reasons if r.startswith("read timed out")]
            say(f"$ sshbite scan --no-crawl --label 'a5 FIFO race {i}'   # entry jump + seed a5\n"
                f"  (exit {p.returncode}) a5: {st}/{priv}, reasons {reasons}")
            if timed:
                hit = sid
                say(p.stdout + p.stderr)
                break
        say(f"# the first scan whose a5 run met the FIFO: scan {hit}")
        if hit:
            sh([SB, "-c", str(cfg), "scans", "show", str(hit)], f"sshbite scans show {hit}")
        host("a5", "set -- procs\n" + (L.LAB / "race.sh").read_text(),
             "lab/race.sh procs   # root processes of sudo or sshbite-collect left on a5 (empty = none)")
    finally:
        host("a5", "set -- stop\n" + (L.LAB / "race.sh").read_text(), "lab/race.sh stop")


def j2_flood(cfg: Path) -> None:
    say("##### J2 a local user on a5 floods ~/.ssh (40 x 1 MB .pub); zvictim, later in /etc/passwd, has one key")
    host("a5", "set -- start flood\n" + (L.LAB / "race.sh").read_text(), "lab/race.sh start flood")
    try:
        host("a5", "getent passwd racer zvictim; cat /home/zvictim/.ssh/authorized_keys | cut -c1-40",
             "the two accounts")
        sh([SB, "-c", str(cfg), "scan", "--label", "a5 flood"], "sshbite scan --label 'a5 flood'")
        sid, rows = latest(W / "sshbite.db")
        sh([SB, "-c", str(cfg), "scans", "show", str(sid)], f"sshbite scans show {sid}")
        c = sqlite3.connect(W / "sshbite.db")
        ak = c.execute("SELECT ae.username, ae.file, ae.comment FROM authorized_entry ae JOIN host h ON "
                       "h.id=ae.host_id WHERE ae.scan_id=? AND h.display_name='a5' ORDER BY 1", (sid,)).fetchall()
        say(f"# a5 in scan {sid}: {rows['a5']}\n# authorized keys of a5 in the database: {ak}\n")
    finally:
        host("a5", "set -- stop\n" + (L.LAB / "race.sh").read_text(), "lab/race.sh stop")


async def _forward(target: str) -> list[str]:
    key = asyncssh.read_private_key(str(L.KEYS / "audit_ed25519"))
    h, p = L.find_r1() if target == "r1" else os.environ.get("SSHBITE_LAB_ENTRY", "jump:22").rsplit(":", 1)
    kh = ([asyncssh.read_public_key(str(L.KEYS / f"{target}_host_ed25519.pub"))], [], [])
    out = []
    async with asyncssh.connect(h, int(p), username="sshbite", client_keys=[key], known_hosts=kh, config=None,
                                agent_path=None) as c:
        for lh, lp in (("", 0), ("localhost", 22), ("127.0.0.1", 8080)):
            try:
                ls = await c.forward_remote_port(lh, lp, "127.0.0.1", 22)
                out.append(f"ssh -R {lh or '*'}:{lp}:127.0.0.1:22 -> OPENED on port {ls.get_port()}")
                ls.close()
            except asyncssh.ChannelListenError as exc:
                out.append(f"ssh -R {lh or '*'}:{lp}:127.0.0.1:22 -> refused: {exc}")
        nxt = "172.30.1.11" if target == "jump" else L.R1_IP
        r, w = await c.open_connection(nxt, 22)
        banner = (await asyncio.wait_for(r.readline(), 10)).decode().strip()
        w.close()
        out.append(f"ssh -L x:{nxt}:22 (direct-tcpip) -> opened, the far end says: {banner}")
    return out


def j3_forward() -> None:
    say("##### J3 the holder of the audit key asks for remote forwards on the entry host (jump) and on r1 (variant A)")
    say("authorized_keys line (A): " + L.installed_line(*AK["jump"]).rsplit(" ", 2)[0] + " <AUDIT-PUBLIC-KEY>\n")
    for t in ("jump", "r1"):
        say(f"[{t}]\n" + "\n".join("  " + x for x in asyncio.run(_forward(t))) + "\n")


OLD = r"""set -e
cp -p /etc/passwd /etc/shadow /etc/group /etc/gshadow /lab/ 2>/dev/null || cp -p /etc/passwd /etc/shadow /etc/group /lab/
for f in passwd- shadow- group- gshadow-; do [ -e /etc/$f ] && cp -p /etc/$f /lab/$f || :; done
touch -r /etc /lab/mtime.etc
usermod -s /bin/bash -aG wheel sshbite
install -m 600 -o sshbite -g sshbite /dev/null /home/sshbite/.ssh/authorized_keys2
printf '%s\n' "$1" > /home/sshbite/.ssh/authorized_keys2
chown sshbite:sshbite /home/sshbite/.ssh/authorized_keys2
echo "prepared: shell bash, group wheel, ~sshbite/.ssh/authorized_keys2 with a key of its own"
"""

RESTORE = r"""for f in passwd shadow group gshadow passwd- shadow- group- gshadow-; do [ -e /lab/$f ] && cp -p /lab/$f /etc/$f || :; done
touch -m -r /lab/mtime.etc /etc
rm -f /lab/passwd /lab/shadow /lab/group /lab/gshadow /lab/passwd- /lab/shadow- /lab/group- /lab/gshadow- /lab/mtime.etc
rm -f /home/sshbite/.ssh/authorized_keys2
echo restored
"""

INSTALL_MD_CHECKS = """getent passwd sshbite | cut -d: -f7
id sshbite
ls -la ~sshbite ~sshbite/.ssh
ls -A ~sshbite/.ssh
crontab -l -u sshbite 2>&1 || :
ps -u sshbite 2>&1 || :
sshd -T | grep -Ei 'authorizedkeysfile|acceptenv|permituserenvironment'
sudo -l -U sshbite | sed -n '/may run/,$p'"""


async def _old_key_login(key) -> str:
    h, p = L.find_r1()
    kh = ([asyncssh.read_public_key(str(L.KEYS / "r1_host_ed25519.pub"))], [], [])
    try:
        async with asyncssh.connect(h, p, username="sshbite", client_keys=[key], known_hosts=kh, config=None,
                                    agent_path=None) as c:
            r = await c.run("id; echo shell=$0; sudo -n -l 2>&1 | tail -2", check=False)
            return f"login accepted, the command ran:\n{r.stdout}{r.stderr}"
    except asyncssh.PermissionDenied as exc:
        return f"login refused: {exc}"


def j4_existing_account() -> None:
    say("##### J4 install.md on r1, where an account sshbite existed before (shell bash, group wheel, "
        "authorized_keys2 with a key of a former admin)")
    old = asyncssh.generate_private_key("ssh-ed25519", comment="former-admin")
    line = old.export_public_key().decode().strip()
    ctl.run_text("r1", f"set -- '{line}'\n" + OLD)
    try:
        say("[r1] the old state:")
        host("r1", "getent passwd sshbite; id sshbite; ls -la ~sshbite/.ssh", "before the installation")
        say("# the former admin's key from authorized_keys2, before the installation:\n" +
            asyncio.run(_old_key_login(old)))
        export = W / "sshbite-export"
        try:
            out = ctl.run_text("r1", L.installed_apply_script(export, L.installed_line(*AK["r1"])))
            say("[r1 as root] the install block of docs/install.md (lab/installed.sh apply, variant A)\n"
                + out.splitlines()[0])
        except RuntimeError as exc:   # its last check, sudo -l -U sshbite, stops at the old wheel rule
            say("[r1 as root] the install block of docs/install.md (lab/installed.sh apply, variant A) stops at "
                f"its own check:\n{exc}\n")
        say("# the same key after the install block - authorized_keys2 is still there:\n"
            + asyncio.run(_old_key_login(old)))
        host("r1", INSTALL_MD_CHECKS, "the checks of 'An account sshbite that existed before' (docs/install.md)")
        host("r1", "usermod -s /bin/sh sshbite\ngpasswd -d sshbite wheel\nrm -f ~sshbite/.ssh/authorized_keys2",
             "remove what the checks found: usermod -s /bin/sh sshbite; gpasswd -d sshbite wheel; "
             "rm ~sshbite/.ssh/authorized_keys2")
        out = ctl.run_text("r1", L.installed_apply_script(export, L.installed_line(*AK["r1"])))
        say("[r1 as root] the install block again\n" + out.splitlines()[0])
        host("r1", INSTALL_MD_CHECKS, "the checks again")
        say("# the former admin's key now:\n" + asyncio.run(_old_key_login(old)))
    finally:
        host("r1", L.installed_remove_script(), "lab/installed.sh remove")
        host("r1", RESTORE, "restore passwd/group (lab only)")


def walk() -> None:
    W.mkdir(parents=True, exist_ok=True)
    cfg = config("sshbite.yaml")
    seeds = W / "seeds-a5.txt"
    seeds.write_text(A5 + "\n")
    a5cfg = config("sshbite-a5.yaml", seeds={"hosts_file": str(seeds)})
    sh([SB, "-c", str(cfg), "collector", "export", "sshbite-export"], "sshbite collector export sshbite-export")
    p = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=W / "sshbite-export", capture_output=True, text=True)
    say(f"$ cd sshbite-export && sha256sum -c SHA256SUMS\n{p.stdout}(exit {p.returncode})\n")
    say("authorized_keys.sshbite:\n" + (W / "sshbite-export" / "authorized_keys.sshbite").read_text())
    for h in HOSTS:
        ctl.run_text(h, L.installed_apply_script(W / "sshbite-export", L.installed_line(*AK[h])))
    say(f"[all {len(HOSTS)} lab hosts as root] lab/installed.sh apply (docs/install.md)\n")
    try:
        sh([SB, "-c", str(cfg), "config", "validate", "--connect"], "sshbite config validate --connect")
        sh([SB, "-c", str(cfg), "scan", "--label", "installed"], "sshbite scan --label installed")
        sh([SB, "-c", str(cfg), "scans", "show", "latest"], "sshbite scans show latest")
        j1_fifo(cfg, a5cfg)
        j2_flood(cfg)
        j3_forward()
    finally:
        for h in HOSTS:
            ctl.run_text(h, L.installed_remove_script())
        say(f"[all {len(HOSTS)} lab hosts as root] lab/installed.sh remove\n")
    j4_existing_account()
    p = subprocess.run([SB, "-c", str(cfg), "user", "add", "admin", "--password-stdin"],
                       input="correct horse battery\n", capture_output=True, text=True)
    (Path(__file__).parent / "walk-c4.txt").write_text("\n".join(OUT).replace(str(W), "$WALK_DIR"))


def screens(out: str) -> None:
    from playwright.sync_api import sync_playwright

    db = sqlite3.connect(W / "sshbite.db")

    def sid_of(label: str) -> int:
        return db.execute("SELECT max(id) FROM scan WHERE label=?", (label,)).fetchone()[0]

    def hid(sid: int, name: str) -> int:
        return db.execute("SELECT hs.host_id FROM host_scan hs JOIN host h ON h.id=hs.host_id WHERE hs.scan_id=? "
                          "AND h.display_name=?", (sid, name)).fetchone()[0]

    inst = sid_of("installed")
    fifo = db.execute("SELECT max(hs.scan_id) FROM host_scan hs JOIN host h ON h.id=hs.host_id WHERE "
                      "h.display_name='a5' AND hs.partial_reasons LIKE '%read timed out%'").fetchone()[0]
    flood = sid_of("a5 flood")
    shots = [("10-hostliste-installed-ok-root", f"/s/{inst}/hosts"),
             ("11-host-a5-fifo-race-read-timed-out", f"/s/{fifo}/hosts/{hid(fifo, 'a5')}"),
             ("12-hostliste-a5-flood-partial", f"/s/{flood}/hosts"),
             ("13-host-a5-output-budget-exceeded", f"/s/{flood}/hosts/{hid(flood, 'a5')}"),
             ("14-host-a5-flood-users-zvictim", f"/s/{flood}/hosts/{hid(flood, 'a5')}?tab=users")]
    with sync_playwright() as p:
        b = p.chromium.launch(args=["--no-sandbox"])
        for w, h, suf in [(1440, 900, "desktop"), (390, 844, "handy")]:
            ctx = b.new_context(viewport={"width": w, "height": h}, color_scheme="light")
            pg = ctx.new_page()
            pg.goto("http://127.0.0.1:8722/login")
            pg.fill("input[name=username]", "admin")
            pg.fill("input[name=password]", "correct horse battery")
            pg.click("button[type=submit]")
            pg.wait_for_url(lambda u: "/login" not in u)
            for name, path in shots:
                pg.goto("http://127.0.0.1:8722" + path)
                pg.wait_for_load_state("networkidle")
                pg.wait_for_timeout(600)
                pg.screenshot(path=f"{out}/{name}-{suf}.png", full_page=True)
            ctx.close()
        b.close()


if __name__ == "__main__":
    if sys.argv[1:2] == ["screens"]:
        screens(sys.argv[2])
    else:
        walk()
