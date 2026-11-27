"""What sudo prints for `sudo -n -l P` / `sudo -n P` in the failure cases of spec 4.3 - on the lab's Debian host a2
(sudo 1.9.13, through jump) and on the AlmaLinux 9 host r1 (directly) - sent with the audit key through the installed
gate, and which SSHBITE message each case gets. Writes sudo-stderr.md. Installs each host first (lab/installed.sh
apply) and restores it at the end (remove)."""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

import asyncssh
from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sshbite.cli import main  # noqa: E402
from sshbite.privilege import installed_probe_error  # noqa: E402
from tests.e2e import lab as L  # noqa: E402
from tests.e2e.test_lab_installed import AK, P  # noqa: E402

ctl = L.LabControl(L.lab_hosts())
CASES = [
    ("rule present (reference)", ":"),
    ("missing rule (sshbite has a rule, but not for P)",
     f"sed -i 's|NOPASSWD: {P} \"\"|NOPASSWD: /bin/true|' /etc/sudoers.d/sshbite"),
    ("rule without NOPASSWD", "sed -i 's/NOPASSWD: //' /etc/sudoers.d/sshbite"),
    ("collector file missing", f"rm {P}"),
    ("sudoers file missing (no rule for sshbite at all)", "rm /etc/sudoers.d/sshbite"),
]
HOSTS = {"a2": "the lab's Debian 12 host a2, reached through jump",
         "r1": "the lab's AlmaLinux 9 host r1, reached directly (variant A)"}


async def probe(host: str) -> list[tuple[str, int, str]]:
    key = asyncssh.read_private_key(str(L.KEYS / "audit_ed25519"))
    kh = lambda h: ([asyncssh.read_public_key(str(L.KEYS / f"{h}_host_ed25519.pub"))], [], [])  # noqa: E731
    out = []
    entry_host, entry_port = L.find_entry()
    async with asyncssh.connect(entry_host, entry_port, username="sshbite", client_keys=[key], known_hosts=kh("jump"),
                                config=None, agent_path=None) as j:
        if host == "r1":
            h, p = L.find_r1()
            cm = asyncssh.connect(h, p, username="sshbite", client_keys=[key], known_hosts=kh("r1"), config=None,
                                  agent_path=None)
        else:
            cm = asyncssh.connect(L.lab_hosts()[host][0], 22, tunnel=j, username="sshbite", client_keys=[key],
                                  known_hosts=kh(host), config=None, agent_path=None)
        async with cm as c:
            for cmd in (f"sudo -n -l {P}", f"sudo -n {P}"):
                r = await c.run(cmd, check=False)
                out.append((cmd, r.exit_status, (r.stderr or "").strip()))
    return out


def table(host: str, exp: Path) -> tuple[list[str], list[tuple]]:
    install = L.installed_apply_script(exp, L.installed_line(*AK[host]))
    sudo_version = ctl.run_text(host, "sudo -V | head -1").strip()
    os_name = ctl.run_text(host, ". /etc/os-release && echo \"$PRETTY_NAME\"").strip()
    lines = [f"## {host}: {os_name}", "", f"`{sudo_version}`; {HOSTS[host]}.", "",
             "| Case | Request | Exit | stderr | SSHBITE message (host status collector_error) |", "|---|---|---|---|---|"]
    rows = []
    try:
        for name, cmd in CASES:
            ctl.run_text(host, install)
            ctl.run_text(host, f"set -eu\n{cmd}\n")
            for req, rc, err in asyncio.run(probe(host)):
                msg = "–" if rc == 0 else (installed_probe_error(P, rc, err) if "-l" in req else "(not sent: the probe failed)")
                rows.append((name, req, rc, err, msg))
                lines.append(f"| {name} | `{req}` | {rc} | {err.splitlines()[0] if err else '(empty)'} | {msg} |")
    finally:
        ctl.run_text(host, L.installed_remove_script())
    return lines + [""], rows


def main_() -> None:
    with tempfile.TemporaryDirectory() as d:
        exp = Path(d) / "export"
        assert CliRunner().invoke(main, ["-c", "/nonexistent", "collector", "export", str(exp)]).exit_code == 0
        out = ["# sudo stderr per failure case of spec 4.3 and the resulting SSHBITE message", "",
               "Requests sent with the audit key through the installed gate (made by `sudo_stderr.py`).", ""]
        msgs = {}
        for host in HOSTS:
            lines, rows = table(host, exp)
            out += lines
            msgs[host] = {(name, req): msg for name, req, _rc, _err, msg in rows}
    same = msgs["a2"] == msgs["r1"]
    out += ["## Debian vs. EL", "",
            ("The SSHBITE message is the same on both hosts for every case: the mapping of sudo's stderr to the texts "
             "of spec 4.3 holds on EL too." if same else
             "**The SSHBITE messages differ between the hosts** for: " + ", ".join(
                 f"{k[0]} ({k[1]})" for k in msgs["a2"] if msgs["a2"][k] != msgs["r1"].get(k))), ""]
    (Path(__file__).parent / "sudo-stderr.md").write_text("\n".join(out))
    print("\n".join(out))


if __name__ == "__main__":
    main_()
