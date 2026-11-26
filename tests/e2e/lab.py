"""Helpers for the lab e2e test: find the lab, run lab scripts on its hosts, snapshots, CLI runs."""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import asyncssh
import yaml

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "lab"
KEYS = LAB / "keys"
CTL_PORT = 2200


def expected() -> dict:
    return yaml.safe_load((LAB / "expected.yaml").read_text())


def _tcp_ok(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        socket.create_connection((host, port), timeout).close()
        return True
    except OSError:
        return False


def find_entry() -> tuple[str, int] | None:
    """Where the lab's jump host answers. Starts the lab with lab/up.sh if docker/podman/root allow it."""
    env = os.environ.get("SSHBITE_LAB_ENTRY")
    cands = [env] if env else ["127.0.0.1:2222", "jump:22"]
    for c in cands:
        h, _, p = c.rpartition(":")
        if _tcp_ok(h, int(p)) and _tcp_ok("172.30.1.5", CTL_PORT):
            return h, int(p)
    if os.environ.get("SSHBITE_LAB_NO_START") != "1" and (
            shutil.which("docker") or shutil.which("podman") or os.geteuid() == 0):
        r = subprocess.run(["sh", str(LAB / "up.sh")], capture_output=True, text=True, timeout=1800)
        if r.returncode == 0 and _tcp_ok("127.0.0.1", 2222):
            return "127.0.0.1", 2222
    return None


def key_fp(name: str) -> str:
    from sshbite.parse.keys import parse_public_key_line

    return parse_public_key_line((KEYS / f"{name}.pub").read_text()).fp


class LabControl:
    """Runs fixed lab scripts as root on lab hosts through the lab-control sshd (port 2200)."""

    def __init__(self, hosts: dict[str, list[str]]):
        self.hosts = hosts
        self.key = asyncssh.read_private_key(str(KEYS / "labctl_ed25519"))
        host_pub = asyncssh.read_public_key(str(KEYS / "labctl_host_ed25519.pub"))
        self.known = ([host_pub], [], [])

    async def _run(self, host: str, script: str, args: str = "") -> str:
        ip = self.hosts[host][0]
        async with asyncssh.connect(ip, CTL_PORT, username="root", client_keys=[self.key], known_hosts=self.known,
                                    config=None, agent_path=None, connect_timeout=15) as c:
            r = await c.run(f"sh -s {args}".strip(), input=script, check=False)
            if r.exit_status != 0:
                raise RuntimeError(f"{host}: {args or 'script'} failed ({r.exit_status}): {r.stderr}")
            return r.stdout

    def run(self, host: str, script_file: str, args: str = "") -> str:
        script = (LAB / script_file).read_text()
        return asyncio.run(self._run(host, script, args))

    def snapshot_all(self) -> dict[str, str]:
        script = (LAB / "snapshot.sh").read_text()

        async def all_():
            names = sorted(self.hosts)
            res = await asyncio.gather(*(self._run(h, script) for h in names))
            return dict(zip(names, res))

        return asyncio.run(all_())


def snapshot_diff(before: dict[str, str], after: dict[str, str]) -> str:
    import difflib

    out = []
    for h in sorted(set(before) | set(after)):
        a, b = before.get(h, ""), after.get(h, "")
        if a != b:
            out.extend(difflib.unified_diff(a.splitlines(), b.splitlines(), f"{h}/before", f"{h}/after", lineterm=""))
    return "\n".join(out)


def sshbite(config: Path, *args: str, env: dict | None = None, input: str | None = None,
            timeout: float = 600) -> subprocess.CompletedProcess:
    e = {k: v for k, v in os.environ.items() if k != "SSHBITE_SUDO_PASSWORD"}
    e.update(env or {})
    return subprocess.run([sys.executable, "-m", "sshbite.cli", "-c", str(config), *args], capture_output=True,
                          text=True, env=e, input=input, timeout=timeout, cwd=str(ROOT))
