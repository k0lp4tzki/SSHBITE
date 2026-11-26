#!/usr/bin/env python3
"""Lab helper (test only): run a command as root on a lab host via the lab-control sshd (port 2200).

Usage: labctl.py HOST 'command' [< stdin]
Uses lab/keys/labctl_ed25519 (test-only key). Host keys are not checked: lab only.
"""
import asyncio
import sys
from pathlib import Path

import asyncssh

KEY = Path(__file__).resolve().parents[2] / "lab" / "keys" / "labctl_ed25519"


async def main(host: str, cmd: str) -> int:
    data = None if sys.stdin.isatty() else sys.stdin.buffer.read()
    async with asyncssh.connect(host, 2200, username="root", client_keys=[str(KEY)], known_hosts=None,
                                agent_path=None, config=None) as c:
        r = await c.run(cmd, input=data, encoding=None)
        sys.stdout.buffer.write(r.stdout or b"")
        sys.stderr.buffer.write(r.stderr or b"")
        return r.exit_status or 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1], sys.argv[2])))
