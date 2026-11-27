#!/usr/bin/env python3
"""Lab helper (test only): act as whoever holds the SSHBITE audit key - i.e. as an attacker who stole it.

Usage: als_sshbite.py [--via IP ...] [--pty] [--tcp HOST:PORT] TARGET 'command' [< stdin]
TARGET "jump" = the entry host; any other value is an address reached through jump (direct-tcpip),
optionally through further hops given with --via. Prints stdout, stderr and the exit status.
"""
import argparse
import asyncio
import sys
from pathlib import Path

import asyncssh

KEY = Path(__file__).resolve().parents[2] / "lab" / "keys" / "audit_ed25519"
OPTS = dict(username="sshbite", client_keys=[str(KEY)], known_hosts=None, agent_path=None, config=None)


async def main(a) -> int:
    data = None if sys.stdin.isatty() else sys.stdin.buffer.read()
    conns = []
    try:
        c = await asyncssh.connect(a.direct or "jump", 22, **OPTS)
        conns.append(c)
        for hop in a.via + ([] if a.target == "jump" or a.direct else [a.target]):
            c = await asyncssh.connect(hop, 22, tunnel=c, **OPTS)
            conns.append(c)
        if a.tcp:
            host, port = a.tcp.rsplit(":", 1)
            _r, w = await asyncio.wait_for(c.open_connection(host, int(port)), timeout=10)
            w.close()
            print(f"[Weiterleitung zu {a.tcp} geoeffnet]")
            return 0
        r = await asyncio.wait_for(c.run(a.command or None, input=data, encoding=None,
                                         term_type="xterm" if a.pty else None), timeout=20)
        sys.stdout.write((r.stdout or b"").decode("utf-8", "replace"))
        sys.stdout.write("[stderr] " + (r.stderr or b"").decode("utf-8", "replace") if r.stderr else "")
        print(f"[exit {r.exit_status}]")
        return 0
    except (asyncssh.Error, OSError, asyncio.TimeoutError) as exc:
        print(f"[{exc.__class__.__name__}] {exc}")
        return 1
    finally:
        for c in reversed(conns):
            c.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--via", action="append", default=[])
    p.add_argument("--pty", action="store_true")
    p.add_argument("--direct", help="connect straight from the scanner to this address (not via jump)")
    p.add_argument("--tcp", help="only open a direct-tcpip channel to HOST:PORT from TARGET")
    p.add_argument("target")
    p.add_argument("command")
    sys.exit(asyncio.run(main(p.parse_args())))
