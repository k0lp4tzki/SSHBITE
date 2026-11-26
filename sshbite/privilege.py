"""Privilege handling (spec 3.4): sudo probe, optional sudo password, unprivileged fallback.

Only these literal commands are ever sent to a target, each on its own exec channel:

    sudo -n /bin/true                 sudo -n -i /bin/true            (probe; -i for sudo-login)
    sudo -n /bin/sh -s                sudo -n -i /bin/sh -s           (collector via NOPASSWD sudo)
    sudo -S -k -p '' /bin/true        sudo -S -k -p '' -i /bin/true   (password probe)
    sudo -S -k -p '' /bin/sh -s       sudo -S -k -p '' -i /bin/sh -s  (collector via password)
    /bin/sh -s                                                        (unprivileged collector)

-k makes sudo ignore (and not write) cached credentials, so the password line on
stdin is always consumed by sudo itself and can never reach the shell as a
command, even when a timestamp from the probe would otherwise be valid.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from .transport import ExecResult, run

log = logging.getLogger("sshbite.privilege")

PASSWORD_REQUIRED = re.compile(r"password is required|a terminal is required|no tty present", re.I)


@dataclass
class SudoSecret:
    """Holds the sudo password for the scan only. repr/str never show it."""

    _value: str | None = None

    def get(self) -> str | None:
        return self._value

    def __bool__(self) -> bool:
        return bool(self._value)

    def __repr__(self) -> str:
        return "SudoSecret(<redacted>)" if self._value else "SudoSecret(None)"

    __str__ = __repr__

    def redact(self, text: str) -> str:
        if self._value and text:
            return text.replace(self._value, "[REDACTED]")
        return text

    def clear(self) -> None:
        self._value = None


class RedactingFilter(logging.Filter):
    """Log filter that removes the secret from every record (message, args, exception text)."""

    def __init__(self, secret: SudoSecret):
        super().__init__()
        self.secret = secret

    def filter(self, record: logging.LogRecord) -> bool:
        if self.secret:
            try:
                msg = record.getMessage()
            except Exception:
                msg = str(record.msg)
            record.msg = self.secret.redact(msg)
            record.args = None
            if record.exc_info and record.exc_info[1] is not None:
                import traceback

                record.exc_text = self.secret.redact("".join(traceback.format_exception(*record.exc_info)))
                record.exc_info = None
            if record.exc_text:
                record.exc_text = self.secret.redact(record.exc_text)
        return True


@dataclass
class CollectOutcome:
    privilege: str                         # root | sudo_password | unprivileged
    result: ExecResult
    partial_reasons: list[str] = field(default_factory=list)
    needs_password: bool = False           # sudo asked for a password and none was given


def _first_line(text: str, secret: SudoSecret) -> str:
    text = secret.redact(text or "")
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line[:200]
    return ""


def commands(mode: str) -> dict[str, str]:
    i = " -i" if mode == "sudo-login" else ""
    return {
        "probe": f"sudo -n{i} /bin/true",
        "run": f"sudo -n{i} /bin/sh -s",
        "pw_probe": f"sudo -S -k -p ''{i} /bin/true",
        "pw_run": f"sudo -S -k -p ''{i} /bin/sh -s",
        "plain": "/bin/sh -s",
    }


async def collect(conn, script: bytes, mode: str, secret: SudoSecret, max_bytes: int) -> CollectOutcome:
    cmds = commands(mode)
    reasons: list[str] = []
    needs_password = False
    if mode != "none":
        probe = await run(conn, cmds["probe"], None, max_bytes=65536)
        if probe.rc == 0:
            res = await run(conn, cmds["run"], script, max_bytes=max_bytes)
            return CollectOutcome("root", res)
        err = probe.stderr
        if PASSWORD_REQUIRED.search(err):
            pw = secret.get()
            if pw:
                line = (pw + "\n").encode("utf-8")
                p2 = await run(conn, cmds["pw_probe"], line, max_bytes=65536)
                if p2.rc == 0:
                    res = await run(conn, cmds["pw_run"], line + script, max_bytes=max_bytes)
                    res.stderr = secret.redact(res.stderr)
                    return CollectOutcome("sudo_password", res)
                reasons.append(_first_line(err, secret) or "sudo: a password is required")
                reasons.append("sudo password not accepted: " + (_first_line(p2.stderr, secret) or f"exit {p2.rc}"))
            else:
                needs_password = True
                reasons.append(_first_line(err, secret) or "sudo: a password is required")
        else:
            reasons.append(_first_line(err, secret) or f"sudo probe failed (exit {probe.rc})")
    else:
        reasons.append("privilege mode is 'none'")
    res = await run(conn, cmds["plain"], script, max_bytes=max_bytes)
    return CollectOutcome("unprivileged", res, reasons, needs_password)
