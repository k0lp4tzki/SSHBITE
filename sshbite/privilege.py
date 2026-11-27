"""Privilege handling (spec 3.4): sudo probe, optional sudo password, unprivileged fallback.

Only these literal commands are ever sent to a target, each on its own exec channel. SUDO stands for
the fixed prefix `test -x /usr/bin/sudo && exec /usr/bin/sudo ARGS; exec /bin/sudo ARGS`: sudo is always
called by its absolute path, never through the account's PATH, and /bin/sudo is only used where
/usr/bin/sudo does not exist.

    SUDO -n /bin/true                 SUDO -n -i /bin/true            (probe; -i for sudo-login)
    SUDO -n /bin/sh -s                SUDO -n -i /bin/sh -s           (collector via NOPASSWD sudo)
    SUDO -S -k -p '' /bin/true        SUDO -S -k -p '' -i /bin/true   (password probe)
    SUDO -S -k -p '' /bin/sh -s       SUDO -S -k -p '' -i /bin/sh -s  (collector via password)
    /bin/sh -s                                                        (unprivileged collector)

privilege.mode installed sends only these (P = privilege.collector_path, installed with `sshbite collector
export`): `sudo -n -l P` (probe) and `sudo -n P` (run), both with empty stdin, plus the resolve file next to P.
No script is sent, no shell is asked for, no password is ever sent and there is no unprivileged fallback.
`sudo` has no path: the gate (sshbite-gate) resolves it to /usr/bin/sudo or /bin/sudo.

The password is only sent to hosts inside privilege.password_scope (empty = every host).

-k makes sudo ignore (and not write) cached credentials, so the password line on
stdin is always consumed by sudo itself and can never reach the shell as a
command, even when a timestamp from the probe would otherwise be valid.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from .config import DEFAULT_COLLECTOR_PATH
from .transport import ExecResult, run

log = logging.getLogger("sshbite.privilege")

PASSWORD_REQUIRED = re.compile(r"password is required|a terminal is required|no tty present", re.I)


@dataclass
class SudoSecret:
    """Holds the sudo password for the scan only. repr/str never show it."""

    _value: str | None = None

    def get(self) -> str | None:
        return self._value

    def set(self, value: str | None) -> None:
        """The password is one line for sudo -S: CR or LF would hand the rest to the root shell."""
        if value and ("\n" in value or "\r" in value):
            raise ValueError("the sudo password must not contain a line break")
        self._value = value or None

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
    privilege: str                         # root | sudo_password | unprivileged | none (installed, probe failed)
    result: ExecResult
    partial_reasons: list[str] = field(default_factory=list)
    needs_password: bool = False           # sudo asked for a password and none was given
    error: str | None = None               # installed: the probe failed; the host becomes collector_error


def _first_line(text: str, secret: SudoSecret) -> str:
    text = secret.redact(text or "")
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line[:200]
    return ""


SUDO_PATH = "/usr/bin/sudo"
SUDO_FALLBACK = "/bin/sudo"
OUTSIDE_SCOPE = "sudo password not sent (outside privilege.password_scope)"


def sudo_cmd(args: str) -> str:
    """sudo by absolute path: /usr/bin/sudo, or /bin/sudo only if the first is not executable (fixed test -x)."""
    return f"test -x {SUDO_PATH} && exec {SUDO_PATH} {args}; exec {SUDO_FALLBACK} {args}"


def commands(mode: str, collector_path: str = DEFAULT_COLLECTOR_PATH) -> dict[str, str]:
    if mode == "installed":
        return {"probe": f"sudo -n -l {collector_path}", "run": f"sudo -n {collector_path}"}
    i = " -i" if mode == "sudo-login" else ""
    return {
        "probe": sudo_cmd(f"-n{i} /bin/true"),
        "run": sudo_cmd(f"-n{i} /bin/sh -s"),
        "pw_probe": sudo_cmd(f"-S -k -p ''{i} /bin/true"),
        "pw_run": sudo_cmd(f"-S -k -p ''{i} /bin/sh -s"),
        "plain": "/bin/sh -s",
    }


INSTALLED = "privilege.mode installed: "


def installed_stderr_error(collector_path: str, stderr: str, secret: SudoSecret | None = None) -> str | None:
    """The first three rows of the installed error table: what stderr alone tells (gate, password, missing file)."""
    secret = secret or SudoSecret()
    first = _first_line(stderr, secret)
    if first.startswith("sshbite-gate:"):
        return f"{INSTALLED}refused by sshbite-gate on this host: {first}"
    if PASSWORD_REQUIRED.search(stderr or ""):
        return f"{INSTALLED}sudo asks for a password - the sudoers rule for {collector_path} must be NOPASSWD"
    if "command not found" in (stderr or ""):
        return f"{INSTALLED}collector not installed at {collector_path}"
    return None


def installed_probe_error(collector_path: str, rc: int | None, stderr: str, secret: SudoSecret | None = None) -> str:
    """Text for a failed `sudo -n -l P` (host status collector_error)."""
    secret = secret or SudoSecret()
    return installed_stderr_error(collector_path, stderr, secret) or (
        f"{INSTALLED}sudo does not allow {collector_path} for this account "
        f"(sudo -n -l exit {rc}: {_first_line(stderr, secret)})")


def installed_version_error(expected: str, got: str) -> str:
    return (f"{INSTALLED}installed collector version differs from this SSHBITE (expected B={expected}, "
            f"host has B={got}) - run 'sshbite collector export' and reinstall sshbite-collect")


async def collect_installed(conn, collector_path: str, max_bytes: int,
                            secret: SudoSecret | None = None) -> CollectOutcome:
    """Mode installed: probe, then the installed collector - two exec channels, stdin empty, nothing else."""
    cmds = commands("installed", collector_path)
    probe = await run(conn, cmds["probe"], None, max_bytes=65536)
    if probe.rc != 0:
        return CollectOutcome("none", probe, [], False,
                              error=installed_probe_error(collector_path, probe.rc, probe.stderr, secret))
    res = await run(conn, cmds["run"], None, max_bytes=max_bytes)
    return CollectOutcome("root", res)


async def collect(conn, script: bytes, mode: str, secret: SudoSecret, max_bytes: int,
                  password_allowed: bool = True, collector_path: str = DEFAULT_COLLECTOR_PATH) -> CollectOutcome:
    """password_allowed=False: the host is outside privilege.password_scope - never send it the password.
    Mode installed ignores script, secret and password_allowed: see collect_installed()."""
    if mode == "installed":
        return await collect_installed(conn, collector_path, max_bytes, secret)
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
            withheld = bool(pw) and not password_allowed
            if withheld:
                pw = None
            # sudoers may want a password for /bin/true but not for /bin/sh (NOPASSWD: /bin/sh): then sudo
            # would not read the password line and the shell would run it. Try the NOPASSWD path first,
            # with empty stdin (the shell exits at once).
            sh_nopw = await run(conn, cmds["run"], None, max_bytes=65536) if pw else None
            if sh_nopw is not None and sh_nopw.rc == 0:
                res = await run(conn, cmds["run"], script, max_bytes=max_bytes)
                return CollectOutcome("root", res)
            if pw:
                line = (pw + "\n").encode("utf-8")
                p2 = await run(conn, cmds["pw_probe"], line, max_bytes=65536)
                if p2.rc == 0:
                    res = await run(conn, cmds["pw_run"], line + script, max_bytes=max_bytes)
                    res.stderr = secret.redact(res.stderr)
                    return CollectOutcome("sudo_password", res)
                reasons.append(_first_line(err, secret) or "sudo: a password is required")
                reasons.append("sudo password not accepted: " + (_first_line(p2.stderr, secret) or f"exit {p2.rc}"))
            elif withheld:
                reasons.append(_first_line(err, secret) or "sudo: a password is required")
                reasons.append(OUTSIDE_SCOPE)
            else:
                needs_password = True
                reasons.append(_first_line(err, secret) or "sudo: a password is required")
        else:
            reasons.append(_first_line(err, secret) or f"sudo probe failed (exit {probe.rc})")
    else:
        reasons.append("privilege mode is 'none'")
    res = await run(conn, cmds["plain"], script, max_bytes=max_bytes)
    return CollectOutcome("unprivileged", res, reasons, needs_password)
