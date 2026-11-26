"""privilege.mode installed: the literal commands and the flow with a fake exec channel (spec 4.1-4.3)."""

from __future__ import annotations

import asyncio

import pytest

from sshbite import privilege
from sshbite.privilege import CollectOutcome, SudoSecret, collect, commands
from sshbite.transport import ExecResult

P = "/usr/local/libexec/sshbite/sshbite-collect"


def test_installed_commands():
    assert commands("installed") == {"probe": f"sudo -n -l {P}", "run": f"sudo -n {P}"}
    assert commands("installed", "/opt/x/c") == {"probe": "sudo -n -l /opt/x/c", "run": "sudo -n /opt/x/c"}
    # the other modes are unchanged
    assert commands("sudo")["run"] == "test -x /usr/bin/sudo && exec /usr/bin/sudo -n /bin/sh -s; exec /bin/sudo -n /bin/sh -s"
    assert commands("sudo-login")["probe"] == ("test -x /usr/bin/sudo && exec /usr/bin/sudo -n -i /bin/true; "
                                               "exec /bin/sudo -n -i /bin/true")


class FakeHost:
    """Answers the probe with (rc, stdout, stderr); the run with the collector output."""

    def __init__(self, probe: tuple[int, str, str], run_out: str = "#SSHBITE 1 abc\n#END 1\n"):
        self.probe = probe
        self.run_out = run_out
        self.calls: list[tuple[str, bytes | None]] = []

    async def __call__(self, conn, command, stdin=None, max_bytes=0, max_stderr=65536):
        self.calls.append((command, stdin))
        if command == f"sudo -n -l {P}":
            rc, out, err = self.probe
            return ExecResult(rc, out.encode(), err, False)
        if command == f"sudo -n {P}":
            return ExecResult(0, self.run_out.encode(), "", False)
        return ExecResult(127, b"", "unexpected", False)


def _run(monkeypatch, host: FakeHost, secret: SudoSecret | None = None) -> CollectOutcome:
    monkeypatch.setattr(privilege, "run", host)
    secret = secret or SudoSecret()
    return asyncio.run(collect(object(), b"LC_ALL=C; script", "installed", secret, 1 << 20, collector_path=P))


PW = "the sudo password"
FAILURES = [
    ((126, "", "sshbite-gate: denied (command not allowed)\n"),
     "privilege.mode installed: refused by sshbite-gate on this host: sshbite-gate: denied (command not allowed)"),
    ((1, "", "sudo: a password is required\n"),
     f"privilege.mode installed: sudo asks for a password - the sudoers rule for {P} must be NOPASSWD"),
    ((1, "", "sudo: a terminal is required to read the password; either use the -S option ...\n"),
     f"privilege.mode installed: sudo asks for a password - the sudoers rule for {P} must be NOPASSWD"),
    ((1, "", f"sudo: {P}: command not found\n"),
     f"privilege.mode installed: collector not installed at {P}"),
    ((1, "", ""),
     f"privilege.mode installed: sudo does not allow {P} for this account (sudo -n -l exit 1: )"),
    ((1, "", "\nsudo: unknown user sshbite\nmore\n"),
     f"privilege.mode installed: sudo does not allow {P} for this account (sudo -n -l exit 1: sudo: unknown user sshbite)"),
    ((127, "", "sh: 1: sudo: not found\n"),
     f"privilege.mode installed: sudo does not allow {P} for this account (sudo -n -l exit 127: sh: 1: sudo: not found)"),
]


def test_installed_flow_probe_ok_runs_collector_without_stdin(monkeypatch):
    host = FakeHost((0, P + "\n", ""))
    s = SudoSecret()
    s.set(PW)
    out = _run(monkeypatch, host, s)
    assert out.privilege == "root" and out.error is None and out.partial_reasons == []
    assert host.calls == [(f"sudo -n -l {P}", None), (f"sudo -n {P}", None)]
    assert out.result.stdout.startswith(b"#SSHBITE 1 ")


@pytest.mark.parametrize("probe,text", FAILURES)
def test_installed_flow_failures(monkeypatch, probe, text):
    host = FakeHost(probe)
    s = SudoSecret()
    s.set(PW)            # even with a password at hand, none is ever sent
    out = _run(monkeypatch, host, s)
    assert out.error == text
    assert out.privilege == "none" and out.partial_reasons == [] and out.needs_password is False
    assert host.calls == [(f"sudo -n -l {P}", None)]       # nothing after a failed probe: no fallback


@pytest.mark.parametrize("probe", [(0, P, "")] + [f[0] for f in FAILURES])
def test_installed_flow_never_sends_a_shell_or_password(monkeypatch, probe):
    host = FakeHost(probe)
    s = SudoSecret()
    s.set(PW)
    _run(monkeypatch, host, s)
    assert 1 <= len(host.calls) <= 2
    for command, stdin in host.calls:
        assert "/bin/sh" not in command and "-S" not in command and "/bin/true" not in command
        assert stdin is None


def test_installed_error_is_cut_to_200_and_redacted():
    s = SudoSecret()
    s.set("hunter2-secret")
    text = privilege.installed_probe_error(P, 1, "x" * 300 + " hunter2-secret\n", s)
    assert text.endswith("x" * 200 + ")") and "hunter2" not in text
    assert privilege.installed_probe_error(P, 1, "sshbite-gate: " + "y" * 300, s).endswith("y" * 186)
