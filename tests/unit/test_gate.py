"""The exported sshbite-gate under sh: every request that is not one of the three literal commands is refused
with exit 126 and the fixed message (spec 5). The allowed requests are tested in the lab (i04)."""

from __future__ import annotations

import os
import re
import subprocess

import pytest
from click.testing import CliRunner

from sshbite.cli import main
from sshbite.privilege import commands

P = "/usr/local/libexec/sshbite/sshbite-collect"
R = "/usr/local/libexec/sshbite/sshbite-resolve"
OLD = commands("sudo")


@pytest.fixture(scope="module")
def gate(tmp_path_factory):
    out = tmp_path_factory.mktemp("g") / "export"
    assert CliRunner().invoke(main, ["-c", "/nonexistent", "collector", "export", str(out)]).exit_code == 0
    return out / "sshbite-gate"


DENY = [
    ("empty", ""),
    ("missing", None),
    ("id", "id"),
    ("old sudo probe", OLD["probe"]),
    ("old sudo run", OLD["run"]),
    ("probe; id", f"sudo -n -l {P}; id"),
    ("extra argument", f"sudo -n {P} x"),
    ("two spaces", f"sudo  -n {P}"),
    ("resolve with argument", f"{R} x"),
    ("sftp", "sftp"),
    ("internal-sftp", "internal-sftp"),
    ("line break", f"sudo -n {P}\nid"),
]


@pytest.mark.parametrize("name,cmd", DENY, ids=[d[0] for d in DENY])
def test_gate_denies(gate, tmp_path, name, cmd):
    env = {k: v for k, v in os.environ.items() if k != "SSH_ORIGINAL_COMMAND"}
    if cmd is not None:
        env["SSH_ORIGINAL_COMMAND"] = cmd
    marker = tmp_path / "ran"
    # a script on stdin that would leave a trace if anything ran it
    r = subprocess.run(["sh", str(gate)], input=f"touch {marker}\nid\n", capture_output=True, text=True,
                       env=env, timeout=10)
    assert r.returncode == 126, (name, r.returncode, r.stderr)
    assert r.stderr == "sshbite-gate: denied (command not allowed)\n", (name, r.stderr)
    assert r.stdout == "" and not marker.exists()


def test_gate_text_has_no_eval_shell_or_stdin(gate):
    text = gate.read_text()
    code = "\n".join(x for x in text.splitlines() if not x.lstrip().startswith("#"))
    for bad in ("eval", "sh -c", "bash", "read ", "sha256sum", "cat ", "$(cat", "case "):
        assert bad not in code, bad
    # exactly three allowed comparisons, each a literal string, each followed by its exec
    assert re.findall(r'^if \[ "\$C" = "([^"$`\\]+)" \]; then$', code, re.M) == [
        f"sudo -n -l {P}", f"sudo -n {P}", R]
    # each allowed request execs exactly its command; the collector with the total time limit where timeout exists
    assert [ln.strip() for ln in code.splitlines() if "exec " in ln] == [
        f'exec "$SUDO" -n -l {P} </dev/null',
        f'[ -x "$TIMEOUT" ] || exec "$SUDO" -n {P} </dev/null',
        f'exec "$TIMEOUT" -k 5 3600 "$SUDO" -n {P} </dev/null',
        f"exec {R}"]
    assert 'C=${SSH_ORIGINAL_COMMAND-}' in code and "PATH=/usr/sbin:/usr/bin:/sbin:/bin" in code
    assert "LC_ALL=C" in code and "umask 077" in code
    # check-4 finding 5: logger with a time limit, its errors ignored
    assert '"$TIMEOUT" -k 1 2 logger -p "$1" -t sshbite-gate -- "$2" </dev/null >/dev/null 2>&1 || :' in code
    assert 'logger -p "$1" -t sshbite-gate -- "$2" </dev/null >/dev/null 2>&1 || :' in code
    assert 'log authpriv.warning "denied: $SHOWN"' in code
    assert "tr -c '[:print:]' '?' | cut -c1-200" in code
    for what in ("probe", "collect", "resolve"):
        assert f'log authpriv.info "allowed: {what}"' in code


def _gate_copy_with_path(gate, tmp_path, first: str):
    """A copy of the exported gate whose fixed PATH starts with FIRST (the gate itself sets PATH; a test that
    wants a fake tool in front has to change the copy, never the gate)."""
    text = gate.read_text()
    fixed = "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"
    assert text.count(fixed) == 1
    copy = tmp_path / "sshbite-gate"
    copy.write_text(text.replace(fixed, f"PATH={first}:/usr/sbin:/usr/bin:/sbin:/bin\n"))
    return copy


@pytest.mark.skipif(not (os.path.exists("/usr/bin/timeout") or os.path.exists("/bin/timeout")),
                    reason="the gate uses /usr/bin/timeout or /bin/timeout; neither exists here")
def test_gate_does_not_wait_for_a_hanging_logger(gate, tmp_path):
    """check-4 finding 5: a logger that hangs (syslog stuck) delays a refusal by at most 2 s (+1 s KILL)."""
    import time

    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "logger").write_text(f"#!/bin/sh\necho \"$*\" > {tmp_path}/logged\nexec sleep 30\n")
    (fake / "logger").chmod(0o755)
    copy = _gate_copy_with_path(gate, tmp_path, str(fake))
    env = {k: v for k, v in os.environ.items() if k != "SSH_ORIGINAL_COMMAND"}
    env["SSH_ORIGINAL_COMMAND"] = "id"
    t0 = time.monotonic()
    r = subprocess.run(["sh", str(copy)], input="", capture_output=True, text=True, env=env, timeout=40)
    took = time.monotonic() - t0
    assert r.returncode == 126 and r.stderr == "sshbite-gate: denied (command not allowed)\n", r
    assert took < 5, took
    assert (tmp_path / "logged").read_text() == "-p authpriv.warning -t sshbite-gate -- denied: id\n"
