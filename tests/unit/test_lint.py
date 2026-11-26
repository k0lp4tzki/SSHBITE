"""Spec 3.6: both target scripts pass the allowlist lint; violations are found."""

import pytest

from sshbite import collector
from sshbite.collector.lint import commands_used, lint


def test_scripts_pass():
    assert lint(collector.collect_script(), "collect.sh") == []
    assert lint(collector.resolve_script(), "resolve.sh") == []


def test_collect_header_and_sha():
    text = collector.collect_script()
    assert text.startswith("LC_ALL=C; export LC_ALL; PATH=/usr/sbin:/usr/bin:/sbin:/bin; set -u\n")
    assert collector.declared_sha_short(text) == collector.body_sha_short(text)


def test_only_allowed_commands_are_used():
    used = commands_used(collector.collect_script())
    assert {"ssh-keygen", "sshd", "awk", "sed", "stat"} <= used
    assert not used & {"rm", "mv", "cp", "tee", "touch", "mkdir", "mktemp", "chmod", "chown", "ln", "dd",
                       "install", "truncate", "ssh", "scp", "sftp", "curl", "wget", "eval", "exec"}


def test_resolve_command_keeps_names_out_of_the_script():
    cmd = collector.resolve_command()
    assert cmd.startswith("/bin/sh -c '") and "getent hosts" in cmd


@pytest.mark.parametrize("bad", [
    "rm -f /tmp/x", "echo x > /tmp/f", "cat a >> b", "x=$(cat a > b)", "sed -i 's/a/b/' f", "sed 's/x/y/w f' g",
    "awk '{print > \"f\"}' x", "awk 'BEGIN{system(\"id\")}'", "awk '{\"date\" | getline d}'", "cat a | tee b",
    "f() { mktemp; }\nf", "case x in a) chmod 777 y;; esac", "ssh-keygen -t ed25519 -f k", "ssh-keygen -R host",
    "sshd -D", "hostname evil", "ip link set eth0 down", "sort -o out in", "printf x 1>&2", "eval \"$x\"",
    "`rm x`", "$cmd arg", "exec 3>/tmp/x", "true &", "cat <<EOF\nx\nEOF", "ssh host true", "mktemp -d",
    "touch /tmp/x", "curl http://x", "x=1 dd if=a of=b",
])
def test_violations_are_found(bad):
    assert lint(bad), bad


@pytest.mark.parametrize("ok", [
    "head -n 5 /etc/passwd 2>/dev/null | sed 's/^/|/'", "o=$(ssh-keygen -y -P '' -f \"$f\" </dev/null 2>&1)",
    "/usr/sbin/sshd -T 2>/dev/null", "[ -f \"$f\" ] || continue", "ip -o addr show 2>/dev/null",
])
def test_allowed_forms(ok):
    assert lint(f"for f in a; do {ok}; done") == [] or lint(ok) == []


# ---------------------------------------------------------------- spec 7.5: setpriv

SP = 'setpriv --reuid="$uid" --regid="$gid" --init-groups --no-new-privs --'
SP_FORM = "setpriv: only '--reuid=\"$uid\" --regid=\"$gid\" --init-groups --no-new-privs -- CMD' is allowed"


def _msgs(text: str) -> list[str]:
    return [v.message for v in lint(text)]


@pytest.mark.parametrize("ok", [
    f'{SP} ls -A -- "$1"', f"{SP} stat -c '%u %U %a %Y %s' -- \"$1\"", f'{SP} ls -lnd -- "$1"',
    f'{SP} head -n "$1" -- "$2"', f'{SP} test "$1" "$2"',
    f"{SP} ssh-keygen -y -P '' -f \"$2\" </dev/null 2>&1", f'{SP} ssh-keygen -l -f "$2" </dev/null 2>&1',
])
def test_setpriv_allowed_form(ok):
    assert lint(ok) == [], ok


@pytest.mark.parametrize("bad", [
    'setpriv --reuid="$uid" --regid="$gid" --init-groups -- head x',               # no --no-new-privs
    'setpriv --reuid="$uid" --regid="$gid" --no-new-privs -- head x',              # no --init-groups
    'setpriv --reuid=$uid --regid="$gid" --init-groups --no-new-privs -- head x',  # unquoted
    'setpriv --reuid="$u" --regid="$gid" --init-groups --no-new-privs -- head x',  # other variable
    'setpriv --reuid=0 --regid=0 --init-groups --no-new-privs -- head x',
    'setpriv --reuid="$uid" --regid="$gid" --init-groups --no-new-privs --inh-caps=+all -- head x',
    'setpriv --reuid="$uid" --regid="$gid" --clear-groups --no-new-privs -- head x',
    'setpriv --reuid="$uid" --regid="$gid" --init-groups --no-new-privs head x',   # no --
    f"{SP}",                                                                       # nothing wrapped
    "setpriv head x",
])
def test_setpriv_other_flags_fail(bad):
    assert _msgs(bad) == [SP_FORM], bad


@pytest.mark.parametrize("cmd,name", [
    ("sh -c id", "sh"), ("cat /etc/shadow", "cat"), ("/bin/sh -s", "sh"), ("bash", "bash"),
    ("awk 1 f", "awk"), ("setpriv --reuid=0 id", "setpriv"), ("runuser -u root id", "runuser"),
])
def test_setpriv_wrapped_command_fails(cmd, name):
    assert _msgs(f"{SP} {cmd}") == [f"setpriv: command '{name}' may not be wrapped"]


@pytest.mark.parametrize("data", ['"$@"', '"$1"', "$cmd", '"$(printf ls)"'])
def test_setpriv_wrapped_variable_fails(data):
    assert _msgs(f"{SP} {data} x") == [f"command name built from data: {data}"]


def test_setpriv_wrapped_arguments_are_checked():
    assert _msgs(f"{SP} ssh-keygen -t ed25519 -f k") == [
        "ssh-keygen: only '-y -P \"\" -f FILE' and '-l -f FILE' are allowed, got ['-t', 'ed25519', '-f', 'k']"]
    assert _msgs(f"{SP} /bin/ls x") == ["unexpected command path /bin/ls"]


def test_setpriv_runuser_is_forbidden():
    assert _msgs("runuser -u alice -- cat /home/alice/.ssh/id_rsa") == ["forbidden command 'runuser'"]
    assert _msgs("x=$(runuser -u alice -- ls)") == ["forbidden command 'runuser'"]


def test_setpriv_collect_sh_lints_clean_and_uses_it():
    text = collector.collect_script()
    assert lint(text, "collect.sh") == []
    used = commands_used(text)
    assert "setpriv" in used and "runuser" not in used
    # every setpriv line of the collector is the one allowed form
    lines = [ln.strip() for ln in text.splitlines() if "setpriv" in ln and not ln.strip().startswith("#")]
    sp = [ln for ln in lines if ln.startswith("setpriv ")]
    assert len(sp) == 7 and all(ln.startswith(SP + " ") for ln in sp), sp
