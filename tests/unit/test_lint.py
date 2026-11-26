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
