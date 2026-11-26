"""Fixes of the security check (check-7): sudo by absolute path and privilege.password_scope (S3), the crawl
scope warning (S5), no password from a non-terminal stdin (S7) and the CSV formula guard (S8)."""

from __future__ import annotations

import os
import sqlite3
import subprocess

import pytest
import yaml
from click.testing import CliRunner

from sshbite import cli as cli_mod
from sshbite import privilege
from sshbite.cli import main
from sshbite.config import CRAWL_UNRESTRICTED_WARNING, parse_config_text
from sshbite.errors import ConfigError
from sshbite.export import csv_safe, to_csv

from .test_scan_offline import CMD, PASSWORD, ServerThread, _config
from .test_scan_offline import audit as audit  # noqa: F401  (pytest fixture)

# ---------------------------------------------------------------- S3: absolute sudo path


def test_every_sudo_command_uses_the_absolute_path():
    for mode in ("sudo", "sudo-login"):
        for name, cmd in privilege.commands(mode).items():
            if name == "plain":
                assert cmd == "/bin/sh -s"
                continue
            assert cmd.startswith("test -x /usr/bin/sudo && exec /usr/bin/sudo -"), cmd
            assert "; exec /bin/sudo -" in cmd
            # no bare 'sudo' that the account's PATH could resolve
            words = cmd.replace(";", " ").split()
            assert "sudo" not in words
    assert privilege.commands("sudo")["pw_run"].endswith("exec /bin/sudo -S -k -p '' /bin/sh -s")
    assert privilege.commands("sudo-login")["probe"].endswith("exec /bin/sudo -n -i /bin/true")


def _fake_sudo(path, tag):
    path.write_text(f"#!/bin/sh\necho {tag} \"$@\"\n")
    path.chmod(0o755)


def test_sudo_path_is_decided_by_test_x_not_by_path(tmp_path, monkeypatch):
    """A hostile 'sudo' early in PATH is never run; /bin/sudo only when /usr/bin/sudo is missing."""
    usr, fallback, evil = tmp_path / "usr_bin_sudo", tmp_path / "bin_sudo", tmp_path / "evil"
    evil.mkdir()
    _fake_sudo(evil / "sudo", "EVIL")
    _fake_sudo(fallback, "FALLBACK")
    monkeypatch.setattr(privilege, "SUDO_PATH", str(usr))
    monkeypatch.setattr(privilege, "SUDO_FALLBACK", str(fallback))
    env = {**os.environ, "PATH": f"{evil}:{os.environ['PATH']}"}

    def run_probe():
        cmd = privilege.commands("sudo")["probe"]
        return subprocess.run(["/bin/sh", "-c", cmd], env=env, capture_output=True, text=True).stdout.strip()

    assert run_probe() == "FALLBACK -n /bin/true"       # /usr/bin/sudo missing
    _fake_sudo(usr, "USR")
    assert run_probe() == "USR -n /bin/true"            # /usr/bin/sudo present: always that one


# ---------------------------------------------------------------- S3: privilege.password_scope


def test_password_scope_config():
    base = "entry: {host: jump}\n"
    assert parse_config_text(base).privilege.password_scope == []
    cfg = parse_config_text(base + "privilege: {password_scope: ['10.0.0.0/8', 'db-*']}\n")
    assert cfg.privilege.password_scope == ["10.0.0.0/8", "db-*"]
    with pytest.raises(ConfigError, match="password_scope"):
        parse_config_text(base + "privilege: {password_scope: ['not a cidr/99']}\n")


def _scan_with_scope(tmp_path, audit, scope):
    key, kp = audit
    with ServerThread("password", key.public_data) as srv:
        cfgp = _config(tmp_path, srv, kp)
        cfg = yaml.safe_load(open(cfgp))
        cfg["privilege"] = {"password_scope": scope}
        open(cfgp, "w").write(yaml.safe_dump(cfg))
        r = CliRunner().invoke(main, ["-c", cfgp, "scan", "--no-crawl"], env={"SSHBITE_SUDO_PASSWORD": PASSWORD})
        assert r.exit_code == 0, r.output
        seen = list(srv.seen)
    c = sqlite3.connect(tmp_path / "data" / "sshbite.db")
    return seen, c.execute("SELECT status, privilege, partial_reasons FROM host_scan").fetchone()


def test_password_not_sent_outside_scope(tmp_path, audit):
    seen, (status, priv, reasons) = _scan_with_scope(tmp_path, audit, ["10.0.0.0/8", "prod-*"])
    # the host (127.0.0.1) asked for a password but is outside the scope: nothing with -S, no stdin password
    assert CMD["probe"] in seen
    assert not [c for c in seen if "-S" in c]
    assert (status, priv) == ("partial", "unprivileged")
    assert "sudo password not sent (outside privilege.password_scope)" in reasons
    assert "sudo: a password is required" in reasons


def test_password_sent_inside_scope(tmp_path, audit):
    seen, (status, priv, _reasons) = _scan_with_scope(tmp_path, audit, ["127.0.0.0/8"])
    assert CMD["pw_probe"] in seen and CMD["pw_run"] in seen
    assert (status, priv) == ("ok", "sudo_password")


def test_empty_scope_means_every_host(tmp_path, audit):
    seen, (status, priv, _reasons) = _scan_with_scope(tmp_path, audit, [])
    assert (status, priv) == ("ok", "sudo_password")


# ---------------------------------------------------------------- S5: crawl scope warning


def _cfgfile(tmp_path, extra: dict | None = None) -> str:
    key = tmp_path / "k"
    import asyncssh

    key.write_bytes(asyncssh.generate_private_key("ssh-ed25519").export_private_key())
    key.chmod(0o600)
    pin = asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh").decode().strip()
    cfg = {"database": str(tmp_path / "s.db"), "entry": {"host": "127.0.0.1", "port": 1, "host_keys": [pin]},
           "audit": {"key_file": str(key)}, **(extra or {})}
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(cfg))
    p.chmod(0o600)
    return str(p)


def test_scope_warning_text():
    assert CRAWL_UNRESTRICTED_WARNING == (
        "crawl.include is empty: crawl targets and ports are taken from target data (known_hosts, ~/.ssh/config, "
        "from=) without restriction; set crawl.include to the networks and host names you mean to scan")


def test_config_validate_and_scan_warn_without_include(tmp_path):
    cfgp = _cfgfile(tmp_path)
    r = CliRunner().invoke(main, ["-c", cfgp, "config", "validate"])
    assert r.exit_code == 0, r.output
    assert "warning: " + CRAWL_UNRESTRICTED_WARNING in r.output
    r = CliRunner().invoke(main, ["-c", cfgp, "scan", "--dry-run"])
    assert r.exit_code == 0 and "warning: " + CRAWL_UNRESTRICTED_WARNING in r.output
    r = CliRunner().invoke(main, ["-c", cfgp, "scan"])            # entry unreachable: exit 3, warned first
    assert r.exit_code == 3 and "warning: " + CRAWL_UNRESTRICTED_WARNING in r.output


def test_no_scope_warning_with_include(tmp_path):
    cfgp = _cfgfile(tmp_path, {"crawl": {"include": ["10.0.0.0/8"]}})
    r = CliRunner().invoke(main, ["-c", cfgp, "config", "validate"])
    assert r.exit_code == 0 and "crawl.include is empty" not in r.output


# ---------------------------------------------------------------- S7: no password without a terminal


def test_ask_sudo_password_refuses_without_tty(tmp_path):
    cfgp = _cfgfile(tmp_path, {"crawl": {"include": ["10.0.0.0/8"]}})
    r = CliRunner().invoke(main, ["-c", cfgp, "scan", "--ask-sudo-password"], input="labsudo\n")
    assert r.exit_code == 2
    assert "refusing to read the sudo password" in r.output and "docker exec -it" in r.output
    assert "labsudo" not in r.output
    assert not os.path.exists(tmp_path / "s.db")    # refused before anything else happened


def test_user_add_and_passwd_refuse_without_tty(tmp_path):
    cfgp = _cfgfile(tmp_path)
    pw = "correct horse battery"
    r = CliRunner().invoke(main, ["-c", cfgp, "user", "add", "admin"], input=f"{pw}\n{pw}\n")
    assert r.exit_code == 2 and "refusing to read the password" in r.output and "docker exec -it" in r.output
    assert "--password-stdin" in r.output
    r = CliRunner().invoke(main, ["-c", cfgp, "user", "add", "admin", "--password-stdin"], input=f"{pw}\n")
    assert r.exit_code == 0 and "user admin added" in r.output and pw not in r.output
    r = CliRunner().invoke(main, ["-c", cfgp, "user", "passwd", "admin"], input=f"{pw}\n{pw}\n")
    assert r.exit_code == 2 and "docker exec -it" in r.output
    r = CliRunner().invoke(main, ["-c", cfgp, "user", "passwd", "admin", "--password-stdin"], input="short\n")
    assert r.exit_code == 2 and "at least 12" in r.output


def test_prompts_still_work_on_a_terminal(tmp_path, monkeypatch):
    monkeypatch.setattr(cli_mod, "_stdin_is_tty", lambda: True)
    cfgp = _cfgfile(tmp_path)
    pw = "correct horse battery"
    r = CliRunner().invoke(main, ["-c", cfgp, "user", "add", "admin"], input=f"{pw}\n{pw}\n")
    assert r.exit_code == 0, r.output


# ---------------------------------------------------------------- S8: CSV formula guard


@pytest.mark.parametrize("bad", ["=1+1", "+1", "-1", "@SUM(1)", "\tx", "\r=cmd|' /C calc'!A0", "\n=1+1", "\rx"])
def test_csv_guard_prefixes_formula_starts(bad):
    assert csv_safe(bad) == "'" + bad


def test_csv_guard_keeps_normal_cells_and_quotes_line_breaks():
    assert csv_safe("normal") == "normal" and csv_safe("a\rb") == "a\rb" and csv_safe(None) == ""
    out = to_csv(["label"], [{"label": "\r=HYPERLINK(\"x\")"}])
    assert out.splitlines()[0] == "label"
    assert "'\r=HYPERLINK" in out
