"""`sshbite collector export DIR` (spec 6): the six files, their modes, checksums and the filled-in paths."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess

import yaml
from click.testing import CliRunner

from sshbite import __version__, collector
from sshbite.cli import main

P = "/usr/local/libexec/sshbite/sshbite-collect"
FILES = {"sshbite-collect": 0o755, "sshbite-resolve": 0o755, "sshbite-gate": 0o755,
         "sudoers.d-sshbite": 0o644, "authorized_keys.sshbite": 0o644, "SHA256SUMS": 0o644}


def _export(*args, config=None):
    pre = ["-c", str(config)] if config else ["-c", "/nonexistent/sshbite.yaml"]
    return CliRunner().invoke(main, [*pre, "collector", "export", *args])


def test_export_files_modes_and_checksums(tmp_path):
    out = tmp_path / "sshbite-export"
    old = os.umask(0o077)       # the modes do not depend on the umask
    try:
        r = _export(str(out))
    finally:
        os.umask(old)
    assert r.exit_code == 0, r.output
    assert stat.S_IMODE(out.stat().st_mode) == 0o755
    assert {f.name: stat.S_IMODE(f.stat().st_mode) for f in out.iterdir()} == FILES
    # stdout: one sha256 line per file (the SHA256SUMS content), then the hint
    lines = r.stdout.splitlines()
    assert lines[:-1] == (out / "SHA256SUMS").read_text().splitlines()
    assert lines[-1] == f"written to {out} - verify with: cd {out} && sha256sum -c SHA256SUMS"
    sums = (out / "SHA256SUMS").read_text()
    names = [line.split("  ", 1)[1] for line in sums.splitlines()]
    assert names == sorted(FILES.keys() - {"SHA256SUMS"})
    for line in sums.splitlines():
        h, name = line.split("  ", 1)
        assert h == hashlib.sha256((out / name).read_bytes()).hexdigest()
    c = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=out, capture_output=True, text=True)
    assert c.returncode == 0 and c.stdout.count(": OK") == 5, c.stdout + c.stderr


def test_export_contents(tmp_path):
    out = tmp_path / "e"
    assert _export(str(out)).exit_code == 0
    collect = (out / "sshbite-collect").read_text()
    assert collect == "#!/bin/sh\n" + collector.collect_script()
    assert collector.declared_sha_short(collect) == collector.declared_sha_short(collector.collect_script())
    assert collector.body_sha_short(collect) == collector.declared_sha_short(collect)      # B stays valid
    assert (out / "sshbite-resolve").read_text() == "#!/bin/sh\n" + collector.resolve_script().strip() + "\n"
    gate = (out / "sshbite-gate").read_text()
    assert gate.startswith("#!/bin/sh\n") and f"SSHBITE {__version__}" in gate
    for literal in (f'[ "$C" = "sudo -n -l {P}" ]', f'exec "$SUDO" -n -l {P} </dev/null',
                    f'[ "$C" = "sudo -n {P}" ]', f'exec "$SUDO" -n {P} </dev/null',
                    '[ "$C" = "/usr/local/libexec/sshbite/sshbite-resolve" ]',
                    "exec /usr/local/libexec/sshbite/sshbite-resolve\n", "exit 126\n"):
        assert literal in gate, literal
    assert "{" + "collector_path}" not in gate and "{gate_path}" not in gate and "{version}" not in gate
    sudoers = (out / "sudoers.d-sshbite").read_text()
    assert sudoers.splitlines()[0] == f"# /etc/sudoers.d/sshbite - SSHBITE {__version__}, privilege.mode installed"
    rules = [x for x in sudoers.splitlines() if x and not x.startswith("#") and not x.startswith("Defaults")]
    assert rules == [f'sshbite ALL=(root) NOPASSWD: {P} ""']
    ak = (out / "authorized_keys.sshbite").read_text()
    keys = [x for x in ak.splitlines() if not x.startswith("#")]
    assert keys == [
        'restrict,port-forwarding,permitopen="*:22",permitlisten="localhost:22",from="<SCANNER-IP>",'
        'command="/usr/local/libexec/sshbite/sshbite-gate" <AUDIT-PUBLIC-KEY>',
        'restrict,from="<ENTRY-HOST-IP>",command="/usr/local/libexec/sshbite/sshbite-gate" <AUDIT-PUBLIC-KEY>',
        'restrict,port-forwarding,permitopen="*:22",permitlisten="localhost:22",from="<PREVIOUS-HOP-IP>",'
        'command="/usr/local/libexec/sshbite/sshbite-gate" <AUDIT-PUBLIC-KEY>',
    ]


def test_export_collector_path_option_and_config(tmp_path):
    out = tmp_path / "o"
    assert _export(str(out), "--collector-path", "/opt/sb/collect").exit_code == 0
    assert 'NOPASSWD: /opt/sb/collect ""' in (out / "sudoers.d-sshbite").read_text()
    assert 'command="/opt/sb/sshbite-gate"' in (out / "authorized_keys.sshbite").read_text()
    gate = (out / "sshbite-gate").read_text()
    assert '[ "$C" = "sudo -n /opt/sb/collect" ]' in gate and "exec /opt/sb/sshbite-resolve" in gate
    # default: privilege.collector_path of a loadable config
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump({"entry": {"host": "j"}, "privilege": {"mode": "installed",
                                                                          "collector_path": "/srv/x/c"}}))
    out2 = tmp_path / "o2"
    assert _export(str(out2), config=cfg).exit_code == 0
    assert 'NOPASSWD: /srv/x/c ""' in (out2 / "sudoers.d-sshbite").read_text()


def test_export_refuses_non_empty_dir_and_bad_path(tmp_path):
    d = tmp_path / "full"
    d.mkdir()
    (d / "x").write_text("x")
    r = _export(str(d))
    assert r.exit_code == 2 and f"export directory is not empty: {d}" in r.stderr
    assert sorted(p.name for p in d.iterdir()) == ["x"]
    empty = tmp_path / "empty"
    empty.mkdir()
    assert _export(str(empty)).exit_code == 0          # an existing empty directory is fine
    for bad in ("relative/path", "/a/../b", "/a b", "/x;id", "/" + "a" * 200, "/a/./b"):
        r = _export(str(tmp_path / "n"), "--collector-path", bad)
        assert r.exit_code == 2, bad
        assert ("--collector-path: must be an absolute path of letters, digits, '.', '_', '-' and '/' "
                "(no '.' or '..' segments, at most 200 characters)") in r.stderr, bad
        assert not (tmp_path / "n").exists()
