"""`sshbite collector export`: the files an owner installs on every host for privilege.mode installed (spec 6).

sshbite-collect   0755  "#!/bin/sh\\n" + collect.sh byte for byte (B stays valid: it hashes only what follows it)
sshbite-resolve   0755  "#!/bin/sh\\n" + the resolve.sh command + "\\n"
sshbite-gate      0755  the forced command (templates/sshbite-gate)
sudoers.d-sshbite 0644  one NOPASSWD rule for the collector, no arguments, for the audit account (audit.user)
authorized_keys.sshbite 0644  the three key-line variants with command="<gate>"
SHA256SUMS        0644  sha256sum format for the five files above, sorted by name
"""

from __future__ import annotations

import hashlib
import os
from importlib import resources

from .. import __version__
from ..config import DEFAULT_AUDIT_USER, audit_user_ok, collector_path_ok, sibling_path
from . import collect_script, resolve_script

SHEBANG = "#!/bin/sh\n"
FILES = ("authorized_keys.sshbite", "sshbite-collect", "sshbite-gate", "sshbite-resolve", "sudoers.d-sshbite")
MODES = {"sshbite-collect": 0o755, "sshbite-resolve": 0o755, "sshbite-gate": 0o755,
         "sudoers.d-sshbite": 0o644, "authorized_keys.sshbite": 0o644, "SHA256SUMS": 0o644}


class ExportError(Exception):
    pass


def collect_file() -> bytes:
    """The installed collector: its SHA-256 is the scan's collector_sha256 in mode installed."""
    return (SHEBANG + collect_script()).encode("utf-8")


def resolve_file() -> bytes:
    return (SHEBANG + resolve_script().strip() + "\n").encode("utf-8")


def _template(name: str, collector_path: str, audit_user: str = DEFAULT_AUDIT_USER) -> bytes:
    text = resources.files(__package__).joinpath("templates", name).read_text(encoding="utf-8")
    # plain replace, not str.format: the shell text is full of braces
    for key, value in (("{collector_path}", collector_path),
                       ("{gate_path}", sibling_path(collector_path, "sshbite-gate")),
                       ("{resolve_path}", sibling_path(collector_path, "sshbite-resolve")),
                       ("{audit_user}", audit_user),
                       ("{version}", __version__)):
        text = text.replace(key, value)
    return text.encode("utf-8")


def render(collector_path: str, audit_user: str = DEFAULT_AUDIT_USER) -> dict[str, bytes]:
    """All six files by name (SHA256SUMS last). AUDIT_USER is the account of the sudoers rule (audit.user)."""
    if not collector_path_ok(collector_path):
        raise ValueError(collector_path)
    if not audit_user_ok(audit_user):
        raise ValueError(audit_user)
    files = {
        "sshbite-collect": collect_file(),
        "sshbite-resolve": resolve_file(),
        "sshbite-gate": _template("sshbite-gate", collector_path),
        "sudoers.d-sshbite": _template("sudoers.d-sshbite", collector_path, audit_user),
        "authorized_keys.sshbite": _template("authorized_keys.sshbite", collector_path, audit_user),
    }
    files["SHA256SUMS"] = "".join(f"{hashlib.sha256(files[n]).hexdigest()}  {n}\n" for n in FILES).encode()
    return files


def write(directory: str, collector_path: str, audit_user: str = DEFAULT_AUDIT_USER) -> dict[str, bytes]:
    """Write the files into DIRECTORY (created 0755 if missing, refused if not empty). Returns them."""
    files = render(collector_path, audit_user)
    if os.path.lexists(directory):
        if not os.path.isdir(directory) or os.listdir(directory):
            raise ExportError(f"export directory is not empty: {directory}")
    else:
        os.makedirs(directory)
        os.chmod(directory, 0o755)
    for name, data in files.items():
        path = os.path.join(directory, name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(path, MODES[name])
    return files
