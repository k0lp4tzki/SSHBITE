"""The fixed scripts that run on targets (spec 3.5, 3.6)."""

from __future__ import annotations

import hashlib
import re
from importlib import resources

_B_RE = re.compile(r"^B=([0-9a-f]{12})$", re.M)


def script_text(name: str) -> str:
    return resources.files(__package__).joinpath(name).read_text(encoding="utf-8")


def collect_script() -> str:
    return script_text("collect.sh")


def resolve_script() -> str:
    return script_text("resolve.sh")


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def body_sha_short(text: str) -> str:
    """Short SHA-256 of everything after the 'B=' line; the script prints it in its header."""
    m = _B_RE.search(text)
    if not m:
        raise ValueError("collect.sh has no B= line")
    return hashlib.sha256(text[m.end() + 1:].encode("utf-8")).hexdigest()[:12]


def declared_sha_short(text: str) -> str:
    m = _B_RE.search(text)
    return m.group(1) if m else ""


def with_updated_sha(text: str) -> str:
    """Developer helper: return the script with B= set to its body hash."""
    return _B_RE.sub("B=" + body_sha_short(text), text, count=1)

