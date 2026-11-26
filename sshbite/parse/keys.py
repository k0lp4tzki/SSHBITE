"""SSH public key blobs: algorithm, bits, fingerprint, certificates, strength class."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import struct
from dataclasses import dataclass

CERT_SUFFIX = "-cert-v01@openssh.com"

KNOWN_ALGS = {
    "ssh-rsa", "ssh-dss", "ssh-ed25519", "ssh-ed448",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
}
_CURVE_BITS = {"nistp256": 256, "nistp384": 384, "nistp521": 521}
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


class BlobError(ValueError):
    pass


@dataclass(frozen=True)
class KeyInfo:
    alg: str          # plain algorithm (certificates: the certified key's algorithm)
    bits: int | None
    fp: str           # SHA256:... of the plain key (for certificates: of the certified key)
    is_cert: bool = False
    blob_alg: str = ""  # the algorithm as written in the blob (may be a -cert- alg)


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def string(self) -> bytes:
        if self.pos + 4 > len(self.data):
            raise BlobError("truncated")
        (n,) = struct.unpack(">I", self.data[self.pos:self.pos + 4])
        self.pos += 4
        if n > len(self.data) - self.pos:
            raise BlobError("truncated")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def raw_string(self) -> bytes:
        """The string including its length prefix."""
        start = self.pos
        self.string()
        return self.data[start:self.pos]


def _mpint_bits(b: bytes) -> int:
    return int.from_bytes(b, "big").bit_length()


def fingerprint(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _wire(s: bytes) -> bytes:
    return struct.pack(">I", len(s)) + s


def parse_blob(blob: bytes) -> KeyInfo:
    r = _Reader(blob)
    alg = r.string().decode("ascii", errors="replace")
    is_cert = alg.endswith(CERT_SUFFIX)
    plain = alg[: -len(CERT_SUFFIX)] if is_cert else alg
    if is_cert:
        plain = plain if plain in KNOWN_ALGS else plain
        r.string()  # nonce
    fields_start = r.pos
    bits: int | None
    if plain == "ssh-rsa":
        _e = r.string()
        n = r.string()
        bits = _mpint_bits(n)
    elif plain == "ssh-dss":
        p = r.string()
        r.string(); r.string(); r.string()
        bits = _mpint_bits(p)
    elif plain.startswith("ecdsa-sha2-"):
        curve = r.string().decode("ascii", errors="replace")
        r.string()
        bits = _CURVE_BITS.get(curve)
    elif plain == "sk-ecdsa-sha2-nistp256@openssh.com":
        r.string(); r.string(); r.string()
        bits = 256
    elif plain == "ssh-ed25519":
        pk = r.string()
        if len(pk) != 32:
            raise BlobError("bad ed25519 key length")
        bits = 256
    elif plain == "sk-ssh-ed25519@openssh.com":
        r.string(); r.string()
        bits = 256
    elif plain == "ssh-ed448":
        r.string()
        bits = 456
    else:
        if is_cert:
            raise BlobError(f"unsupported certificate type {alg}")
        # unknown algorithm: still fingerprintable
        return KeyInfo(alg=alg, bits=None, fp=fingerprint(blob), is_cert=False, blob_alg=alg)
    if is_cert:
        plain_blob = _wire(plain.encode()) + blob[fields_start:r.pos]
        return KeyInfo(alg=plain, bits=bits, fp=fingerprint(plain_blob), is_cert=True, blob_alg=alg)
    if r.pos != len(blob):
        raise BlobError("trailing data")
    return KeyInfo(alg=alg, bits=bits, fp=fingerprint(blob), is_cert=False, blob_alg=alg)


def decode_b64(text: str) -> bytes | None:
    if not text or len(text) > 16384 or not _B64_RE.match(text):
        return None
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def looks_like_alg(token: str) -> bool:
    return token in KNOWN_ALGS or (token.endswith(CERT_SUFFIX) and token[: -len(CERT_SUFFIX)] in KNOWN_ALGS) \
        or bool(re.match(r"^(ssh|ecdsa|sk)-[A-Za-z0-9@._-]+$", token))


@dataclass(frozen=True)
class PublicKey:
    info: KeyInfo
    b64: str
    comment: str

    @property
    def fp(self) -> str:
        return self.info.fp

    @property
    def alg(self) -> str:
        return self.info.alg

    @property
    def bits(self) -> int | None:
        return self.info.bits


def parse_key_fields(alg_tok: str, b64: str, comment: str = "") -> PublicKey | None:
    blob = decode_b64(b64)
    if blob is None:
        return None
    try:
        info = parse_blob(blob)
    except BlobError:
        return None
    if info.blob_alg != alg_tok:
        return None
    return PublicKey(info=info, b64=b64, comment=comment)


def parse_public_key_line(line: str) -> PublicKey | None:
    """'alg base64 [comment]' -> PublicKey, or None."""
    parts = line.strip().split(None, 2)
    if len(parts) < 2:
        return None
    return parse_key_fields(parts[0], parts[1], parts[2].strip() if len(parts) > 2 else "")


# ---- strength classes -------------------------------------------------------------

_RULE_RE = re.compile(r"^([A-Za-z0-9@._-]+)(?:(>=|<=|>|<|==)(\d+))?$")


def _rule_matches(rule: str, alg: str, bits: int | None) -> bool:
    m = _RULE_RE.match(rule)
    if not m:
        return False
    ralg, op, val = m.groups()
    if ralg != alg:
        return False
    if not op:
        return True
    if bits is None:
        return False
    v = int(val)
    return {">=": bits >= v, "<=": bits <= v, ">": bits > v, "<": bits < v, "==": bits == v}[op]


STRENGTH_ORDER = ("good", "ok", "weak", "critical")


def classify_strength(alg: str, bits: int | None, rules) -> str:
    """rules: object with good/ok/weak/critical lists (config StrengthCfg) or a dict. First match wins."""
    for cls in STRENGTH_ORDER:
        lst = rules.get(cls, []) if isinstance(rules, dict) else getattr(rules, cls)
        for rule in lst:
            if _rule_matches(rule, alg, bits):
                return cls
    return "unknown"
