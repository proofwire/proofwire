"""Domain-separated SHA-256, and the byte encodings the wire format uses.

Mirrors packages/core/src/hash.js. Every hash carries a one-byte domain tag,
so a leaf can never also be read as an interior node (the second-preimage
attack RFC 6962 closed), nor a receipt digest as a checkpoint digest.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from typing import Any

from .canonical import canonical_bytes

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
RECEIPT_PREFIX = b"\x02"
CHECKPOINT_PREFIX = b"\x03"

_HEX = re.compile(r"^[0-9a-f]*$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def hash_object(prefix: bytes, value: Any) -> bytes:
    """SHA-256 of a value's canonical form, under a domain tag."""
    return sha256(prefix, canonical_bytes(value))


def to_hex(b: bytes) -> str:
    return b.hex()


def from_hex(s: str) -> bytes:
    """Lowercase hex only, as the wire format writes it."""
    if not isinstance(s, str) or not _HEX.match(s) or len(s) % 2:
        raise ValueError(f"not lowercase hex: {str(s)[:32]!r}")
    return bytes.fromhex(s)


def b64url(b: bytes) -> str:
    """Unpadded base64url."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def from_b64url(s: str) -> bytes:
    """Decode unpadded base64url, accepting only the one canonical spelling.

    A final character with unused bits set (``QB`` where ``QA`` is canonical)
    decodes to the same bytes, so without this check two strings would name the
    same key or signature. The JavaScript verifier refuses them; so does this.
    """
    if not isinstance(s, str) or not _B64URL.match(s) or len(s) % 4 == 1:
        raise ValueError("not base64url")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if b64url(raw) != s:
        raise ValueError("not canonical base64url")
    return raw


def equal_bytes(a: bytes, b: bytes) -> bool:
    """Constant-time comparison."""
    return hmac.compare_digest(a, b)
