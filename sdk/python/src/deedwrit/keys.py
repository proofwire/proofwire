"""Ed25519 identities, matching packages/core/src/keys.js.

A key id is ``pw1`` plus the first 16 bytes of SHA-256 over the raw 32-byte
public key, in hex. Public keys and signatures travel as canonical, unpadded
base64url. Private keys are stored as PKCS#8 PEM, the same file the
JavaScript side writes, so either can open a log the other created.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .hashing import b64url, from_b64url, sha256


@dataclass(frozen=True)
class Identity:
    kid: str
    public_key: str
    private_key: Optional[Ed25519PrivateKey] = None

    @property
    def can_sign(self) -> bool:
        return self.private_key is not None


def key_id_for(raw_public: bytes) -> str:
    return "pw1" + sha256(raw_public)[:16].hex()


def _raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def generate_identity() -> tuple[Identity, str]:
    """A new identity, and its private key as PKCS#8 PEM for storing."""
    key = Ed25519PrivateKey.generate()
    raw = _raw(key.public_key())
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode("ascii")
    return Identity(key_id_for(raw), b64url(raw), key), pem


def identity_from_pem(pem: str) -> Identity:
    key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"expected an Ed25519 private key, got {type(key).__name__}")
    raw = _raw(key.public_key())
    return Identity(key_id_for(raw), b64url(raw), key)


def identity_from_public_key(public_key: str) -> Identity:
    raw = from_b64url(public_key)
    if len(raw) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
    return Identity(key_id_for(raw), b64url(raw))


def sign(identity: Identity, message: bytes) -> str:
    if identity.private_key is None:
        raise ValueError(f"identity {identity.kid} is verify-only; cannot sign")
    return b64url(identity.private_key.sign(message))


def verify(public_key: str, message: bytes, signature: str) -> bool:
    """Never raises: a malformed key or signature is simply not valid."""
    try:
        sig = from_b64url(signature)
        raw = from_b64url(public_key)
    except (ValueError, TypeError):
        return False
    if len(sig) != 64 or len(raw) != 32:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, message)
        return True
    except (InvalidSignature, ValueError):
        return False
