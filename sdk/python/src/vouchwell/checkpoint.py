"""Signed checkpoints: a log's size, root and head at a moment, signed by the
log and countersigned by witnesses. Mirrors packages/core/src/checkpoint.js."""

from __future__ import annotations

from typing import Optional

from .hashing import CHECKPOINT_PREFIX, hash_object
from .keys import Identity, sign, verify
from .receipt import now_iso

CHECKPOINT_VERSION = 1


def build_checkpoint(*, log: str, size: int, root: str, head: str, ts: Optional[str] = None) -> dict:
    return {"v": CHECKPOINT_VERSION, "log": log, "size": size, "root": root, "head": head, "ts": ts or now_iso()}


def checkpoint_digest(body: dict) -> bytes:
    return hash_object(CHECKPOINT_PREFIX, body)


def sign_checkpoint(identity: Identity, body: dict, role: str = "log") -> dict:
    return {"body": body, "sigs": [{"role": role, "kid": identity.kid, "sig": sign(identity, checkpoint_digest(body))}]}


def cosign(checkpoint: dict, witness: Identity) -> dict:
    """Add (or replace) a witness signature."""
    sig = sign(witness, checkpoint_digest(checkpoint["body"]))
    others = [s for s in checkpoint["sigs"] if s.get("kid") != witness.kid]
    return {"body": checkpoint["body"], "sigs": [*others, {"role": "witness", "kid": witness.kid, "sig": sig, "ts": now_iso()}]}


def verify_checkpoint(
    checkpoint: dict,
    keyring: dict,
    min_witnesses: int = 0,
    trusted_witnesses: Optional[dict] = None,
) -> dict:
    """Check a checkpoint's signatures.

    With ``trusted_witnesses`` (kid → public key, obtained from outside the
    evidence), witness signatures are checked against those keys only, and
    witnesses not on the list are ignored rather than counted. Without it,
    witness signatures are checked against ``keyring`` and count only as a
    claim; ``min_witnesses`` then cannot be met from the evidence itself.
    """
    issues: list[str] = []
    signers: list[str] = []
    witnesses = 0
    pinned = isinstance(trusted_witnesses, dict)
    if not isinstance(checkpoint, dict) or not isinstance(checkpoint.get("body"), dict) or not isinstance(checkpoint.get("sigs"), list):
        return {"ok": False, "issues": ["malformed checkpoint"], "signers": signers, "witnesses": 0, "pinned": pinned}
    body = checkpoint["body"]
    if body.get("v") != CHECKPOINT_VERSION:
        issues.append(f"unsupported checkpoint version {body.get('v')}")
    digest = checkpoint_digest(body)
    has_log_sig = False
    # Each witness counts once, however often its signature is repeated;
    # keyed by public key, so one key pinned under two names is one witness.
    counted: set = set()
    for s in checkpoint["sigs"]:
        if not isinstance(s, dict):
            issues.append("malformed signature entry")
            continue
        kid, role = s.get("kid"), s.get("role")
        if pinned and role == "witness":
            if kid not in trusted_witnesses:
                continue
            if trusted_witnesses[kid] in counted:
                continue
            if verify(trusted_witnesses[kid], digest, s.get("sig", "")):
                counted.add(trusted_witnesses[kid])
                signers.append(kid)
                witnesses += 1
            else:
                issues.append(f"invalid witness signature from {kid}")
            continue
        if pinned and role == "log" and kid in trusted_witnesses:
            issues.append(f"signature from pinned witness {kid} is labelled as the log's")
            continue
        if kid not in keyring:
            issues.append(f"no public key for signer {kid}")
            continue
        if not verify(keyring[kid], digest, s.get("sig", "")):
            issues.append(f"invalid {role} signature from {kid}")
            continue
        if role == "witness":
            if keyring[kid] in counted:
                continue
            counted.add(keyring[kid])
            witnesses += 1  # unpinned: a claim, not evidence
        signers.append(kid)
        if role == "log":
            has_log_sig = True
    if not has_log_sig:
        issues.append("checkpoint carries no valid log signature")
    if witnesses < min_witnesses:
        issues.append(f"only {witnesses} valid witness signature(s), policy requires {min_witnesses}")
    return {"ok": not issues, "issues": issues, "signers": signers, "witnesses": witnesses, "pinned": pinned}
