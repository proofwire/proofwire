"""Receipts: build, seal, sign, verify. Mirrors packages/core/src/receipt.js.

A receipt's signature covers ``SHA-256(0x02 || canonical(body without attest))``,
and its place in the log's Merkle tree is ``SHA-256(0x00 || canonical(receipt))``.
Arguments and results are *sealed*: a salted hash commits to them, and only a
redacted preview is stored in the clear.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Optional

from .canonical import canonical_bytes
from .hashing import RECEIPT_PREFIX, b64url, equal_bytes, from_b64url, from_hex, hash_object, sha256, to_hex
from .keys import Identity, sign, verify
from .merkle import leaf_hash
from .redact import redact

RECEIPT_VERSION = 1
GENESIS_PREV = "0" * 64
PHASES = ("atomic", "intent", "outcome")


def now_iso() -> str:
    """UTC, millisecond precision, ``Z``: the same shape as JavaScript's toISOString()."""
    t = datetime.now(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def seal(value: Any, preview: bool = True) -> tuple[dict, str]:
    """Commit to a value without storing it.

    Returns the sealed form that goes into the receipt, and the salt, which
    goes to the log's separate salts file. Destroying the salt later makes
    the value permanently unprovable while the receipt still verifies.
    """
    salt = os.urandom(16)
    data = canonical_bytes(value)
    sealed: dict[str, Any] = {"hash": to_hex(sha256(salt, data)), "size": len(data)}
    if preview:
        masked, findings = redact(value)
        sealed["preview"] = masked
        if findings:
            sealed["redacted"] = sorted({f.type for f in findings})
    return sealed, b64url(salt)


def open_seal(sealed: dict, salt: Optional[str], value: Any) -> bool:
    """Whether ``value`` is what the seal committed to."""
    if not sealed or not isinstance(salt, str):
        return False
    try:
        expect = sha256(from_b64url(salt), canonical_bytes(value))
        return equal_bytes(expect, from_hex(sealed["hash"]))
    except (ValueError, KeyError, TypeError):
        return False


def _require(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"build_receipt: {field} is required and must be a non-empty string")


def build_receipt(
    *,
    log: str,
    seq: int,
    prev: str,
    actor: dict,
    action: dict,
    decision: dict,
    result: Optional[dict] = None,
    phase: str = "atomic",
    ref: Optional[str] = None,
    ts: Optional[str] = None,
) -> tuple[dict, dict]:
    """An unsigned receipt body, and the salts to keep beside it.

    ``action`` is ``{kind, target, params, metrics?}``; ``result`` is
    ``{status, code?, latencyMs?, payload}``.
    """
    for path, v in (
        ("actor.principal", actor.get("principal")),
        ("actor.agent", actor.get("agent")),
        ("actor.session", actor.get("session")),
        ("action.kind", action.get("kind")),
        ("action.target", action.get("target")),
        ("decision.outcome", decision.get("outcome")),
    ):
        _require(v, path)
    if phase not in PHASES:
        raise ValueError(f"phase must be one of {', '.join(PHASES)}")

    params_sealed, params_salt = seal(action.get("params"))
    act: dict[str, Any] = {"kind": action["kind"], "target": action["target"]}
    # Metrics stay in the clear: budgets are computed from them, and a cap
    # nobody can recompute from the log is not auditable.
    if action.get("metrics"):
        act["metrics"] = action["metrics"]
    act["params"] = params_sealed

    salts: dict[str, str] = {"params": params_salt}
    res: Optional[dict] = None
    if result is not None:
        payload_sealed, payload_salt = seal(result.get("payload"))
        salts["result"] = payload_salt
        res = {"status": result["status"]}
        if result.get("code") is not None:
            res["code"] = result["code"]
        if result.get("latencyMs") is not None:
            res["latencyMs"] = result["latencyMs"]
        res["payload"] = payload_sealed

    body: dict[str, Any] = {
        "v": RECEIPT_VERSION,
        "log": log,
        "seq": seq,
        "prev": prev,
        "ts": ts or now_iso(),
        "phase": phase,
        "actor": actor,
        "action": act,
        "decision": decision,
        "result": res,
    }
    if ref:
        body["ref"] = ref
    return body, salts


def receipt_digest(body: dict) -> bytes:
    return hash_object(RECEIPT_PREFIX, {k: v for k, v in body.items() if k != "attest"})


def entry_hash(receipt: dict) -> str:
    """The receipt's leaf in the log's Merkle tree, and the next receipt's ``prev``."""
    return to_hex(leaf_hash(canonical_bytes(receipt)))


def sign_receipt(identity: Identity, body: dict) -> dict:
    return {**body, "attest": {"alg": "ed25519", "kid": identity.kid, "sig": sign(identity, receipt_digest(body))}}


def verify_receipt(receipt: Any, keyring: dict) -> list[dict]:
    """Problems with one receipt, as ``{seq, kind, message}``; empty means valid."""
    if not isinstance(receipt, dict):
        return [{"kind": "format", "message": "receipt is not an object"}]
    seq = receipt.get("seq")
    issues: list[dict] = []
    if receipt.get("v") != RECEIPT_VERSION:
        issues.append({"seq": seq, "kind": "format", "message": f"unsupported receipt version {receipt.get('v')}"})
    actor = receipt.get("actor") or {}
    action = receipt.get("action") or {}
    decision = receipt.get("decision") or {}
    for path, v in (
        ("ts", receipt.get("ts")),
        ("actor.principal", actor.get("principal")),
        ("actor.agent", actor.get("agent")),
        ("actor.session", actor.get("session")),
        ("action.kind", action.get("kind")),
        ("action.target", action.get("target")),
        ("decision.outcome", decision.get("outcome")),
    ):
        if not isinstance(v, str) or not v:
            issues.append({"seq": seq, "kind": "format", "message": f"{path} is required and must be a non-empty string"})
    if receipt.get("phase") not in PHASES:
        issues.append({"seq": seq, "kind": "format", "message": f"phase must be one of atomic, intent, outcome; got {receipt.get('phase')!r}"})
    attest = receipt.get("attest")
    if not isinstance(attest, dict) or attest.get("alg") != "ed25519" or not isinstance(attest.get("sig"), str):
        issues.append({"seq": seq, "kind": "format", "message": "missing or malformed attestation"})
        return issues
    pub = keyring.get(attest.get("kid"))
    if not pub:
        issues.append({"seq": seq, "kind": "key", "message": f"no public key for kid {attest.get('kid')}"})
        return issues
    if not verify(pub, receipt_digest(receipt), attest["sig"]):
        issues.append({"seq": seq, "kind": "signature", "message": f"signature does not verify for kid {attest.get('kid')}"})
    return issues


def verify_chain(receipts: list[dict], keyring: dict, expect_prev: str = GENESIS_PREV, expect_seq: int = 0) -> dict:
    """Signatures, sequence, hash chain and timestamp order, end to end."""
    issues: list[dict] = []
    prev, expected, last_ts = expect_prev, expect_seq, None
    for r in receipts:
        issues.extend(verify_receipt(r, keyring))
        seq = r.get("seq")
        if seq != expected:
            issues.append({"seq": seq, "kind": "sequence", "message": f"expected seq {expected}, found {seq}: entries missing or reordered"})
        if r.get("prev") != prev:
            issues.append({"seq": seq, "kind": "chain", "message": f"chain break: prev is {str(r.get('prev'))[:12]}…, expected {prev[:12]}…"})
        ts = r.get("ts")
        if last_ts and isinstance(ts, str) and ts < last_ts:
            issues.append({"seq": seq, "kind": "time", "message": f"timestamp {ts} precedes the previous entry's {last_ts}"})
        last_ts = ts
        prev = entry_hash(r)
        expected = (seq if isinstance(seq, int) else expected) + 1
    return {"ok": not issues, "issues": issues, "head": prev, "count": len(receipts)}
