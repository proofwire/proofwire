"""Deedwrit for Python: tamper-evident receipts for what AI agents do.

Wire-compatible with the ``deedwrit`` npm packages: a log written here
passes ``dw verify``, a bundle exported here passes ``dw check``, and logs
and bundles written by the JavaScript side open and verify here.
"""

__version__ = "0.5.0"

from .canonical import canonical_bytes, canonicalize
from .checkpoint import build_checkpoint, checkpoint_digest, cosign, sign_checkpoint, verify_checkpoint
from .keys import Identity, generate_identity, identity_from_pem, identity_from_public_key, key_id_for, sign, verify
from .log import ProofLog, verify_bundle
from .merkle import (
    MerkleTree,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    node_hash,
    verify_consistency,
    verify_inclusion,
)
from .record import PolicyDenied, Recorder
from .redact import redact
from .receipt import (
    GENESIS_PREV,
    build_receipt,
    entry_hash,
    open_seal,
    receipt_digest,
    seal,
    sign_receipt,
    verify_chain,
    verify_receipt,
)
from .remote import HubError, push
from .unfinished import DEFAULT_GRACE_MS, find_unfinished

__all__ = [
    "__version__",
    "DEFAULT_GRACE_MS",
    "GENESIS_PREV",
    "HubError",
    "Identity",
    "MerkleTree",
    "PolicyDenied",
    "ProofLog",
    "Recorder",
    "build_checkpoint",
    "build_receipt",
    "canonical_bytes",
    "canonicalize",
    "checkpoint_digest",
    "consistency_proof",
    "cosign",
    "entry_hash",
    "find_unfinished",
    "generate_identity",
    "identity_from_pem",
    "identity_from_public_key",
    "inclusion_proof",
    "key_id_for",
    "leaf_hash",
    "merkle_root",
    "node_hash",
    "open_seal",
    "push",
    "receipt_digest",
    "redact",
    "seal",
    "sign",
    "sign_checkpoint",
    "sign_receipt",
    "verify",
    "verify_bundle",
    "verify_chain",
    "verify_checkpoint",
    "verify_consistency",
    "verify_inclusion",
    "verify_receipt",
]
