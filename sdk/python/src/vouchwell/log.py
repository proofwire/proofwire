"""The local log, and bundle verification. Mirrors packages/core/src/log.js.

The directory layout is the one the JavaScript CLI reads and writes, so a log
written here passes ``vw verify``, and a bundle exported here passes
``vw check``, and the other way round:

    config.json        {log, created, kid}
    key.pem            the log's Ed25519 key, PKCS#8 (keep private)
    keyring.json       kid → public key, for this log and trusted witnesses
    entries.jsonl      one canonical receipt per line
    checkpoints.jsonl  one signed checkpoint per line
    salts.jsonl        one {seq, params, result?} per line (keep private)

Files are written as bytes with ``\\n`` line endings on every platform, so a
log written on Windows is byte-identical to one written anywhere else.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Callable, Optional, Union

from .canonical import canonical_bytes, canonicalize
from .checkpoint import build_checkpoint, sign_checkpoint, verify_checkpoint
from .hashing import from_hex, to_hex
from .keys import Identity, generate_identity, identity_from_pem, identity_from_public_key
from .merkle import MerkleTree, leaf_hash, verify_consistency, verify_inclusion
from .receipt import GENESIS_PREV, build_receipt, entry_hash, now_iso, open_seal, sign_receipt, verify_chain, verify_receipt

FILES = {
    "config": "config.json",
    "key": "key.pem",
    "keyring": "keyring.json",
    "entries": "entries.jsonl",
    "checkpoints": "checkpoints.jsonl",
    "salts": "salts.jsonl",
}

PathLike = Union[str, "os.PathLike[str]"]


def _read_lines(p: Path) -> list[str]:
    if not p.exists():
        return []
    return [line for line in p.read_bytes().decode("utf-8").split("\n") if line.strip()]


def _write(p: Path, text: str, private: bool = False) -> None:
    data = text.encode("utf-8")
    if private:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    else:
        p.write_bytes(data)


def _append(p: Path, text: str) -> None:
    with open(p, "ab") as f:
        f.write(text.encode("utf-8"))
        f.flush()
        os.fsync(f.fileno())


def _pretty(obj: Any) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


class ProofLog:
    """An append-only, signed, Merkle-committed log of receipts in a directory."""

    def __init__(self, directory: Path, config: dict, identity: Identity, keyring: dict, entries: list[dict], tree: MerkleTree, head: str):
        self.dir = directory
        self.config = config
        self.identity = identity
        self.keyring = keyring
        self.entries = entries
        self.tree = tree
        self.head = head
        self._lock = threading.Lock()

    # ── lifecycle ──────────────────────────────────────────────────────────

    @classmethod
    def create(cls, directory: PathLike, log_id: Optional[str] = None) -> "ProofLog":
        d = Path(directory)
        if (d / FILES["config"]).exists():
            raise FileExistsError(f"a Vouchwell log already exists at {d}")
        d.mkdir(parents=True, exist_ok=True)
        identity, pem = generate_identity()
        config = {"log": log_id or "lg_" + os.urandom(8).hex(), "created": now_iso(), "kid": identity.kid}
        _write(d / FILES["config"], _pretty(config))
        _write(d / FILES["key"], pem, private=True)
        _write(d / FILES["keyring"], _pretty({identity.kid: identity.public_key}))
        _write(d / FILES["entries"], "")
        _write(d / FILES["checkpoints"], "")
        _write(d / FILES["salts"], "", private=True)
        return cls.open(d)

    @classmethod
    def open(cls, directory: PathLike, read_only: bool = False) -> "ProofLog":
        d = Path(directory)
        if not (d / FILES["config"]).exists():
            raise FileNotFoundError(f"no Vouchwell log at {d} (create one with ProofLog.create or `vw init`)")
        config = json.loads((d / FILES["config"]).read_bytes().decode("utf-8"))
        keyring = json.loads((d / FILES["keyring"]).read_bytes().decode("utf-8"))
        if read_only:
            identity = identity_from_public_key(keyring[config["kid"]])
        else:
            identity = identity_from_pem((d / FILES["key"]).read_bytes().decode("ascii"))
            if identity.kid != config["kid"]:
                raise ValueError(f"key.pem does not match config: key is {identity.kid}, config says {config['kid']}")
        entries: list[dict] = []
        tree = MerkleTree()
        head = GENESIS_PREV
        for i, line in enumerate(_read_lines(d / FILES["entries"])):
            try:
                receipt = json.loads(line)
            except json.JSONDecodeError as err:
                raise ValueError(f"entries.jsonl line {i + 1} is not valid JSON: {err}") from err
            entries.append(receipt)
            tree.append(leaf_hash(canonical_bytes(receipt)))
            head = entry_hash(receipt)
        return cls(d, config, identity, keyring, entries, tree, head)

    @classmethod
    def open_or_create(cls, directory: PathLike) -> "ProofLog":
        d = Path(directory)
        return cls.open(d) if (d / FILES["config"]).exists() else cls.create(d)

    # ── state ──────────────────────────────────────────────────────────────

    @property
    def size(self) -> int:
        return len(self.entries)

    @property
    def root(self) -> str:
        return to_hex(self.tree.root)

    @property
    def log_id(self) -> str:
        return self.config["log"]

    # ── writing ────────────────────────────────────────────────────────────

    def append(self, **kwargs: Any) -> dict:
        """Sign and durably record a receipt; see ``build_receipt`` for the fields.

        Returns once the receipt is on disk (fsync'd). Thread-safe.
        """
        if not self.identity.can_sign:
            raise PermissionError("log is open read-only; cannot append")
        with self._lock:
            body, salts = build_receipt(log=self.config["log"], seq=len(self.entries), prev=self.head, **kwargs)
            receipt = sign_receipt(self.identity, body)
            _append(self.dir / FILES["entries"], canonicalize(receipt) + "\n")
            _append(self.dir / FILES["salts"], canonicalize({"seq": receipt["seq"], **salts}) + "\n")
            self.entries.append(receipt)
            self.tree.append(leaf_hash(canonical_bytes(receipt)))
            self.head = entry_hash(receipt)
            return receipt

    def checkpoint(self) -> dict:
        """Sign the log's current state: what witnesses countersign."""
        with self._lock:
            body = build_checkpoint(log=self.config["log"], size=self.size, root=self.root, head=self.head)
            cp = sign_checkpoint(self.identity, body, "log")
            _append(self.dir / FILES["checkpoints"], canonicalize(cp) + "\n")
            return cp

    def checkpoints(self) -> list[dict]:
        return [json.loads(line) for line in _read_lines(self.dir / FILES["checkpoints"])]

    def add_signature(self, size: int, signature: dict) -> dict:
        """Attach a witness countersignature to the checkpoint at ``size``."""
        with self._lock:
            all_cps = self.checkpoints()
            target = next((cp for cp in all_cps if cp["body"]["size"] == size), None)
            if target is None:
                raise ValueError(f"no checkpoint at size {size} in this log")
            target["sigs"] = [s for s in target["sigs"] if s.get("kid") != signature.get("kid")] + [signature]
            _write(self.dir / FILES["checkpoints"], "".join(canonicalize(cp) + "\n" for cp in all_cps))
            return target

    def trust_key(self, kid: str, public_key: str) -> None:
        """Keep another key (a witness's) with the log, so its signatures verify here."""
        self.keyring = {**self.keyring, kid: public_key}
        _write(self.dir / FILES["keyring"], _pretty(self.keyring))

    # ── payloads ───────────────────────────────────────────────────────────

    def salts_for(self, seq: int) -> dict:
        for line in _read_lines(self.dir / FILES["salts"]):
            row = json.loads(line)
            if row.get("seq") == seq:
                return {k: v for k, v in row.items() if k != "seq"}
        return {}

    def reveal(self, seq: int, which: str, value: Any) -> bool:
        """Prove ``value`` is what receipt ``seq`` committed to (``which`` is 'params' or 'result')."""
        if not 0 <= seq < self.size:
            return False
        r = self.entries[seq]
        sealed = r["action"]["params"] if which == "params" else (r.get("result") or {}).get("payload")
        return bool(sealed) and open_seal(sealed, self.salts_for(seq).get(which), value)

    def shred(self, predicate: Callable[[dict], bool]) -> int:
        """Destroy the salts of matching receipts: their payloads become permanently
        unprovable, and every receipt still verifies."""
        doomed = {r["seq"] for r in self.entries if predicate(r)}
        if not doomed:
            return 0
        with self._lock:
            kept = [line for line in _read_lines(self.dir / FILES["salts"]) if json.loads(line).get("seq") not in doomed]
            _write(self.dir / FILES["salts"], "".join(line + "\n" for line in kept), private=True)
        return len(doomed)

    # ── proving ────────────────────────────────────────────────────────────

    def proof_for(self, seq: int) -> dict:
        if not isinstance(seq, int) or not 0 <= seq < self.size:
            raise IndexError(f"no entry {seq} in a log of {self.size}")
        return {
            "log": self.config["log"],
            "seq": seq,
            "treeSize": self.size,
            "root": self.root,
            "leaf": to_hex(self.tree.leaves[seq]),
            "proof": [to_hex(p) for p in self.tree.inclusion_proof(seq)],
        }

    def audit(self) -> dict:
        """Re-verify everything: signatures, chain, tree, and every checkpoint."""
        chain = verify_chain(self.entries, self.keyring)
        issues = list(chain["issues"])
        root = self.tree.root
        for i in range(self.size):
            if not verify_inclusion(self.tree.leaves[i], i, self.size, self.tree.inclusion_proof(i), root):
                issues.append({"seq": i, "kind": "chain", "message": "entry is not provably in the tree"})
        for cp in self.checkpoints():
            res = verify_checkpoint(cp, self.keyring)
            size = cp["body"].get("size")
            if not res["ok"]:
                issues.extend({"kind": "signature", "message": f"checkpoint at size {size}: {m}"} for m in res["issues"])
                continue
            if size > self.size:
                issues.append({"kind": "chain", "message": f"a signed checkpoint covers {size} entries but the log holds only {self.size}: entries have been removed"})
                continue
            if not verify_consistency(size, self.size, from_hex(cp["body"]["root"]), root, self.tree.consistency_proof(size)):
                issues.append({"kind": "chain", "message": f"the log no longer extends the checkpoint signed at size {size} ({cp['body'].get('ts')}): history was rewritten"})
        return {"ok": not issues, "size": self.size, "root": self.root, "issues": issues}

    def bundle(self, filter: Optional[Callable[[dict], bool]] = None) -> dict:
        """Evidence for a third party: receipts with inclusion proofs, the keys,
        and the checkpoints. No payloads and no salts, so it is safe to send."""
        selected = [r for r in self.entries if filter(r)] if filter else list(self.entries)
        checkpoints = self.checkpoints()
        return {
            "v": 1,
            "kind": "vouchwell.bundle",
            "log": self.config["log"],
            "exported": now_iso(),
            "treeSize": self.size,
            "root": self.root,
            "head": self.head,
            "keyring": self.keyring,
            "checkpoints": checkpoints,
            "consistency": consistency_for(self.tree, checkpoints),
            "partial": len(selected) != self.size,
            "entries": [{"receipt": r, "proof": [to_hex(p) for p in self.tree.inclusion_proof(r["seq"])]} for r in selected],
        }


def consistency_for(tree: MerkleTree, checkpoints: list[dict]) -> dict:
    """A consistency proof from the latest witnessed checkpoint to the tree's
    current root, keyed by size, so a filtered bundle can tie its witnesses to
    its own root. Mirrors ``consistencyFor`` in @vouchwell/core."""
    sizes = [
        cp["body"]["size"]
        for cp in checkpoints
        if any(isinstance(s, dict) and s.get("role") == "witness" for s in cp.get("sigs") or [])
        and isinstance(cp["body"].get("size"), int)
        and 0 < cp["body"]["size"] < tree.size
    ]
    if not sizes:
        return {}
    size = max(sizes)
    return {str(size): [to_hex(p) for p in tree.consistency_proof(size)]}


def verify_bundle(
    bundle: Any,
    expect_root: Optional[str] = None,
    min_witnesses: int = 0,
    trusted_witnesses: Optional[dict] = None,
) -> dict:
    """Verify an evidence bundle with nothing but itself (and, optionally,
    witness keys you obtained elsewhere). The same checks as ``vw check``."""
    try:
        return _verify_bundle(bundle, expect_root, min_witnesses, trusted_witnesses)
    except Exception as err:  # a malformed bundle must fail verification, never crash it
        return {"ok": False, "issues": [f"could not verify this bundle: {err}"], "checked": 0}


def _verify_bundle(bundle: Any, expect_root: Optional[str], min_witnesses: int, trusted: Optional[dict]) -> dict:
    issues: list[str] = []
    # "proofwire.bundle" is what the project wrote before it was renamed
    # Vouchwell (0.5.0 and earlier); the receipts inside verify as they always did.
    if not isinstance(bundle, dict) or bundle.get("kind") not in ("vouchwell.bundle", "proofwire.bundle") or bundle.get("v") != 1:
        return {"ok": False, "issues": ["not a Vouchwell v1 bundle"], "checked": 0}
    keyring = bundle.get("keyring") or {}
    try:
        root = from_hex(bundle.get("root"))
    except (ValueError, TypeError):
        return {"ok": False, "issues": ["bundle root is not valid hex"], "checked": 0}
    if expect_root and expect_root != bundle["root"]:
        issues.append(f"bundle root {bundle['root'][:16]}… does not match the expected {expect_root[:16]}…: you were shown a different history")
    if not isinstance(min_witnesses, int) or isinstance(min_witnesses, bool) or min_witnesses < 0:
        return {"ok": False, "issues": [f"min_witnesses must be a non-negative integer, got {min_witnesses!r}"], "checked": 0}
    pinned = trusted if isinstance(trusted, dict) else None
    if min_witnesses > 0 and pinned is None:
        issues.append(f"{min_witnesses} witness signature(s) required, but no trusted witness keys were supplied: a bundle's own keyring cannot vouch for its witnesses")
    checkpoints = bundle.get("checkpoints") or []
    checkpoint_results: list[tuple[Any, bool]] = []
    for cp in checkpoints:
        res = verify_checkpoint(cp, keyring, min_witnesses if pinned is not None else 0, pinned)
        checkpoint_results.append((cp, res["ok"]))
        if not res["ok"]:
            issues.append(f"checkpoint at size {(cp.get('body') or {}).get('size') if isinstance(cp, dict) else None}: {'; '.join(res['issues'])}")

    tree_size = bundle.get("treeSize")
    checked = 0
    receipts: list[dict] = []
    leaves: list[bytes] = []
    for entry in bundle.get("entries") or []:
        try:
            receipt = entry.get("receipt")
            if not isinstance(receipt, dict) or not isinstance(receipt.get("seq"), int) or isinstance(receipt.get("seq"), bool):
                raise ValueError("entry carries no receipt with a sequence number")
            leaf = leaf_hash(canonical_bytes(receipt))
            receipts.append(receipt)
            leaves.append(leaf)
            proof = [from_hex(p) for p in entry.get("proof") or []]
            if not verify_inclusion(leaf, receipt["seq"], tree_size, proof, root):
                issues.append(f"entry {receipt['seq']} is not provably part of the logged tree")
        except Exception as err:
            issues.append(f"malformed entry: {err}")
        checked += 1

    if not isinstance(tree_size, int) or isinstance(tree_size, bool) or tree_size < 0:
        issues.append("bundle treeSize is not a non-negative integer")
        tree_size = -1
    tip = next((r for r in receipts if r["seq"] == tree_size - 1), None)
    if tip is not None and entry_hash(tip) != bundle.get("head"):
        issues.append(f"bundle head {str(bundle.get('head'))[:16]}… is not the hash of its final entry")

    prefix_roots: Optional[dict[int, str]] = None
    if not bundle.get("partial"):
        if len(receipts) != tree_size:
            issues.append(f"bundle is marked complete but holds {len(receipts)} of {tree_size} entries: entries were left out")
        else:
            wanted = {cp["body"]["size"] for cp in checkpoints if isinstance(cp, dict) and isinstance((cp.get("body") or {}).get("size"), int)}
            tree = MerkleTree()
            # A checkpoint of the empty log names the empty root.
            prefix_roots = {0: to_hex(tree.root)} if 0 in wanted else {}
            for k, leaf in enumerate(leaves):
                tree.append(leaf)
                if k + 1 in wanted:
                    prefix_roots[k + 1] = to_hex(tree.root)
            if to_hex(tree.root) != bundle["root"]:
                issues.append("bundle root does not match the root of its own entries")
            if tree_size == 0 and bundle.get("head") != GENESIS_PREV:
                issues.append("an empty bundle must carry the genesis head")
            for cp in checkpoints:
                size = (cp.get("body") or {}).get("size") if isinstance(cp, dict) else None
                if not isinstance(size, int):
                    continue
                if size > tree_size:
                    issues.append(f"checkpoint at size {size} covers more entries than this bundle holds")
                    continue
                if prefix_roots.get(size) != cp["body"].get("root"):
                    issues.append(f"checkpoint at size {size} names root {str(cp['body'].get('root'))[:16]}…, but this bundle's own entries hash to a different one: history was rewritten")

    # Which checkpoints vouch for *these* entries: a checkpoint's witnesses say
    # nothing about this bundle unless its root is tied to the bundle's tree.
    witnessed_size = _anchor_checkpoints(bundle, root, tree_size, prefix_roots, checkpoint_results, issues)
    witnessing = pinned is not None and min_witnesses > 0
    if witnessing and witnessed_size is None:
        issues.append(
            f"no checkpoint carrying {min_witnesses} trusted witness signature(s) covers this "
            "bundle's entries: nothing independent vouches for this history"
        )

    if not bundle.get("partial"):
        chain = verify_chain(receipts, keyring)
        issues.extend(f"entry {i.get('seq')}: {i['message']}" for i in chain["issues"])
    else:
        for r in receipts:
            issues.extend(f"entry {i.get('seq')}: {i['message']}" for i in verify_receipt(r, keyring))

    result = {"ok": not issues, "issues": issues, "checked": checked}
    if witnessing:
        # Entries at or past this are signed by the log alone.
        result["witnessedSize"] = witnessed_size or 0
    return result


def _anchor_checkpoints(
    bundle: dict, root: bytes, tree_size: int, prefix_roots: Optional[dict], results: list, issues: list[str]
) -> Optional[int]:
    """Tie each checkpoint to the bundle's tree, report any that contradict
    it, and return the largest size covered by one that passed (None if none)."""
    if tree_size < 0:
        return None
    proofs = bundle.get("consistency") if isinstance(bundle.get("consistency"), dict) else {}
    best: Optional[int] = None
    for cp, ok in results:
        body = cp.get("body") if isinstance(cp, dict) else None
        size = body.get("size") if isinstance(body, dict) else None
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            continue
        anchored = False
        try:
            if prefix_roots is not None:
                anchored = size <= tree_size and prefix_roots.get(size) == body.get("root")
            elif size > tree_size:
                issues.append(f"checkpoint at size {size} covers more entries than this bundle holds")
            elif size == tree_size:
                anchored = body.get("root") == bundle.get("root")
                if not anchored:
                    issues.append(
                        f"checkpoint at size {size} names root {str(body.get('root'))[:16]}…, but this "
                        f"bundle's root is {str(bundle.get('root'))[:16]}…: history was rewritten"
                    )
            elif size == 0:
                anchored = body.get("root") == to_hex(MerkleTree().root)
            elif str(size) in proofs:
                proof = proofs[str(size)]
                if not isinstance(proof, list):
                    raise ValueError("consistency proof is not a list")
                anchored = verify_consistency(size, tree_size, from_hex(body.get("root")), root, [from_hex(p) for p in proof])
                if not anchored:
                    issues.append(f"checkpoint at size {size} is not consistent with this bundle's root: history was rewritten")
        except Exception as err:
            issues.append(f"checkpoint at size {size}: malformed consistency evidence: {err}")
            anchored = False
        if anchored and ok and (best is None or size > best):
            best = size
    return best
