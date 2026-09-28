"""RFC 6962 Merkle trees, proofs and their verification.

A line-for-line port of packages/core/src/merkle.js, and checked against the
same Certificate Transparency reference tree in the tests.
"""

from __future__ import annotations

from typing import Sequence

from .hashing import LEAF_PREFIX, NODE_PREFIX, equal_bytes, sha256

EMPTY_ROOT = sha256(b"")


def leaf_hash(data: bytes) -> bytes:
    return sha256(LEAF_PREFIX, data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(NODE_PREFIX, left, right)


def _split_point(n: int) -> int:
    """The largest power of two strictly less than n."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    if not leaves:
        return EMPTY_ROOT
    if len(leaves) == 1:
        return leaves[0]
    k = _split_point(len(leaves))
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_proof(leaves: Sequence[bytes], index: int) -> list[bytes]:
    if not isinstance(index, int) or index < 0 or index >= len(leaves):
        raise IndexError(f"leaf index {index} out of range for {len(leaves)} leaves")
    if len(leaves) == 1:
        return []
    k = _split_point(len(leaves))
    if index < k:
        return inclusion_proof(leaves[:k], index) + [merkle_root(leaves[k:])]
    return inclusion_proof(leaves[k:], index - k) + [merkle_root(leaves[:k])]


def consistency_proof(leaves: Sequence[bytes], from_size: int) -> list[bytes]:
    n = len(leaves)
    if not isinstance(from_size, int) or from_size < 0 or from_size > n:
        raise IndexError(f"from_size {from_size} out of range for {n} leaves")
    if from_size in (0, n):
        return []
    return _sub_proof(leaves, from_size, True)


def _sub_proof(leaves: Sequence[bytes], m: int, is_root_of_old: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if is_root_of_old else [merkle_root(leaves)]
    k = _split_point(n)
    if m <= k:
        return _sub_proof(leaves[:k], m, is_root_of_old) + [merkle_root(leaves[k:])]
    return _sub_proof(leaves[k:], m - k, False) + [merkle_root(leaves[:k])]


def verify_inclusion(leaf: bytes, index: int, tree_size: int, proof: Sequence[bytes], root: bytes) -> bool:
    if not isinstance(index, int) or not isinstance(tree_size, int):
        return False
    if index < 0 or tree_size <= 0 or index >= tree_size:
        return False
    fn, sn, acc = index, tree_size - 1, leaf
    for sibling in proof:
        if sn == 0 or len(sibling) != 32:
            return False
        if fn & 1 or fn == sn:
            acc = node_hash(sibling, acc)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            acc = node_hash(acc, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and equal_bytes(acc, root)


def verify_consistency(
    first_size: int, second_size: int, first_root: bytes, second_root: bytes, proof: Sequence[bytes]
) -> bool:
    if not isinstance(first_size, int) or not isinstance(second_size, int):
        return False
    if first_size < 0 or second_size < first_size:
        return False
    if first_size == second_size:
        return len(proof) == 0 and equal_bytes(first_root, second_root)
    if first_size == 0:
        return len(proof) == 0
    fn, sn = first_size - 1, second_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if not proof:
        return False
    i = 0
    if fn:
        fr = sr = proof[0]
        i = 1
    else:
        fr = sr = first_root
    for p in proof[i:]:
        if sn == 0 or len(p) != 32:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(p, fr)
            sr = node_hash(p, sr)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and equal_bytes(fr, first_root) and equal_bytes(sr, second_root)


class MerkleTree:
    """Append-only tree with an O(log n) incremental root."""

    def __init__(self, leaves: Sequence[bytes] = ()) -> None:
        self.leaves: list[bytes] = []
        self._stack: list[tuple[int, bytes]] = []
        self._levels: list[list[bytes]] | None = None
        for leaf in leaves:
            self.append(leaf)

    def _build_levels(self) -> list[list[bytes]]:
        """Every level of the full tree, bottom up; an odd node rises unpaired.

        Makes a full-size inclusion proof O(log n) rather than O(n), which is
        the difference between exporting a large log in seconds or in hours.
        """
        if self._levels is None:
            levels = [list(self.leaves)]
            while len(levels[-1]) > 1:
                below = levels[-1]
                levels.append(
                    [node_hash(below[i], below[i + 1]) if i + 1 < len(below) else below[i] for i in range(0, len(below), 2)]
                )
            self._levels = levels
        return self._levels

    @property
    def size(self) -> int:
        return len(self.leaves)

    def append(self, h: bytes) -> int:
        self.leaves.append(h)
        self._levels = None
        self._stack.append((1, h))
        while len(self._stack) > 1 and self._stack[-1][0] == self._stack[-2][0]:
            (ls, lh), (rs, rh) = self._stack[-2], self._stack[-1]
            self._stack[-2:] = [(ls + rs, node_hash(lh, rh))]
        return len(self.leaves) - 1

    @property
    def root(self) -> bytes:
        if not self._stack:
            return EMPTY_ROOT
        acc = self._stack[-1][1]
        for _, h in reversed(self._stack[:-1]):
            acc = node_hash(h, acc)
        return acc

    def root_at(self, size: int) -> bytes:
        if size < 0 or size > len(self.leaves):
            raise IndexError(f"size {size} out of range for tree of {len(self.leaves)}")
        return merkle_root(self.leaves[:size])

    def inclusion_proof(self, index: int, tree_size: int | None = None) -> list[bytes]:
        if tree_size is not None and tree_size != len(self.leaves):
            return inclusion_proof(self.leaves[:tree_size], index)
        if not isinstance(index, int) or index < 0 or index >= len(self.leaves):
            raise IndexError(f"leaf index {index} out of range for {len(self.leaves)} leaves")
        levels = self._build_levels()
        proof, i = [], index
        for level in levels[:-1]:
            sibling = i ^ 1
            if sibling < len(level):
                proof.append(level[sibling])
            i >>= 1
        return proof

    def consistency_proof(self, from_size: int, to_size: int | None = None) -> list[bytes]:
        n = len(self.leaves) if to_size is None else to_size
        return consistency_proof(self.leaves[:n], from_size)
