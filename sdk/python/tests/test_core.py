"""Canonical JSON, keys and the Merkle tree against external vectors."""

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouchwell import (
    MerkleTree,
    canonicalize,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    node_hash,
    verify,
    verify_consistency,
    verify_inclusion,
)
from vouchwell.hashing import b64url, from_b64url
from vouchwell.keys import Identity, key_id_for, sign

from vectors import CT_LEAVES, CT_ROOTS, ED25519

# ── RFC 8785 ────────────────────────────────────────────────────────────────


def test_keys_sort_by_utf16_code_unit():
    assert canonicalize({"b": 1, "a": 2, "A": 3, "1": 4}) == '{"1":4,"A":3,"a":2,"b":1}'
    assert canonicalize({"é": 1, "e": 2, "z": 3}) == '{"e":2,"z":3,"é":1}'
    # An astral character sorts by its surrogates (0xD83D…), below U+E000–U+FFFF.
    # Code-point order would put it last; UTF-16 order puts it first.
    assert canonicalize({"ﬁ": 1, "\U0001F600": 2}) == '{"\U0001F600":2,"ﬁ":1}'


def test_numbers_follow_ecmascript():
    # A list, not a dict: 0 == -0.0 and 2**60 == 2.0**60 as dict keys.
    cases = [
        (0, "0"), (-0.0, "0"), (1e21, "1e+21"), (1e-7, "1e-7"), (0.1, "0.1"), (1 / 3, "0.3333333333333333"),
        (9007199254740991, "9007199254740991"), (1.5, "1.5"), (-2.5e-8, "-2.5e-8"),
        (1e20, "100000000000000000000"), (123456789.123, "123456789.123"), (5e-324, "5e-324"),
        (2.0**60, "1152921504606847000"), (2**60, "1152921504606847000"),
        (1.7976931348623157e308, "1.7976931348623157e+308"), (0.000001, "0.000001"), (-1e-7, "-1e-7"),
        (100.0, "100"), (-17, "-17"), (1e21 + 1e6, "1.000000000000001e+21"),
    ]
    for value, expected in cases:
        assert canonicalize(value) == expected, repr(value)
    for bad in (float("nan"), float("inf")):
        with pytest.raises(TypeError):
            canonicalize(bad)


def test_strings_escape_exactly_as_jcs_says():
    assert canonicalize('\b\t\n\f\r"\\') == '"\\b\\t\\n\\f\\r\\"\\\\"'
    assert canonicalize("\x00") == '"\\u0000"'
    assert canonicalize("\x1f") == '"\\u001f"'
    assert canonicalize("é☃") == '"é☃"'
    assert canonicalize("") == '""'
    assert canonicalize("\ud800") == '"�"'  # a lone surrogate, as JavaScript's encoder writes it


def test_booleans_are_not_numbers_and_unknown_types_are_refused():
    assert canonicalize([True, False, None]) == "[true,false,null]"
    with pytest.raises(TypeError):
        canonicalize({1: "x"})
    with pytest.raises(TypeError):
        canonicalize(object())


# ── RFC 6962 ────────────────────────────────────────────────────────────────


def test_the_two_anchors():
    assert merkle_root([]).hex() == hashlib.sha256(b"").hexdigest() == CT_ROOTS[0]
    assert leaf_hash(b"").hex() == hashlib.sha256(b"\x00").hexdigest() == CT_ROOTS[1]


def test_every_ct_reference_root_both_ways():
    leaves = [leaf_hash(x) for x in CT_LEAVES]
    tree = MerkleTree()
    assert tree.root.hex() == CT_ROOTS[0]
    for n in range(1, 9):
        assert merkle_root(leaves[:n]).hex() == CT_ROOTS[n]
        tree.append(leaves[n - 1])
        assert tree.root.hex() == CT_ROOTS[n]
    assert node_hash(node_hash(leaves[0], leaves[1]), leaves[2]).hex() == CT_ROOTS[3]


def test_proofs_verify_against_the_reference_roots():
    leaves = [leaf_hash(x) for x in CT_LEAVES]
    for n in range(1, 9):
        root = bytes.fromhex(CT_ROOTS[n])
        for i in range(n):
            assert verify_inclusion(leaves[i], i, n, inclusion_proof(leaves[:n], i), root)
        for m in range(n + 1):
            assert verify_consistency(m, n, bytes.fromhex(CT_ROOTS[m]), root, consistency_proof(leaves[:n], m))


def test_fast_proofs_equal_reference_proofs_and_bad_ones_fail():
    leaves = [leaf_hash(bytes([i])) for i in range(70)]
    for n in (1, 2, 3, 5, 8, 13, 31, 32, 33, 64, 70):
        tree = MerkleTree(leaves[:n])
        for i in range(n):
            fast = tree.inclusion_proof(i)
            assert fast == inclusion_proof(leaves[:n], i), (n, i)
        if n > 1:
            proof = tree.inclusion_proof(0)
            assert not verify_inclusion(leaves[1], 0, n, proof, tree.root), "wrong leaf verified"
            assert not verify_inclusion(leaves[0], 1, n, proof, tree.root), "wrong index verified"
            # (The tree size itself is not authenticated by an inclusion proof:
            # it comes from a signed checkpoint, which is why checkpoints exist.)
    big = MerkleTree(leaves)
    for m in range(1, 70):
        proof = big.consistency_proof(m)
        assert verify_consistency(m, 70, big.root_at(m), big.root, proof)
        assert not verify_consistency(m, 70, node_hash(big.root_at(m), big.root_at(m)), big.root, proof)


# ── RFC 8032 ────────────────────────────────────────────────────────────────


def test_ed25519_signatures_match_rfc_8032_byte_for_byte():
    for v in ED25519:
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(v["secret"]))
        pub = b64url(bytes.fromhex(v["public"]))
        ident = Identity(key_id_for(bytes.fromhex(v["public"])), pub, key)
        sig = sign(ident, bytes.fromhex(v["message"]))
        assert from_b64url(sig).hex() == v["signature"]
        assert verify(pub, bytes.fromhex(v["message"]), sig)
        assert not verify(pub, bytes.fromhex(v["message"]) + b"x", sig)


def test_non_canonical_base64url_is_refused():
    # QA and QB decode to the same byte; only QA is canonical.
    assert from_b64url("QA") == b"@"
    with pytest.raises(ValueError):
        from_b64url("QB")
    with pytest.raises(ValueError):
        from_b64url("QA==")
    # A 64-byte signature's last base64url character carries 2 bits and 4
    # unused ones. Setting an unused bit spells the same bytes differently,
    # and that spelling must not verify.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    v = ED25519[0]
    pub = b64url(bytes.fromhex(v["public"]))
    sig = b64url(bytes.fromhex(v["signature"]))
    tweaked = sig[:-1] + alphabet[alphabet.index(sig[-1]) ^ 1]
    assert verify(pub, b"", sig)
    assert not verify(pub, b"", tweaked)
