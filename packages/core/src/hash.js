import { createHash } from 'node:crypto';
import { canonicalBytes } from './canonical.js';

/**
 * Domain-separated SHA-256 helpers.
 *
 * Every hash in Deedwrit is prefixed with a one-byte domain tag. Without it,
 * an attacker who controls a leaf's contents could craft a leaf whose bytes
 * are also a valid interior node, and splice a forged subtree into the tree —
 * the classic second-preimage attack on Merkle trees that RFC 6962 fixed.
 */

/** Tag for a Merkle leaf (RFC 6962 §2.1). */
export const LEAF_PREFIX = Buffer.from([0x00]);
/** Tag for a Merkle interior node (RFC 6962 §2.1). */
export const NODE_PREFIX = Buffer.from([0x01]);
/** Tag for a receipt body, so a receipt hash is never also a tree node. */
export const RECEIPT_PREFIX = Buffer.from([0x02]);
/** Tag for a signed checkpoint. */
export const CHECKPOINT_PREFIX = Buffer.from([0x03]);

/**
 * @param {...Buffer} parts
 * @returns {Buffer} 32-byte digest
 */
export function sha256(...parts) {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
}

/**
 * Hash of an object's canonical form, under a given domain tag.
 *
 * @param {Buffer} prefix one of the *_PREFIX constants
 * @param {unknown} value
 * @returns {Buffer}
 */
export function hashObject(prefix, value) {
  return sha256(prefix, canonicalBytes(value));
}

/**
 * Lowercase hex, the form used everywhere in the wire format and on disk.
 *
 * @param {Buffer} buf
 * @returns {string}
 */
export function hex(buf) {
  return buf.toString('hex');
}

/**
 * @param {string} s
 * @returns {Buffer}
 */
export function unhex(s) {
  if (!/^[0-9a-f]*$/.test(s) || s.length % 2 !== 0) {
    throw new TypeError(`not lowercase hex: ${JSON.stringify(s.slice(0, 32))}`);
  }
  return Buffer.from(s, 'hex');
}

/**
 * Constant-time comparison, for anywhere a mismatch is attacker-observable.
 *
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {boolean}
 */
export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
