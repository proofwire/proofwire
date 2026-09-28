import { randomBytes } from 'node:crypto';
import { canonicalBytes } from './canonical.js';
import { sha256, hashObject, hex, unhex, RECEIPT_PREFIX, equalBytes } from './hash.js';
import { leafHash } from './merkle.js';
import { sign, verify } from './keys.js';
import { redact } from './redact.js';

/**
 * The receipt: one signed, chained record of one thing an agent did.
 *
 * Three properties are load-bearing, and each exists because a specific
 * dispute is foreseeable:
 *
 *   signed    "your logs say X" → the signature says a specific key asserted
 *             X, and the private key never leaves the agent runtime.
 *   chained   every receipt commits to its predecessor's hash, so removing or
 *             reordering a single entry invalidates everything after it.
 *   sealed    arguments and results are stored as salted commitments plus a
 *             redacted preview. The log can be handed to an outside auditor
 *             without handing over customer data — and the holder of the
 *             original can still prove, later, exactly what it was.
 */

/** Wire format version. Bump only for breaking changes. */
export const RECEIPT_VERSION = 1;

/** `prev` for the first entry in a log. */
export const GENESIS_PREV = '0'.repeat(64);

/**
 * @typedef {object} Sealed
 * @property {string} hash  sha256(salt || canonical(value)), hex.
 * @property {number} size  Byte length of the canonical form — cheap signal of scale.
 * @property {unknown} [preview]  Redacted copy, safe to publish.
 * @property {string[]} [redacted]  Types that were masked, e.g. `["email"]`.
 */

/**
 * Commit to a value without storing it.
 *
 * The salt is what makes this worth doing. A bare hash of a low-entropy value
 * — `{"amount": 50}`, a customer's email — is trivially brute-forced, so an
 * unsalted commitment leaks exactly the data it pretends to protect.
 *
 * The salt is returned *alongside* the commitment rather than inside it, and
 * it is never part of what gets signed. Two consequences, both deliberate:
 *
 *   - A receipt is safe to publish as-is. There is no "remember to strip the
 *     secrets before exporting" step to forget.
 *   - Destroying the salts renders the commitments permanently un-openable
 *     while leaving every signature and chain link intact. That is a real
 *     erasure — a GDPR Article 17 request can be honoured without gutting the
 *     audit trail, which is otherwise a direct conflict between two duties.
 *
 * @param {unknown} value
 * @param {object} [opts]
 * @param {boolean} [opts.preview=true]  Include a redacted copy.
 * @returns {{ sealed: Sealed, salt: string }}
 */
export function seal(value, opts = {}) {
  const salt = randomBytes(16);
  const bytes = canonicalBytes(value ?? null);
  /** @type {Sealed} */
  const sealed = {
    hash: hex(sha256(salt, bytes)),
    size: bytes.length,
  };
  if (opts.preview !== false) {
    const { value: masked, findings } = redact(value ?? null);
    sealed.preview = masked;
    if (findings.length > 0) {
      sealed.redacted = [...new Set(findings.map((f) => f.type))].sort();
    }
  }
  return { sealed, salt: salt.toString('base64url') };
}

/**
 * Prove that `value` is what a sealed commitment referred to.
 *
 * @param {Sealed} sealed
 * @param {string|undefined} saltB64u  From the log's salt store. Absent means
 *   the payload was crypto-shredded and can no longer be opened by anyone.
 * @param {unknown} value
 * @returns {boolean}
 */
export function openSeal(sealed, saltB64u, value) {
  if (!sealed || typeof saltB64u !== 'string') return false;
  let salt;
  try {
    salt = Buffer.from(saltB64u, 'base64url');
  } catch {
    return false;
  }
  const expect = sha256(salt, canonicalBytes(value ?? null));
  try {
    return equalBytes(expect, unhex(sealed.hash));
  } catch {
    return false;
  }
}

/**
 * @typedef {object} Actor
 * @property {string} agent      Model or agent identifier, e.g. `claude-opus-5`.
 * @property {string} runtime    What produced the receipt, e.g. `vouchwell-proxy/0.1.0`.
 * @property {string} session    Groups the receipts of one agent run.
 * @property {string} principal  Whose authority the agent acted under.
 */

/**
 * @typedef {object} Decision
 * @property {'allow'|'deny'|'escalate'} outcome
 * @property {string} policy     Hash of the policy document in force.
 * @property {string[]} rules    Rule ids that fired, in evaluation order.
 * @property {string} [reason]   Human-readable justification.
 * @property {{ by: string, at: string, note?: string }} [approval]  An escalation a person approved.
 * @property {{ by: string, at: string, note?: string }} [declined]  An escalation that was not
 *   approved: by a person, or by a fallback such as `policy:timeout` or `policy:no-approver`.
 * @property {false} [enforced]  Present, and false, when the policy was only
 *   observed (monitor mode): the call ran whatever the policy said.
 * @property {'deny'|'escalate'} [wouldBe]  In monitor mode, what enforcement
 *   would have done instead of letting the call through.
 */

/**
 * @typedef {object} ReceiptBody
 * @property {number} v
 * @property {string} log
 * @property {number} seq
 * @property {string} prev
 * @property {string} ts
 * @property {'atomic'|'intent'|'outcome'} phase
 * @property {string} [ref]
 * @property {Actor} actor
 * @property {{ kind: string, target: string, metrics?: Record<string, number>, params: Sealed }} action
 * @property {Decision} decision
 * @property {null | { status: 'ok'|'error', code?: string, latencyMs?: number, payload: Sealed }} result
 */

/**
 * @typedef {ReceiptBody & { attest: { alg: 'ed25519', kid: string, sig: string } }} Receipt
 */

/**
 * `buildReceipt` insists on these because a hub does: they are bound straight
 * into non-null SQLite columns, and a receipt lacking one is only discovered
 * when the hub crashes on it — a raw `TypeError` from the driver, on whichever
 * request happens to be routed to that connection first, with no indication
 * which field or which receipt. Catching it here, at construction, turns that
 * into a clear error before the receipt is even signed.
 *
 * @param {unknown} value
 * @param {string} field
 */
function requireField(value, field) {
  if (typeof value !== 'string' || value === '') {
    throw new Error(`buildReceipt: ${field} is required and must be a non-empty string`);
  }
}

/**
 * Assemble an unsigned receipt body.
 *
 * @param {object} args
 * @param {string} args.log
 * @param {number} args.seq
 * @param {string} args.prev
 * @param {Actor} args.actor
 * @param {{ kind: string, target: string, params: unknown, metrics?: Record<string, number> }} args.action
 * @param {Decision} args.decision
 * @param {null | { status: 'ok'|'error', code?: string, latencyMs?: number, payload?: unknown }} [args.result]
 * @param {'atomic'|'intent'|'outcome'} [args.phase]
 * @param {string} [args.ref]
 * @param {string} [args.ts]
 * @returns {{ body: ReceiptBody, salts: { params: string, result?: string } }}
 *   The salts are the caller's to store separately — see `seal`.
 */
export function buildReceipt(args) {
  requireField(args.actor?.principal, 'actor.principal');
  requireField(args.actor?.agent, 'actor.agent');
  requireField(args.actor?.session, 'actor.session');
  requireField(args.action?.kind, 'action.kind');
  requireField(args.action?.target, 'action.target');
  requireField(args.decision?.outcome, 'decision.outcome');

  const params = seal(args.action.params);
  const payload = args.result ? seal(args.result.payload) : null;

  /** @type {ReceiptBody} */
  const body = {
    v: RECEIPT_VERSION,
    log: args.log,
    seq: args.seq,
    prev: args.prev,
    ts: args.ts ?? new Date().toISOString(),
    phase: args.phase ?? 'atomic',
    actor: args.actor,
    action: {
      kind: args.action.kind,
      target: args.action.target,
      // Metrics stay in the clear by design: budgets are aggregated from them,
      // and a spend cap you cannot recompute from the log is not auditable.
      // Only non-sensitive numbers belong here.
      ...(args.action.metrics ? { metrics: args.action.metrics } : {}),
      params: params.sealed,
    },
    decision: args.decision,
    result:
      args.result && payload
        ? {
            status: args.result.status,
            ...(args.result.code !== undefined ? { code: args.result.code } : {}),
            ...(args.result.latencyMs !== undefined ? { latencyMs: args.result.latencyMs } : {}),
            payload: payload.sealed,
          }
        : null,
  };
  if (args.ref) body.ref = args.ref;

  return {
    body,
    salts: { params: params.salt, ...(payload ? { result: payload.salt } : {}) },
  };
}

/**
 * The bytes a signature covers: the body, canonicalized, under the receipt tag.
 *
 * @param {ReceiptBody} body
 * @returns {Buffer}
 */
export function receiptDigest(body) {
  const { attest, ...rest } = /** @type {Record<string, unknown>} */ (body);
  return hashObject(RECEIPT_PREFIX, rest);
}

/**
 * The receipt's identity — and, deliberately, its Merkle leaf hash.
 *
 * Reusing one value for the chain pointer and the tree leaf means an inclusion
 * proof and a chain link cannot disagree about which receipt they refer to.
 *
 * @param {Receipt} receipt
 * @returns {string} hex
 */
export function entryHash(receipt) {
  return hex(leafHash(canonicalBytes(receipt)));
}

/**
 * @param {import('./keys.js').Identity} identity
 * @param {ReceiptBody} body
 * @returns {Receipt}
 */
export function signReceipt(identity, body) {
  const sig = sign(identity, receiptDigest(body));
  return { ...body, attest: { alg: 'ed25519', kid: identity.kid, sig } };
}

/**
 * @typedef {Record<string, string>} Keyring  kid → base64url public key.
 */

/**
 * @typedef {object} VerifyIssue
 * @property {number} [seq]
 * @property {'signature'|'chain'|'sequence'|'format'|'key'|'time'} kind
 * @property {string} message
 */

/**
 * Check one receipt's signature against a keyring.
 *
 * @param {Receipt} receipt
 * @param {Keyring} keyring
 * @returns {VerifyIssue[]}  Empty when the receipt is sound.
 */
export function verifyReceipt(receipt, keyring) {
  /** @type {VerifyIssue[]} */
  const issues = [];
  const seq = receipt?.seq;

  if (!receipt || typeof receipt !== 'object') {
    return [{ kind: 'format', message: 'receipt is not an object' }];
  }
  if (receipt.v !== RECEIPT_VERSION) {
    issues.push({ seq, kind: 'format', message: `unsupported receipt version ${receipt.v}` });
  }
  // A hub binds these straight into non-null database columns. Catching a
  // missing one here, before the signature is even checked, is what stands
  // between a malformed-but-validly-signed receipt and a server crash — a
  // receipt need not have come from `buildReceipt` to reach this function.
  for (const [path, value] of [
    ['ts', receipt.ts],
    ['actor.principal', receipt.actor?.principal],
    ['actor.agent', receipt.actor?.agent],
    ['actor.session', receipt.actor?.session],
    ['action.kind', receipt.action?.kind],
    ['action.target', receipt.action?.target],
    ['decision.outcome', receipt.decision?.outcome],
  ]) {
    if (typeof value !== 'string' || value === '') {
      issues.push({ seq, kind: 'format', message: `${path} is required and must be a non-empty string` });
    }
  }
  if (!['atomic', 'intent', 'outcome'].includes(receipt.phase)) {
    issues.push({ seq, kind: 'format', message: `phase must be one of atomic, intent, outcome; got ${JSON.stringify(receipt.phase)}` });
  }
  const attest = receipt.attest;
  if (!attest || attest.alg !== 'ed25519' || typeof attest.sig !== 'string') {
    issues.push({ seq, kind: 'format', message: 'missing or malformed attestation' });
    return issues;
  }
  const pub = Object.prototype.hasOwnProperty.call(keyring ?? {}, attest.kid) ? keyring[attest.kid] : undefined;
  if (typeof pub !== 'string') {
    issues.push({ seq, kind: 'key', message: `no public key for kid ${attest.kid}` });
    return issues;
  }
  const { attest: _drop, ...body } = receipt;
  if (!verify(pub, receiptDigest(/** @type {ReceiptBody} */ (body)), attest.sig)) {
    issues.push({ seq, kind: 'signature', message: `signature does not verify for kid ${attest.kid}` });
  }
  return issues;
}

/**
 * Verify a contiguous run of receipts: signatures, sequence numbers, chain
 * links, and monotonic timestamps.
 *
 * Timestamp regressions are reported but treated as a weaker signal than the
 * rest — clocks genuinely do step backwards, whereas a broken chain link
 * cannot happen by accident.
 *
 * @param {Receipt[]} receipts  Oldest first.
 * @param {Keyring} keyring
 * @param {object} [opts]
 * @param {string} [opts.expectPrev]  Chain hash the run should start from.
 * @param {number} [opts.expectSeq]   Sequence the run should start at.
 * @returns {{ ok: boolean, issues: VerifyIssue[], head: string, count: number }}
 */
export function verifyChain(receipts, keyring, opts = {}) {
  /** @type {VerifyIssue[]} */
  const issues = [];
  let prev = opts.expectPrev ?? GENESIS_PREV;
  let expectedSeq = opts.expectSeq ?? 0;
  let lastTs = null;

  for (const receipt of receipts) {
    issues.push(...verifyReceipt(receipt, keyring));

    if (receipt.seq !== expectedSeq) {
      issues.push({
        seq: receipt.seq,
        kind: 'sequence',
        message: `expected seq ${expectedSeq}, found ${receipt.seq} — entries missing or reordered`,
      });
    }
    if (receipt.prev !== prev) {
      issues.push({
        seq: receipt.seq,
        kind: 'chain',
        message: `chain break: prev is ${String(receipt.prev).slice(0, 12)}…, expected ${prev.slice(0, 12)}…`,
      });
    }
    if (lastTs && receipt.ts < lastTs) {
      issues.push({
        seq: receipt.seq,
        kind: 'time',
        message: `timestamp ${receipt.ts} precedes the previous entry's ${lastTs}`,
      });
    }

    lastTs = receipt.ts;
    prev = entryHash(receipt);
    expectedSeq = receipt.seq + 1;
  }

  return { ok: issues.length === 0, issues, head: prev, count: receipts.length };
}
