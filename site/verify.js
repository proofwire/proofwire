/**
 * Deedwrit evidence-bundle verifier, for browsers.
 *
 * This is a second, independent implementation of what `dw check` does. It
 * shares no code with @deedwrit/core: canonical JSON, the RFC 6962 tree, the
 * receipt and checkpoint digests and the Ed25519 checks are all written again
 * here against WebCrypto, so it runs in a browser tab with nothing installed
 * and nothing uploaded.
 *
 * Two implementations that disagree on any input are a bug in one of them, so
 * `site/test/verify.test.js` runs both over the same bundles — honest, tampered
 * and randomly mutated — and requires the same verdict every time.
 *
 * It depends only on `crypto.subtle` and `TextEncoder`, so it also runs
 * unchanged in Node >= 20.
 */

const enc = new TextEncoder();
const subtle = globalThis.crypto?.subtle;

const LEAF = 0x00; // RFC 6962 leaf tag
const NODE = 0x01; // RFC 6962 interior-node tag
const RECEIPT = 0x02; // a receipt body
const CHECKPOINT = 0x03; // a signed tree head
const GENESIS_PREV = '0'.repeat(64);

// ── bytes ───────────────────────────────────────────────────────────────

/** @param {...Uint8Array} parts */
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** @param {...Uint8Array} parts @returns {Promise<Uint8Array>} */
async function sha256(...parts) {
  return new Uint8Array(await subtle.digest('SHA-256', concat(...parts)));
}

/** @param {Uint8Array} b */
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/**
 * Strict on purpose: a verifier that quietly accepts malformed encodings is one
 * that can be argued into agreeing with something it should have rejected.
 *
 * @param {string} s
 * @returns {Uint8Array}
 */
function unhex(s) {
  if (typeof s !== 'string' || !/^([0-9a-f]{2})*$/.test(s)) throw new TypeError('not lowercase hex');
  return Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
}

/**
 * @param {string} s @returns {Uint8Array}
 *
 * `atob` is exactly as lenient as Node's `Buffer.from(s, 'base64url')` about a
 * final quantum's unused low bits — `'QA'` and `'QB'` both decode to `0x40` —
 * so re-encoding and comparing is required here too, for the same reason it
 * is required in `packages/core/src/keys.js`: two implementations that are
 * each internally lenient in the same way will still *agree*, which is
 * exactly what makes this class of gap invisible to differential testing
 * between them.
 */
function fromB64u(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) {
    throw new TypeError('not base64url');
  }
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  if (toB64u(bytes) !== s) throw new TypeError('not canonical base64url');
  return bytes;
}

/** @param {Uint8Array} bytes @returns {string} */
function toB64u(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** @param {Uint8Array} a @param {Uint8Array} b */
function same(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ── canonical JSON (RFC 8785) ───────────────────────────────────────────

const ESCAPES = { 0x08: '\\b', 0x09: '\\t', 0x0a: '\\n', 0x0c: '\\f', 0x0d: '\\r', 0x22: '\\"', 0x5c: '\\\\' };

/** @param {string} s */
function encodeString(s) {
  let out = '"';
  for (const ch of s) {
    const cp = /** @type {number} */ (ch.codePointAt(0));
    const esc = ESCAPES[cp];
    if (esc !== undefined) out += esc;
    else if (cp < 0x20) out += '\\u' + cp.toString(16).padStart(4, '0');
    else out += ch;
  }
  return out + '"';
}

/**
 * Deterministic serialization. Two parties must produce identical bytes for the
 * same object or every signature is arguable; `JSON.stringify` does not promise
 * that, because key order follows insertion order.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalize(value) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError('cannot canonicalize a non-finite number');
      return value === 0 ? '0' : String(value); // RFC 8785: -0 is 0
    case 'string':
      return encodeString(value);
    case 'object':
      break;
    default:
      throw new TypeError(`cannot canonicalize ${typeof value}`);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((v) => (v === undefined ? 'null' : canonicalize(v))).join(',') + ']';
  }
  // UTF-16 code-unit order, which is what the default sort does on strings.
  const obj = /** @type {Record<string, unknown>} */ (value);
  const parts = [];
  for (const k of Object.keys(obj).sort()) {
    if (obj[k] === undefined) continue;
    parts.push(encodeString(k) + ':' + canonicalize(obj[k]));
  }
  return '{' + parts.join(',') + '}';
}

const bytesOf = (v) => enc.encode(canonicalize(v));

// ── Merkle tree (RFC 6962) ──────────────────────────────────────────────

const leafHash = (data) => sha256(Uint8Array.of(LEAF), data);
const nodeHash = (l, r) => sha256(Uint8Array.of(NODE), l, r);

/**
 * Append-only accumulator: a stack of complete subtrees, merged like a binary
 * counter. One pass yields every historical root a checkpoint might name.
 */
class Accumulator {
  constructor() {
    /** @type {{ size: number, hash: Uint8Array }[]} */
    this.stack = [];
  }

  /** @param {Uint8Array} leaf */
  async append(leaf) {
    this.stack.push({ size: 1, hash: leaf });
    while (this.stack.length > 1) {
      const right = this.stack[this.stack.length - 1];
      const left = this.stack[this.stack.length - 2];
      if (left.size !== right.size) break;
      this.stack.splice(-2, 2, { size: left.size * 2, hash: await nodeHash(left.hash, right.hash) });
    }
  }

  async root() {
    if (this.stack.length === 0) return sha256(); // RFC 6962: MTH({}) = SHA-256("")
    let acc = this.stack[this.stack.length - 1].hash;
    for (let i = this.stack.length - 2; i >= 0; i--) acc = await nodeHash(this.stack[i].hash, acc);
    return acc;
  }
}

/**
 * Recompute the root a proof implies, then compare. Returns false rather than
 * throwing: a verifier is fed hostile data by definition.
 *
 * @param {{ leaf: Uint8Array, index: number, treeSize: number, proof: Uint8Array[], root: Uint8Array }} a
 */
async function verifyInclusion({ leaf, index, treeSize, proof, root }) {
  if (!Number.isInteger(index) || !Number.isInteger(treeSize)) return false;
  if (index < 0 || treeSize <= 0 || index >= treeSize) return false;

  let fn = index;
  let sn = treeSize - 1;
  let acc = leaf;

  for (const sibling of proof) {
    if (sn === 0) return false;
    if (sibling.length !== 32) return false;
    if ((fn & 1) === 1 || fn === sn) {
      acc = await nodeHash(sibling, acc);
      while (fn !== 0 && (fn & 1) === 0) {
        fn >>>= 1;
        sn >>>= 1;
      }
    } else {
      acc = await nodeHash(acc, sibling);
    }
    fn >>>= 1;
    sn >>>= 1;
  }
  // A proof that runs out before reaching the root proves nothing.
  return sn === 0 && same(acc, root);
}

/**
 * Check that `secondRoot` extends `firstRoot` (RFC 6962 §2.1.2). The same
 * walk as @deedwrit/core's verifyConsistency, asynchronously.
 *
 * @param {{ firstSize: number, secondSize: number, firstRoot: Uint8Array,
 *   secondRoot: Uint8Array, proof: Uint8Array[] }} a
 */
async function verifyConsistency({ firstSize, secondSize, firstRoot, secondRoot, proof }) {
  if (!Number.isInteger(firstSize) || !Number.isInteger(secondSize)) return false;
  if (firstSize < 0 || secondSize < firstSize) return false;
  if (firstSize === secondSize) return proof.length === 0 && same(firstRoot, secondRoot);
  if (firstSize === 0) return proof.length === 0;

  let fn = firstSize - 1;
  let sn = secondSize - 1;
  while ((fn & 1) === 1) {
    fn >>>= 1;
    sn >>>= 1;
  }
  if (proof.length === 0) return false;
  let i = 0;
  let fr;
  let sr;
  if (fn !== 0) {
    fr = proof[i];
    sr = proof[i];
    i++;
  } else {
    fr = firstRoot;
    sr = firstRoot;
  }
  for (; i < proof.length; i++) {
    const p = proof[i];
    if (sn === 0) return false;
    if (p.length !== 32) return false;
    if ((fn & 1) === 1 || fn === sn) {
      fr = await nodeHash(p, fr);
      sr = await nodeHash(p, sr);
      while (fn !== 0 && (fn & 1) === 0) {
        fn >>>= 1;
        sn >>>= 1;
      }
    } else {
      sr = await nodeHash(sr, p);
    }
    fn >>>= 1;
    sn >>>= 1;
  }
  return sn === 0 && same(fr, firstRoot) && same(sr, secondRoot);
}

// ── Ed25519 ─────────────────────────────────────────────────────────────

/** @type {Map<string, Promise<CryptoKey>>} */
const keyCache = new Map();

/** @param {string} b64u */
function importKey(b64u) {
  let pending = keyCache.get(b64u);
  if (!pending) {
    pending = (async () => {
      const raw = fromB64u(b64u);
      if (raw.length !== 32) throw new TypeError('an Ed25519 public key is 32 bytes');
      return subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
    })();
    keyCache.set(b64u, pending);
  }
  return pending;
}

/**
 * @param {string} publicKey  Raw 32-byte key, base64url.
 * @param {Uint8Array} message
 * @param {string} signature  base64url
 */
async function verifySignature(publicKey, message, signature) {
  try {
    const sig = fromB64u(signature);
    if (sig.length !== 64) return false;
    return await subtle.verify({ name: 'Ed25519' }, await importKey(publicKey), sig, message);
  } catch {
    return false;
  }
}

/**
 * Whether this environment can verify Ed25519 at all. Browsers shipped it in
 * 2024–25; an older one should be told to use the CLI rather than shown a
 * misleading failure.
 *
 * The probe key is the public key from RFC 8032 test vector 1.
 */
export async function ed25519Supported() {
  try {
    const key = unhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
    await subtle.importKey('raw', key, { name: 'Ed25519' }, false, ['verify']);
    return true;
  } catch {
    return false;
  }
}

// ── receipts, chains, checkpoints ───────────────────────────────────────

const has = (obj, key) => obj != null && Object.prototype.hasOwnProperty.call(obj, key);

/** @param {any} receipt */
const receiptDigest = (receipt) => {
  const { attest: _attest, ...body } = receipt;
  return sha256(Uint8Array.of(RECEIPT), bytesOf(body));
};

/** @param {any} receipt @returns {Promise<string>} */
const entryHash = async (receipt) => hex(await leafHash(bytesOf(receipt)));

/**
 * @param {any} receipt
 * @param {Record<string, string>} keyring
 * @returns {Promise<{ issues: { seq?: number, kind: string, message: string }[], signed: boolean }>}
 */
async function checkReceipt(receipt, keyring) {
  const seq = receipt?.seq;
  if (!receipt || typeof receipt !== 'object') {
    return { issues: [{ kind: 'format', message: 'receipt is not an object' }], signed: false };
  }
  const issues = [];
  if (receipt.v !== 1) issues.push({ seq, kind: 'format', message: `unsupported receipt version ${receipt.v}` });

  const attest = receipt.attest;
  if (!attest || attest.alg !== 'ed25519' || typeof attest.sig !== 'string') {
    issues.push({ seq, kind: 'format', message: 'missing or malformed attestation' });
    return { issues, signed: false };
  }
  if (!has(keyring, attest.kid)) {
    issues.push({ seq, kind: 'key', message: `no public key for kid ${attest.kid}` });
    return { issues, signed: false };
  }
  const ok = await verifySignature(keyring[attest.kid], await receiptDigest(receipt), attest.sig);
  if (!ok) {
    issues.push({ seq, kind: 'signature', message: `signature does not verify for kid ${attest.kid}` });
  }
  return { issues, signed: ok };
}

/**
 * Signatures, sequence numbers, chain links and monotonic timestamps over a
 * contiguous run.
 *
 * @param {any[]} receipts
 * @param {Record<string, string>} keyring
 */
async function verifyChain(receipts, keyring) {
  const issues = [];
  let prev = GENESIS_PREV;
  let expectedSeq = 0;
  let lastTs = null;
  let signed = 0;

  for (const receipt of receipts) {
    const res = await checkReceipt(receipt, keyring);
    issues.push(...res.issues);
    if (res.signed) signed++;

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
    prev = await entryHash(receipt);
    expectedSeq = receipt.seq + 1;
  }
  return { issues, signed };
}

/**
 * Check a checkpoint's signatures. Witnesses count only when pinned: the bundle's
 * keyring is supplied by the party under suspicion, so it cannot vouch for them.
 * See the same function in @deedwrit/core for the reasoning.
 *
 * @param {any} checkpoint
 * @param {Record<string, string>} keyring
 * @param {{ minWitnesses?: number, trusted?: Record<string, string> }} opts
 */
async function verifyCheckpoint(checkpoint, keyring, { minWitnesses = 0, trusted } = {}) {
  const issues = [];
  let witnesses = 0;
  const pinned = Boolean(trusted) && typeof trusted === 'object';

  if (!checkpoint?.body || !Array.isArray(checkpoint.sigs)) {
    return { ok: false, issues: ['malformed checkpoint'], witnesses, pinned };
  }
  if (checkpoint.body.v !== 1) issues.push(`unsupported checkpoint version ${checkpoint.body.v}`);

  const digest = await sha256(Uint8Array.of(CHECKPOINT), bytesOf(checkpoint.body));
  let hasLogSig = false;
  // Each witness counts once, however often its signature is repeated.
  const counted = new Set();

  for (const s of checkpoint.sigs) {
    if (pinned && s?.role === 'witness') {
      if (!has(trusted, s.kid)) continue; // a witness we were not told to trust
      if (counted.has(trusted[s.kid])) continue;
      if (await verifySignature(trusted[s.kid], digest, s.sig)) {
        counted.add(trusted[s.kid]);
        witnesses++;
      } else issues.push(`invalid witness signature from ${s.kid}`);
      continue;
    }
    if (pinned && s?.role === 'log' && has(trusted, s.kid)) {
      issues.push(`signature from pinned witness ${s.kid} is labelled as the log's`);
      continue;
    }

    if (!has(keyring, s?.kid)) {
      issues.push(`no public key for signer ${s?.kid}`);
      continue;
    }
    if (!(await verifySignature(keyring[s.kid], digest, s.sig))) {
      issues.push(`invalid ${s.role} signature from ${s.kid}`);
      continue;
    }
    if (s.role === 'witness' && !counted.has(keyring[s.kid])) {
      counted.add(keyring[s.kid]);
      witnesses++; // unpinned: a claim, not evidence
    }
    if (s.role === 'log') hasLogSig = true;
  }

  if (!hasLogSig) issues.push('checkpoint carries no valid log signature');
  if (witnesses < minWitnesses) {
    issues.push(`only ${witnesses} valid witness signature(s), policy requires ${minWitnesses}`);
  }
  return { ok: issues.length === 0, issues, witnesses, pinned };
}

// ── the bundle ──────────────────────────────────────────────────────────

/**
 * Verify an evidence bundle standing alone, exactly as `dw check` does.
 *
 * A bundle proves it was not altered after signing, using the keys it carries.
 * It does not prove those are the keys you ought to trust — pin that by passing
 * a root obtained from somewhere else (`expectRoot`) and by requiring witnesses.
 *
 * @param {any} bundle
 * @param {{ expectRoot?: string, minWitnesses?: number, trustedWitnesses?: Record<string, string> }} [opts]
 * @returns {Promise<{ ok: boolean, issues: string[], checked: number, summary: object|null,
 *   badSeqs: Set<number> }>}
 */
async function verifyBundleUnchecked(bundle, opts = {}) {
  /** @type {string[]} */
  const issues = [];
  const badSeqs = new Set();
  const empty = { checked: 0, summary: null, badSeqs };

  // `proofwire.bundle` and `vouchwell.bundle`: written under the project's
  // earlier names. The label is not signed; what is inside verifies as ever.
  if (!['deedwrit.bundle', 'vouchwell.bundle', 'proofwire.bundle'].includes(bundle?.kind) || bundle.v !== 1) {
    return { ok: false, issues: ['not a Deedwrit v1 bundle'], ...empty };
  }
  const keyring = bundle.keyring ?? {};
  let root;
  try {
    root = unhex(bundle.root);
  } catch {
    return { ok: false, issues: ['bundle root is not valid hex'], ...empty };
  }

  if (opts.expectRoot && opts.expectRoot !== bundle.root) {
    issues.push(
      `bundle root ${bundle.root.slice(0, 16)}… does not match the expected ` +
        `${opts.expectRoot.slice(0, 16)}… — you were shown a different history`,
    );
  }

  const minWitnesses = opts.minWitnesses ?? 0;
  if (!Number.isInteger(minWitnesses) || minWitnesses < 0) {
    return {
      ok: false,
      issues: [`minWitnesses must be a non-negative integer, got ${String(opts.minWitnesses)}`],
      ...empty,
    };
  }
  const trusted =
    opts.trustedWitnesses && typeof opts.trustedWitnesses === 'object' ? opts.trustedWitnesses : undefined;
  if (minWitnesses > 0 && !trusted) {
    issues.push(
      `${minWitnesses} witness signature(s) required, but no trusted witness keys were ` +
        `supplied — a bundle's own keyring cannot vouch for its witnesses`,
    );
  }

  const checkpoints = [];
  const checkpointResults = [];
  for (const cp of bundle.checkpoints ?? []) {
    let res;
    try {
      res = await verifyCheckpoint(cp, keyring, { minWitnesses: trusted ? minWitnesses : 0, trusted });
    } catch (err) {
      res = { ok: false, issues: [String(err.message ?? err)], witnesses: 0, pinned: Boolean(trusted) };
    }
    if (!res.ok) issues.push(`checkpoint at size ${cp?.body?.size}: ${res.issues.join('; ')}`);
    checkpoints.push({ size: cp?.body?.size, witnesses: res.witnesses, pinned: res.pinned, ok: res.ok });
    checkpointResults.push({ cp, ok: res.ok });
  }

  let checked = 0;
  const receipts = [];
  const leaves = [];

  for (const entry of bundle.entries ?? []) {
    try {
      const { receipt, proof } = entry;
      if (!receipt || typeof receipt !== 'object' || !Number.isInteger(receipt.seq)) {
        throw new Error('entry carries no receipt with a sequence number');
      }
      const leaf = await leafHash(bytesOf(receipt));
      receipts.push(receipt);
      leaves.push(leaf);

      const ok = await verifyInclusion({
        leaf,
        index: receipt.seq,
        treeSize: bundle.treeSize,
        proof: (proof ?? []).map(unhex),
        root,
      });
      if (!ok) {
        issues.push(`entry ${receipt.seq} is not provably part of the logged tree`);
        badSeqs.add(receipt.seq);
      }
    } catch (err) {
      issues.push(`malformed entry: ${err.message}`);
    }
    checked++;
  }

  // What the bundle claims about itself. Every proof above can be genuine while
  // entries have simply been left out, so a bundle that says it is complete has
  // to actually be.
  const treeSize = bundle.treeSize;
  if (!Number.isInteger(treeSize) || treeSize < 0) {
    issues.push('bundle treeSize is not a non-negative integer');
  }

  const tip = receipts.find((r) => r.seq === treeSize - 1);
  if (tip && (await entryHash(tip)) !== bundle.head) {
    issues.push(`bundle head ${String(bundle.head).slice(0, 16)}… is not the hash of its final entry`);
  }

  /** @type {Map<number, string> | null} */
  let prefixRoots = null;
  if (!bundle.partial) {
    if (receipts.length !== treeSize) {
      issues.push(
        `bundle is marked complete but holds ${receipts.length} of ${treeSize} entries — entries were left out`,
      );
    } else {
      const wanted = new Set((bundle.checkpoints ?? []).map((cp) => cp?.body?.size).filter(Number.isInteger));
      const tree = new Accumulator();
      prefixRoots = new Map();
      // A checkpoint of the empty log names the empty root; without this it
      // was compared against nothing and reported as a rewritten history.
      if (wanted.has(0)) prefixRoots.set(0, hex(await tree.root()));
      for (const [k, leaf] of leaves.entries()) {
        await tree.append(leaf);
        if (wanted.has(k + 1)) prefixRoots.set(k + 1, hex(await tree.root()));
      }

      if (hex(await tree.root()) !== bundle.root) {
        issues.push('bundle root does not match the root of its own entries');
      }
      if (treeSize === 0 && bundle.head !== GENESIS_PREV) {
        issues.push('an empty bundle must carry the genesis head');
      }

      for (const cp of bundle.checkpoints ?? []) {
        const size = cp?.body?.size;
        if (!Number.isInteger(size)) continue;
        if (size > treeSize) {
          issues.push(`checkpoint at size ${size} covers more entries than this bundle holds`);
          continue;
        }
        if (prefixRoots.get(size) !== cp.body.root) {
          issues.push(
            `checkpoint at size ${size} names root ${String(cp.body.root).slice(0, 16)}…, but ` +
              `this bundle's own entries hash to a different one — history was rewritten`,
          );
        }
      }
    }
  }

  // Which checkpoints vouch for *these* entries: a checkpoint's witnesses say
  // nothing about this bundle unless its root is tied to the bundle's tree.
  // See anchorCheckpoints in @deedwrit/core.
  const witnessedSize = await anchorCheckpoints({
    bundle, root, treeSize, prefixRoots, checkpointResults, issues,
  });
  if (trusted && minWitnesses > 0 && witnessedSize === null) {
    issues.push(
      `no checkpoint carrying ${minWitnesses} trusted witness signature(s) covers this ` +
        `bundle's entries — nothing independent vouches for this history`,
    );
  }

  // A complete bundle must also form an unbroken chain. A filtered one cannot,
  // by construction, so inclusion proofs carry the weight there instead.
  let signed = 0;
  try {
    if (!bundle.partial) {
      const chain = await verifyChain(receipts, keyring);
      signed = chain.signed;
      for (const i of chain.issues) {
        issues.push(`entry ${i.seq}: ${i.message}`);
        if (Number.isInteger(i.seq)) badSeqs.add(i.seq);
      }
    } else {
      for (const receipt of receipts) {
        const res = await checkReceipt(receipt, keyring);
        if (res.signed) signed++;
        for (const i of res.issues) {
          issues.push(`entry ${i.seq}: ${i.message}`);
          if (Number.isInteger(i.seq)) badSeqs.add(i.seq);
        }
      }
    }
  } catch (err) {
    issues.push(`could not verify the receipts: ${err.message}`);
  }

  const outcomes = { allow: 0, deny: 0, escalate: 0 };
  for (const r of receipts) {
    if (r.decision?.outcome in outcomes) outcomes[r.decision.outcome]++;
  }

  return {
    ok: issues.length === 0,
    issues,
    checked,
    badSeqs,
    summary: {
      log: bundle.log,
      treeSize,
      root: bundle.root,
      head: bundle.head,
      partial: Boolean(bundle.partial),
      entries: receipts.length,
      signed,
      outcomes,
      checkpoints,
      receipts,
      witnessedSize: trusted && minWitnesses > 0 ? (witnessedSize ?? 0) : null,
    },
  };
}

/**
 * Tie each valid checkpoint to the bundle's tree, report any that contradict
 * it, and return the largest size covered by one that passed (null if none).
 */
async function anchorCheckpoints({ bundle, root, treeSize, prefixRoots, checkpointResults, issues }) {
  if (!Number.isInteger(treeSize)) return null;
  const proofs = bundle.consistency && typeof bundle.consistency === 'object' ? bundle.consistency : {};
  let best = null;

  for (const { cp, ok } of checkpointResults) {
    const size = cp?.body?.size;
    if (!Number.isInteger(size) || size < 0) continue;
    let anchored = false;
    try {
      if (prefixRoots) {
        anchored = size <= treeSize && prefixRoots.get(size) === cp.body.root;
      } else if (size > treeSize) {
        issues.push(`checkpoint at size ${size} covers more entries than this bundle holds`);
      } else if (size === treeSize) {
        anchored = cp.body.root === bundle.root;
        if (!anchored) {
          issues.push(
            `checkpoint at size ${size} names root ${String(cp.body.root).slice(0, 16)}…, but ` +
              `this bundle's root is ${String(bundle.root).slice(0, 16)}… — history was rewritten`,
          );
        }
      } else if (size === 0) {
        anchored = cp.body.root === hex(await sha256());
      } else if (has(proofs, String(size))) {
        const proof = proofs[String(size)];
        if (!Array.isArray(proof)) throw new Error('consistency proof is not a list');
        anchored = await verifyConsistency({
          firstSize: size,
          secondSize: treeSize,
          firstRoot: unhex(cp.body.root),
          secondRoot: root,
          proof: proof.map(unhex),
        });
        if (!anchored) {
          issues.push(`checkpoint at size ${size} is not consistent with this bundle's root — history was rewritten`);
        }
      }
    } catch (err) {
      issues.push(`checkpoint at size ${size}: malformed consistency evidence: ${err?.message ?? err}`);
      anchored = false;
    }
    if (anchored && ok && (best === null || size > best)) best = size;
  }
  return best;
}

/**
 * Verify an evidence bundle standing alone. Never throws: anything unexpected
 * is reported as a failed verification, because a caller can misread a crash as
 * "could not check, so carry on".
 *
 * @param {any} bundle
 * @param {{ expectRoot?: string, minWitnesses?: number }} [opts]
 */
export async function verifyBundle(bundle, opts = {}) {
  try {
    return await verifyBundleUnchecked(bundle, opts);
  } catch (err) {
    return {
      ok: false,
      issues: [`could not verify this bundle: ${err?.message ?? err}`],
      checked: 0,
      summary: null,
      badSeqs: new Set(),
    };
  }
}
