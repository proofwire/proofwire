import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { canonicalize, canonicalBytes } from './canonical.js';
import { hex, unhex } from './hash.js';
import { MerkleTree, leafHash, verifyInclusion, verifyConsistency } from './merkle.js';
import { generateIdentity, identityFromPem, identityFromPublicKey } from './keys.js';
import {
  buildReceipt,
  signReceipt,
  entryHash,
  verifyChain,
  verifyReceipt,
  openSeal,
  GENESIS_PREV,
} from './receipt.js';
import { buildCheckpoint, signCheckpoint, verifyCheckpoint } from './checkpoint.js';

/** Bundle kinds this verifier accepts: the current one, and the one written before the rename. */
const BUNDLE_KINDS = new Set(['vouchwell.bundle', 'proofwire.bundle']);

/**
 * A local, file-backed transparency log.
 *
 * Layout under the log directory:
 *
 *   config.json        log id, creation time, signing key id
 *   key.pem            Ed25519 private key — the one file that must not leave
 *   keyring.json       kid → public key, for every key that has ever signed here
 *   entries.jsonl      one canonical receipt per line, append-only
 *   checkpoints.jsonl  signed tree heads, append-only
 *   salts.jsonl        commitment salts — the only file holding anything
 *                      sensitive, and the one you delete to crypto-shred
 *
 * Writes are synchronous on purpose. An audit log that returns before the
 * record is durable will, on the one day it matters, be missing the record
 * that matters.
 */

const FILES = {
  config: 'config.json',
  key: 'key.pem',
  keyring: 'keyring.json',
  entries: 'entries.jsonl',
  checkpoints: 'checkpoints.jsonl',
  salts: 'salts.jsonl',
};

/**
 * @param {string} file
 * @returns {string[]} Non-empty lines.
 */
function readLines(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split('\n').filter((l) => l.trim() !== '');
}

export class ProofLog {
  /**
   * @param {string} dir
   * @param {object} state
   * @private
   */
  constructor(dir, state) {
    this.dir = dir;
    /** @type {{ log: string, created: string, kid: string }} */
    this.config = state.config;
    /** @type {import('./keys.js').Identity} */
    this.identity = state.identity;
    /** @type {import('./receipt.js').Keyring} */
    this.keyring = state.keyring;
    /** @type {import('./receipt.js').Receipt[]} */
    this.entries = state.entries;
    /** @type {MerkleTree} */
    this.tree = state.tree;
    /** @type {string} */
    this.head = state.head;
  }

  /**
   * Create a new log, generating a fresh signing identity.
   *
   * @param {string} dir
   * @param {object} [opts]
   * @param {string} [opts.logId]
   * @returns {ProofLog}
   */
  static create(dir, opts = {}) {
    if (fs.existsSync(path.join(dir, FILES.config))) {
      throw new Error(`a Vouchwell log already exists at ${dir}`);
    }
    fs.mkdirSync(dir, { recursive: true });

    const { identity, privateKeyPem } = generateIdentity();
    const config = {
      log: opts.logId ?? 'lg_' + randomBytes(8).toString('hex'),
      created: new Date().toISOString(),
      kid: identity.kid,
    };

    fs.writeFileSync(path.join(dir, FILES.config), JSON.stringify(config, null, 2) + '\n');
    // 0600 is advisory on Windows but correct and enforced on POSIX.
    fs.writeFileSync(path.join(dir, FILES.key), privateKeyPem, { mode: 0o600 });
    fs.writeFileSync(
      path.join(dir, FILES.keyring),
      JSON.stringify({ [identity.kid]: identity.publicKey }, null, 2) + '\n',
    );
    fs.writeFileSync(path.join(dir, FILES.entries), '');
    fs.writeFileSync(path.join(dir, FILES.checkpoints), '');
    fs.writeFileSync(path.join(dir, FILES.salts), '', { mode: 0o600 });

    return ProofLog.open(dir);
  }

  /**
   * Open an existing log, rebuilding the Merkle tree from the entry file.
   *
   * @param {string} dir
   * @param {object} [opts]
   * @param {boolean} [opts.readOnly=false]  Skip loading the private key — the
   *   mode an auditor uses, and the mode that cannot accidentally append.
   * @returns {ProofLog}
   */
  static open(dir, opts = {}) {
    const configPath = path.join(dir, FILES.config);
    if (!fs.existsSync(configPath)) {
      throw new Error(`no Vouchwell log at ${dir} (run \`vw init\` first)`);
    }
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

    /** @type {import('./receipt.js').Keyring} */
    const keyring = JSON.parse(fs.readFileSync(path.join(dir, FILES.keyring), 'utf8'));

    let identity;
    if (opts.readOnly) {
      identity = identityFromPublicKey(keyring[config.kid]);
    } else {
      identity = identityFromPem(fs.readFileSync(path.join(dir, FILES.key), 'utf8'));
      if (identity.kid !== config.kid) {
        throw new Error(
          `key.pem does not match config: key is ${identity.kid}, config says ${config.kid}`,
        );
      }
    }

    /** @type {import('./receipt.js').Receipt[]} */
    const entries = [];
    const tree = new MerkleTree();
    let head = GENESIS_PREV;

    for (const [i, line] of readLines(path.join(dir, FILES.entries)).entries()) {
      let receipt;
      try {
        receipt = JSON.parse(line);
      } catch (err) {
        throw new Error(`entries.jsonl line ${i + 1} is not valid JSON: ${err.message}`);
      }
      entries.push(receipt);
      tree.append(leafHash(canonicalBytes(receipt)));
      head = entryHash(receipt);
    }

    return new ProofLog(dir, { config, identity, keyring, entries, tree, head });
  }

  /** @returns {number} */
  get size() {
    return this.entries.length;
  }

  /** @returns {string} Current Merkle root, hex. */
  get root() {
    return hex(this.tree.root);
  }

  /** @returns {string} */
  get logId() {
    return this.config.log;
  }

  /**
   * Record an action. Returns the signed, durable receipt.
   *
   * @param {object} args
   * @param {import('./receipt.js').Actor} args.actor
   * @param {{ kind: string, target: string, params: unknown }} args.action
   * @param {import('./receipt.js').Decision} args.decision
   * @param {null | { status: 'ok'|'error', code?: string, latencyMs?: number, payload?: unknown }} [args.result]
   * @param {'atomic'|'intent'|'outcome'} [args.phase]
   * @param {string} [args.ref]
   * @param {{ params?: boolean, result?: boolean }} [args.previews]  See `buildReceipt`.
   * @returns {import('./receipt.js').Receipt}
   */
  append(args) {
    if (!this.identity.privateKeyObject) {
      throw new Error('log is open read-only; cannot append');
    }
    const { body, salts } = buildReceipt({
      log: this.config.log,
      seq: this.entries.length,
      prev: this.head,
      ...args,
    });
    const receipt = signReceipt(this.identity, body);

    // Durable before in-memory: if the process dies mid-append we would rather
    // have an entry on disk that memory never saw than the reverse.
    fs.appendFileSync(path.join(this.dir, FILES.entries), canonicalize(receipt) + '\n');
    // Salts go to their own file so it can be destroyed independently. They
    // are written second: a receipt without its salt is merely unopenable, a
    // salt without its receipt is a dangling secret.
    fs.appendFileSync(
      path.join(this.dir, FILES.salts),
      canonicalize({ seq: receipt.seq, ...salts }) + '\n',
      { mode: 0o600 },
    );

    this.entries.push(receipt);
    this.tree.append(leafHash(canonicalBytes(receipt)));
    this.head = entryHash(receipt);
    return receipt;
  }

  /**
   * Sign and store the current tree head.
   *
   * @returns {import('./checkpoint.js').Checkpoint}
   */
  checkpoint() {
    const body = buildCheckpoint({
      log: this.config.log,
      size: this.size,
      root: this.root,
      head: this.head,
    });
    const cp = signCheckpoint(this.identity, body, 'log');
    fs.appendFileSync(path.join(this.dir, FILES.checkpoints), canonicalize(cp) + '\n');
    return cp;
  }

  /** @returns {import('./checkpoint.js').Checkpoint[]} */
  checkpoints() {
    return readLines(path.join(this.dir, FILES.checkpoints)).map((l) => JSON.parse(l));
  }

  /**
   * Attach a signature — normally a witness countersignature — to the stored
   * checkpoint at `size`.
   *
   * Obtaining a witness signature and not keeping it would be pointless: the
   * signature is the evidence, and it has to be in the file that gets exported.
   * The checkpoint body is unchanged, so every existing signature over it stays
   * valid; only the signature set grows.
   *
   * @param {number} size
   * @param {import('./checkpoint.js').Signature} signature
   * @returns {import('./checkpoint.js').Checkpoint}
   */
  addSignature(size, signature) {
    const file = path.join(this.dir, FILES.checkpoints);
    const all = this.checkpoints();
    const target = all.find((cp) => cp.body.size === size);
    if (!target) {
      throw new Error(`no checkpoint at size ${size} in this log`);
    }
    // Replacing by kid keeps this idempotent: re-witnessing the same root
    // updates the signature rather than accumulating duplicates.
    target.sigs = [...target.sigs.filter((s) => s.kid !== signature.kid), signature];

    fs.writeFileSync(file, all.map((cp) => canonicalize(cp)).join('\n') + '\n');
    return target;
  }

  /**
   * The commitment salts for one entry, if they still exist.
   *
   * @param {number} seq
   * @returns {{ params?: string, result?: string }}
   */
  saltsFor(seq) {
    for (const line of readLines(path.join(this.dir, FILES.salts))) {
      const row = JSON.parse(line);
      if (row.seq === seq) {
        const { seq: _drop, ...salts } = row;
        return salts;
      }
    }
    return {};
  }

  /**
   * Reveal a payload: confirm that `value` is what entry `seq` committed to.
   *
   * This is how a disclosure works in practice. You hand someone the receipt
   * (safe to publish) and, separately, the payload and its salt. They check
   * the commitment themselves. You never had to put the payload in the log.
   *
   * @param {number} seq
   * @param {'params'|'result'} which
   * @param {unknown} value
   * @returns {boolean}
   */
  reveal(seq, which, value) {
    const receipt = this.entries[seq];
    if (!receipt) return false;
    const sealed = which === 'params' ? receipt.action.params : receipt.result?.payload;
    if (!sealed) return false;
    return openSeal(sealed, this.saltsFor(seq)[which], value);
  }

  /**
   * Crypto-shred: destroy the salts, permanently, for matching entries.
   *
   * After this the commitments cannot be opened by us, by a court, or by a
   * future attacker who steals the whole directory — while every signature,
   * chain link and inclusion proof still verifies. An erasure request and an
   * immutable audit trail stop being in conflict.
   *
   * @param {(receipt: import('./receipt.js').Receipt) => boolean} predicate
   * @returns {number} How many entries were shredded.
   */
  shred(predicate) {
    const doomed = new Set(this.entries.filter(predicate).map((r) => r.seq));
    if (doomed.size === 0) return 0;
    const file = path.join(this.dir, FILES.salts);
    const kept = readLines(file).filter((l) => !doomed.has(JSON.parse(l).seq));
    fs.writeFileSync(file, kept.length ? kept.join('\n') + '\n' : '', { mode: 0o600 });
    return doomed.size;
  }

  /**
   * Register another party's public key so their signatures verify here.
   *
   * @param {string} kid
   * @param {string} publicKey  base64url
   */
  trustKey(kid, publicKey) {
    this.keyring = { ...this.keyring, [kid]: publicKey };
    fs.writeFileSync(
      path.join(this.dir, FILES.keyring),
      JSON.stringify(this.keyring, null, 2) + '\n',
    );
  }

  /**
   * A portable proof that entry `seq` is in the log at the current size.
   *
   * @param {number} seq
   * @returns {{ log: string, seq: number, treeSize: number, root: string, leaf: string, proof: string[] }}
   */
  proofFor(seq) {
    if (!Number.isInteger(seq) || seq < 0 || seq >= this.size) {
      throw new RangeError(`no entry ${seq} in a log of ${this.size}`);
    }
    return {
      log: this.config.log,
      seq,
      treeSize: this.size,
      root: this.root,
      leaf: hex(this.tree.leaves[seq]),
      proof: this.tree.inclusionProof(seq).map(hex),
    };
  }

  /**
   * Full local audit: signatures, chain links, tree consistency, and every
   * historical checkpoint replayed against the log as it stands now.
   *
   * @returns {{ ok: boolean, size: number, root: string, issues: import('./receipt.js').VerifyIssue[] }}
   */
  audit() {
    const chain = verifyChain(this.entries, this.keyring);
    const issues = [...chain.issues];

    // Every entry must actually sit where the tree says it does.
    for (let i = 0; i < this.entries.length; i++) {
      const ok = verifyInclusion({
        leafHash: this.tree.leaves[i],
        index: i,
        treeSize: this.size,
        proof: this.tree.inclusionProof(i),
        root: this.tree.root,
      });
      if (!ok) {
        issues.push({ seq: i, kind: 'chain', message: 'entry is not provably in the tree' });
      }
    }

    // Replay history: each past checkpoint must still describe a prefix of the
    // log we hold. This is what catches an edit made after a root was published.
    for (const cp of this.checkpoints()) {
      const sigCheck = verifyCheckpoint(cp, this.keyring);
      if (!sigCheck.ok) {
        for (const m of sigCheck.issues) {
          issues.push({ kind: 'signature', message: `checkpoint at size ${cp.body.size}: ${m}` });
        }
        continue;
      }
      if (cp.body.size > this.size) {
        issues.push({
          kind: 'chain',
          message:
            `a signed checkpoint covers ${cp.body.size} entries but the log holds ` +
            `only ${this.size} — entries have been removed`,
        });
        continue;
      }
      const ok = verifyConsistency({
        firstSize: cp.body.size,
        secondSize: this.size,
        firstRoot: unhex(cp.body.root),
        secondRoot: this.tree.root,
        proof: this.tree.consistencyProof(cp.body.size).map((b) => b),
      });
      if (!ok) {
        issues.push({
          kind: 'chain',
          message:
            `the log no longer extends the checkpoint signed at size ${cp.body.size} ` +
            `(${cp.body.ts}) — history was rewritten`,
        });
      }
    }

    return { ok: issues.length === 0, size: this.size, root: this.root, issues };
  }

  /**
   * An evidence bundle: everything an outside party needs to verify this log,
   * and nothing they need to trust us about.
   *
   * Receipts are publishable by construction — the salts live elsewhere and
   * are never included — so there is no "sanitise before sending" step here
   * to get wrong.
   *
   * @param {object} [opts]
   * @param {(r: import('./receipt.js').Receipt) => boolean} [opts.filter]
   * @returns {object}
   */
  bundle(opts = {}) {
    const selected = opts.filter ? this.entries.filter(opts.filter) : this.entries;
    const entries = selected;
    const checkpoints = this.checkpoints();
    return {
      v: 1,
      kind: 'vouchwell.bundle',
      log: this.config.log,
      exported: new Date().toISOString(),
      treeSize: this.size,
      root: this.root,
      head: this.head,
      keyring: this.keyring,
      checkpoints,
      consistency: consistencyFor(this.tree, checkpoints),
      partial: selected.length !== this.entries.length,
      // Inclusion proofs let a filtered bundle still tie each entry to the
      // full-log root, so exporting a subset proves no selective omission
      // within it.
      entries: entries.map((receipt, i) => ({
        receipt,
        proof: this.tree.inclusionProof(selected[i].seq).map(hex),
      })),
    };
  }
}

/**
 * Consistency proofs from the latest witnessed checkpoint to the bundle's
 * root, keyed by the checkpoint's size.
 *
 * A filtered bundle cannot rebuild the tree, so without this its entries could
 * only be tied to a witnessed checkpoint taken at exactly the bundle's size.
 * One proof is enough for a verifier to anchor the witnesses, and one keeps an
 * export at a single O(n) pass however many checkpoints the log has taken.
 *
 * @param {MerkleTree} tree
 * @param {import('./checkpoint.js').Checkpoint[]} checkpoints
 * @returns {Record<string, string[]>}
 */
export function consistencyFor(tree, checkpoints) {
  const witnessed = checkpoints
    .filter((cp) => (cp.sigs ?? []).some((s) => s.role === 'witness'))
    .map((cp) => cp.body.size)
    .filter((size) => Number.isInteger(size) && size > 0 && size < tree.size);
  if (witnessed.length === 0) return {};
  const size = Math.max(...witnessed);
  return { [size]: tree.consistencyProof(size).map(hex) };
}

/**
 * Verify an evidence bundle standing alone — no access to the original log.
 *
 * This is the function an auditor, regulator, or opposing counsel runs. It
 * deliberately takes nothing but the bundle and, optionally, a root they
 * obtained independently.
 *
 * @param {object} bundle
 * @param {object} [opts]
 * @param {string} [opts.expectRoot]  A root from a witness or a prior export.
 * @param {number} [opts.minWitnesses=0]
 * @returns {{ ok: boolean, issues: string[], checked: number }}
 */
function verifyBundleUnchecked(bundle, opts = {}) {
  /** @type {string[]} */
  const issues = [];

  // `proofwire.bundle` is what the project wrote before it was renamed
  // Vouchwell (0.5.0 and earlier). The kind is a label, not signed; the
  // receipts and checkpoints inside verify exactly as they always did.
  if (!BUNDLE_KINDS.has(bundle?.kind) || bundle.v !== 1) {
    return { ok: false, issues: ['not a Vouchwell v1 bundle'], checked: 0 };
  }
  const keyring = bundle.keyring ?? {};
  let root;
  try {
    root = unhex(bundle.root);
  } catch {
    return { ok: false, issues: ['bundle root is not valid hex'], checked: 0 };
  }

  if (opts.expectRoot && opts.expectRoot !== bundle.root) {
    issues.push(
      `bundle root ${bundle.root.slice(0, 16)}… does not match the expected ` +
        `${opts.expectRoot.slice(0, 16)}… — you were shown a different history`,
    );
  }

  // Witnesses are only evidence if the verifier chose them. A bundle's own
  // keyring is supplied by the party under suspicion, so it cannot vouch for
  // witnesses: asking for N without saying whose keys to trust is refused
  // rather than answered by counting whatever the bundle happens to contain.
  const minWitnesses = opts.minWitnesses ?? 0;
  if (!Number.isInteger(minWitnesses) || minWitnesses < 0) {
    // A NaN here used to compare false against everything and so quietly
    // switched the witness requirement off.
    return {
      ok: false,
      issues: [`minWitnesses must be a non-negative integer, got ${String(opts.minWitnesses)}`],
      checked: 0,
    };
  }
  const trustedWitnesses =
    opts.trustedWitnesses && typeof opts.trustedWitnesses === 'object'
      ? opts.trustedWitnesses
      : undefined;
  if (minWitnesses > 0 && !trustedWitnesses) {
    issues.push(
      `${minWitnesses} witness signature(s) required, but no trusted witness keys were ` +
        `supplied — a bundle's own keyring cannot vouch for its witnesses`,
    );
  }

  /** @type {{ cp: any, ok: boolean }[]} */
  const checkpointResults = [];
  for (const cp of bundle.checkpoints ?? []) {
    const res = verifyCheckpoint(cp, keyring, {
      minWitnesses: trustedWitnesses ? minWitnesses : 0,
      trustedWitnesses,
    });
    checkpointResults.push({ cp, ok: res.ok });
    if (!res.ok) {
      issues.push(`checkpoint at size ${cp.body?.size}: ${res.issues.join('; ')}`);
    }
  }

  let checked = 0;
  /** @type {import('./receipt.js').Receipt[]} */
  const receipts = [];
  /** @type {Buffer[]} */
  const leaves = [];

  for (const entry of bundle.entries ?? []) {
    // A verifier is fed hostile data by definition. One malformed entry has to
    // be reported, not allowed to throw and take the whole check down with it.
    try {
      const { receipt, proof } = entry;
      // Everything below assumes an object with a sequence number. Anything
      // else is reported here, before it can reach code that would throw.
      if (!receipt || typeof receipt !== 'object' || !Number.isInteger(receipt.seq)) {
        throw new Error('entry carries no receipt with a sequence number');
      }
      const leaf = leafHash(canonicalBytes(receipt));
      receipts.push(receipt);
      leaves.push(leaf);

      const ok = verifyInclusion({
        leafHash: leaf,
        index: receipt.seq,
        treeSize: bundle.treeSize,
        proof: (proof ?? []).map(unhex),
        root,
      });
      if (!ok) {
        issues.push(`entry ${receipt.seq} is not provably part of the logged tree`);
      }
    } catch (err) {
      issues.push(`malformed entry: ${/** @type {Error} */ (err).message}`);
    }
    checked++;
  }

  // ── what the bundle claims about itself ────────────────────────────────
  //
  // Every inclusion proof above can be perfectly genuine while entries have
  // simply been left out, so the *contents* of a bundle passing says nothing
  // about whether it is the *whole* log. A bundle that declares itself
  // complete has to actually be, and its own summary fields have to agree with
  // the entries it carries.
  //
  // This was missing: a bundle with its last entries removed and `partial`
  // left false verified clean, as did one whose `head` had been replaced.
  const treeSize = bundle.treeSize;
  if (!Number.isInteger(treeSize) || treeSize < 0) {
    issues.push('bundle treeSize is not a non-negative integer');
  }

  // The head names the last entry. When that entry is present — always, in a
  // complete bundle — the claim can simply be checked.
  const tip = receipts.find((r) => r.seq === treeSize - 1);
  if (tip && entryHash(tip) !== bundle.head) {
    issues.push(
      `bundle head ${String(bundle.head).slice(0, 16)}… is not the hash of its final entry`,
    );
  }

  /** @type {Map<number, string> | null} */
  let prefixRoots = null;
  if (!bundle.partial) {
    if (receipts.length !== treeSize) {
      issues.push(
        `bundle is marked complete but holds ${receipts.length} of ${treeSize} entries — ` +
          `entries were left out`,
      );
    } else {
      // Rebuild the tree from the entries alone. One incremental pass yields
      // the final root and every historical root a checkpoint names, without
      // the quadratic cost of recomputing each from scratch.
      const wanted = new Set(
        (bundle.checkpoints ?? []).map((cp) => cp?.body?.size).filter(Number.isInteger),
      );
      const tree = new MerkleTree();
      /** @type {Map<number, string>} */
      // A checkpoint of the empty log is legitimate and names the empty root.
      // Without this entry it was compared against nothing and reported as a
      // rewritten history: a false tampering alarm.
      prefixRoots = new Map(wanted.has(0) ? [[0, hex(new MerkleTree().root)]] : []);
      leaves.forEach((leaf, k) => {
        tree.append(leaf);
        if (wanted.has(k + 1)) prefixRoots.set(k + 1, hex(tree.root));
      });

      if (hex(tree.root) !== bundle.root) {
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

  // ── which checkpoints vouch for *these* entries ────────────────────────
  //
  // A checkpoint's signatures prove only that someone signed that body. For
  // witnesses to say anything about this bundle, the checkpoint's root has to
  // be tied to the bundle's own tree: rebuilt from the entries when the bundle
  // is complete, equal to the bundle root at the same size, or linked to it by
  // a consistency proof. Without this a filtered bundle of forged entries
  // passed a witness check by carrying a genuine witnessed checkpoint of some
  // other log, and a bundle with no checkpoints at all passed any minimum.
  const witnessedSize = anchorCheckpoints({
    bundle, root, treeSize, prefixRoots, checkpointResults, issues,
  });
  if (trustedWitnesses && minWitnesses > 0 && witnessedSize === null) {
    issues.push(
      `no checkpoint carrying ${minWitnesses} trusted witness signature(s) covers this ` +
        `bundle's entries — nothing independent vouches for this history`,
    );
  }

  // A complete bundle must also form an unbroken chain. A filtered one cannot,
  // by construction, so inclusion proofs carry the weight there instead.
  try {
    if (!bundle.partial) {
      const chain = verifyChain(receipts, keyring);
      for (const i of chain.issues) issues.push(`entry ${i.seq}: ${i.message}`);
    } else {
      for (const receipt of receipts) {
        for (const i of verifyReceipt(receipt, keyring)) {
          issues.push(`entry ${i.seq}: ${i.message}`);
        }
      }
    }
  } catch (err) {
    // Malformed fields inside an otherwise well-shaped receipt. Report it as
    // a failure of the bundle; never let it escape as an exception that a
    // caller might mistake for "could not check, so carry on".
    issues.push(`could not verify the receipts: ${/** @type {Error} */ (err).message}`);
  }

  return {
    ok: issues.length === 0,
    issues,
    checked,
    // How many leading entries a checkpoint meeting the witness requirement
    // covers. Entries at or past this are signed by the log alone.
    ...(trustedWitnesses && minWitnesses > 0 ? { witnessedSize: witnessedSize ?? 0 } : {}),
  };
}

/**
 * Tie each valid checkpoint to the bundle's tree, reporting any that
 * contradict it, and return the largest size covered by one that passed
 * verification (null when none did).
 *
 * @param {object} a
 * @param {any} a.bundle
 * @param {Buffer} a.root
 * @param {unknown} a.treeSize
 * @param {Map<number, string> | null} a.prefixRoots  Set when the tree was rebuilt.
 * @param {{ cp: any, ok: boolean }[]} a.checkpointResults
 * @param {string[]} a.issues
 * @returns {number | null}
 */
function anchorCheckpoints({ bundle, root, treeSize, prefixRoots, checkpointResults, issues }) {
  if (!Number.isInteger(treeSize)) return null;
  const n = /** @type {number} */ (treeSize);
  const proofs = bundle.consistency && typeof bundle.consistency === 'object' ? bundle.consistency : {};
  let best = null;

  for (const { cp, ok } of checkpointResults) {
    const size = cp?.body?.size;
    if (!Number.isInteger(size) || size < 0) continue;
    let anchored = false;
    try {
      if (prefixRoots) {
        // Complete bundle: any disagreement was reported above.
        anchored = size <= n && prefixRoots.get(size) === cp.body.root;
      } else if (size > n) {
        issues.push(`checkpoint at size ${size} covers more entries than this bundle holds`);
      } else if (size === n) {
        anchored = cp.body.root === bundle.root;
        if (!anchored) {
          issues.push(
            `checkpoint at size ${size} names root ${String(cp.body.root).slice(0, 16)}…, but ` +
              `this bundle's root is ${String(bundle.root).slice(0, 16)}… — history was rewritten`,
          );
        }
      } else if (size === 0) {
        anchored = cp.body.root === hex(new MerkleTree().root);
      } else if (Object.prototype.hasOwnProperty.call(proofs, String(size))) {
        const proof = proofs[String(size)];
        if (!Array.isArray(proof)) throw new Error('consistency proof is not a list');
        anchored = verifyConsistency({
          firstSize: size,
          secondSize: n,
          firstRoot: unhex(cp.body.root),
          secondRoot: root,
          proof: proof.map(unhex),
        });
        if (!anchored) {
          issues.push(
            `checkpoint at size ${size} is not consistent with this bundle's root — history was rewritten`,
          );
        }
      }
    } catch (err) {
      issues.push(`checkpoint at size ${size}: malformed consistency evidence: ${/** @type {Error} */ (err).message}`);
      anchored = false;
    }
    if (anchored && ok && (best === null || size > best)) best = size;
  }
  return best;
}

/**
 * Verify an evidence bundle standing alone. Never throws.
 *
 * A verifier is fed hostile data by definition, and an exception is the worst
 * thing it can return: a caller can read "it crashed" as "it could not check,
 * so carry on". Anything unexpected becomes a failed verification instead.
 *
 * @param {object} bundle
 * @param {object} [opts]
 * @param {string} [opts.expectRoot]  A root from a witness or a prior export.
 * @param {number} [opts.minWitnesses=0]  Require this many valid witness
 *   signatures on every checkpoint. Needs `trustedWitnesses`.
 * @param {Record<string, string>} [opts.trustedWitnesses]  kid → public key
 *   (base64url) of the witnesses you chose, obtained from outside the bundle.
 * @returns {{ ok: boolean, issues: string[], checked: number }}
 */
export function verifyBundle(bundle, opts = {}) {
  try {
    return verifyBundleUnchecked(bundle, opts);
  } catch (err) {
    return {
      ok: false,
      issues: [`could not verify this bundle: ${/** @type {Error} */ (err).message}`],
      checked: 0,
    };
  }
}
