import { createHash } from 'node:crypto';
import {
  MerkleTree,
  leafHash,
  canonicalBytes,
  canonicalize,
  verifyReceipt,
  entryHash,
  hex,
  unhex,
  verifyInclusion,
  verifyConsistency,
  GENESIS_PREV,
  buildCheckpoint,
  signCheckpointWith,
  identityFromPem,
  generateIdentity,
  consistencyFor,
  DEFAULT_GRACE_MS,
} from '@deedwrit/core';
import { newId, now, today, transact } from './db.js';

/**
 * The hub's view of a customer's logs.
 *
 * The central design commitment: **the hub is not trusted and does not need to
 * be.** It never holds an agent's signing key, so it cannot manufacture a
 * receipt. What it can do — drop entries, reorder them, show two customers two
 * different histories — is exactly what the chain check on ingest and the
 * witnessed checkpoints afterwards are there to catch.
 *
 * That constraint drives the one rule this file never bends: **nothing is
 * stored that has not been verified first.** A hub that accepts a receipt it
 * cannot verify produces an audit trail nobody can rely on, which is worse
 * than having none, because it looks like one.
 */

export class Store {
  /**
   * @param {import('node:sqlite').DatabaseSync} db
   */
  constructor(db) {
    this.db = db;
    /**
     * Per-log Merkle trees, kept warm so an append is O(log n) rather than a
     * full reload. Bounded, because an idle tenant's tree should not pin
     * memory forever.
     * @type {Map<string, { tree: MerkleTree, touched: number }>}
     */
    this._trees = new Map();
    this._maxTrees = 64;
    /**
     * Told the organisation after each audit event is committed, so event
     * streaming can pick it up. Never allowed to fail the event.
     * @type {((orgId: string) => void) | null}
     */
    this.onAuditEvent = null;
  }

  // ── tenancy ───────────────────────────────────────────────────────────

  /**
   * @param {object} args
   * @param {string} args.slug
   * @param {string} args.name
   * @param {string} [args.plan]
   * @returns {object}
   */
  createOrg(args) {
    const org = {
      id: newId('org'),
      slug: args.slug,
      name: args.name,
      plan: args.plan ?? 'open',
      settings: '{}',
      created_at: now(),
    };
    this.db
      .prepare(
        `INSERT INTO orgs(id, slug, name, plan, settings, created_at)
         VALUES(?, ?, ?, ?, ?, ?)`,
      )
      .run(org.id, org.slug, org.name, org.plan, org.settings, org.created_at);
    return org;
  }

  /** @param {string} id */
  org(id) {
    return this.db.prepare('SELECT * FROM orgs WHERE id = ?').get(id) ?? null;
  }

  /** @param {string} slug */
  orgBySlug(slug) {
    return this.db.prepare('SELECT * FROM orgs WHERE slug = ?').get(slug) ?? null;
  }

  // ── logs ──────────────────────────────────────────────────────────────

  /**
   * Register a log and the public key that is allowed to write to it.
   *
   * The key is bound at creation and never changes. Rotation creates a new
   * log: a single chain signed by two different keys over its lifetime is a
   * chain whose validity depends on knowing exactly when the swap happened,
   * which is a fact the log itself cannot establish.
   *
   * @param {object} args
   * @param {string} args.orgId
   * @param {string} args.slug        Human-facing name, chosen by the operator.
   * @param {string} args.kid
   * @param {string} args.publicKey
   * @param {string} [args.canonical]  The identifier the agent writes into the
   *   `log` field of every receipt it signs. Defaults to the slug. This is what
   *   ingest checks, because it is the half that is signed.
   * @param {string} [args.name]
   * @returns {object}
   */
  createLog(args) {
    const existing = this.db
      .prepare('SELECT * FROM logs WHERE org_id = ? AND slug = ?')
      .get(args.orgId, args.slug);
    if (existing) {
      if (existing.kid !== args.kid) {
        throw new StoreError(
          409,
          'log_key_mismatch',
          `log "${args.slug}" is already registered to key ${existing.kid}; ` +
            `register a new log rather than rebinding this one`,
        );
      }
      return existing;
    }

    const log = {
      id: newId('log'),
      org_id: args.orgId,
      slug: args.slug,
      canonical: args.canonical ?? args.slug,
      name: args.name ?? args.slug,
      kid: args.kid,
      public_key: args.publicKey,
      size: 0,
      head: GENESIS_PREV,
      root: hex(new MerkleTree().root),
      created_at: now(),
    };
    this.db
      .prepare(
        `INSERT INTO logs(id, org_id, slug, canonical, name, kid, public_key, size, head, root, created_at)
         VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        log.id, log.org_id, log.slug, log.canonical, log.name, log.kid, log.public_key,
        log.size, log.head, log.root, log.created_at,
      );
    return log;
  }

  /**
   * Always scoped by org. There is deliberately no `logById(id)` without a
   * tenant: a caller holding an id from somewhere else must not be able to
   * read across the boundary by guessing or by leaking one.
   *
   * @param {string} orgId
   * @param {string} logId
   */
  log(orgId, logId) {
    return (
      this.db.prepare('SELECT * FROM logs WHERE org_id = ? AND id = ?').get(orgId, logId) ?? null
    );
  }

  /**
   * @param {string} orgId
   * @param {string} slug
   */
  logBySlug(orgId, slug) {
    return (
      this.db.prepare('SELECT * FROM logs WHERE org_id = ? AND slug = ?').get(orgId, slug) ?? null
    );
  }

  /** @param {string} orgId */
  logs(orgId) {
    return this.db
      .prepare('SELECT * FROM logs WHERE org_id = ? ORDER BY created_at DESC')
      .all(orgId);
  }

  // ── merkle ────────────────────────────────────────────────────────────

  /**
   * The Merkle tree for a log, loaded from stored leaf hashes on first use.
   *
   * @param {string} logId
   * @returns {MerkleTree}
   */
  tree(logId) {
    const cached = this._trees.get(logId);
    if (cached) {
      cached.touched = Date.now();
      return cached.tree;
    }

    const rows = this.db
      .prepare('SELECT hash FROM receipts WHERE log_id = ? ORDER BY seq ASC')
      .all(logId);
    const tree = new MerkleTree(rows.map((r) => unhex(r.hash)));

    if (this._trees.size >= this._maxTrees) {
      // Drop the least recently touched tree. Rebuilding costs one scan.
      let oldest = null;
      for (const [id, v] of this._trees) {
        if (!oldest || v.touched < oldest[1].touched) oldest = [id, v];
      }
      if (oldest) this._trees.delete(oldest[0]);
    }
    this._trees.set(logId, { tree, touched: Date.now() });
    return tree;
  }

  /** @param {string} logId */
  forgetTree(logId) {
    this._trees.delete(logId);
  }

  // ── ingest ────────────────────────────────────────────────────────────

  /**
   * Append a batch of receipts to a log, verifying every one first.
   *
   * Four checks, in order, and any failure rejects the whole batch:
   *
   *   1. **Signature** against the key bound to this log at creation.
   *   2. **Log identity** — the receipt names the log it claims to be in.
   *   3. **Sequence** — contiguous from the hub's current size.
   *   4. **Chain** — `prev` equals the hub's current head.
   *
   * Rejecting the whole batch rather than the first valid prefix is
   * deliberate. A partial accept leaves the client's idea of the head and the
   * hub's silently diverged, and the next batch fails for a reason that has
   * nothing to do with what actually went wrong.
   *
   * @param {object} args
   * @param {string} args.orgId
   * @param {string} args.logId
   * @param {import('@deedwrit/core').Receipt[]} args.receipts
   * @param {string} [args.batchId]  Client-supplied; makes a retry idempotent.
   * @returns {{ accepted: number, size: number, head: string, root: string, duplicate: boolean }}
   */
  ingest(args) {
    const log = this.log(args.orgId, args.logId);
    if (!log) throw new StoreError(404, 'no_such_log', 'no such log in this organization');
    if (log.archived_at) {
      throw new StoreError(409, 'log_archived', 'this log is archived and accepts no new receipts');
    }

    if (args.batchId) {
      const seen = this.db
        .prepare('SELECT * FROM ingest_batches WHERE id = ? AND log_id = ?')
        .get(args.batchId, args.logId);
      if (seen) {
        // A retry of a batch we already committed. Returning the original
        // result is what makes at-least-once delivery safe for the client.
        return {
          accepted: seen.accepted,
          size: seen.size,
          head: seen.head,
          root: seen.root,
          duplicate: true,
        };
      }
    }

    if (!Array.isArray(args.receipts) || args.receipts.length === 0) {
      throw new StoreError(400, 'empty_batch', 'a batch must contain at least one receipt');
    }

    const keyring = { [log.kid]: log.public_key };
    const tree = this.tree(log.id);

    let expectSeq = log.size;
    let expectPrev = log.head;
    /** @type {{ receipt: any, hash: string, leaf: Buffer }[]} */
    const prepared = [];

    for (const receipt of args.receipts) {
      const issues = verifyReceipt(receipt, keyring);
      if (issues.length > 0) {
        throw new StoreError(
          422,
          'receipt_rejected',
          `receipt ${receipt?.seq} rejected: ${issues.map((i) => i.message).join('; ')}`,
          { seq: receipt?.seq, issues },
        );
      }
      // The receipt names the log it belongs to, and that name is covered by
      // the signature. Checking it stops a receipt from one log being replayed
      // into another, which would otherwise be a valid signature in the wrong
      // place.
      if (receipt.log !== log.canonical && receipt.log !== log.slug && receipt.log !== log.id) {
        throw new StoreError(
          422,
          'wrong_log',
          `receipt ${receipt.seq} names log "${receipt.log}" but this log is registered ` +
            `as "${log.canonical}"`,
        );
      }
      if (receipt.seq !== expectSeq) {
        throw new StoreError(
          409,
          'sequence_gap',
          `expected seq ${expectSeq}, got ${receipt.seq} — resend from ${expectSeq}`,
          { expected: expectSeq, got: receipt.seq, head: log.head },
        );
      }
      if (receipt.prev !== expectPrev) {
        throw new StoreError(
          409,
          'chain_mismatch',
          `receipt ${receipt.seq} chains to ${receipt.prev.slice(0, 12)}… but this log's head ` +
            `is ${expectPrev.slice(0, 12)}…`,
          { expected: expectPrev, got: receipt.prev },
        );
      }

      const hash = entryHash(receipt);
      prepared.push({ receipt, hash, leaf: leafHash(canonicalBytes(receipt)) });
      expectSeq++;
      expectPrev = hash;
    }

    return transact(this.db, () => {
      const insert = this.db.prepare(
        `INSERT INTO receipts(
           log_id, seq, org_id, hash, prev, ts, phase, ref, kind, target, outcome,
           principal, agent, session, status, latency_ms, metrics, body, received_at)
         VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      );
      const receivedAt = now();
      let denials = 0;

      for (const { receipt, hash } of prepared) {
        insert.run(
          log.id,
          receipt.seq,
          log.org_id,
          hash,
          receipt.prev,
          receipt.ts,
          receipt.phase,
          receipt.ref ?? null,
          receipt.action.kind,
          receipt.action.target,
          receipt.decision.outcome,
          receipt.actor.principal,
          receipt.actor.agent,
          receipt.actor.session,
          receipt.result?.status ?? null,
          receipt.result?.latencyMs ?? null,
          canonicalize(receipt.action.metrics ?? {}),
          canonicalize(receipt),
          receivedAt,
        );
        if (receipt.decision.outcome !== 'allow') denials++;
      }

      // The tree is mutated only after the rows are in, so a failed insert
      // cannot leave an in-memory tree ahead of the database.
      for (const { leaf } of prepared) tree.append(leaf);

      const size = log.size + prepared.length;
      const head = prepared[prepared.length - 1].hash;
      const root = hex(tree.root);

      this.db
        .prepare('UPDATE logs SET size = ?, head = ?, root = ?, last_seen_at = ? WHERE id = ?')
        .run(size, head, root, receivedAt, log.id);

      this.db
        .prepare(
          `INSERT INTO usage_daily(org_id, day, receipts, denials) VALUES(?, ?, ?, ?)
           ON CONFLICT(org_id, day) DO UPDATE SET
             receipts = receipts + excluded.receipts,
             denials  = denials  + excluded.denials`,
        )
        .run(log.org_id, today(), prepared.length, denials);

      if (args.batchId) {
        this.db
          .prepare(
            `INSERT INTO ingest_batches(id, log_id, org_id, accepted, first_seq, last_seq, head, root, size, at)
             VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .run(
            args.batchId, log.id, log.org_id, prepared.length,
            prepared[0].receipt.seq, prepared[prepared.length - 1].receipt.seq,
            head, root, size, receivedAt,
          );
      }

      return { accepted: prepared.length, size, head, root, duplicate: false };
    });
  }

  // ── reading ───────────────────────────────────────────────────────────

  /**
   * @param {string} orgId
   * @param {object} [q]
   * @returns {{ entries: object[], total: number }}
   */
  receipts(orgId, q = {}) {
    // Pruned receipts have no content left to list; they still count in the
    // log's size and tree, which is where their existence is proven.
    const where = ['org_id = ?', 'pruned_at IS NULL'];
    const params = [orgId];

    if (q.logId) { where.push('log_id = ?'); params.push(q.logId); }
    if (q.outcome) { where.push('outcome = ?'); params.push(q.outcome); }
    if (q.denied) { where.push("outcome != 'allow'"); }
    if (q.phase) { where.push('phase = ?'); params.push(q.phase); }
    if (q.session) { where.push('session = ?'); params.push(q.session); }
    if (q.principal) { where.push('principal = ?'); params.push(q.principal); }
    if (q.target) { where.push('target LIKE ?'); params.push(`%${q.target}%`); }
    if (q.since) { where.push('ts >= ?'); params.push(q.since); }
    if (q.until) { where.push('ts <= ?'); params.push(q.until); }

    const clause = where.join(' AND ');
    const total = this.db
      .prepare(`SELECT count(*) AS n FROM receipts WHERE ${clause}`)
      .get(...params).n;

    const limit = Math.min(Math.max(Number(q.limit ?? 50), 1), 500);
    const offset = Math.max(Number(q.offset ?? 0), 0);

    const entries = this.db
      .prepare(
        `SELECT log_id, seq, hash, ts, phase, ref, kind, target, outcome,
                principal, agent, session, status, latency_ms, metrics, body
         FROM receipts WHERE ${clause}
         ORDER BY ts DESC, log_id, seq DESC
         LIMIT ? OFFSET ?`,
      )
      .all(...params, limit, offset);

    return { entries, total };
  }

  /**
   * @param {string} orgId
   * @param {string} logId
   * @param {number} seq
   */
  receipt(orgId, logId, seq) {
    return (
      this.db
        .prepare('SELECT * FROM receipts WHERE org_id = ? AND log_id = ? AND seq = ?')
        .get(orgId, logId, seq) ?? null
    );
  }

  /**
   * An inclusion proof for one entry, against the log's current root.
   *
   * @param {string} orgId
   * @param {string} logId
   * @param {number} seq
   */
  proof(orgId, logId, seq) {
    const log = this.log(orgId, logId);
    if (!log) throw new StoreError(404, 'no_such_log', 'no such log in this organization');
    if (!Number.isInteger(seq) || seq < 0 || seq >= log.size) {
      throw new StoreError(404, 'no_such_entry', `no entry ${seq} in a log of ${log.size}`);
    }
    const tree = this.tree(log.id);
    return {
      log: log.slug,
      seq,
      treeSize: log.size,
      root: hex(tree.root),
      leaf: hex(tree.leaves[seq]),
      proof: tree.inclusionProof(seq).map(hex),
    };
  }

  /**
   * A consistency proof between two sizes of the same log — the check that
   * proves nothing was rewritten between them.
   *
   * @param {string} orgId
   * @param {string} logId
   * @param {number} fromSize
   * @param {number} [toSize]
   */
  consistency(orgId, logId, fromSize, toSize) {
    const log = this.log(orgId, logId);
    if (!log) throw new StoreError(404, 'no_such_log', 'no such log in this organization');
    const to = toSize ?? log.size;
    if (fromSize < 0 || fromSize > to || to > log.size) {
      throw new StoreError(400, 'bad_range', `cannot prove ${fromSize} → ${to} in a log of ${log.size}`);
    }
    const tree = this.tree(log.id);
    return {
      log: log.slug,
      fromSize,
      toSize: to,
      fromRoot: hex(tree.rootAt(fromSize)),
      toRoot: hex(tree.rootAt(to)),
      proof: tree.consistencyProof(fromSize, to).map(hex),
    };
  }

  // ── checkpoints ───────────────────────────────────────────────────────

  /**
   * Sign the current tree head.
   *
   * Async because the signer may be a KMS. The signature is produced *before*
   * anything is written, so a signer failure leaves no half-formed checkpoint
   * row claiming a root nobody attested to.
   *
   * @param {string} orgId
   * @param {string} logId
   * @param {import('./signer.js').Signer} signer
   * @returns {Promise<import('@deedwrit/core').Checkpoint>}
   */
  async checkpoint(orgId, logId, signer) {
    const log = this.log(orgId, logId);
    if (!log) throw new StoreError(404, 'no_such_log', 'no such log in this organization');
    if (log.size === 0) {
      throw new StoreError(409, 'empty_log', 'nothing to checkpoint yet');
    }

    const existing = this.db
      .prepare('SELECT * FROM checkpoints WHERE log_id = ? AND size = ?')
      .get(log.id, log.size);
    if (existing) return hydrateCheckpoint(existing);

    const body = buildCheckpoint({
      log: log.slug,
      size: log.size,
      root: log.root,
      head: log.head,
    });
    const cp = await signCheckpointWith(signer, body, 'log');

    this.db
      .prepare(
        `INSERT INTO checkpoints(id, log_id, org_id, size, root, head, ts, body, sigs, witness_count)
         VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
         ON CONFLICT(log_id, size) DO NOTHING`,
      )
      .run(
        newId('checkpoint'), log.id, log.org_id, body.size, body.root, body.head,
        body.ts, canonicalize(body), canonicalize(cp.sigs),
      );

    // Another request may have checkpointed the same size while we were
    // waiting on the signer. Whichever landed first is the one that counts.
    const stored = this.db
      .prepare('SELECT * FROM checkpoints WHERE log_id = ? AND size = ?')
      .get(log.id, log.size);
    return stored ? hydrateCheckpoint(stored) : cp;
  }

  /**
   * @param {string} orgId
   * @param {string} logId
   * @param {number} [limit]
   */
  checkpoints(orgId, logId, limit = 50) {
    return this.db
      .prepare(
        `SELECT * FROM checkpoints WHERE org_id = ? AND log_id = ?
         ORDER BY size DESC LIMIT ?`,
      )
      .all(orgId, logId, limit)
      .map(hydrateCheckpoint);
  }

  /**
   * Attach a witness signature to a stored checkpoint.
   *
   * @param {string} orgId
   * @param {string} logId
   * @param {number} size
   * @param {import('@deedwrit/core').Signature} sig
   */
  addWitnessSignature(orgId, logId, size, sig) {
    const row = this.db
      .prepare('SELECT * FROM checkpoints WHERE org_id = ? AND log_id = ? AND size = ?')
      .get(orgId, logId, size);
    if (!row) throw new StoreError(404, 'no_such_checkpoint', `no checkpoint at size ${size}`);

    const sigs = JSON.parse(row.sigs).filter((s) => s.kid !== sig.kid);
    sigs.push(sig);
    this.db
      .prepare('UPDATE checkpoints SET sigs = ?, witness_count = ? WHERE id = ?')
      .run(
        canonicalize(sigs),
        sigs.filter((s) => s.role === 'witness').length,
        row.id,
      );
    return hydrateCheckpoint({ ...row, sigs: canonicalize(sigs) });
  }

  // ── witnessing ────────────────────────────────────────────────────────

  /**
   * The last root this witness signed for a log, if any.
   *
   * @param {string} witnessKid
   * @param {string} positionKey  `${orgId}:${log}`
   */
  witnessPosition(witnessKid, positionKey) {
    return (
      this.db
        .prepare('SELECT * FROM witness_state WHERE witness_kid = ? AND log_id = ?')
        .get(witnessKid, positionKey) ?? null
    );
  }

  /**
   * The key this witness requires a log's checkpoints to be signed with.
   *
   * @param {string} witnessKid
   * @param {string} positionKey  `${orgId}:${log}`
   * @returns {{ kid: string, public_key: string, bound_at: string, bound_by: string }|null}
   */
  witnessBinding(witnessKid, positionKey) {
    return (
      this.db
        .prepare('SELECT * FROM witness_log_keys WHERE witness_kid = ? AND log_id = ?')
        .get(witnessKid, positionKey) ?? null
    );
  }

  /**
   * Bind (or, for an operator, rebind) a log to a signing key. Never touches
   * the recorded position: a rebind that also reset it would let whoever asked
   * for the rebind rewrite what the witness has already attested to.
   *
   * @param {{ witnessKid: string, positionKey: string, kid: string, publicKey: string, by: 'first-use'|'operator' }} args
   */
  bindWitnessLogKey(args) {
    const boundAt = now();
    this.db
      .prepare(
        `INSERT INTO witness_log_keys(witness_kid, log_id, kid, public_key, bound_at, bound_by)
         VALUES(?, ?, ?, ?, ?, ?)
         ON CONFLICT(witness_kid, log_id) DO UPDATE SET
           kid = excluded.kid, public_key = excluded.public_key,
           bound_at = excluded.bound_at, bound_by = excluded.bound_by`,
      )
      .run(args.witnessKid, args.positionKey, args.kid, args.publicKey, boundAt, args.by);
    return { kid: args.kid, public_key: args.publicKey, bound_at: boundAt, bound_by: args.by };
  }

  /**
   * Set a witness's recorded position outright. Only for catching up from
   * the witness's own journal or a checkpoint it provably signed; co-signing
   * moves the position through `/v1/witness/cosign`, with its checks.
   *
   * @param {string} witnessKid
   * @param {string} positionKey
   * @param {number} size
   * @param {string} root
   */
  setWitnessPosition(witnessKid, positionKey, size, root) {
    this.db
      .prepare(
        `INSERT INTO witness_state(witness_kid, log_id, size, root, updated_at)
         VALUES(?, ?, ?, ?, ?)
         ON CONFLICT(witness_kid, log_id) DO UPDATE SET
           size = excluded.size, root = excluded.root, updated_at = excluded.updated_at`,
      )
      .run(witnessKid, positionKey, size, root, now());
  }

  /**
   * Why this witness won't co-sign for a log, if it won't.
   *
   * @param {string} witnessKid
   * @param {string} positionKey
   * @returns {{ reason: string, since: string } | null}
   */
  witnessHold(witnessKid, positionKey) {
    return /** @type {any} */ (
      this.db
        .prepare('SELECT reason, since FROM witness_holds WHERE witness_kid = ? AND log_id = ?')
        .get(witnessKid, positionKey) ?? null
    );
  }

  /**
   * @param {string} witnessKid
   * @param {string} positionKey
   * @param {string} reason
   */
  holdWitnessLog(witnessKid, positionKey, reason) {
    this.db
      .prepare(
        `INSERT INTO witness_holds(witness_kid, log_id, reason, since) VALUES(?, ?, ?, ?)
         ON CONFLICT(witness_kid, log_id) DO NOTHING`,
      )
      .run(witnessKid, positionKey, reason, now());
  }

  /** @param {string} witnessKid @param {string} positionKey */
  releaseWitnessLog(witnessKid, positionKey) {
    return this.db
      .prepare('DELETE FROM witness_holds WHERE witness_kid = ? AND log_id = ?')
      .run(witnessKid, positionKey).changes > 0;
  }

  // ── retention ─────────────────────────────────────────────────────────

  /**
   * @param {string} orgId
   * @returns {{ days: number | null, capDays: number | null, effectiveDays: number | null, pruned: number, oldest: string | null }}
   */
  retention(orgId) {
    const org = this.org(orgId);
    const days = org?.retention_days ?? null;
    const capDays = org?.retention_cap_days ?? null;
    const counts = this.db
      .prepare(
        `SELECT sum(pruned_at IS NOT NULL) AS pruned, min(CASE WHEN pruned_at IS NULL THEN ts END) AS oldest
         FROM receipts WHERE org_id = ?`,
      )
      .get(orgId);
    return {
      days,
      capDays,
      effectiveDays: effectiveRetention(days, capDays),
      pruned: counts?.pruned ?? 0,
      oldest: counts?.oldest ?? null,
    };
  }

  /**
   * @param {string} orgId
   * @param {{ days?: number | null, capDays?: number | null }} set  Only the keys given change.
   */
  setRetention(orgId, set) {
    if ('days' in set) this.db.prepare('UPDATE orgs SET retention_days = ? WHERE id = ?').run(set.days, orgId);
    if ('capDays' in set) this.db.prepare('UPDATE orgs SET retention_cap_days = ? WHERE id = ?').run(set.capDays, orgId);
  }

  /**
   * Clear the content of an organisation's receipts older than `before`.
   *
   * What goes: the signed body and every column that could identify a person,
   * a customer or a deal: tool, principal, agent, session, metrics, result.
   * What stays: seq, hash and prev, which hold the log's structure, plus ts,
   * phase, kind and outcome, which say nothing about anyone. The tree is built
   * from the hashes, so roots, checkpoints and witness signatures still verify.
   *
   * @param {string} orgId
   * @param {string} before  ISO time; receipts strictly older are pruned.
   * @returns {number} How many were pruned now.
   */
  prune(orgId, before) {
    return this.db
      .prepare(
        `UPDATE receipts SET body = '', target = '', principal = '', agent = '', session = '',
           metrics = '{}', status = NULL, latency_ms = NULL, pruned_at = ?
         WHERE org_id = ? AND ts < ? AND pruned_at IS NULL`,
      )
      .run(now(), orgId, before).changes;
  }

  /**
   * Apply every organisation's retention. Run on a schedule by `serve`.
   *
   * @param {number} [nowMs]
   * @returns {{ orgId: string, before: string, pruned: number }[]}
   */
  pruneExpired(nowMs = Date.now()) {
    const out = [];
    const orgs = this.db
      .prepare('SELECT id, retention_days, retention_cap_days FROM orgs WHERE retention_days IS NOT NULL OR retention_cap_days IS NOT NULL')
      .all();
    for (const org of orgs) {
      const days = effectiveRetention(org.retention_days, org.retention_cap_days);
      if (days === null) continue;
      const before = new Date(nowMs - days * 86_400_000).toISOString();
      const pruned = this.prune(org.id, before);
      if (pruned > 0) {
        this.recordEvent({
          orgId: org.id,
          actor: 'retention',
          actorKind: 'system',
          action: 'retention.pruned',
          subject: `${pruned} receipt(s)`,
          meta: { pruned, before, days },
        });
      }
      out.push({ orgId: org.id, before, pruned });
    }
    return out;
  }

  // ── integrations ──────────────────────────────────────────────────────

  /**
   * @param {string} orgId
   * @param {string} kind
   * @returns {{ config: any, createdAt: string, updatedAt: string } | null}
   */
  integration(orgId, kind) {
    const row = this.db.prepare('SELECT * FROM integrations WHERE org_id = ? AND kind = ?').get(orgId, kind);
    return row ? { config: JSON.parse(row.config), createdAt: row.created_at, updatedAt: row.updated_at } : null;
  }

  /**
   * @param {string} orgId
   * @param {string} kind
   * @param {object} config
   */
  setIntegration(orgId, kind, config) {
    const at = now();
    this.db
      .prepare(
        `INSERT INTO integrations(org_id, kind, config, created_at, updated_at) VALUES(?, ?, ?, ?, ?)
         ON CONFLICT(org_id, kind) DO UPDATE SET config = excluded.config, updated_at = excluded.updated_at`,
      )
      .run(orgId, kind, JSON.stringify(config), at, at);
  }

  /**
   * @param {string} orgId
   * @param {string} kind
   * @returns {boolean} Whether there was one to remove.
   */
  deleteIntegration(orgId, kind) {
    return this.db.prepare('DELETE FROM integrations WHERE org_id = ? AND kind = ?').run(orgId, kind).changes > 0;
  }

  // ── self-audit ────────────────────────────────────────────────────────

  /**
   * Actions an agent authorised and sent that never came back: intents with
   * no outcome (the agent died mid-call), and outcomes recorded as
   * `unfinished` (it shut down while the call was out).
   *
   * @param {string} orgId
   * @param {string} logId
   * @param {{ now?: number, graceMs?: number }} [opts]
   */
  unfinished(orgId, logId, opts = {}) {
    const log = this.log(orgId, logId);
    if (!log) throw new StoreError(404, 'no_such_log', 'no such log in this organization');
    const now = opts.now ?? Date.now();
    const graceMs = opts.graceMs ?? DEFAULT_GRACE_MS;

    // Same rules as findUnfinished in @deedwrit/core, answered by the
    // database: the hub may hold millions of receipts, and pruned rows keep
    // exactly the columns this needs (hash, phase, ref, ts).
    const open = this.db
      .prepare(
        `SELECT i.seq, i.ts, i.target, i.principal, i.agent, i.session, i.hash AS intent,
                i.pruned_at IS NOT NULL AS pruned
           FROM receipts i
          WHERE i.log_id = ? AND i.phase = 'intent'
            AND NOT EXISTS (SELECT 1 FROM receipts o
                             WHERE o.log_id = i.log_id AND o.ref = i.hash AND o.phase = 'outcome')
          ORDER BY i.seq`,
      )
      .all(log.id);
    const abandoned = this.db
      .prepare(
        `SELECT i.seq, i.ts, i.target, i.principal, i.agent, i.session, i.hash AS intent,
                o.ts AS closedAt, o.seq AS outcomeSeq
           FROM receipts o JOIN receipts i ON i.log_id = o.log_id AND i.hash = o.ref AND i.phase = 'intent'
          WHERE o.log_id = ? AND o.phase = 'outcome' AND o.status = 'error' AND o.pruned_at IS NULL
            AND json_extract(o.body, '$.result.code') = 'unfinished'
          ORDER BY i.seq`,
      )
      .all(log.id);
    const orphans = this.db
      .prepare(
        `SELECT o.seq, o.ref FROM receipts o
          WHERE o.log_id = ? AND o.phase = 'outcome'
            AND NOT EXISTS (SELECT 1 FROM receipts i
                             WHERE i.log_id = o.log_id AND i.hash = o.ref AND i.phase = 'intent')
          ORDER BY o.seq`,
      )
      .all(log.id);

    const plain = (/** @type {any} */ r) => ({ ...r, ...(r.pruned !== undefined ? { pruned: Boolean(r.pruned) } : {}) });
    const unfinished = [];
    const inFlight = [];
    for (const r of open.map(plain)) {
      const at = Date.parse(r.ts);
      (Number.isFinite(at) && now - at < graceMs ? inFlight : unfinished).push(r);
    }
    return { unfinished, abandoned: abandoned.map(plain), inFlight, orphans: orphans.map((o) => ({ seq: o.seq, ref: o.ref ?? '' })) };
  }

  /**
   * Re-verify a stored log from scratch: every signature, every chain link,
   * every inclusion proof, and every checkpoint replayed against it.
   *
   * This is what the hub runs on a schedule against itself. A hosted log that
   * only ever checks its customers' data and never its own is asking to be
   * taken at its word.
   *
   * @param {string} orgId
   * @param {string} logId
   */
  audit(orgId, logId) {
    const log = this.log(orgId, logId);
    if (!log) throw new StoreError(404, 'no_such_log', 'no such log in this organization');

    /** @type {{ kind: string, seq?: number, message: string }[]} */
    const issues = [];
    const keyring = { [log.kid]: log.public_key };
    const rows = this.db
      .prepare('SELECT seq, hash, prev, body, pruned_at FROM receipts WHERE log_id = ? ORDER BY seq ASC')
      .all(log.id);

    let prev = GENESIS_PREV;
    const tree = new MerkleTree();

    for (const [i, row] of rows.entries()) {
      if (row.pruned_at) {
        // Retention cleared this receipt's content. What is left still has to
        // link: its stored prev must be the hash before it, and the next
        // receipt, whose signature covers its own prev, must name this hash.
        // The tree is rebuilt from the same hashes, so the root and every
        // checkpoint are still checked in full below.
        if (row.seq !== i) {
          issues.push({ kind: 'sequence', seq: row.seq, message: `expected seq ${i}, stored ${row.seq}` });
        }
        if (row.prev !== prev) {
          issues.push({ kind: 'chain', seq: row.seq, message: `chain break at ${row.seq} (pruned)` });
        }
        prev = row.hash;
        tree.append(unhex(row.hash));
        continue;
      }
      const receipt = JSON.parse(row.body);
      for (const issue of verifyReceipt(receipt, keyring)) {
        issues.push({ kind: issue.kind, seq: row.seq, message: issue.message });
      }
      if (row.seq !== i) {
        issues.push({ kind: 'sequence', seq: row.seq, message: `expected seq ${i}, stored ${row.seq}` });
      }
      if (receipt.prev !== prev) {
        issues.push({ kind: 'chain', seq: row.seq, message: `chain break at ${row.seq}` });
      }
      const computed = entryHash(receipt);
      if (computed !== row.hash) {
        issues.push({
          kind: 'chain',
          seq: row.seq,
          message: `stored hash does not match the receipt body at ${row.seq}`,
        });
      }
      prev = computed;
      tree.append(leafHash(canonicalBytes(receipt)));
    }

    const root = hex(tree.root);
    if (rows.length !== log.size) {
      issues.push({
        kind: 'chain',
        message: `log row says ${log.size} entries, ${rows.length} are stored`,
      });
    }
    if (rows.length > 0 && root !== log.root) {
      issues.push({ kind: 'chain', message: 'stored root does not match a recomputation' });
    }

    for (const cp of this.checkpoints(orgId, logId, 1000)) {
      if (cp.body.size > rows.length) {
        issues.push({
          kind: 'chain',
          message:
            `a signed checkpoint covers ${cp.body.size} entries but only ${rows.length} ` +
            `are stored — entries have been removed`,
        });
        continue;
      }
      const ok = verifyConsistency({
        firstSize: cp.body.size,
        secondSize: rows.length,
        firstRoot: unhex(cp.body.root),
        secondRoot: tree.root,
        proof: tree.consistencyProof(cp.body.size, rows.length),
      });
      if (!ok) {
        issues.push({
          kind: 'chain',
          message: `the log no longer extends the checkpoint signed at size ${cp.body.size} (${cp.body.ts})`,
        });
      }
    }

    return { ok: issues.length === 0, size: rows.length, root, issues };
  }

  /**
   * An evidence bundle for a third party, assembled from stored receipts.
   *
   * @param {string} orgId
   * @param {string} logId
   * @param {object} [opts]
   */
  bundle(orgId, logId, opts = {}) {
    const log = this.log(orgId, logId);
    if (!log) throw new StoreError(404, 'no_such_log', 'no such log in this organization');

    // Pruned receipts have no body to ship. Leaving them out makes the bundle
    // partial, and every entry in it still proves inclusion in the full tree.
    const where = ['log_id = ?', 'pruned_at IS NULL'];
    const params = [log.id];
    if (opts.since) { where.push('ts >= ?'); params.push(opts.since); }
    if (opts.until) { where.push('ts <= ?'); params.push(opts.until); }
    if (opts.session) { where.push('session = ?'); params.push(opts.session); }

    const rows = this.db
      .prepare(`SELECT seq, body FROM receipts WHERE ${where.join(' AND ')} ORDER BY seq ASC`)
      .all(...params);

    const tree = this.tree(log.id);
    const checkpoints = this.checkpoints(orgId, logId, 1000);

    // The keyring must cover *everything* in the bundle, not just the receipts.
    // On a hosted log the receipts are signed by the agent while the
    // checkpoints are signed by the hub and its witnesses — three different
    // keys. Shipping only the agent's leaves the recipient unable to verify the
    // checkpoints, which are precisely the part that proves nothing was
    // rewritten.
    /** @type {Record<string,string>} */
    const keyring = { [log.kid]: log.public_key };
    for (const cp of checkpoints) {
      for (const sig of cp.sigs) {
        if (keyring[sig.kid]) continue;
        const pub = this.publicKeyFor(orgId, sig.kid);
        if (pub) keyring[sig.kid] = pub;
      }
    }

    return {
      v: 1,
      kind: 'deedwrit.bundle',
      log: log.slug,
      exported: now(),
      treeSize: log.size,
      root: hex(tree.root),
      head: log.head,
      keyring,
      checkpoints,
      // Retention makes most hub bundles partial, and a partial bundle can
      // only tie its witnesses to its root through one of these.
      consistency: consistencyFor(tree, checkpoints),
      partial: rows.length !== log.size,
      entries: rows.map((r) => ({
        receipt: JSON.parse(r.body),
        proof: tree.inclusionProof(r.seq).map(hex),
      })),
    };
  }

  // ── the hub's own audit trail ─────────────────────────────────────────

  /**
   * Record an administrative action, hash-chained.
   *
   * The hub asks customers to trust a tamper-evident record, so its own
   * control plane keeps one too. Who revoked a key, who changed a policy, who
   * approved a payment — chained, so the hub operator cannot quietly edit it
   * either.
   *
   * @param {object} args
   * @param {string} args.orgId
   * @param {string} args.actor
   * @param {'user'|'key'|'system'} args.actorKind
   * @param {string} args.action
   * @param {string} [args.subject]
   * @param {object} [args.meta]
   */
  recordEvent(args) {
    const res = this._recordEvent(args);
    try {
      this.onAuditEvent?.(args.orgId);
    } catch {
      // Streaming is downstream of the record; it must never undo it.
    }
    return res;
  }

  /** @param {Parameters<Store['recordEvent']>[0]} args */
  _recordEvent(args) {
    return transact(this.db, () => {
      const last = this.db
        .prepare('SELECT seq, hash FROM audit_events WHERE org_id = ? ORDER BY seq DESC LIMIT 1')
        .get(args.orgId);
      const seq = last ? last.seq + 1 : 0;
      const prev = last ? last.hash : GENESIS_PREV;
      const at = now();

      const payload = {
        seq,
        prev,
        org: args.orgId,
        actor: args.actor,
        actorKind: args.actorKind,
        action: args.action,
        subject: args.subject ?? '',
        meta: args.meta ?? {},
        at,
      };
      const hash = createHash('sha256').update(canonicalBytes(payload)).digest('hex');

      this.db
        .prepare(
          `INSERT INTO audit_events(id, org_id, seq, prev, hash, actor, actor_kind, action, subject, meta, at)
           VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          newId('event'), args.orgId, seq, prev, hash, args.actor, args.actorKind,
          args.action, args.subject ?? '', canonicalize(args.meta ?? {}), at,
        );
      return { seq, hash, at };
    });
  }

  /**
   * @param {string} orgId
   * @param {number} [limit]
   */
  events(orgId, limit = 100) {
    return this.db
      .prepare('SELECT * FROM audit_events WHERE org_id = ? ORDER BY seq DESC LIMIT ?')
      .all(orgId, limit);
  }

  /**
   * Verify the control-plane audit chain.
   *
   * @param {string} orgId
   */
  auditEvents(orgId) {
    const rows = this.db
      .prepare('SELECT * FROM audit_events WHERE org_id = ? ORDER BY seq ASC')
      .all(orgId);
    /** @type {string[]} */
    const issues = [];
    let prev = GENESIS_PREV;

    for (const [i, row] of rows.entries()) {
      if (row.seq !== i) issues.push(`event ${row.seq}: expected seq ${i}`);
      if (row.prev !== prev) issues.push(`event ${row.seq}: chain break`);
      const hash = createHash('sha256')
        .update(
          canonicalBytes({
            seq: row.seq,
            prev: row.prev,
            org: row.org_id,
            actor: row.actor,
            actorKind: row.actor_kind,
            action: row.action,
            subject: row.subject,
            meta: JSON.parse(row.meta),
            at: row.at,
          }),
        )
        .digest('hex');
      if (hash !== row.hash) issues.push(`event ${row.seq}: content does not match its hash`);
      prev = row.hash;
    }
    return { ok: issues.length === 0, count: rows.length, issues };
  }

  // ── server identity ───────────────────────────────────────────────────

  /**
   * Look up the public half of any key that may have signed something in this
   * org's bundles: the hub itself, a witness, or an agent's log key.
   *
   * @param {string} orgId
   * @param {string} kid
   * @returns {string|null}
   */
  /**
   * Keep the key of an outside witness an organisation uses, so the bundles
   * it exports can verify that witness's signatures. A label, not trust:
   * auditors who require witnesses pin keys they obtained elsewhere.
   *
   * @param {string} orgId
   * @param {{ name: string, url?: string, kid: string, publicKey: string }} w
   */
  rememberWitnessKey(orgId, w) {
    this.db
      .prepare(
        `INSERT INTO witnesses(id, org_id, kid, public_key, name, url, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(org_id, kid) DO NOTHING`,
      )
      .run(newId('witness'), orgId, w.kid, w.publicKey, w.name, w.url ?? null, now());
  }

  publicKeyFor(orgId, kid) {
    // Deliberately not filtered by retired_at: a signature made before a
    // rotation is still a valid signature, and a verifier must be able to
    // check it.
    const server = this.db.prepare('SELECT public_key FROM server_keys WHERE kid = ?').get(kid);
    if (server) return server.public_key;

    const witness = this.db
      .prepare('SELECT public_key FROM witnesses WHERE org_id = ? AND kid = ?')
      .get(orgId, kid);
    if (witness) return witness.public_key;

    const log = this.db
      .prepare('SELECT public_key FROM logs WHERE org_id = ? AND kid = ?')
      .get(orgId, kid);
    return log ? log.public_key : null;
  }

  /**
   * The current, un-retired key for a role, if there is one.
   *
   * @param {'hub'|'witness'} role
   * @returns {object|null}
   */
  activeServerKey(role) {
    return (
      this.db
        .prepare(
          `SELECT * FROM server_keys WHERE role = ? AND retired_at IS NULL
           ORDER BY created_at DESC LIMIT 1`,
        )
        .get(role) ?? null
    );
  }

  /**
   * Record a server key. `privatePem` is null for every backend except local —
   * with an external signer the private half is, by construction, not ours.
   *
   * @param {object} args
   * @param {string} args.kid
   * @param {string} args.role
   * @param {string} args.publicKey
   * @param {string|null} args.privatePem
   * @param {string} [args.backend]
   */
  recordServerKey(args) {
    const existing = this.db.prepare('SELECT kid FROM server_keys WHERE kid = ?').get(args.kid);
    if (existing) return;

    // A new key for a role retires the old one rather than competing with it,
    // so "which key is current" is never ambiguous.
    this.db
      .prepare('UPDATE server_keys SET retired_at = ? WHERE role = ? AND retired_at IS NULL')
      .run(now(), args.role);

    this.db
      .prepare(
        `INSERT INTO server_keys(kid, role, public_key, private_pem, backend, created_at)
         VALUES(?, ?, ?, ?, ?, ?)`,
      )
      .run(
        args.kid, args.role, args.publicKey, args.privatePem ?? null,
        args.backend ?? (args.privatePem ? 'local' : 'external'), now(),
      );
  }

  /**
   * Every server key that has ever signed, current and retired.
   *
   * Retired keys are never dropped. A checkpoint signed last year by a key
   * rotated since must still verify, or rotating would quietly invalidate the
   * history it was meant to protect.
   *
   * @returns {object[]}
   */
  serverKeys() {
    return this.db.prepare('SELECT * FROM server_keys ORDER BY created_at ASC').all();
  }

  /**
   * True when any server key's private half is sitting in this database.
   *
   * Surfaced in the console and in `hub check`, because an operator who
   * believes they moved to a KMS and did not should find out from us.
   *
   * @returns {boolean}
   */
  holdsPrivateKeys() {
    return (
      this.db
        .prepare('SELECT count(*) AS n FROM server_keys WHERE private_pem IS NOT NULL')
        .get().n > 0
    );
  }

  /**
   * The hub's own signing identity, created on first use.
   *
   * Retained for the local backend and for tests; the hub itself now goes
   * through a `Signer`, which may hold no key material at all.
   *
   * @param {'hub'|'witness'} role
   * @returns {import('@deedwrit/core').Identity}
   */
  serverIdentity(role) {
    const row = this.activeServerKey(role);
    if (row?.private_pem) return identityFromPem(row.private_pem);

    const { identity, privateKeyPem } = generateIdentity();
    this.recordServerKey({
      kid: identity.kid,
      role,
      publicKey: identity.publicKey,
      privatePem: privateKeyPem,
    });
    return identity;
  }
}

/**
 * @param {object} row
 */
function hydrateCheckpoint(row) {
  return { body: JSON.parse(row.body), sigs: JSON.parse(row.sigs) };
}

/**
 * An error that already knows what HTTP status and machine-readable code it
 * should produce, so route handlers do not each invent their own mapping.
 */
export class StoreError extends Error {
  /**
   * @param {number} status
   * @param {string} code
   * @param {string} message
   * @param {object} [detail]
   */
  constructor(status, code, message, detail) {
    super(message);
    this.name = 'StoreError';
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

export { verifyInclusion };

/**
 * The retention actually applied: the organisation's choice, never longer
 * than the operator's cap. Null is forever.
 *
 * @param {number | null} days
 * @param {number | null} capDays
 * @returns {number | null}
 */
export function effectiveRetention(days, capDays) {
  if (days == null) return capDays ?? null;
  if (capDays == null) return days;
  return Math.min(days, capDays);
}
