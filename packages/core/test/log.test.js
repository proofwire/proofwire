import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ProofLog, verifyBundle } from '../src/log.js';
import { canonicalize } from '../src/canonical.js';
import { identityFromPem, generateIdentity } from '../src/keys.js';
import { signReceipt, entryHash, GENESIS_PREV } from '../src/receipt.js';
import { cosign, verifyCheckpoint } from '../src/checkpoint.js';

/** @returns {string} */
function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'deedwrit-test-'));
}

/**
 * @param {ProofLog} log
 * @param {number} n
 * @param {object} [over]
 */
function fill(log, n, over = {}) {
  for (let i = 0; i < n; i++) {
    log.append({
      actor: {
        agent: 'claude-opus-5',
        runtime: 'deedwrit-test/0.1.0',
        session: 'sess_a',
        principal: 'ops@acme.test',
      },
      action: {
        kind: 'tool_call',
        target: 'stripe.refund',
        params: { order: `ord_${i}`, amount: 10 + i },
        metrics: { amount_usd: 10 + i },
      },
      decision: { outcome: 'allow', policy: 'p_test', rules: [] },
      result: { status: 'ok', payload: { id: `re_${i}` }, latencyMs: 12 },
      ...over,
    });
  }
}

test('a fresh log audits clean and reopens identically', () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 25);
  const root = log.root;

  const audit = log.audit();
  assert.ok(audit.ok, JSON.stringify(audit.issues, null, 2));
  assert.equal(audit.size, 25);

  const reopened = ProofLog.open(dir, { readOnly: true });
  assert.equal(reopened.root, root, 'root must survive a round-trip through disk');
  assert.equal(reopened.size, 25);
  assert.ok(reopened.audit().ok);
});

test('a read-only log refuses to append', () => {
  const dir = tmpdir();
  ProofLog.create(dir);
  const ro = ProofLog.open(dir, { readOnly: true });
  assert.throws(() => fill(ro, 1), /read-only/);
});

test('editing an entry on disk is caught', () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 8);

  const file = path.join(dir, 'entries.jsonl');
  const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
  const doctored = JSON.parse(lines[3]);
  doctored.action.metrics.amount_usd = 999999;
  lines[3] = canonicalize(doctored);
  fs.writeFileSync(file, lines.join('\n') + '\n');

  const audit = ProofLog.open(dir, { readOnly: true }).audit();
  assert.equal(audit.ok, false);
  assert.ok(audit.issues.some((i) => i.kind === 'signature' && i.seq === 3));
});

test('deleting an entry on disk is caught', () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 8);

  const file = path.join(dir, 'entries.jsonl');
  const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
  lines.splice(5, 1);
  fs.writeFileSync(file, lines.join('\n') + '\n');

  const audit = ProofLog.open(dir, { readOnly: true }).audit();
  assert.equal(audit.ok, false);
  assert.ok(audit.issues.some((i) => i.kind === 'chain' || i.kind === 'sequence'));
});

test('an insider with the signing key still cannot rewrite checkpointed history', () => {
  // The hard case. Someone with full write access and the private key deletes
  // an embarrassing entry and re-signs the entire chain so that sequence
  // numbers and chain links are all internally perfect. Local chain checks
  // pass. The published checkpoint is what convicts them.
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 12);
  const published = log.checkpoint();

  const identity = identityFromPem(fs.readFileSync(path.join(dir, 'key.pem'), 'utf8'));
  const originals = fs
    .readFileSync(path.join(dir, 'entries.jsonl'), 'utf8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l));

  const kept = originals.filter((r) => r.seq !== 7);
  let prev = GENESIS_PREV;
  const rebuilt = kept.map((r, i) => {
    const { attest: _drop, ...body } = r;
    const resigned = signReceipt(identity, { ...body, seq: i, prev });
    prev = entryHash(resigned);
    return canonicalize(resigned);
  });
  fs.writeFileSync(path.join(dir, 'entries.jsonl'), rebuilt.join('\n') + '\n');

  const reopened = ProofLog.open(dir, { readOnly: true });
  const audit = reopened.audit();

  assert.equal(audit.ok, false, 'a rewritten history passed audit');
  assert.ok(
    audit.issues.some((i) => /history was rewritten|entries have been removed/.test(i.message)),
    `expected a rewrite finding, got: ${JSON.stringify(audit.issues)}`,
  );
  // And the log can no longer produce the root it published: at the size the
  // checkpoint covers, its own history now hashes to something else.
  assert.equal(reopened.size, 11);
  assert.notEqual(
    reopened.tree.rootAt(Math.min(published.body.size, reopened.size)).toString('hex'),
    published.body.root,
  );
});

test('a checkpoint signed over a size the log no longer reaches is caught', () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 10);
  log.checkpoint();

  const file = path.join(dir, 'entries.jsonl');
  const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
  fs.writeFileSync(file, lines.slice(0, 6).join('\n') + '\n');

  const audit = ProofLog.open(dir, { readOnly: true }).audit();
  assert.equal(audit.ok, false);
  assert.ok(audit.issues.some((i) => /entries have been removed/.test(i.message)));
});

test('witness co-signatures accumulate on a checkpoint', () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 4);
  const cp = log.checkpoint();

  const w1 = generateIdentity().identity;
  const w2 = generateIdentity().identity;
  log.trustKey(w1.kid, w1.publicKey);
  log.trustKey(w2.kid, w2.publicKey);

  const cosigned = cosign(cosign(cp, w1), w2);
  const res = verifyCheckpoint(cosigned, log.keyring, { minWitnesses: 2 });
  assert.ok(res.ok, JSON.stringify(res.issues));
  assert.equal(res.witnesses, 2);

  // The same checkpoint, judged by a policy that demands three witnesses.
  assert.equal(verifyCheckpoint(cosigned, log.keyring, { minWitnesses: 3 }).ok, false);
});

test('a forged witness signature does not count', () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 2);
  const cp = log.checkpoint();

  const impostor = generateIdentity().identity;
  log.trustKey(impostor.kid, impostor.publicKey);
  const cosigned = cosign(cp, impostor);
  cosigned.sigs[cosigned.sigs.length - 1].sig = 'A'.repeat(86);

  const res = verifyCheckpoint(cosigned, log.keyring, { minWitnesses: 1 });
  assert.equal(res.ok, false);
  assert.ok(res.issues.some((m) => /invalid witness signature/.test(m)));
});

test('an exported bundle verifies with nothing but itself', () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 15);
  log.checkpoint();

  const bundle = JSON.parse(JSON.stringify(log.bundle()));
  const res = verifyBundle(bundle);
  assert.ok(res.ok, JSON.stringify(res.issues, null, 2));
  assert.equal(res.checked, 15);
});

test('a bundle with an entry swapped out fails verification', () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 15);

  const bundle = JSON.parse(JSON.stringify(log.bundle()));
  bundle.entries[6].receipt.action.metrics.amount_usd = 1;
  const res = verifyBundle(bundle);
  assert.equal(res.ok, false);
  assert.ok(res.issues.some((m) => /not provably part of the logged tree/.test(m)));
});

test('a bundle shown with a root the auditor did not expect is flagged', () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 5);
  const bundle = JSON.parse(JSON.stringify(log.bundle()));

  const res = verifyBundle(bundle, { expectRoot: 'ab'.repeat(32) });
  assert.equal(res.ok, false);
  assert.ok(res.issues.some((m) => /different history/.test(m)));
});

test('a filtered bundle still proves each entry belongs to the full log', () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 20);

  const bundle = JSON.parse(
    JSON.stringify(log.bundle({ filter: (r) => r.seq % 2 === 0 })),
  );
  assert.equal(bundle.partial, true);
  assert.equal(bundle.entries.length, 10);

  const res = verifyBundle(bundle);
  assert.ok(res.ok, JSON.stringify(res.issues, null, 2));
  // The tree size still refers to the whole log, so the recipient can see
  // that they were handed a subset rather than being told it is everything.
  assert.equal(bundle.treeSize, 20);
});

test('reveal confirms a payload; shredding makes it permanently unopenable', () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  log.append({
    actor: { agent: 'a', runtime: 'r', session: 's', principal: 'p' },
    action: {
      kind: 'tool_call',
      target: 'crm.lookup',
      params: { email: 'jordan@example.test', ssn: '123-45-6789' },
    },
    decision: { outcome: 'allow', policy: 'p_test', rules: [] },
  });

  assert.ok(log.reveal(0, 'params', { email: 'jordan@example.test', ssn: '123-45-6789' }));
  assert.equal(log.reveal(0, 'params', { email: 'someone@example.test' }), false);

  assert.equal(log.shred((r) => r.seq === 0), 1);

  const after = ProofLog.open(dir, { readOnly: true });
  assert.equal(
    after.reveal(0, 'params', { email: 'jordan@example.test', ssn: '123-45-6789' }),
    false,
    'the payload should no longer be confirmable',
  );
  assert.ok(after.audit().ok, 'erasure must leave the audit trail intact');
});

test('inclusion proofs handed out for individual entries verify standalone', async () => {
  const { verifyInclusion } = await import('../src/merkle.js');
  const { unhex } = await import('../src/hash.js');
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 33);

  for (const seq of [0, 1, 16, 31, 32]) {
    const p = log.proofFor(seq);
    assert.ok(
      verifyInclusion({
        leafHash: unhex(p.leaf),
        index: p.seq,
        treeSize: p.treeSize,
        proof: p.proof.map(unhex),
        root: unhex(p.root),
      }),
      `standalone proof failed for entry ${seq}`,
    );
  }
});

test('opening a log whose key does not match its config is refused', () => {
  const dir = tmpdir();
  ProofLog.create(dir);
  const { privateKeyPem } = generateIdentity();
  fs.writeFileSync(path.join(dir, 'key.pem'), privateKeyPem);
  assert.throws(() => ProofLog.open(dir), /does not match config/);
});

test('a witness signature attached to a checkpoint survives export and verification', async () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 6);
  const cp = log.checkpoint();

  const witness = generateIdentity().identity;
  log.trustKey(witness.kid, witness.publicKey);

  const { cosign: cosignFn } = await import('../src/checkpoint.js');
  const signature = cosignFn(cp, witness).sigs.find((s) => s.role === 'witness');
  log.addSignature(cp.body.size, signature);

  // It must be on disk, not just in memory — the bundle is read from the file.
  const reopened = ProofLog.open(dir, { readOnly: true });
  const stored = reopened.checkpoints().find((c) => c.body.size === cp.body.size);
  assert.equal(stored.sigs.filter((s) => s.role === 'witness').length, 1);

  const bundle = JSON.parse(JSON.stringify(reopened.bundle()));
  const pinned = { [witness.kid]: witness.publicKey };
  const res = verifyBundle(bundle, { minWitnesses: 1, trustedWitnesses: pinned });
  assert.ok(res.ok, JSON.stringify(res.issues, null, 2));

  // And a policy demanding two witnesses must not be satisfied by one.
  assert.equal(verifyBundle(bundle, { minWitnesses: 2, trustedWitnesses: pinned }).ok, false);
});

test('re-witnessing the same root replaces rather than duplicates', async () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 3);
  const cp = log.checkpoint();
  const witness = generateIdentity().identity;
  log.trustKey(witness.kid, witness.publicKey);

  const { cosign: cosignFn } = await import('../src/checkpoint.js');
  const sig = cosignFn(cp, witness).sigs.find((s) => s.role === 'witness');
  log.addSignature(cp.body.size, sig);
  log.addSignature(cp.body.size, sig);

  const stored = ProofLog.open(dir, { readOnly: true })
    .checkpoints()
    .find((c) => c.body.size === cp.body.size);
  assert.equal(stored.sigs.length, 2, 'one log signature plus one witness, not three');
  assert.ok(log.audit().ok);
});

// ── a bundle has to be what it says it is ────────────────────────────────

test('a bundle marked complete but missing its tail is rejected', () => {
  // Every remaining inclusion proof is genuine, so a check that only looks at
  // what is present passes. This was accepted before completeness was checked.
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 8);

  const bundle = JSON.parse(JSON.stringify(log.bundle()));
  assert.equal(bundle.partial, false);
  assert.ok(verifyBundle(bundle).ok, 'the honest bundle must still verify');

  bundle.entries = bundle.entries.slice(0, 5);
  const res = verifyBundle(bundle);
  assert.equal(res.ok, false);
  assert.ok(
    res.issues.some((m) => /marked complete but holds 5 of 8 entries/.test(m)),
    `expected a completeness finding, got: ${JSON.stringify(res.issues)}`,
  );
});

test('a bundle whose head was replaced is rejected', () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 6);

  const bundle = JSON.parse(JSON.stringify(log.bundle()));
  bundle.head = 'ab'.repeat(32);
  const res = verifyBundle(bundle);
  assert.equal(res.ok, false);
  assert.ok(res.issues.some((m) => /is not the hash of its final entry/.test(m)));
});

test('a partial bundle that includes the tip still has its head checked', () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 10);

  const bundle = JSON.parse(JSON.stringify(log.bundle({ filter: (r) => r.seq % 3 === 0 || r.seq === 9 })));
  assert.equal(bundle.partial, true);
  assert.ok(verifyBundle(bundle).ok, 'a genuine partial bundle must still verify');

  bundle.head = 'cd'.repeat(32);
  assert.equal(verifyBundle(bundle).ok, false);
});

test('a bundle whose root does not match its own entries is rejected', () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 7);

  const bundle = JSON.parse(JSON.stringify(log.bundle()));
  bundle.root = 'ef'.repeat(32);
  const res = verifyBundle(bundle);
  assert.equal(res.ok, false);
  assert.ok(res.issues.some((m) => /does not match the root of its own entries/.test(m)));
});

test('an insider who re-signs history cannot keep the old checkpoint in the bundle', () => {
  // The insider edits an entry and re-signs the whole chain, so signatures,
  // links and inclusion proofs are all internally perfect. The checkpoint that
  // was signed before the edit is what convicts them, and now the bundle
  // itself says so rather than leaving it to a separate audit.
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 8);
  log.checkpoint();

  const identity = identityFromPem(fs.readFileSync(path.join(dir, 'key.pem'), 'utf8'));
  const originals = fs
    .readFileSync(path.join(dir, 'entries.jsonl'), 'utf8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l));

  let prev = GENESIS_PREV;
  const rebuilt = originals.map((r, i) => {
    const { attest: _drop, ...body } = r;
    if (i === 3) body.action = { ...body.action, target: 'stripe.something-else' };
    const resigned = signReceipt(identity, { ...body, seq: i, prev });
    prev = entryHash(resigned);
    return canonicalize(resigned);
  });
  fs.writeFileSync(path.join(dir, 'entries.jsonl'), rebuilt.join('\n') + '\n');

  const bundle = JSON.parse(JSON.stringify(ProofLog.open(dir, { readOnly: true }).bundle()));
  const res = verifyBundle(bundle);
  assert.equal(res.ok, false);
  assert.ok(
    res.issues.some((m) => /history was rewritten/.test(m)),
    `expected the checkpoint to convict the rewrite, got: ${JSON.stringify(res.issues)}`,
  );
});

test('a checkpoint from beyond the bundle is reported', () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 6);
  log.checkpoint();

  const bundle = JSON.parse(JSON.stringify(log.bundle()));
  bundle.entries = bundle.entries.slice(0, 4);
  bundle.treeSize = 4;
  const res = verifyBundle(bundle);
  assert.equal(res.ok, false);
});

test('malformed entries are reported instead of crashing the verifier', () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 3);

  for (const junk of [null, {}, { receipt: null }, { receipt: 5, proof: 'x' }, { receipt: { seq: 0 }, proof: ['zz'] }]) {
    const bundle = JSON.parse(JSON.stringify(log.bundle()));
    bundle.entries.push(junk);
    let res;
    assert.doesNotThrow(() => { res = verifyBundle(bundle); }, `threw on ${JSON.stringify(junk)}`);
    assert.equal(res.ok, false, `accepted ${JSON.stringify(junk)}`);
  }
});

test('an empty log exports a bundle that verifies, and a forged empty head does not', () => {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  const bundle = JSON.parse(JSON.stringify(log.bundle()));
  assert.equal(bundle.entries.length, 0);
  assert.ok(verifyBundle(bundle).ok, JSON.stringify(verifyBundle(bundle).issues));

  bundle.head = 'ab'.repeat(32);
  assert.equal(verifyBundle(bundle).ok, false);
});

test('a checkpoint of the empty log is not mistaken for a rewritten history', () => {
  // Found by the Python port: the size-0 checkpoint was compared against no
  // prefix root at all, and every such bundle "failed".
  const log = ProofLog.create(tmpdir());
  log.checkpoint();
  fill(log, 3);
  log.checkpoint();
  const res = verifyBundle(JSON.parse(JSON.stringify(log.bundle())));
  assert.ok(res.ok, JSON.stringify(res.issues));

  // And a size-0 checkpoint naming some other root is still caught.
  const forged = JSON.parse(JSON.stringify(log.bundle()));
  forged.checkpoints[0].body.root = 'cd'.repeat(32);
  assert.equal(verifyBundle(forged).ok, false);
});

// ── witnesses have to be the verifier's, not the bundle's ────────────────

/**
 * A log with one checkpoint and one real, independent witness.
 *
 * @returns {{ log: ProofLog, cp: any, witness: any }}
 */
function witnessedLog() {
  const dir = tmpdir();
  const log = ProofLog.create(dir);
  fill(log, 6);
  const cp = log.checkpoint();
  const witness = generateIdentity().identity;
  log.trustKey(witness.kid, witness.publicKey);
  log.addSignature(cp.body.size, cosign(cp, witness).sigs.find((x) => x.kid === witness.kid));
  return { log, cp, witness };
}

test('a bundle cannot vouch for its own witnesses', () => {
  // The operator invents three witnesses by adding fresh keys to the bundle's
  // keyring and signing their own checkpoint with each. Counting signatures
  // against the bundle's keyring would call that "three independent
  // witnesses".
  const { log, cp } = witnessedLog();
  const invented = Array.from({ length: 3 }, () => generateIdentity().identity);
  for (const w of invented) {
    log.trustKey(w.kid, w.publicKey);
    log.addSignature(cp.body.size, cosign(cp, w).sigs.find((x) => x.kid === w.kid));
  }
  const bundle = JSON.parse(JSON.stringify(log.bundle()));

  // Asking for witnesses without saying whose keys to trust is refused, rather
  // than answered by counting whatever the bundle happens to contain.
  const unpinned = verifyBundle(bundle, { minWitnesses: 2 });
  assert.equal(unpinned.ok, false);
  assert.ok(unpinned.issues.some((m) => /no trusted witness keys were supplied/.test(m)));

  // The verifier pins the one witness it actually chose. The invented ones are
  // ignored, so two is not reachable.
  const real = log.checkpoints()[0].sigs.find((x) => x.role === 'witness' && !invented.some((w) => w.kid === x.kid));
  const pinnedReal = { [real.kid]: log.keyring[real.kid] };
  assert.equal(verifyBundle(bundle, { minWitnesses: 1, trustedWitnesses: pinnedReal }).ok, true);
  const two = verifyBundle(bundle, { minWitnesses: 2, trustedWitnesses: pinnedReal });
  assert.equal(two.ok, false);
  assert.ok(two.issues.some((m) => /only 1 valid witness signature/.test(m)));
});

test('a pinned witness is checked against the pinned key, never the bundle\'s', () => {
  // The attacker signs with their own key but claims to be the real witness,
  // and swaps the bundle's keyring entry for that kid to their own public key.
  // Judged by the bundle's keyring the forgery verifies perfectly.
  const { log, cp, witness } = witnessedLog();
  const attacker = generateIdentity().identity;

  const forged = cosign({ body: cp.body, sigs: [] }, attacker).sigs.find((x) => x.role === 'witness');
  forged.kid = witness.kid;

  const bundle = JSON.parse(JSON.stringify(log.bundle()));
  const target = bundle.checkpoints[0];
  target.sigs = target.sigs.filter((x) => x.role !== 'witness');
  target.sigs.push(forged);
  bundle.keyring[witness.kid] = attacker.publicKey;

  // Unpinned, nothing looks wrong. That is the whole problem.
  assert.equal(verifyBundle(bundle).ok, true);

  const res = verifyBundle(bundle, {
    minWitnesses: 1,
    trustedWitnesses: { [witness.kid]: witness.publicKey },
  });
  assert.equal(res.ok, false);
  assert.ok(res.issues.some((m) => /invalid witness signature/.test(m)), JSON.stringify(res.issues));
});

test('a pinned witness relabelled as the log is not a log signature', () => {
  const { log, witness } = witnessedLog();
  const bundle = JSON.parse(JSON.stringify(log.bundle()));

  const cpj = bundle.checkpoints[0];
  const w = cpj.sigs.find((x) => x.role === 'witness');
  cpj.sigs = [{ ...w, role: 'log' }]; // the only signature left claims to be the log's

  const res = verifyBundle(bundle, { trustedWitnesses: { [witness.kid]: witness.publicKey } });
  assert.equal(res.ok, false);
  assert.ok(res.issues.some((m) => /labelled as the log's/.test(m)), JSON.stringify(res.issues));
  assert.ok(res.issues.some((m) => /no valid log signature/.test(m)));
});

test('witnesses the verifier was not told about are ignored rather than counted', () => {
  const { log, cp, witness } = witnessedLog();
  const stranger = generateIdentity().identity;
  log.trustKey(stranger.kid, stranger.publicKey);
  log.addSignature(cp.body.size, cosign(cp, stranger).sigs.find((x) => x.kid === stranger.kid));

  const bundle = JSON.parse(JSON.stringify(log.bundle()));
  const pinned = { [witness.kid]: witness.publicKey };

  assert.equal(verifyBundle(bundle, { minWitnesses: 1, trustedWitnesses: pinned }).ok, true);
  assert.equal(verifyBundle(bundle, { minWitnesses: 2, trustedWitnesses: pinned }).ok, false);
});

test('pinning nothing at all is not the same as not pinning', () => {
  // An empty set of trusted witnesses means "I trust no one", so a policy
  // demanding one can never be met — it must not fall back to the bundle.
  const { log } = witnessedLog();
  const bundle = JSON.parse(JSON.stringify(log.bundle()));
  const res = verifyBundle(bundle, { minWitnesses: 1, trustedWitnesses: {} });
  assert.equal(res.ok, false);
  assert.ok(res.issues.some((m) => /only 0 valid witness signature/.test(m)));
});

// ── witnesses have to vouch for *this* bundle ─────────────────────────────

/**
 * A log of `before` entries, checkpointed and witnessed, then `after` more.
 *
 * @param {number} before
 * @param {number} after
 */
function witnessedAt(before, after) {
  const log = ProofLog.create(tmpdir());
  fill(log, before);
  const cp = log.checkpoint();
  const witness = generateIdentity().identity;
  log.addSignature(before, cosign(cp, witness).sigs.find((s) => s.role === 'witness'));
  fill(log, after);
  return { log, trusted: { [witness.kid]: witness.publicKey } };
}

test('one witness signature repeated counts as one witness', () => {
  const { log, trusted } = witnessedAt(4, 0);
  const bundle = JSON.parse(JSON.stringify(log.bundle()));
  const sig = bundle.checkpoints[0].sigs.find((s) => s.role === 'witness');
  bundle.checkpoints[0].sigs.push({ ...sig }, { ...sig });

  assert.ok(verifyBundle(bundle, { minWitnesses: 1, trustedWitnesses: trusted }).ok);
  const res = verifyBundle(bundle, { minWitnesses: 3, trustedWitnesses: trusted });
  assert.equal(res.ok, false);
  assert.ok(res.issues.some((m) => /only 1 valid witness/.test(m)), res.issues.join('\n'));
});

test('a witness requirement fails when no checkpoint carries it', () => {
  const log = ProofLog.create(tmpdir());
  fill(log, 3);
  const witness = generateIdentity().identity;
  const res = verifyBundle(log.bundle(), {
    minWitnesses: 1,
    trustedWitnesses: { [witness.kid]: witness.publicKey },
  });
  assert.equal(res.ok, false);
  assert.equal(res.witnessedSize, 0);
});

test('a filtered bundle ties an older witnessed checkpoint to its root', () => {
  const { log, trusted } = witnessedAt(5, 4);
  const opts = { minWitnesses: 1, trustedWitnesses: trusted };

  const full = verifyBundle(log.bundle(), opts);
  assert.ok(full.ok, full.issues.join('\n'));
  assert.equal(full.witnessedSize, 5, 'the last four entries are signed by the log alone');

  const bundle = JSON.parse(JSON.stringify(log.bundle({ filter: (r) => r.seq % 2 === 0 })));
  const res = verifyBundle(bundle, opts);
  assert.ok(res.ok, res.issues.join('\n'));
  assert.equal(res.witnessedSize, 5);

  bundle.consistency = {};
  assert.equal(verifyBundle(bundle, opts).ok, false, 'an unanchored checkpoint vouches for nothing');
});

test('a tampered consistency proof is reported as a rewrite', () => {
  const { log, trusted } = witnessedAt(5, 4);
  const bundle = JSON.parse(JSON.stringify(log.bundle({ filter: (r) => r.seq % 2 === 0 })));
  const proof = bundle.consistency['5'];
  proof[0] = proof[0].replace(/^./, (ch) => (ch === '0' ? '1' : '0'));
  const res = verifyBundle(bundle, { minWitnesses: 1, trustedWitnesses: trusted });
  assert.equal(res.ok, false);
  assert.ok(res.issues.some((m) => /not consistent with this bundle's root/.test(m)), res.issues.join('\n'));
});

test('a genuine witnessed checkpoint does not vouch for forged entries', () => {
  const { log: real, trusted } = witnessedAt(4, 0);
  const forged = ProofLog.create(tmpdir());
  fill(forged, 4);
  const bundle = JSON.parse(JSON.stringify(forged.bundle({ filter: (r) => r.seq < 3 })));
  bundle.keyring = { ...bundle.keyring, ...real.keyring };
  bundle.checkpoints = real.checkpoints();

  assert.equal(verifyBundle(bundle, { minWitnesses: 1, trustedWitnesses: trusted }).ok, false);
});

test('a witness minimum that is not a non-negative integer is refused, not ignored', () => {
  const log = ProofLog.create(tmpdir());
  fill(log, 2);
  for (const minWitnesses of [NaN, -1, 1.5, '1']) {
    assert.equal(verifyBundle(log.bundle(), { minWitnesses }).ok, false, String(minWitnesses));
  }
});
