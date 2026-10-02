import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ProofLog,
  verifyBundle as coreVerify,
  canonicalize as coreCanonicalize,
  generateIdentity,
  cosign,
} from '@deedwrit/core';
import * as web from '../verify.js';

/**
 * The browser verifier against the Node one.
 *
 * `site/verify.js` is a second implementation that shares no code with
 * @deedwrit/core. Two implementations that disagree on any input mean one of
 * them is wrong, so nearly everything here is a differential test: run both
 * over the same bundle and require the same verdict.
 *
 * The property that matters most is one-sided. The browser page must never say
 * "verified" about something the CLI would reject, because a visitor treats a
 * green tick as evidence.
 */

const SAMPLE = JSON.parse(
  fs.readFileSync(fileURLToPath(new URL('../sample.bundle.json', import.meta.url)), 'utf8'),
);

/** @param {any} x */
const clone = (x) => JSON.parse(JSON.stringify(x));

/**
 * The witnesses' public keys as their operators would have published them. Read
 * from the sample here only because this is a test; in real use they come from
 * outside the bundle, which is the entire point.
 */
const WITNESS_KEYS = Object.fromEntries(
  SAMPLE.checkpoints
    .flatMap((cp) => cp.sigs.filter((s) => s.role === 'witness'))
    .map((s) => [s.kid, SAMPLE.keyring[s.kid]]),
);

/**
 * Run both verifiers and demand the same verdict.
 *
 * @param {any} bundle
 * @param {object} [opts]
 * @param {string} [label]
 */
async function agree(bundle, opts = {}, label = 'bundle') {
  const c = coreVerify(clone(bundle), opts);
  const w = await web.verifyBundle(clone(bundle), opts);
  assert.equal(
    w.ok,
    c.ok,
    `${label}: browser says ${w.ok}, core says ${c.ok}\n  core: ${JSON.stringify(c.issues)}\n  web:  ${JSON.stringify(w.issues)}`,
  );
  assert.equal(w.checked, c.checked, `${label}: the two disagree on how many entries were checked`);
  return { c, w };
}

// ── canonical JSON ───────────────────────────────────────────────────────

const rand = (lo, hi) => lo + Math.floor(Math.random() * (hi - lo + 1));
const pick = (xs) => xs[rand(0, xs.length - 1)];

const NUMBERS = [0, -0, 1, -1, 0.1, 1 / 3, 1e21, 1e-7, 123456789012345680000, 2 ** 53, -(2 ** 31), 5e-324];
const ALPHABET = ['a', 'Z', '0', ' ', '"', '\\', '/', '\n', '\t', '\u0000', '\u001f', 'é', '☃', '😀', '\u2028', '\u007f'];

function randomString(max = 8) {
  return Array.from({ length: rand(0, max) }, () => pick(ALPHABET)).join('');
}

function randomNumber() {
  return Math.random() < 0.5 ? pick(NUMBERS) : (Math.random() - 0.5) * 10 ** rand(0, 12);
}

function randomValue(depth = 0) {
  const r = Math.random();
  if (depth > 3 || r < 0.35) {
    return pick([null, true, false, randomNumber(), randomNumber(), randomString(), randomString()]);
  }
  if (r < 0.65) return Array.from({ length: rand(0, 4) }, () => randomValue(depth + 1));
  const obj = {};
  for (let i = 0, n = rand(0, 5); i < n; i++) obj[randomString(6)] = randomValue(depth + 1);
  return obj;
}

test('canonical JSON matches the core implementation on thousands of random values', () => {
  for (let i = 0; i < 3000; i++) {
    const v = randomValue();
    assert.equal(web.canonicalize(v), coreCanonicalize(v), `diverged on ${JSON.stringify(v)}`);
  }
});

test('canonical JSON handles the documented awkward cases', () => {
  assert.equal(web.canonicalize({ b: 1, a: 2, A: 3, '1': 4 }), '{"1":4,"A":3,"a":2,"b":1}');
  assert.equal(web.canonicalize(-0), '0');
  assert.equal(web.canonicalize(1e21), '1e+21');
  assert.equal(web.canonicalize('\b\t\n\f\r"\\'), '"\\b\\t\\n\\f\\r\\"\\\\"');
  assert.equal(web.canonicalize('\u001f'), '"\\u001f"');
  assert.throws(() => web.canonicalize(NaN), /non-finite/);
  assert.throws(() => web.canonicalize(Infinity), /non-finite/);
});

// ── the sample ───────────────────────────────────────────────────────────

test('this environment can verify Ed25519', async () => {
  assert.equal(await web.ed25519Supported(), true);
});

test('the shipped sample bundle verifies in both implementations', async () => {
  const { c, w } = await agree(SAMPLE, {}, 'sample');
  assert.ok(c.ok, JSON.stringify(c.issues));
  assert.ok(w.ok, JSON.stringify(w.issues));
  assert.equal(w.checked, 11);

  // What the page displays comes from here, so check it is right.
  assert.equal(w.summary.entries, 11);
  assert.equal(w.summary.signed, 11, 'every signature should have verified');
  assert.equal(w.summary.outcomes.deny, 3);
  assert.equal(w.summary.partial, false);
  assert.deepEqual(w.summary.checkpoints.map((cp) => cp.witnesses), [1, 2]);
});

test('witness requirements need pinned keys, and are enforced identically', async () => {
  // Asking for witnesses without saying whose keys to trust is refused: the
  // bundle's own keyring cannot vouch for its witnesses.
  const bare = await agree(SAMPLE, { minWitnesses: 1 }, 'min 1, nothing pinned');
  assert.equal(bare.w.ok, false);
  assert.ok(bare.w.issues.some((m) => /no trusted witness keys were supplied/.test(m)));

  const pinned = { trustedWitnesses: WITNESS_KEYS };
  await agree(SAMPLE, { minWitnesses: 1, ...pinned }, 'min 1, pinned');
  assert.equal((await agree(SAMPLE, { minWitnesses: 1, ...pinned }, 'min 1')).w.ok, true);

  const strict = await agree(SAMPLE, { minWitnesses: 2, ...pinned }, 'min 2');
  assert.equal(strict.w.ok, false, 'the older checkpoint has only one witness');
  assert.ok(strict.w.issues.some((m) => /only 1 valid witness/.test(m)));
  assert.equal((await agree(SAMPLE, { minWitnesses: 3, ...pinned }, 'min 3')).w.ok, false);
});

test('witnesses the verifier did not pin are not counted', async () => {
  const [first] = Object.keys(WITNESS_KEYS);
  const onlyOne = { trustedWitnesses: { [first]: WITNESS_KEYS[first] } };

  assert.equal((await agree(SAMPLE, { minWitnesses: 1, ...onlyOne }, 'one pinned, want 1')).w.ok, true);
  // The newer checkpoint carries two, but only one of them is ours.
  assert.equal((await agree(SAMPLE, { minWitnesses: 2, ...onlyOne }, 'one pinned, want 2')).w.ok, false);
  // Trusting no one can never satisfy a demand for someone.
  assert.equal((await agree(SAMPLE, { minWitnesses: 1, trustedWitnesses: {} }, 'none pinned')).w.ok, false);
});

test('a bundle that invents its own witnesses is not fooled by them', async () => {
  const bundle = clone(SAMPLE);
  const last = bundle.checkpoints[1];
  last.sigs = last.sigs.filter((s) => s.role !== 'witness');

  // Three fabricated witnesses, each with a fresh key added to the keyring.
  for (let i = 0; i < 3; i++) {
    const fake = other();
    bundle.keyring[fake.kid] = fake.publicKey;
    last.sigs.push(cosign({ body: last.body, sigs: [] }, fake).sigs.find((s) => s.kid === fake.kid));
  }

  // Counted against the bundle's own keyring this would look like three
  // independent witnesses. Against the ones the verifier chose it is none.
  const res = await agree(bundle, { minWitnesses: 1, trustedWitnesses: WITNESS_KEYS }, 'invented witnesses');
  assert.equal(res.w.ok, false);
  assert.equal((await agree(bundle, { minWitnesses: 1 }, 'invented, unpinned')).w.ok, false);
});

test('a pinned witness is checked against the pinned key, not the bundle\'s', async () => {
  const [kid] = Object.keys(WITNESS_KEYS);
  const attacker = other();
  const bundle = clone(SAMPLE);

  // Sign with the attacker's key, claim to be the real witness, and replace the
  // bundle's keyring entry for that kid so the forgery verifies against it.
  for (const cp of bundle.checkpoints) {
    const forged = cosign({ body: cp.body, sigs: [] }, attacker).sigs.find((s) => s.role === 'witness');
    forged.kid = kid;
    cp.sigs = cp.sigs.filter((s) => s.kid !== kid);
    cp.sigs.push(forged);
  }
  bundle.keyring[kid] = attacker.publicKey;

  // Unpinned, the forgery is indistinguishable from the real thing.
  assert.equal((await agree(bundle, {}, 'forged witness, unpinned')).w.ok, true);
  // Pinned to the operator's real key, it is exposed.
  const res = await agree(bundle, { minWitnesses: 1, trustedWitnesses: WITNESS_KEYS }, 'forged witness, pinned');
  assert.equal(res.w.ok, false);
  assert.ok(res.w.issues.some((m) => /invalid witness signature/.test(m)));
});

test('a pinned witness relabelled as the log is not a log signature', async () => {
  const bundle = clone(SAMPLE);
  const cp = bundle.checkpoints[0];
  const w = cp.sigs.find((s) => s.role === 'witness');
  cp.sigs = [{ ...w, role: 'log' }];

  const res = await agree(bundle, { trustedWitnesses: WITNESS_KEYS }, 'relabelled witness');
  assert.equal(res.w.ok, false);
  assert.ok(res.w.issues.some((m) => /labelled as the log's/.test(m)));
  assert.ok(res.w.issues.some((m) => /no valid log signature/.test(m)));

  // Without pinning, a role is only a label — which is exactly why witnesses
  // have to be pinned. Both implementations still agree.
  await agree(bundle, {}, 'relabelled witness, unpinned');
});

test('malformed witness options are treated as not pinned, in both', async () => {
  for (const trustedWitnesses of ['x', 5, null, true, undefined]) {
    const res = await agree(SAMPLE, { minWitnesses: 1, trustedWitnesses }, `trusted=${JSON.stringify(trustedWitnesses)}`);
    assert.equal(res.w.ok, false);
  }
});

test('an expected root pins the history', async () => {
  assert.equal((await agree(SAMPLE, { expectRoot: SAMPLE.root }, 'right root')).w.ok, true);
  const wrong = await agree(SAMPLE, { expectRoot: 'ab'.repeat(32) }, 'wrong root');
  assert.equal(wrong.w.ok, false);
  assert.ok(wrong.w.issues.some((m) => /shown a different history/.test(m)));
});

// ── tampering ────────────────────────────────────────────────────────────

const other = () => generateIdentity().identity;

/** @type {[string, (b: any) => void, object?][]} */
const ATTACKS = [
  ['edit a refund amount', (b) => {
    const e = b.entries.find((x) => x.receipt.action.metrics?.amount_usd > 0);
    e.receipt.action.metrics.amount_usd = 1;
  }],
  ['flip a decision from deny to allow', (b) => {
    b.entries.find((x) => x.receipt.decision.outcome === 'deny').receipt.decision.outcome = 'allow';
  }],
  ['change a timestamp', (b) => { b.entries[4].receipt.ts = '2020-01-01T00:00:00.000Z'; }],
  ['change the tool that was called', (b) => { b.entries[3].receipt.action.target = 'ops.payout'; }],
  ['change the principal', (b) => { b.entries[2].receipt.actor.principal = 'someone.else@acme.test'; }],
  ['change a sequence number', (b) => { b.entries[5].receipt.seq = 99; }],
  ['delete an entry from the middle', (b) => { b.entries.splice(5, 1); }],
  ['delete the first entry', (b) => { b.entries.splice(0, 1); }],
  ['cut off the last three entries but still claim completeness', (b) => { b.entries = b.entries.slice(0, 8); }],
  ['cut off the last entry', (b) => { b.entries.pop(); }],
  ['reorder two entries', (b) => { [b.entries[2], b.entries[3]] = [b.entries[3], b.entries[2]]; }],
  ['duplicate an entry', (b) => { b.entries.push(clone(b.entries[3])); }],
  ['replace the head', (b) => { b.head = 'ab'.repeat(32); }],
  ['replace the root', (b) => { b.root = 'ef'.repeat(32); }],
  ['inflate the tree size', (b) => { b.treeSize += 5; }],
  ['shrink the tree size', (b) => { b.treeSize -= 3; }],
  ['corrupt one proof hash', (b) => {
    const p = b.entries[6].proof;
    p[0] = p[0].replace(/./, (c) => (c === '0' ? '1' : '0'));
  }],
  ['drop a proof entirely', (b) => { b.entries[6].proof = []; }],
  ['truncate a proof', (b) => { b.entries[6].proof.pop(); }],
  ['alter a checkpoint root', (b) => { b.checkpoints[0].body.root = 'cd'.repeat(32); }],
  ['alter a checkpoint size', (b) => { b.checkpoints[1].body.size = 4; }],
  ['forge a witness signature', (b) => {
    const s = b.checkpoints[1].sigs.find((x) => x.role === 'witness');
    s.sig = 'A'.repeat(86);
  }],
  ['swap the log key for another', (b) => {
    const kid = b.entries[0].receipt.attest.kid;
    b.keyring[kid] = other().publicKey;
  }],
  ['remove the log key', (b) => { delete b.keyring[b.entries[0].receipt.attest.kid]; }],
  ['claim a different key signed a receipt', (b) => { b.entries[1].receipt.attest.kid = 'pw1' + '0'.repeat(32); }],
  ['drop the signature block from a receipt', (b) => { delete b.entries[2].receipt.attest; }],
  ['change the receipt version', (b) => { b.entries[2].receipt.v = 2; }],
  ['remove the log signature from a checkpoint', (b) => {
    b.checkpoints[1].sigs = b.checkpoints[1].sigs.filter((s) => s.role !== 'log');
  }],
  ['claim a wrong bundle kind', (b) => { b.kind = 'something.else'; }],
  ['claim a future format version', (b) => { b.v = 2; }],
  ['put the checkpoints beyond the bundle', (b) => {
    b.entries = b.entries.slice(0, 4);
    b.treeSize = 4;
  }],
  ['add a fabricated entry', (b) => {
    const forged = clone(b.entries[10]);
    forged.receipt.seq = 11;
    b.entries.push(forged);
  }],
];

for (const [label, mutate] of ATTACKS) {
  test(`rejected by both: ${label}`, async () => {
    const bundle = clone(SAMPLE);
    mutate(bundle);
    const { c, w } = await agree(bundle, {}, label);
    assert.equal(c.ok, false, `the core verifier accepted: ${label}`);
    assert.equal(w.ok, false, `the browser verifier accepted: ${label}`);
    assert.ok(w.issues.length > 0);
  });
}

test('removing a witness only matters once a policy demands one', async () => {
  const bundle = clone(SAMPLE);
  bundle.checkpoints[1].sigs = bundle.checkpoints[1].sigs.filter((s) => s.role !== 'witness');

  // Nothing forged, nothing altered — one fewer attestation. That is fine
  // until the reader says it is not.
  assert.equal((await agree(bundle, {}, 'no policy')).w.ok, true);
  assert.equal(
    (await agree(bundle, { minWitnesses: 1, trustedWitnesses: WITNESS_KEYS }, 'policy')).w.ok,
    false,
  );
});

test('an honestly labelled partial bundle verifies, and a fake one does not', async () => {
  // Truncation with `partial: true` is a subset that says it is a subset. Each
  // entry is proven genuine and nothing pretends otherwise.
  const honest = clone(SAMPLE);
  honest.entries = honest.entries.slice(0, 8);
  honest.partial = true;
  const res = await agree(honest, {}, 'honest partial');
  assert.equal(res.w.ok, true, JSON.stringify(res.w.issues));
  assert.equal(res.w.summary.partial, true);

  // Erasing that label is the lie.
  const fake = clone(honest);
  fake.partial = false;
  assert.equal((await agree(fake, {}, 'partial relabelled complete')).w.ok, false);
});

test('a real filtered export verifies in both, and lying about its head does not', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-site-'));
  const log = ProofLog.create(dir);
  for (let i = 0; i < 21; i++) {
    log.append({
      actor: { agent: 'a', runtime: 'r', session: i % 2 ? 'odd' : 'even', principal: 'p' },
      action: { kind: 'tool_call', target: 'ops.q', params: { i }, metrics: { n: i } },
      decision: { outcome: i % 5 === 0 ? 'deny' : 'allow', policy: 'p', rules: [], reason: 'r' },
    });
  }
  log.checkpoint();

  const filtered = clone(log.bundle({ filter: (r) => r.actor.session === 'even' || r.seq === 20 }));
  assert.equal(filtered.partial, true);
  assert.equal((await agree(filtered, {}, 'filtered export')).w.ok, true);

  filtered.head = 'cd'.repeat(32);
  assert.equal((await agree(filtered, {}, 'filtered, head replaced')).w.ok, false);
});

// ── hostile input ────────────────────────────────────────────────────────

test('hostile shapes never throw and never verify', async () => {
  const shapes = [
    undefined, null, 0, 1, 'x', true, [], [1, 2], {}, { kind: 'deedwrit.bundle' },
    { kind: 'deedwrit.bundle', v: 1 },
    { kind: 'deedwrit.bundle', v: 1, root: 'zz' },
    { kind: 'deedwrit.bundle', v: 1, root: 5 },
    { ...clone(SAMPLE), entries: 'not-an-array' },
    { ...clone(SAMPLE), entries: 5 },
    { ...clone(SAMPLE), entries: [null, 3, 'x', [], {}] },
    { ...clone(SAMPLE), checkpoints: 5 },
    { ...clone(SAMPLE), checkpoints: [null, {}, { body: null }, { body: {}, sigs: 5 }] },
    { ...clone(SAMPLE), keyring: 'nope' },
    { ...clone(SAMPLE), keyring: null },
    { ...clone(SAMPLE), treeSize: 'big' },
    { ...clone(SAMPLE), treeSize: -1 },
    { ...clone(SAMPLE), treeSize: 1.5 },
    { ...clone(SAMPLE), root: SAMPLE.root.toUpperCase() },
    { ...clone(SAMPLE), keyring: { __proto__: { evil: 1 }, constructor: 'x' } },
  ];

  for (const [i, shape] of shapes.entries()) {
    const label = `shape ${i}: ${JSON.stringify(shape)?.slice(0, 60)}`;
    let c;
    let w;
    assert.doesNotThrow(() => { c = coreVerify(shape); }, `core threw on ${label}`);
    await assert.doesNotReject(async () => { w = await web.verifyBundle(shape); }, `browser threw on ${label}`);
    assert.equal(c.ok, false, `core accepted ${label}`);
    assert.equal(w.ok, false, `browser accepted ${label}`);
  }
});

test('a receipt claiming a signer named like an Object.prototype property is not trusted', async () => {
  for (const kid of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) {
    const bundle = clone(SAMPLE);
    bundle.entries[0].receipt.attest.kid = kid;
    const { w } = await agree(bundle, {}, `kid ${kid}`);
    assert.equal(w.ok, false);
  }
});

// ── differential fuzzing ─────────────────────────────────────────────────

/**
 * Every leaf value in the bundle, as a path.
 *
 * @param {any} node
 * @param {(string|number)[]} at
 * @param {(string|number)[][]} out
 */
function leafPaths(node, at = [], out = []) {
  if (node !== null && typeof node === 'object') {
    for (const k of Object.keys(node)) leafPaths(node[k], [...at, Array.isArray(node) ? Number(k) : k], out);
  } else {
    out.push(at);
  }
  return out;
}

/** @param {any} root @param {(string|number)[]} at */
function parentOf(root, at) {
  return at.slice(0, -1).reduce((n, k) => n[k], root);
}

test('random single-value mutations get the same verdict from both', async () => {
  const paths = leafPaths(SAMPLE);
  let rejected = 0;
  const rounds = 300;

  for (let i = 0; i < rounds; i++) {
    const bundle = clone(SAMPLE);
    const at = pick(paths);
    const parent = parentOf(bundle, at);
    const key = at[at.length - 1];
    const value = parent[key];

    if (typeof value === 'string') {
      const cut = rand(0, Math.max(0, value.length - 1));
      parent[key] = pick([
        value.slice(0, cut) + pick(['x', '0', 'f', ' ', '"']) + value.slice(cut + 1),
        value.slice(0, Math.max(0, value.length - 1)),
        value + pick(['0', 'a', '=', ' ', '\n', '+', '/']),
        '',
      ]);
    } else if (typeof value === 'number') {
      parent[key] = pick([value + 1, value - 1, value * 2, 0, -1, 1.5]);
    } else if (typeof value === 'boolean') {
      parent[key] = !value;
    } else {
      parent[key] = pick([0, 'x', true, [], {}]);
    }

    const { c } = await agree(bundle, {}, `mutation ${i} at ${at.join('.')}`);
    if (!c.ok) rejected++;
  }

  // The fuzz needs teeth: most single-value changes touch something signed,
  // hashed or proven, so most of them must be caught.
  assert.ok(rejected > rounds * 0.5, `only ${rejected} of ${rounds} mutations were rejected`);
});

test('random structural mutations get the same verdict from both', async () => {
  for (let i = 0; i < 150; i++) {
    const bundle = clone(SAMPLE);
    const op = rand(0, 4);
    const n = bundle.entries.length;

    if (op === 0) bundle.entries.splice(rand(0, n - 1), 1);
    else if (op === 1) {
      const a = rand(0, n - 1);
      const b = rand(0, n - 1);
      [bundle.entries[a], bundle.entries[b]] = [bundle.entries[b], bundle.entries[a]];
    } else if (op === 2) bundle.entries.splice(rand(0, n), 0, clone(pick(bundle.entries)));
    else if (op === 3) bundle.entries = bundle.entries.slice(rand(0, n - 1), rand(1, n));
    else delete bundle[pick(['head', 'root', 'treeSize', 'keyring', 'checkpoints', 'partial'])];

    await agree(bundle, {}, `structural mutation ${i} (op ${op})`);
  }
});

test('freshly generated random logs verify in both, complete and filtered', async () => {
  for (let round = 0; round < 12; round++) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-site-rand-'));
    const log = ProofLog.create(dir);
    const witnesses = Array.from({ length: rand(0, 3) }, () => generateIdentity().identity);
    for (const w of witnesses) log.trustKey(w.kid, w.publicKey);

    const size = rand(1, 45);
    for (let i = 0; i < size; i++) {
      log.append({
        actor: { agent: 'a', runtime: 'r', session: `s${i % 4}`, principal: `p${i % 3}` },
        action: {
          kind: 'tool_call',
          target: pick(['ops.refund', 'ops.query', 'crm.lookup']),
          params: { i, note: randomString(12) },
          metrics: { amount_usd: rand(0, 200) },
        },
        decision: {
          outcome: pick(['allow', 'allow', 'deny', 'escalate']),
          policy: 'p',
          rules: [],
          reason: randomString(20),
        },
        result: Math.random() < 0.5 ? { status: 'ok', payload: { i }, latencyMs: rand(1, 90) } : null,
      });
      if (Math.random() < 0.15) {
        const cp = log.checkpoint();
        for (const w of witnesses) {
          const sig = cosign(cp, w).sigs.find((s) => s.kid === w.kid);
          log.addSignature(cp.body.size, sig);
        }
      }
    }

    const complete = clone(log.bundle());
    const resComplete = await agree(complete, {}, `random log ${round} complete`);
    assert.equal(resComplete.w.ok, true, JSON.stringify(resComplete.w.issues));

    const k = rand(2, 5);
    const partial = clone(log.bundle({ filter: (r) => r.seq % k === 0 || r.seq === size - 1 }));
    const resPartial = await agree(partial, {}, `random log ${round} filtered`);
    assert.equal(resPartial.w.ok, true, JSON.stringify(resPartial.w.issues));

    // And the same log with one entry quietly altered.
    if (complete.entries.length > 1) {
      const tampered = clone(complete);
      tampered.entries[rand(0, tampered.entries.length - 1)].receipt.ts = '1999-01-01T00:00:00.000Z';
      assert.equal((await agree(tampered, {}, `random log ${round} tampered`)).w.ok, false);
    }
  }
});

test('an empty log exports a bundle both verify, and a forged head is rejected', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-site-empty-'));
  const log = ProofLog.create(dir);
  const bundle = clone(log.bundle());
  assert.equal((await agree(bundle, {}, 'empty')).w.ok, true);

  bundle.head = 'ab'.repeat(32);
  assert.equal((await agree(bundle, {}, 'empty, forged head')).w.ok, false);
});

test('a checkpoint of the empty log verifies in both, rather than looking like a rewrite', async () => {
  const log = ProofLog.create(fs.mkdtempSync(path.join(os.tmpdir(), 'pw-site-cp0-')));
  log.checkpoint();
  assert.equal((await agree(clone(log.bundle()), {}, 'checkpointed while empty')).w.ok, true);
});

test('random mutations agree on the witness path too', async () => {
  const paths = leafPaths(SAMPLE);
  const opts = { minWitnesses: 1, trustedWitnesses: WITNESS_KEYS };

  for (let i = 0; i < 200; i++) {
    const bundle = clone(SAMPLE);
    const at = pick(paths);
    const parent = parentOf(bundle, at);
    const key = at[at.length - 1];
    const value = parent[key];
    parent[key] =
      typeof value === 'string' ? value.slice(0, -1) + pick(['x', '0', 'A'])
      : typeof value === 'number' ? value + 1
      : typeof value === 'boolean' ? !value
      : 0;
    await agree(bundle, opts, `pinned mutation ${i} at ${at.join('.')}`);
  }
});

test('both anchor witnesses to the bundle, and refuse repeated or unanchored ones', async () => {
  const actor = { agent: 'a', runtime: 'r', session: 's', principal: 'p@acme.test' };
  const make = (n, target) => {
    const log = ProofLog.create(fs.mkdtempSync(path.join(os.tmpdir(), 'pw-site-anchor-')));
    for (let i = 0; i < n; i++) {
      log.append({ actor, action: { kind: 'tool_call', target, params: { i } }, decision: { outcome: 'allow' } });
    }
    return log;
  };
  const witness = generateIdentity().identity;
  const trusted = { [witness.kid]: witness.publicKey };
  const log = make(5, 'real');
  const cp = log.checkpoint();
  log.addSignature(5, cosign(cp, witness).sigs.find((s) => s.role === 'witness'));
  for (let i = 0; i < 4; i++) {
    log.append({ actor, action: { kind: 'tool_call', target: 'real', params: { i } }, decision: { outcome: 'allow' } });
  }
  const opts = { minWitnesses: 1, trustedWitnesses: trusted };

  const partial = clone(log.bundle({ filter: (r) => r.seq % 2 === 0 }));
  const { c, w } = await agree(partial, opts, 'honest partial');
  assert.ok(c.ok && w.ok);
  assert.equal(w.summary.witnessedSize, 5);

  const unanchored = clone(partial);
  unanchored.consistency = {};
  assert.equal((await agree(unanchored, opts, 'unanchored')).w.ok, false);

  const repeated = clone(log.bundle());
  const sig = repeated.checkpoints[0].sigs.find((s) => s.role === 'witness');
  repeated.checkpoints[0].sigs.push({ ...sig }, { ...sig });
  assert.equal((await agree(repeated, { minWitnesses: 3, trustedWitnesses: trusted }, 'repeated')).w.ok, false);

  assert.equal((await agree(clone(make(3, 'x').bundle()), opts, 'no checkpoints')).w.ok, false);

  const forged = clone(make(4, 'forged').bundle({ filter: (r) => r.seq < 3 }));
  forged.keyring = { ...forged.keyring, ...log.keyring };
  forged.checkpoints = log.checkpoints();
  assert.equal((await agree(forged, opts, 'spliced checkpoint')).w.ok, false);

  assert.equal((await agree(clone(log.bundle()), { minWitnesses: NaN }, 'NaN minimum')).w.ok, false);
});
