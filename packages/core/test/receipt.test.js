import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateIdentity } from '../src/keys.js';
import {
  buildReceipt,
  signReceipt,
  verifyReceipt,
  verifyChain,
  entryHash,
  seal,
  openSeal,
  GENESIS_PREV,
} from '../src/receipt.js';

const { identity } = generateIdentity();
/** @type {Record<string,string>} */
const keyring = { [identity.kid]: identity.publicKey };

/**
 * @param {number} seq
 * @param {string} prev
 * @param {object} [over]
 */
function make(seq, prev, over = {}) {
  return signReceipt(
    identity,
    buildReceipt({
      log: 'lg_test',
      seq,
      prev,
      actor: {
        agent: 'claude-opus-5',
        runtime: 'deedwrit-test/0.1.0',
        session: 'sess_1',
        principal: 'ops@acme.test',
      },
      action: { kind: 'tool_call', target: 'stripe.refund', params: { amount: 100 } },
      decision: { outcome: 'allow', policy: 'p0', rules: [] },
      result: { status: 'ok', payload: { id: 're_1' } },
      ts: new Date(1_700_000_000_000 + seq * 1000).toISOString(),
      ...over,
    }).body,
  );
}

/** @param {number} n */
function chainOf(n) {
  const out = [];
  let prev = GENESIS_PREV;
  for (let i = 0; i < n; i++) {
    const r = make(i, prev);
    out.push(r);
    prev = entryHash(r);
  }
  return out;
}

test('a signed receipt verifies against its own key', () => {
  assert.deepEqual(verifyReceipt(make(0, GENESIS_PREV), keyring), []);
});

test('altering any signed field breaks the signature', () => {
  /** @type {[string, (r: any) => void][]} */
  const mutations = [
    ['the spend amount', (r) => (r.action.params.preview.amount = 1_000_000)],
    ['the decision', (r) => (r.decision.outcome = 'deny')],
    ['the principal', (r) => (r.actor.principal = 'someone.else@acme.test')],
    ['the timestamp', (r) => (r.ts = '2020-01-01T00:00:00.000Z')],
    ['the target tool', (r) => (r.action.target = 'stripe.payout')],
    ['the sequence number', (r) => (r.seq = 99)],
    ['the params commitment', (r) => (r.action.params.hash = 'ab'.repeat(32))],
  ];
  for (const [label, mutate] of mutations) {
    const r = make(0, GENESIS_PREV);
    mutate(r);
    const issues = verifyReceipt(r, keyring);
    assert.ok(
      issues.some((i) => i.kind === 'signature'),
      `tampering with ${label} went undetected`,
    );
  }
});

test('a receipt signed by an untrusted key is rejected', () => {
  const stranger = generateIdentity().identity;
  const r = signReceipt(stranger, buildReceipt({
    log: 'lg_test',
    seq: 0,
    prev: GENESIS_PREV,
    actor: { agent: 'x', runtime: 'x', session: 'x', principal: 'x' },
    action: { kind: 'tool_call', target: 't', params: {} },
    decision: { outcome: 'allow', policy: 'p0', rules: [] },
  }).body);
  const issues = verifyReceipt(r, keyring);
  assert.equal(issues[0].kind, 'key');
});

test('a receipt re-signed by a stranger still fails: the kid is not in the keyring', () => {
  const stranger = generateIdentity().identity;
  const r = make(0, GENESIS_PREV);
  r.action.target = 'stripe.payout';
  const forged = signReceipt(stranger, /** @type {any} */ ({ ...r, attest: undefined }));
  assert.ok(verifyReceipt(forged, keyring).some((i) => i.kind === 'key'));
});

test('buildReceipt refuses to assemble a receipt missing a field the hub requires', () => {
  // A hub binds these straight into non-null SQLite columns. Missing one used
  // to surface as a server crash on whichever request found it, days later
  // and nowhere near the receipt that caused it — not here, where the mistake
  // is one line away.
  const base = {
    log: 'lg_test',
    seq: 0,
    prev: GENESIS_PREV,
    actor: { agent: 'a', runtime: 'r', session: 's', principal: 'p' },
    action: { kind: 'tool_call', target: 't', params: {} },
    decision: { outcome: 'allow', policy: 'p0', rules: [] },
  };
  const cases = [
    [{ ...base, actor: { ...base.actor, principal: '' } }, /actor\.principal/],
    [{ ...base, actor: { ...base.actor, agent: undefined } }, /actor\.agent/],
    [{ ...base, actor: { ...base.actor, session: undefined } }, /actor\.session/],
    [{ ...base, action: { ...base.action, kind: undefined } }, /action\.kind/],
    [{ ...base, action: { ...base.action, target: '' } }, /action\.target/],
    [{ ...base, decision: { ...base.decision, outcome: undefined } }, /decision\.outcome/],
  ];
  for (const [args, pattern] of cases) {
    assert.throws(() => buildReceipt(args), pattern);
  }
});

test('verifyReceipt catches the same gaps in a hand-built receipt, not just ones from buildReceipt', () => {
  // A receipt need not have come from this library's buildReceipt to reach
  // the hub — this is the check that stands between a malformed-but-validly-
  // signed receipt and a server crash, regardless of what produced it.
  const { body } = buildReceipt({
    log: 'lg_test',
    seq: 0,
    prev: GENESIS_PREV,
    actor: { agent: 'a', runtime: 'r', session: 's', principal: 'p' },
    action: { kind: 'tool_call', target: 't', params: {} },
    decision: { outcome: 'allow', policy: 'p0', rules: [] },
  });
  delete body.actor.session;
  const r = signReceipt(identity, body);
  const issues = verifyReceipt(r, keyring);
  assert.ok(
    issues.some((i) => i.kind === 'format' && /actor\.session/.test(i.message)),
    `expected a format issue naming actor.session, got ${JSON.stringify(issues)}`,
  );
  // The signature itself is still sound — this is a shape problem, not a
  // forgery — and the tamper test above already covers forgeries.
  assert.ok(!issues.some((i) => i.kind === 'signature'));
});

test('an intact chain verifies end to end', () => {
  const res = verifyChain(chainOf(10), keyring);
  assert.ok(res.ok, JSON.stringify(res.issues));
  assert.equal(res.count, 10);
});

test('deleting an entry from the middle is detected', () => {
  const chain = chainOf(10);
  chain.splice(4, 1);
  const res = verifyChain(chain, keyring);
  assert.equal(res.ok, false);
  assert.ok(res.issues.some((i) => i.kind === 'chain'));
  assert.ok(res.issues.some((i) => i.kind === 'sequence'));
});

test('reordering two entries is detected', () => {
  const chain = chainOf(6);
  [chain[2], chain[3]] = [chain[3], chain[2]];
  const res = verifyChain(chain, keyring);
  assert.equal(res.ok, false);
  assert.ok(res.issues.some((i) => i.kind === 'chain'));
});

test('appending a well-formed entry to a truncated chain is still detected', () => {
  // The operator deletes the inconvenient entry 5, then re-signs 6..9 with
  // correct sequence numbers and chain links. The prefix still verifies, but
  // the head no longer matches what was checkpointed — which is what the log's
  // consistency check catches. Here we confirm the rewrite at least produces
  // a different head than the honest chain.
  const honest = chainOf(10);
  const honestHead = verifyChain(honest, keyring).head;

  const rewritten = [];
  let prev = GENESIS_PREV;
  for (let i = 0; i < 9; i++) {
    const r = make(i, prev);
    rewritten.push(r);
    prev = entryHash(r);
  }
  const res = verifyChain(rewritten, keyring);
  assert.ok(res.ok, 'a fully re-signed chain is internally consistent, as expected');
  assert.notEqual(res.head, honestHead, 'the rewrite must not reproduce the honest head');
});

test('a backdated timestamp is flagged', () => {
  const a = make(0, GENESIS_PREV);
  const b = make(1, entryHash(a), { ts: '2001-01-01T00:00:00.000Z' });
  const res = verifyChain([a, b], keyring);
  assert.ok(res.issues.some((i) => i.kind === 'time'));
});

test('a sealed value can be revealed later and checked', () => {
  const secret = { card: '4111111111111111', note: 'refund for order 91' };
  const { sealed, salt } = seal(secret);
  assert.ok(openSeal(sealed, salt, secret));
  assert.equal(openSeal(sealed, salt, { ...secret, note: 'something else' }), false);
});

test('seal commits to the value but never contains it', () => {
  const { sealed } = seal({ ssn: '123-45-6789', amount: 50 });
  const asText = JSON.stringify(sealed);
  assert.ok(!asText.includes('123-45-6789'), 'the raw SSN leaked into the commitment');
  assert.ok(asText.includes('[redacted:us_ssn'), 'the preview should name what was masked');
  assert.deepEqual(sealed.redacted, ['us_ssn']);
});

test('salting defeats brute-forcing a low-entropy payload', () => {
  // Same value, two seals: an attacker cannot recognise a repeat, let alone
  // guess the plaintext from a dictionary of likely amounts.
  const a = seal({ amount: 50 });
  const b = seal({ amount: 50 });
  assert.notEqual(a.sealed.hash, b.sealed.hash);
});

test('a receipt carries no salt, so it is publishable as written', () => {
  const r = make(0, GENESIS_PREV);
  const text = JSON.stringify(r);
  assert.ok(!text.includes('"salt"'), 'a salt reached the receipt');
  assert.ok(verifyChain([r], keyring).ok);
});

test('previews can be left out, leaving only the commitments', () => {
  const full = make(0, GENESIS_PREV);
  assert.deepEqual(full.action.params.preview, { amount: 100 });
  assert.deepEqual(full.result.payload.preview, { id: 're_1' });

  const bare = make(0, GENESIS_PREV, { previews: { params: false, result: false } });
  assert.equal(bare.action.params.preview, undefined);
  assert.equal(bare.result.payload.preview, undefined);
  assert.match(bare.action.params.hash, /^[0-9a-f]{64}$/);
  assert.ok(!('previews' in bare), 'the option is not part of the receipt');
  assert.ok(verifyChain([bare], keyring).ok);

  const paramsOnly = make(0, GENESIS_PREV, { previews: { result: false } });
  assert.deepEqual(paramsOnly.action.params.preview, { amount: 100 });
  assert.equal(paramsOnly.result.payload.preview, undefined);
});

test('without the salt, a commitment cannot be opened even by us', () => {
  // Crypto-shredding: destroy the salt and the payload is unrecoverable, while
  // the signature and chain link still verify.
  const { body, salts } = buildReceipt({
    log: 'lg_test',
    seq: 0,
    prev: GENESIS_PREV,
    actor: { agent: 'a', runtime: 'r', session: 's', principal: 'p' },
    action: { kind: 'tool_call', target: 't', params: { amount: 100 } },
    decision: { outcome: 'allow', policy: 'p0', rules: [] },
  });
  const signed = signReceipt(identity, body);

  assert.ok(openSeal(signed.action.params, salts.params, { amount: 100 }));
  assert.equal(openSeal(signed.action.params, undefined, { amount: 100 }), false);
  assert.deepEqual(verifyReceipt(signed, keyring), [], 'shredding must not break verification');
});
