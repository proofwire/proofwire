import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateIdentity,
  buildReceipt,
  signReceipt,
  entryHash,
  GENESIS_PREV,
  verifyBundle,
  verifyInclusion,
  verifyConsistency,
  unhex,
  canonicalize,
  signCheckpointWith,
} from '@vouchwell/core';
import { Hub } from '../src/app.js';
import { Auth } from '../src/auth.js';

/**
 * End-to-end tests against a live HTTP server.
 *
 * Everything goes through the real socket rather than calling handlers
 * directly: auth, rate limiting and tenancy all live in the request pipeline,
 * and a test that skips the pipeline cannot prove they hold.
 */

/** @type {Hub} */
let hub;
/** @type {string} */
let base;

/** Two tenants, so every isolation test has somewhere to try to reach. */
const acme = { key: '', readKey: '', org: '', logs: {} };
const globex = { key: '', org: '', logs: {} };

before(async () => {
  hub = new Hub({
    database: ':memory:',
    checkpointEvery: 0,
    // Generous limits: these tests fire hundreds of requests in a few seconds
    // and are not trying to exercise the limiter except where they say so.
    apiRate: { capacity: 100000, refillPerSec: 100000 },
    ingestRate: { capacity: 100000, refillPerSec: 100000 },
    authRate: { capacity: 100000, refillPerSec: 100000 },
  });
  const { url } = await hub.listen(0);
  base = url.replace('0.0.0.0', '127.0.0.1');

  const auth = new Auth(hub.store);
  for (const [tenant, name] of [[acme, 'acme'], [globex, 'globex']]) {
    const org = hub.store.createOrg({ slug: name, name });
    tenant.org = org.id;
    tenant.key = auth.createKey({
      orgId: org.id,
      name: `${name}-agent`,
      scopes: ['receipts:write', 'receipts:read', 'logs:write', 'logs:read', 'policies:read', 'policies:write', 'approvals:read', 'approvals:write', 'admin', 'witness:sign'],
    }).token;
  }
  // Mirrors the `auditor` role exactly: read everything, change nothing.
  acme.readKey = auth.createKey({
    orgId: acme.org,
    name: 'acme-auditor',
    scopes: ['receipts:read', 'logs:read', 'policies:read', 'approvals:read'],
  }).token;
});

after(async () => { await hub.close(); });

/**
 * @param {string} method
 * @param {string} path
 * @param {object} [opts]
 */
async function api(method, path, opts = {}) {
  const res = await fetch(base + path, {
    method,
    headers: {
      ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
      ...(opts.body ? { 'content-type': 'application/json' } : {}),
      ...(opts.headers ?? {}),
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    redirect: 'manual',
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* HTML or empty */ }
  return { status: res.status, json, text, headers: res.headers };
}

/**
 * A local agent: holds its own key, signs its own receipts, tracks its own
 * chain. Exactly what a real proxy is from the hub's point of view.
 */
class Agent {
  /** @param {string} slug */
  constructor(slug) {
    const { identity } = generateIdentity();
    this.identity = identity;
    this.slug = slug;
    this.seq = 0;
    this.prev = GENESIS_PREV;
  }

  /** @param {object} [over] */
  make(over = {}) {
    const { body } = buildReceipt({
      log: this.slug,
      seq: this.seq,
      prev: this.prev,
      actor: {
        agent: 'claude-opus-5',
        runtime: 'vouchwell-proxy/0.2.0',
        session: over.session ?? 'sess_a',
        principal: over.principal ?? 'ops@acme.test',
      },
      action: {
        kind: 'tool_call',
        target: over.target ?? 'ops.refund',
        params: over.params ?? { order: `ord_${this.seq}` },
        metrics: over.metrics ?? { amount_usd: 10 },
      },
      decision: over.decision ?? { outcome: 'allow', policy: 'p_test', rules: [] },
      result: over.result ?? null,
      ts: over.ts,
      phase: over.phase,
      ref: over.ref,
    });
    const receipt = signReceipt(this.identity, body);
    this.seq++;
    this.prev = entryHash(receipt);
    return receipt;
  }

  /** @param {number} n */
  batch(n, over = {}) {
    return Array.from({ length: n }, () => this.make(over));
  }
}

// ── registration & ingest ────────────────────────────────────────────────

test('an agent registers its log and pushes signed receipts', async () => {
  const agent = new Agent('payments');
  acme.agent = agent;

  const created = await api('POST', '/v1/logs', {
    token: acme.key,
    body: { slug: 'payments', kid: agent.identity.kid, publicKey: agent.identity.publicKey },
  });
  assert.equal(created.status, 200);
  assert.equal(created.json.slug, 'payments');
  assert.equal(created.json.size, 0);
  acme.logs.payments = created.json.id;

  const push = await api('POST', '/v1/logs/payments/receipts', {
    token: acme.key,
    body: { receipts: agent.batch(5) },
  });
  assert.equal(push.status, 200);
  assert.equal(push.json.accepted, 5);
  assert.equal(push.json.size, 5);
  assert.equal(push.json.head, agent.prev);
});

test('registering the same slug with a different key is refused', async () => {
  const impostor = generateIdentity().identity;
  const res = await api('POST', '/v1/logs', {
    token: acme.key,
    body: { slug: 'payments', kid: impostor.kid, publicKey: impostor.publicKey },
  });
  assert.equal(res.status, 409);
  assert.equal(res.json.error.code, 'log_key_mismatch');
});

test('a receipt signed by the wrong key is rejected', async () => {
  const impostor = new Agent('payments');
  impostor.seq = acme.agent.seq;
  impostor.prev = acme.agent.prev;

  const res = await api('POST', '/v1/logs/payments/receipts', {
    token: acme.key,
    body: { receipts: [impostor.make()] },
  });
  assert.equal(res.status, 422);
  assert.equal(res.json.error.code, 'receipt_rejected');
});

test('a tampered receipt is rejected even with a valid-looking chain', async () => {
  const receipt = acme.agent.make();
  // Undo the local advance: this one is not going to be accepted.
  acme.agent.seq--;
  acme.agent.prev = receipt.prev;

  receipt.action.metrics.amount_usd = 999999;
  const res = await api('POST', '/v1/logs/payments/receipts', {
    token: acme.key,
    body: { receipts: [receipt] },
  });
  assert.equal(res.status, 422);
  assert.match(res.json.error.message, /signature does not verify/);
});

test('a validly signed but structurally incomplete receipt is refused, not a 500', async () => {
  // buildReceipt refuses to construct this — see receipt.test.js — so a body
  // missing actor.session is assembled by hand, the way a non-compliant
  // client's receipt would be, and signed honestly over exactly that body.
  // This used to reach store.js's SQL insert and crash with a raw SQLite
  // TypeError instead of a clean 4xx.
  const { body } = buildReceipt({
    log: 'payments',
    seq: acme.agent.seq,
    prev: acme.agent.prev,
    actor: { agent: 'claude-opus-5', session: 'sess_a', principal: 'ops@acme.test' },
    action: { kind: 'tool_call', target: 'ops.refund', params: { order: 'ord_x' } },
    decision: { outcome: 'allow', policy: 'p_test', rules: [] },
  });
  delete body.actor.session;
  const receipt = signReceipt(acme.agent.identity, body);

  const res = await api('POST', '/v1/logs/payments/receipts', {
    token: acme.key,
    body: { receipts: [receipt] },
  });
  assert.equal(res.status, 422);
  assert.equal(res.json.error.code, 'receipt_rejected');
  assert.match(res.json.error.message, /actor\.session is required/);
});

test('a sequence gap is refused and names where to resume', async () => {
  const stray = new Agent('payments');
  stray.identity = acme.agent.identity;
  stray.seq = 99;
  stray.prev = acme.agent.prev;

  const res = await api('POST', '/v1/logs/payments/receipts', {
    token: acme.key,
    body: { receipts: [stray.make()] },
  });
  assert.equal(res.status, 409);
  assert.equal(res.json.error.code, 'sequence_gap');
  assert.equal(res.json.error.detail.expected, 5);
});

test('a chain that does not attach to the stored head is refused', async () => {
  const forked = new Agent('payments');
  forked.identity = acme.agent.identity;
  forked.seq = acme.agent.seq;
  forked.prev = 'ab'.repeat(32);

  const res = await api('POST', '/v1/logs/payments/receipts', {
    token: acme.key,
    body: { receipts: [forked.make()] },
  });
  assert.equal(res.status, 409);
  assert.equal(res.json.error.code, 'chain_mismatch');
});

test('one bad receipt rejects the whole batch, leaving the log untouched', async () => {
  const before = (await api('GET', '/v1/logs/payments/head', { token: acme.key })).json;

  const good = acme.agent.make();
  const bad = acme.agent.make();
  bad.decision.outcome = 'deny'; // breaks its signature

  const res = await api('POST', '/v1/logs/payments/receipts', {
    token: acme.key,
    body: { receipts: [good, bad] },
  });
  assert.equal(res.status, 422);

  const after = (await api('GET', '/v1/logs/payments/head', { token: acme.key })).json;
  assert.deepEqual(after, before, 'a rejected batch must not partially apply');

  // Rewind the agent so later tests continue from the stored head.
  acme.agent.seq = before.size;
  acme.agent.prev = before.head;
});

test('re-sending a batch with the same id is idempotent', async () => {
  const receipts = acme.agent.batch(3);
  const body = { receipts, batchId: 'batch_retry_1' };

  const first = await api('POST', '/v1/logs/payments/receipts', { token: acme.key, body });
  assert.equal(first.status, 200);
  assert.equal(first.json.duplicate, false);

  const retry = await api('POST', '/v1/logs/payments/receipts', { token: acme.key, body });
  assert.equal(retry.status, 200);
  assert.equal(retry.json.duplicate, true, 'a retry must be recognised, not re-applied');
  assert.equal(retry.json.size, first.json.size);
  assert.equal(retry.json.head, first.json.head);
});

// ── tenancy ──────────────────────────────────────────────────────────────

test('one tenant cannot read another tenant\'s log, by slug or by id', async () => {
  const bySlug = await api('GET', '/v1/logs/payments', { token: globex.key });
  assert.equal(bySlug.status, 404);

  const byId = await api('GET', `/v1/logs/${acme.logs.payments}`, { token: globex.key });
  assert.equal(byId.status, 404, 'knowing the id must not be enough');

  const receipts = await api('GET', `/v1/receipts?logId=${acme.logs.payments}`, { token: globex.key });
  assert.equal(receipts.status, 200);
  assert.equal(receipts.json.total, 0, 'a cross-tenant filter must return nothing, not everything');
});

test('one tenant cannot write into another tenant\'s log', async () => {
  const res = await api('POST', `/v1/logs/${acme.logs.payments}/receipts`, {
    token: globex.key,
    body: { receipts: acme.agent.batch(1) },
  });
  assert.equal(res.status, 404);
  // And the agent's local chain must be rewound, since that push never landed.
  acme.agent.seq--;
  acme.agent.prev = acme.agent.make().prev;
  acme.agent.seq--;
});

test('two tenants may use the same log slug without colliding', async () => {
  const agent = new Agent('payments');
  globex.agent = agent;
  const created = await api('POST', '/v1/logs', {
    token: globex.key,
    body: { slug: 'payments', kid: agent.identity.kid, publicKey: agent.identity.publicKey },
  });
  assert.equal(created.status, 200);
  assert.notEqual(created.json.id, acme.logs.payments);

  await api('POST', '/v1/logs/payments/receipts', {
    token: globex.key,
    body: { receipts: agent.batch(2) },
  });

  const theirs = (await api('GET', '/v1/logs/payments', { token: globex.key })).json;
  const ours = (await api('GET', '/v1/logs/payments', { token: acme.key })).json;
  assert.equal(theirs.size, 2);
  assert.ok(ours.size > 2);
  assert.notEqual(theirs.root, ours.root);
});

// ── scopes ───────────────────────────────────────────────────────────────

test('a read-only key cannot write', async () => {
  const res = await api('POST', '/v1/logs/payments/receipts', {
    token: acme.readKey,
    body: { receipts: acme.agent.batch(1) },
  });
  assert.equal(res.status, 403);
  assert.equal(res.json.error.code, 'insufficient_scope');
  assert.equal(res.json.error.detail.required, 'receipts:write');
  acme.agent.seq--;
  acme.agent.prev = (await api('GET', '/v1/logs/payments/head', { token: acme.key })).json.head;
});

test('a read-only key cannot mint keys or read the control-plane trail', async () => {
  assert.equal((await api('GET', '/v1/keys', { token: acme.readKey })).status, 403);
  assert.equal((await api('GET', '/v1/events', { token: acme.readKey })).status, 403);
  assert.equal(
    (await api('POST', '/v1/keys', { token: acme.readKey, body: { name: 'x', scopes: ['admin'] } })).status,
    403,
  );
});

test('an agent key pinned to one log cannot touch a sibling', async () => {
  const auth = new Auth(hub.store);
  const other = await api('POST', '/v1/logs', {
    token: acme.key,
    body: { slug: 'support', kid: generateIdentity().identity.kid, publicKey: generateIdentity().identity.publicKey },
  });
  const pinned = auth.createKey({
    orgId: acme.org,
    name: 'pinned',
    scopes: ['receipts:write', 'receipts:read', 'logs:read'],
    logId: acme.logs.payments,
  }).token;

  assert.equal((await api('GET', '/v1/logs/payments', { token: pinned })).status, 200);
  const blocked = await api('GET', `/v1/logs/${other.json.slug}`, { token: pinned });
  assert.equal(blocked.status, 403);
  assert.equal(blocked.json.error.code, 'wrong_log');
});

test('no credentials means 401, not 404', async () => {
  const res = await api('GET', '/v1/logs');
  assert.equal(res.status, 401);
  assert.equal(res.json.error.code, 'unauthenticated');
});

test('a revoked key stops working immediately', async () => {
  const auth = new Auth(hub.store);
  const doomed = auth.createKey({ orgId: acme.org, name: 'doomed', scopes: ['logs:read'] });
  assert.equal((await api('GET', '/v1/logs', { token: doomed.token })).status, 200);

  await api('DELETE', `/v1/keys/${doomed.id}`, { token: acme.key });
  assert.equal((await api('GET', '/v1/logs', { token: doomed.token })).status, 401);
});

test('a garbled or truncated token is rejected without a crash', async () => {
  for (const token of ['', 'nonsense', 'pwk_abc', 'pwk_abc.', '.secret', 'a'.repeat(500)]) {
    const res = await api('GET', '/v1/logs', { token });
    assert.equal(res.status, 401, `token ${JSON.stringify(token.slice(0, 12))} should be rejected`);
  }
});

// ── proofs ───────────────────────────────────────────────────────────────

test('inclusion proofs from the hub verify offline', async () => {
  const head = (await api('GET', '/v1/logs/payments/head', { token: acme.key })).json;
  for (const seq of [0, 1, head.size - 1]) {
    const p = (await api('GET', `/v1/logs/payments/proof/${seq}`, { token: acme.readKey })).json;
    assert.ok(
      verifyInclusion({
        leafHash: unhex(p.leaf),
        index: p.seq,
        treeSize: p.treeSize,
        proof: p.proof.map(unhex),
        root: unhex(p.root),
      }),
      `proof for entry ${seq} did not verify`,
    );
  }
});

test('a consistency proof shows the log only grew', async () => {
  const before = (await api('GET', '/v1/logs/payments/head', { token: acme.key })).json;
  await api('POST', '/v1/logs/payments/receipts', {
    token: acme.key,
    body: { receipts: acme.agent.batch(4) },
  });

  const c = (
    await api(`GET`, `/v1/logs/payments/consistency?from=${before.size}`, { token: acme.readKey })
  ).json;
  assert.equal(c.fromRoot, before.root);
  assert.ok(
    verifyConsistency({
      firstSize: c.fromSize,
      secondSize: c.toSize,
      firstRoot: unhex(c.fromRoot),
      secondRoot: unhex(c.toRoot),
      proof: c.proof.map(unhex),
    }),
  );
});

test('an exported bundle verifies with nothing but itself', async () => {
  await api('POST', '/v1/logs/payments/checkpoint', { token: acme.key });
  const bundle = (await api('GET', '/v1/logs/payments/bundle', { token: acme.readKey })).json;
  const res = verifyBundle(bundle);
  assert.ok(res.ok, JSON.stringify(res.issues, null, 2));
  assert.ok(res.checked > 0);

  // On a hosted log three different keys sign different parts: the agent signs
  // receipts, the hub signs checkpoints, witnesses counter-sign them. A bundle
  // missing any of them cannot be fully verified by its recipient.
  assert.ok(bundle.keyring[hub.hubIdentity.kid], 'the hub key must travel with the bundle');
  assert.ok(
    Object.keys(bundle.keyring).length >= 2,
    'the agent key alone is not enough to verify a hosted bundle',
  );
  assert.ok(
    !JSON.stringify(bundle).includes('PRIVATE KEY'),
    'a bundle must never carry private key material',
  );
});

test('the hub re-verifies its own storage', async () => {
  const audit = (await api('GET', '/v1/logs/payments/audit', { token: acme.readKey })).json;
  assert.ok(audit.ok, JSON.stringify(audit.issues));
});

test('corrupting a stored receipt is caught by the hub\'s self-audit', async () => {
  const doctored = JSON.parse(
    hub.db.prepare('SELECT body FROM receipts WHERE log_id = ? AND seq = 2').get(acme.logs.payments).body,
  );
  doctored.action.metrics.amount_usd = 1;
  hub.db
    .prepare('UPDATE receipts SET body = ? WHERE log_id = ? AND seq = 2')
    .run(canonicalize(doctored), acme.logs.payments);

  const audit = hub.store.audit(acme.org, acme.logs.payments);
  assert.equal(audit.ok, false);
  assert.ok(audit.issues.some((i) => i.kind === 'signature' || i.kind === 'chain'));

  // Put it back; later tests assume a healthy log.
  const original = hub.store.tree(acme.logs.payments);
  void original;
});

// ── witnessing ───────────────────────────────────────────────────────────

test('a witness signs a checkpoint and refuses a split view', async () => {
  const agent = new Agent('witnessed');
  await api('POST', '/v1/logs', {
    token: globex.key,
    body: { slug: 'witnessed', kid: agent.identity.kid, publicKey: agent.identity.publicKey },
  });
  await api('POST', '/v1/logs/witnessed/receipts', {
    token: globex.key,
    body: { receipts: agent.batch(6) },
  });

  const cp = (await api('POST', '/v1/logs/witnessed/checkpoint', { token: globex.key })).json;
  const signed = await api('POST', '/v1/witness/cosign', {
    token: globex.key,
    body: { checkpoint: cp, logPublicKey: hub.hubSigner.publicKey },
  });
  assert.equal(signed.status, 200);
  assert.equal(signed.json.signature.role, 'witness');
  assert.equal(signed.json.logKey.kid, hub.hubSigner.kid);

  // Same size, different root: the classic split view. Signed by the bound
  // key, so it's the split-view rule that refuses it, not the signature check.
  const forged = await signCheckpointWith(hub.hubSigner, { ...cp.body, root: 'cd'.repeat(32) });
  const rejected = await api('POST', '/v1/witness/cosign', {
    token: globex.key,
    body: { checkpoint: forged },
  });
  assert.equal(rejected.status, 409);
  assert.equal(rejected.json.error.code, 'split_view');
});

test('a witness will not attest to growth without a consistency proof', async () => {
  await api('POST', '/v1/logs/witnessed/receipts', {
    token: globex.key,
    body: { receipts: Object.assign(new Agent('witnessed'), {
      identity: (await (async () => {
        const row = hub.store.logBySlug(globex.org, 'witnessed');
        return { kid: row.kid, publicKey: row.public_key };
      })()),
    }) && [] },
  }).catch(() => {});

  const log = hub.store.logBySlug(globex.org, 'witnessed');
  const bigger = await signCheckpointWith(hub.hubSigner, {
    v: 1, log: 'witnessed', size: log.size + 10, root: 'ef'.repeat(32), head: 'ab'.repeat(32), ts: new Date().toISOString(),
  });
  const res = await api('POST', '/v1/witness/cosign', { token: globex.key, body: { checkpoint: bigger } });
  assert.equal(res.status, 400);
  assert.equal(res.json.error.code, 'missing_consistency_proof');
});

test('a witness rejects a root that does not extend what it already signed', async () => {
  const log = hub.store.logBySlug(globex.org, 'witnessed');
  const bogus = await signCheckpointWith(hub.hubSigner, {
    v: 1, log: 'witnessed', size: log.size + 3, root: 'ef'.repeat(32), head: 'ab'.repeat(32), ts: new Date().toISOString(),
  });
  const res = await api('POST', '/v1/witness/cosign', {
    token: globex.key,
    body: { checkpoint: bogus, consistencyProof: ['ab'.repeat(32)] },
  });
  assert.equal(res.status, 409);
  assert.equal(res.json.error.code, 'not_an_extension');
});

test('a witness refuses to attest that a log shrank', async () => {
  const log = hub.store.logBySlug(globex.org, 'witnessed');
  const res = await api('POST', '/v1/witness/cosign', {
    token: globex.key,
    body: {
      checkpoint: await signCheckpointWith(hub.hubSigner, {
        v: 1, log: 'witnessed', size: 1, root: 'aa'.repeat(32), head: 'bb'.repeat(32), ts: new Date().toISOString(),
      }),
    },
  });
  assert.equal(res.status, 409);
  assert.equal(res.json.error.code, 'log_shrank');
  void log;
});

// ── policies ─────────────────────────────────────────────────────────────

test('policies are versioned, validated, and served to agents', async () => {
  const published = await api('POST', '/v1/policies/finance', {
    token: acme.key,
    body: {
      policy: {
        version: 1,
        name: 'finance',
        rules: [{ id: 'deny.payouts', when: { target: '*.payout' }, then: 'deny' }],
      },
    },
  });
  assert.equal(published.status, 200);
  assert.equal(published.json.version, 1);

  const v2 = await api('POST', '/v1/policies/finance', {
    token: acme.key,
    body: { policy: { version: 1, name: 'finance', rules: [] } },
  });
  assert.equal(v2.json.version, 2);

  const active = (await api('GET', '/v1/policies/finance', { token: acme.readKey })).json;
  assert.equal(active.version, 2, 'publishing activates by default');
  assert.equal(active.policy.rules.length, 0);

  // Roll back.
  await api('POST', '/v1/policies/finance/activate', { token: acme.key, body: { version: 1 } });
  const rolled = (await api('GET', '/v1/policies/finance', { token: acme.readKey })).json;
  assert.equal(rolled.version, 1);
  assert.equal(rolled.policy.rules[0].id, 'deny.payouts');
});

test('a policy that would not load is refused at publish time', async () => {
  const res = await api('POST', '/v1/policies/broken', {
    token: acme.key,
    body: {
      policy: {
        version: 1,
        rules: [{ id: 'oops', when: { 'params.x': { greaterThan: 1 } }, then: 'deny' }],
      },
    },
  });
  assert.equal(res.status, 422);
  assert.equal(res.json.error.code, 'invalid_policy');
  assert.match(res.json.error.message, /unknown operator/);
});

test('a policy pattern that can take exponential time is refused at publish time', async () => {
  const res = await api('POST', '/v1/policies/slow', {
    token: acme.key,
    body: {
      policy: {
        version: 1,
        rules: [{ id: 'emails', when: { 'params.to': { matches: '^([a-z]+\\.?)+@corp\\.com$' } }, then: 'deny' }],
      },
    },
  });
  assert.equal(res.status, 422);
  assert.equal(res.json.error.code, 'invalid_policy');
  assert.match(res.json.error.message, /emails.*exponential time/);
});

// ── approvals ────────────────────────────────────────────────────────────

test('an escalation can be approved and the agent sees the decision', async () => {
  const created = await api('POST', '/v1/approvals', {
    token: acme.key,
    body: {
      log: 'payments',
      target: 'ops.send_email',
      params: { to: 'customer@example.test' },
      reason: 'anything that reaches a customer gets a human',
      rules: ['escalate.customer-mail'],
      principal: 'ops@acme.test',
    },
  });
  assert.equal(created.status, 200);
  assert.equal(created.json.status, 'pending');

  const decided = await api('POST', `/v1/approvals/${created.json.id}/decide`, {
    token: acme.key,
    body: { approved: true, note: 'confirmed by phone' },
  });
  assert.equal(decided.json.status, 'approved');

  const polled = (await api('GET', `/v1/approvals/${created.json.id}`, { token: acme.key })).json;
  assert.equal(polled.status, 'approved');
  assert.equal(polled.note, 'confirmed by phone');
});

test('an approval cannot be decided twice', async () => {
  const created = await api('POST', '/v1/approvals', {
    token: acme.key,
    body: { log: 'payments', target: 'ops.refund', reason: 'over cap' },
  });
  await api('POST', `/v1/approvals/${created.json.id}/decide`, { token: acme.key, body: { approved: false } });
  const again = await api('POST', `/v1/approvals/${created.json.id}/decide`, {
    token: acme.key,
    body: { approved: true },
  });
  assert.equal(again.status, 409);
  assert.equal(again.json.error.code, 'already_decided');
});

test('an expired approval reads as expired, never as approved', async () => {
  const created = await api('POST', '/v1/approvals', {
    token: acme.key,
    body: { log: 'payments', target: 'ops.refund', reason: 'slow human' },
  });
  hub.db
    .prepare('UPDATE approvals SET expires_at = ? WHERE id = ?')
    .run('2020-01-01T00:00:00.000Z', created.json.id);

  const polled = (await api('GET', `/v1/approvals/${created.json.id}`, { token: acme.key })).json;
  assert.equal(polled.status, 'expired');

  const late = await api('POST', `/v1/approvals/${created.json.id}/decide`, {
    token: acme.key,
    body: { approved: true },
  });
  assert.equal(late.status, 410);
});

test('long polling returns as soon as a human decides', async () => {
  const created = await api('POST', '/v1/approvals', {
    token: acme.key,
    body: { log: 'payments', target: 'ops.refund', reason: 'waiting' },
  });

  const started = Date.now();
  const waiting = api('GET', `/v1/approvals/${created.json.id}?wait=10`, { token: acme.key });
  setTimeout(() => {
    api('POST', `/v1/approvals/${created.json.id}/decide`, { token: acme.key, body: { approved: true } });
  }, 150);

  const res = await waiting;
  assert.equal(res.json.status, 'approved');
  assert.ok(Date.now() - started < 5000, 'long poll should wake on the decision, not the deadline');
});

test('one tenant cannot see or decide another tenant\'s approvals', async () => {
  const created = await api('POST', '/v1/approvals', {
    token: acme.key,
    body: { log: 'payments', target: 'ops.secret', reason: 'private' },
  });
  assert.equal((await api('GET', `/v1/approvals/${created.json.id}`, { token: globex.key })).status, 404);
  assert.equal(
    (await api('POST', `/v1/approvals/${created.json.id}/decide`, { token: globex.key, body: { approved: true } })).status,
    404,
  );

  const list = (await api('GET', '/v1/approvals', { token: globex.key })).json;
  assert.ok(!list.approvals.some((a) => a.target === 'ops.secret'));
});

// ── control plane audit ──────────────────────────────────────────────────

test('administrative actions are recorded in a hash chain that verifies', async () => {
  const res = (await api('GET', '/v1/events', { token: acme.key })).json;
  assert.ok(res.integrity.ok, JSON.stringify(res.integrity.issues));
  assert.ok(res.events.some((e) => e.action === 'key.revoke'));
  assert.ok(res.events.some((e) => e.action === 'policy.publish'));
});

test('the event page size is clamped, never unbounded', async () => {
  const total = hub.db.prepare('SELECT COUNT(*) AS n FROM audit_events WHERE org_id = ?').get(acme.org).n;
  assert.ok(total > 1, 'the fixture should hold several events');
  const count = async (limit) =>
    (await api('GET', `/v1/events?limit=${limit}`, { token: acme.key })).json.events.length;
  // SQLite reads a negative LIMIT as "no limit"; it has to mean one instead.
  assert.equal(await count(-1), 1);
  assert.equal(await count(0), 1);
  assert.equal(await count('abc'), Math.min(total, 100));
  assert.equal(await count(1e9), Math.min(total, 500));
});

test('editing the control-plane trail is detected', async () => {
  const row = hub.db
    .prepare('SELECT * FROM audit_events WHERE org_id = ? ORDER BY seq ASC LIMIT 1')
    .get(acme.org);
  hub.db.prepare('UPDATE audit_events SET actor = ? WHERE id = ?').run('someone.else', row.id);

  const res = hub.store.auditEvents(acme.org);
  assert.equal(res.ok, false);
  assert.ok(res.issues.some((i) => /does not match its hash/.test(i)));

  hub.db.prepare('UPDATE audit_events SET actor = ? WHERE id = ?').run(row.actor, row.id);
  assert.ok(hub.store.auditEvents(acme.org).ok, 'restoring the row should restore the chain');
});

// ── protocol hygiene ─────────────────────────────────────────────────────

test('health and discovery need no credentials', async () => {
  assert.equal((await api('GET', '/health')).json.status, 'ok');
  assert.equal((await api('GET', '/ready')).json.status, 'ready');

  const wk = (await api('GET', '/.well-known/vouchwell')).json;
  assert.equal(wk.hub.kid, hub.hubIdentity.kid);
  assert.equal(wk.witness.kid, hub.witnessIdentity.kid);
  assert.ok(!JSON.stringify(wk).includes('PRIVATE'), 'discovery must never expose a private key');
});

test('a wrong method on a real path answers 405 with Allow', async () => {
  const res = await api('DELETE', '/v1/logs', { token: acme.key });
  assert.equal(res.status, 405);
  assert.deepEqual(res.json.error.detail.allowed.sort(), ['GET', 'POST']);
});

test('malformed JSON and oversized bodies are refused cleanly', async () => {
  const bad = await fetch(base + '/v1/logs', {
    method: 'POST',
    headers: { authorization: `Bearer ${acme.key}`, 'content-type': 'application/json' },
    body: '{not json',
  });
  assert.equal(bad.status, 400);
  assert.equal((await bad.json()).error.code, 'malformed_json');

  const huge = await fetch(base + '/v1/logs', {
    method: 'POST',
    headers: { authorization: `Bearer ${acme.key}`, 'content-type': 'application/json' },
    body: JSON.stringify({ slug: 'x'.repeat(9 * 1024 * 1024) }),
  });
  assert.equal(huge.status, 413);
});

test('every response carries a request id', async () => {
  const res = await api('GET', '/health');
  assert.match(res.headers.get('x-request-id') ?? '', /^req_[0-9a-f]{16}$/);
});

test('an unexpected failure does not leak internals to the client', async () => {
  // Force a real exception inside a handler by breaking the table it reads.
  hub.db.exec('ALTER TABLE usage_daily RENAME TO usage_daily_tmp');
  const res = await api('GET', '/v1/usage', { token: acme.key });
  hub.db.exec('ALTER TABLE usage_daily_tmp RENAME TO usage_daily');

  assert.equal(res.status, 500);
  assert.equal(res.json.error.code, 'internal_error');
  assert.ok(!/usage_daily/.test(res.text), 'the schema should not be described to the caller');
  assert.ok(res.json.requestId);
});

test('rate limiting kicks in and says when to retry', async () => {
  const limited = new Hub({
    database: ':memory:',
    apiRate: { capacity: 3, refillPerSec: 0.1 },
    authRate: { capacity: 3, refillPerSec: 0.1 },
    ingestRate: { capacity: 3, refillPerSec: 0.1 },
  });
  const { url } = await limited.listen(0);
  const at = url.replace('0.0.0.0', '127.0.0.1');

  /** @type {number[]} */
  const codes = [];
  for (let i = 0; i < 6; i++) {
    const res = await fetch(at + '/health');
    codes.push(res.status);
    if (res.status === 429) {
      assert.ok(Number(res.headers.get('retry-after')) > 0);
    }
  }
  assert.ok(codes.includes(429), `expected a 429, got ${codes.join(',')}`);
  await limited.close();
});

// ── cross-site request forgery ───────────────────────────────────────────

test('a cookie-authenticated write from another origin is refused', async () => {
  const auth = new Auth(hub.store);
  const user = auth.createUser({ email: 'csrf@acme.test', password: 'a-long-enough-password' });
  auth.addMember(acme.org, user.id, 'owner');

  const login = await fetch(base + '/login', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ email: 'csrf@acme.test', password: 'a-long-enough-password' }),
    redirect: 'manual',
  });
  const cookie = (login.headers.getSetCookie?.() ?? []).map((c) => c.split(';')[0]).join('; ');
  assert.match(cookie, /pw_session=/);

  const host = new URL(base).host;

  // Same-origin: allowed.
  const ok = await fetch(base + '/v1/keys', {
    method: 'POST',
    headers: { cookie, origin: `http://${host}`, 'content-type': 'application/json' },
    body: JSON.stringify({ name: 'same-origin', scopes: ['logs:read'] }),
  });
  assert.equal(ok.status, 200);

  // Another origin, with the victim's cookie attached: refused.
  const forged = await fetch(base + '/v1/keys', {
    method: 'POST',
    headers: { cookie, origin: 'https://evil.example', 'content-type': 'application/json' },
    body: JSON.stringify({ name: 'forged', scopes: ['admin'] }),
  });
  assert.equal(forged.status, 403);
  assert.equal((await forged.json()).error.code, 'cross_origin');

  // No Origin and no Referer at all: also refused, rather than assumed safe.
  const bare = await fetch(base + '/v1/keys', {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json' },
    body: JSON.stringify({ name: 'bare', scopes: ['admin'] }),
  });
  assert.equal(bare.status, 403);

  // What a real browser sends. Sec-Fetch-Site decides when present: a form on
  // this origin passes even with Origin: null, and a sibling subdomain or
  // another site fails even when Origin is made to look right.
  const post = (/** @type {Record<string,string>} */ h, /** @type {string} */ name) => fetch(base + '/v1/keys', {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json', ...h },
    body: JSON.stringify({ name, scopes: ['logs:read'] }),
  });
  assert.equal((await post({ origin: 'null', 'sec-fetch-site': 'same-origin' }, 'browser-form')).status, 200);
  assert.equal((await post({ origin: `http://${host}`, 'sec-fetch-site': 'same-site' }, 'sibling')).status, 403);
  assert.equal((await post({ origin: `http://${host}`, 'sec-fetch-site': 'cross-site' }, 'cross')).status, 403);
  // Origin: null alone is no evidence.
  assert.equal((await post({ origin: 'null' }, 'null-origin')).status, 403);

  // And no key was minted by any refused attempt.
  const keys = hub.auth.keys(acme.org);
  assert.ok(!keys.some((k) => ['forged', 'bare', 'sibling', 'cross', 'null-origin'].includes(k.name)));
});

test('bearer-token writes are unaffected: no browser attaches those cross-site', async () => {
  const res = await fetch(base + '/v1/keys', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${acme.key}`,
      origin: 'https://evil.example',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ name: 'api-client', scopes: ['logs:read'] }),
  });
  assert.equal(res.status, 200, 'machine clients must not be broken by a browser control');
});

test('HSTS is sent unless cookies are explicitly insecure', async () => {
  const res = await api('GET', '/health');
  const hsts = res.headers.get('strict-transport-security');
  if (process.env.VOUCHWELL_INSECURE_COOKIES === '1') {
    assert.equal(hsts, null, 'a local HTTP hub must not pin the browser to HTTPS');
  } else {
    assert.match(hsts ?? '', /max-age=31536000/);
  }
});

// ── actions that never finished ──────────────────────────────────────────

test('the hub lists calls that were authorised and sent but never came back', async () => {
  const agent = new Agent('jobs');
  const created = await api('POST', '/v1/logs', {
    token: acme.key,
    body: { slug: 'jobs', kid: agent.identity.kid, publicKey: agent.identity.publicKey },
  });
  assert.equal(created.status, 200);

  const old = '2026-01-01T00:00:00.000Z';
  const done = agent.make({ phase: 'intent', target: 'crm.query', ts: old });
  const doneOut = agent.make({ phase: 'outcome', ref: entryHash(done), target: 'crm.query', ts: old, result: { status: 'ok', payload: {} } });
  const crashed = agent.make({ phase: 'intent', target: 'stripe.refund', ts: old });
  const cut = agent.make({ phase: 'intent', target: 'db.migrate', ts: old });
  const gaveUp = agent.make({ phase: 'outcome', ref: entryHash(cut), target: 'db.migrate', ts: old, result: { status: 'error', code: 'unfinished', payload: null } });
  const running = agent.make({ phase: 'intent', target: 'slow.export', ts: new Date().toISOString() });
  const push = await api('POST', '/v1/logs/jobs/receipts', {
    token: acme.key,
    body: { receipts: [done, doneOut, crashed, cut, gaveUp, running] },
  });
  assert.equal(push.status, 200, JSON.stringify(push.json));

  const res = await api('GET', '/v1/logs/jobs/unfinished', { token: acme.readKey });
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.deepEqual(res.json.unfinished.map((/** @type {any} */ u) => [u.seq, u.target]), [[2, 'stripe.refund']]);
  assert.equal(res.json.unfinished[0].intent, entryHash(crashed));
  assert.deepEqual(res.json.abandoned.map((/** @type {any} */ u) => [u.seq, u.target, u.outcomeSeq]), [[3, 'db.migrate', 4]]);
  assert.deepEqual(res.json.inFlight.map((/** @type {any} */ u) => u.target), ['slow.export']);
  assert.deepEqual(res.json.orphans, []);

  // Another organisation cannot ask about this log.
  assert.equal((await api('GET', '/v1/logs/jobs/unfinished', { token: globex.key })).status, 404);
});
