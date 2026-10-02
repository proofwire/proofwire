import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { generateIdentity, buildReceipt, signReceipt, entryHash, GENESIS_PREV, verifyBundle } from '@deedwrit/core';
import { Hub } from '../src/app.js';
import { Auth } from '../src/auth.js';

/**
 * A hub whose organisation has two outside witnesses: every checkpoint of
 * its logs is sent to both, and the signatures land on the checkpoint.
 */

/** @type {Hub} */
let hub;
let base = '';
let admin = '';
let agentKey = '';
/** @type {{ hub: Hub, url: string, token: string, kid: string, publicKey: string }[]} */
const witnesses = [];
const agent = { identity: generateIdentity().identity, seq: 0, prev: GENESIS_PREV };

const fast = { capacity: 1e5, refillPerSec: 1e5 };

before(async () => {
  for (const name of ['one', 'two']) {
    const w = new Hub({ database: ':memory:', witnessOnly: true, apiRate: fast, authRate: fast });
    const { url } = await w.listen(0);
    const org = w.store.createOrg({ slug: 'acme-hub', name: 'Acme via hub' });
    const { token } = new Auth(w.store).createKey({ orgId: org.id, name, scopes: ['witness:sign', 'logs:read'] });
    witnesses.push({ hub: w, url: url.replace('0.0.0.0', '127.0.0.1'), token, kid: w.witnessSigner.kid, publicKey: w.witnessSigner.publicKey });
  }
  hub = new Hub({ database: ':memory:', checkpointEvery: 5, egressAllowPrivate: true, apiRate: fast, ingestRate: fast, authRate: fast });
  base = (await hub.listen(0)).url.replace('0.0.0.0', '127.0.0.1');
  const org = hub.store.createOrg({ slug: 'acme', name: 'Acme' });
  const auth = new Auth(hub.store);
  admin = auth.createKey({ orgId: org.id, name: 'admin', scopes: ['admin'] }).token;
  agentKey = auth.createKey({ orgId: org.id, name: 'agent', scopes: ['receipts:write', 'logs:write', 'logs:read', 'receipts:read'] }).token;
});

after(async () => {
  await hub.close();
  for (const w of witnesses) await w.hub.close();
});

/** @param {string} method @param {string} p @param {string} token @param {any} [body] */
async function api(method, p, token, body) {
  const res = await fetch(base + p, {
    method,
    headers: { authorization: `Bearer ${token}`, ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, json: await res.json().catch(() => null) };
}

function receipts(/** @type {number} */ n) {
  return Array.from({ length: n }, () => {
    const { body } = buildReceipt({
      log: 'payments', seq: agent.seq, prev: agent.prev,
      actor: { agent: 'bot', runtime: 'test', session: 's', principal: 'p@acme.test' },
      action: { kind: 'tool_call', target: 'stripe.refund', params: { n: agent.seq } },
      decision: { outcome: 'allow', policy: 'p', rules: [] }, result: null,
    });
    const r = signReceipt(agent.identity, body);
    agent.seq++;
    agent.prev = entryHash(r);
    return r;
  });
}

/** Wait for the hub's background witnessing to settle. */
const settle = () => Promise.allSettled([...hub._background]);
const pinned = () => Object.fromEntries(witnesses.map((w) => [w.kid, w.publicKey]));

test('an admin names the witnesses; the hub checks each answers, and never hands a token back', async () => {
  const set = await api('PUT', '/v1/integrations/witnesses', admin, {
    witnesses: witnesses.map((w, i) => ({ name: `w${i + 1}`, url: w.url, token: w.token })),
  });
  assert.equal(set.status, 200, JSON.stringify(set.json));
  assert.deepEqual(set.json.witnesses.map((/** @type {any} */ w) => w.kid), witnesses.map((w) => w.kid));
  const got = await api('GET', '/v1/integrations/witnesses', admin);
  assert.ok(!JSON.stringify(got.json).includes(witnesses[0].token), 'a token must never be returned');
  assert.equal((await api('GET', '/v1/integrations/witnesses', agentKey)).status, 403);

  const unreachable = await api('PUT', '/v1/integrations/witnesses', admin, { witnesses: [{ name: 'gone', url: 'http://127.0.0.1:1', token: 't' }] });
  assert.equal(unreachable.json.error.code, 'witness_unreachable');
  // Reconfiguring without the tokens keeps them, for the same URLs only.
  const same = await api('PUT', '/v1/integrations/witnesses', admin, {
    witnesses: witnesses.map((w, i) => ({ name: `w${i + 1}`, url: w.url })),
  });
  assert.equal(same.status, 200, JSON.stringify(same.json));
  const moved = await api('PUT', '/v1/integrations/witnesses', admin, { witnesses: [{ name: 'w1', url: witnesses[1].url }] });
  assert.equal(moved.json.error.code, 'bad_witness_token');

  const dup = await api('PUT', '/v1/integrations/witnesses', admin, { witnesses: [{ name: 'a', url: witnesses[0].url, token: 't' }, { name: 'a', url: witnesses[1].url, token: 't' }] });
  assert.equal(dup.json.error.code, 'bad_witness_name');
});

test('every checkpoint is co-signed by both witnesses, and the bundle proves it to an auditor pinning them', async () => {
  assert.equal((await api('POST', '/v1/logs', agentKey, { slug: 'payments', kid: agent.identity.kid, publicKey: agent.identity.publicKey })).status, 200);
  assert.equal((await api('POST', '/v1/logs/payments/receipts', agentKey, { receipts: receipts(5) })).status, 200);
  await new Promise((r) => setTimeout(r, 50));
  await settle();
  // Growth: the second checkpoint must be proven to extend the first.
  assert.equal((await api('POST', '/v1/logs/payments/receipts', agentKey, { receipts: receipts(5) })).status, 200);
  await new Promise((r) => setTimeout(r, 50));
  await settle();

  const cps = (await api('GET', '/v1/logs/payments/checkpoints', agentKey)).json.checkpoints;
  assert.ok(cps.length >= 2, `expected two checkpoints, got ${cps.length}`);
  for (const cp of cps) {
    const kids = cp.sigs.filter((/** @type {any} */ s) => s.role === 'witness').map((/** @type {any} */ s) => s.kid).sort();
    assert.deepEqual(kids, witnesses.map((w) => w.kid).sort(), `checkpoint at ${cp.body.size}`);
  }

  const bundle = (await api('GET', '/v1/logs/payments/bundle', agentKey)).json;
  const v = verifyBundle(bundle, { minWitnesses: 2, trustedWitnesses: pinned() });
  assert.ok(v.ok, v.issues.join('\n'));
  assert.equal(v.witnessedSize, 10);
  assert.ok(verifyBundle(bundle).ok, 'without pinning, the keyring still covers the witnesses\' signatures');
});

test('a witness that saw a different history refuses, and the organisation\'s trail records it', async () => {
  // Tell witness one it has already signed a different root for this log at 10.
  const w = witnesses[0].hub;
  w.db.prepare('UPDATE witness_state SET root = ? WHERE size = 10').run('ee'.repeat(32));
  assert.equal((await api('POST', '/v1/logs/payments/receipts', agentKey, { receipts: receipts(5) })).status, 200);
  await new Promise((r) => setTimeout(r, 50));
  await settle();

  const events = (await api('GET', '/v1/events', admin)).json.events;
  const alarm = events.find((/** @type {any} */ e) => e.action === 'witness.refused');
  assert.ok(alarm, 'the refusal should be in the audit trail');
  assert.match(alarm.meta, /diverged/);
  const latest = (await api('GET', '/v1/logs/payments/checkpoints', agentKey)).json.checkpoints[0];
  assert.deepEqual(latest.sigs.filter((/** @type {any} */ s) => s.role === 'witness').map((/** @type {any} */ s) => s.kid), [witnesses[1].kid], 'the other witness still signs');
});

test('on a hub that may not reach private addresses, a private or plain-http witness is refused', async () => {
  const strict = new Hub({ database: ':memory:' });
  const at = (await strict.listen(0)).url.replace('0.0.0.0', '127.0.0.1');
  try {
    const org = strict.store.createOrg({ slug: 'x', name: 'x' });
    const token = new Auth(strict.store).createKey({ orgId: org.id, name: 'a', scopes: ['admin'] }).token;
    for (const url of [witnesses[0].url, 'https://169.254.169.254', 'https://10.0.0.1', 'https://localhost', 'http://witness.example.com']) {
      const res = await fetch(`${at}/v1/integrations/witnesses`, {
        method: 'PUT',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ witnesses: [{ name: 'w', url, token: 't' }] }),
      });
      assert.equal((await res.json()).error.code, 'bad_witness_url', url);
    }
  } finally {
    await strict.close();
  }
});
