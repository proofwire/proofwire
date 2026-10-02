import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  generateIdentity,
  buildReceipt,
  signReceipt,
  entryHash,
  GENESIS_PREV,
  verifyBundle,
  verifyInclusion,
  unhex,
  cosignWith,
} from '@vouchwell/core';
import { Hub } from '../src/app.js';
import { Auth } from '../src/auth.js';

/**
 * Retention: after a period, the hub clears what receipts say but keeps what
 * holds the log together. The claim under test is that pruning costs detail
 * and nothing else: roots, proofs, checkpoints and further ingest all still
 * work, and tampering is still caught.
 */

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/bin.js');
const DAY = 86_400_000;

/** @type {Hub} */
let hub;
let base = '';
const t = { org: '', admin: '', agent: '', reader: '' };

class Agent {
  constructor() {
    this.identity = generateIdentity().identity;
    this.seq = 0;
    this.prev = GENESIS_PREV;
  }

  /** @param {string} ts */
  make(ts) {
    const { body } = buildReceipt({
      log: 'payments',
      seq: this.seq,
      prev: this.prev,
      ts,
      actor: { agent: 'claude-opus-5', runtime: 'test', session: 'sess_secret', principal: 'dana@customer.test' },
      action: { kind: 'tool_call', target: 'stripe.refund', params: { order: `ord_${this.seq}` }, metrics: { amount_usd: 10 } },
      decision: { outcome: 'allow', policy: 'p1', rules: [] },
    });
    const r = signReceipt(this.identity, body);
    this.seq++;
    this.prev = entryHash(r);
    return r;
  }
}
const agent = new Agent();

before(async () => {
  hub = new Hub({
    database: ':memory:',
    checkpointEvery: 5,
    apiRate: { capacity: 100000, refillPerSec: 100000 },
    ingestRate: { capacity: 100000, refillPerSec: 100000 },
  });
  base = (await hub.listen(0)).url.replace('0.0.0.0', '127.0.0.1');
  const auth = new Auth(hub.store);
  const org = hub.store.createOrg({ slug: 'acme', name: 'Acme' });
  t.org = org.id;
  t.admin = auth.createKey({ orgId: org.id, name: 'admin', scopes: ['admin'] }).token;
  t.agent = auth.createKey({ orgId: org.id, name: 'agent', scopes: ['receipts:write', 'logs:write', 'logs:read', 'receipts:read'] }).token;

  await api('POST', '/v1/logs', t.agent, { slug: 'payments', kid: agent.identity.kid, publicKey: agent.identity.publicKey });
  // Six from 100 days ago, four from yesterday: two checkpoints' worth.
  const old = Array.from({ length: 6 }, (_, i) => agent.make(new Date(Date.now() - 100 * DAY + i * 1000).toISOString()));
  const recent = Array.from({ length: 4 }, (_, i) => agent.make(new Date(Date.now() - DAY + i * 1000).toISOString()));
  const pushed = await api('POST', '/v1/logs/payments/receipts', t.agent, { receipts: [...old, ...recent] });
  assert.equal(pushed.status, 200, JSON.stringify(pushed.json));
  // Let the hub's automatic checkpoint land.
  await new Promise((r) => setTimeout(r, 100));
});

after(async () => {
  await hub.close();
});

/**
 * @param {string} method
 * @param {string} p
 * @param {string} token
 * @param {any} [body]
 */
async function api(method, p, token, body) {
  const res = await fetch(base + p, {
    method,
    headers: { authorization: `Bearer ${token}`, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

/** @type {{ root: string, checkpoints: any[] }} */
const beforePrune = { root: '', checkpoints: [] };

test('before retention: everything is kept, forever by default', async () => {
  const r = await api('GET', '/v1/settings/retention', t.admin);
  assert.equal(r.json.effectiveDays, null);
  const bundle = (await api('GET', '/v1/logs/payments/bundle', t.agent)).json;
  assert.equal(bundle.entries.length, 10);
  assert.ok(bundle.checkpoints.length >= 1, 'expected an automatic checkpoint');
  beforePrune.root = bundle.root;
  beforePrune.checkpoints = bundle.checkpoints;
  assert.equal(hub.store.pruneExpired().filter((x) => x.pruned).length, 0, 'nothing is pruned without a setting');
});

test('only an admin sets retention, within sane bounds', async () => {
  assert.equal((await api('PUT', '/v1/settings/retention', t.agent, { days: 30 })).status, 403);
  for (const days of [0, -1, 1.5, 'soon', 100000]) {
    assert.equal((await api('PUT', '/v1/settings/retention', t.admin, { days })).json.error.code, 'bad_retention', String(days));
  }
  const long = await api('PUT', '/v1/settings/retention', t.admin, { days: 400 });
  assert.equal(long.json.warning, undefined);
  const set = await api('PUT', '/v1/settings/retention', t.admin, { days: 30 });
  assert.equal(set.status, 200);
  assert.equal(set.json.effectiveDays, 30);
  assert.match(set.json.warning, /six months/);
  assert.ok(hub.store.events(t.org, 20).some((e) => e.action === 'retention.set'));
});

test('pruning clears the old receipts\' content and every identifying column, and nothing else', () => {
  const [res] = hub.store.pruneExpired();
  assert.equal(res.pruned, 6);
  assert.equal(hub.store.pruneExpired()[0].pruned, 0, 'a second sweep has nothing left to do');

  const rows = hub.db.prepare('SELECT * FROM receipts WHERE org_id = ? ORDER BY seq').all(t.org);
  const pruned = rows.filter((r) => r.pruned_at);
  assert.equal(pruned.length, 6);
  for (const r of pruned) {
    assert.equal(r.body, '');
    for (const col of ['target', 'principal', 'agent', 'session']) assert.equal(r[col], '', col);
    assert.equal(r.metrics, '{}');
    assert.ok(r.hash && r.prev && r.ts && r.outcome, 'the log\'s structure and the non-identifying facts stay');
  }
  assert.ok(!JSON.stringify(pruned).includes('dana@customer.test'), 'a pruned row still names the customer');
  assert.ok(!JSON.stringify(pruned).includes('sess_secret'));
  assert.equal(rows.filter((r) => !r.pruned_at).length, 4);
  assert.ok(hub.store.events(t.org, 20).some((e) => e.action === 'retention.pruned'));
});

test('after pruning, the root, the checkpoints and the self-audit are exactly as before', async () => {
  const bundle = (await api('GET', '/v1/logs/payments/bundle', t.agent)).json;
  assert.equal(bundle.root, beforePrune.root, 'pruning changed the root');
  assert.deepEqual(bundle.checkpoints, beforePrune.checkpoints);
  assert.equal(bundle.entries.length, 4);
  assert.equal(bundle.partial, true);
  const v = verifyBundle(bundle);
  assert.ok(v.ok, JSON.stringify(v.issues));

  const audit = (await api('GET', '/v1/logs/payments/audit', t.agent)).json;
  assert.equal(audit.ok, true, JSON.stringify(audit.issues));
});

test('a pruned receipt answers 410 with its hash, and its inclusion proof still verifies', async () => {
  const gone = await api('GET', '/v1/logs/payments/receipts/2', t.agent);
  assert.equal(gone.status, 410);
  assert.equal(gone.json.error.code, 'pruned');
  const hash = gone.json.error.detail.hash;

  const proof = (await api('GET', '/v1/logs/payments/proof/2', t.agent)).json;
  assert.equal(proof.leaf, hash);
  assert.ok(
    verifyInclusion({
      leafHash: unhex(proof.leaf),
      index: 2,
      treeSize: proof.treeSize,
      proof: proof.proof.map(unhex),
      root: unhex(proof.root),
    }),
  );

  // A kept one reads normally, and listings show only what still has content.
  assert.equal((await api('GET', '/v1/logs/payments/receipts/8', t.agent)).status, 200);
  const list = (await api('GET', '/v1/receipts?limit=100', t.agent)).json;
  assert.equal(list.total, 4);
});

test('the log keeps growing after pruning: the chain continues from the kept head', async () => {
  const more = [agent.make(new Date().toISOString()), agent.make(new Date().toISOString())];
  const res = await api('POST', '/v1/logs/payments/receipts', t.agent, { receipts: more });
  assert.equal(res.status, 200, JSON.stringify(res.json));
  const audit = (await api('GET', '/v1/logs/payments/audit', t.agent)).json;
  assert.equal(audit.ok, true, JSON.stringify(audit.issues));
});

test('tampering with a pruned row is still caught', () => {
  const row = hub.db.prepare('SELECT seq, hash FROM receipts WHERE org_id = ? AND seq = 3').get(t.org);
  const forged = 'ab'.repeat(32);
  hub.db.prepare('UPDATE receipts SET hash = ? WHERE org_id = ? AND seq = 3').run(forged, t.org);
  hub.store.forgetTree(hub.store.logBySlug(t.org, 'payments').id);
  try {
    const log = hub.store.logBySlug(t.org, 'payments');
    const audit = hub.store.audit(t.org, log.id);
    assert.equal(audit.ok, false);
    assert.ok(audit.issues.some((i) => i.kind === 'chain'), JSON.stringify(audit.issues));
  } finally {
    hub.db.prepare('UPDATE receipts SET hash = ? WHERE org_id = ? AND seq = 3').run(row.hash, t.org);
    hub.store.forgetTree(hub.store.logBySlug(t.org, 'payments').id);
  }
});

test("the operator's cap bounds what an admin may choose", async () => {
  hub.store.setRetention(t.org, { capDays: 20 });
  const over = await api('PUT', '/v1/settings/retention', t.admin, { days: 30 });
  assert.equal(over.json.error.code, 'over_cap');
  assert.equal((await api('PUT', '/v1/settings/retention', t.admin, { days: null })).json.error.code, 'over_cap');
  const ok = await api('PUT', '/v1/settings/retention', t.admin, { days: 10 });
  assert.equal(ok.json.effectiveDays, 10);
  // And the API has no way to raise the cap.
  await api('PUT', '/v1/settings/retention', t.admin, { days: 10, capDays: null });
  assert.equal(hub.store.retention(t.org).capDays, 20);
});

test('vouchwell-hub retention shows and sets it from the host', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-retention-'));
  const env = { ...process.env, VOUCHWELL_DB: path.join(dir, 'hub.db'), NODE_OPTIONS: '--no-warnings=ExperimentalWarning' };
  const run = (/** @type {string[]} */ args) => {
    const r = spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', env });
    return { code: r.status, out: (r.stdout + r.stderr).replace(/\x1b\[[0-9;]*m/g, '') };
  };
  const setup = new Hub({ database: path.join(dir, 'hub.db') });
  setup.store.createOrg({ slug: 'globex', name: 'Globex' });
  setup.close();

  assert.equal(run(['retention']).code, 2);
  assert.equal(run(['retention', 'nobody']).code, 1);
  assert.equal(run(['retention', 'globex', '--days', 'soon']).code, 2);
  const set = run(['retention', 'globex', '--cap', '365', '--days', '400']);
  assert.equal(set.code, 0, set.out);
  assert.match(set.out, /applied\s+365 days/);
  assert.match(run(['retention', 'globex', '--days', 'forever', '--cap', 'none']).out, /applied\s+forever/);
});

test('a pruned bundle ties an older witnessed checkpoint to its root, so pinned witnesses still count', async () => {
  // Retention makes every hub bundle partial, and a partial bundle cannot
  // rebuild its tree. With the log grown past its witnessed checkpoint, only
  // the consistency proof the hub ships can tie the witness to this bundle.
  const log = hub.store.logBySlug(t.org, 'payments');
  const [latest] = hub.store.checkpoints(t.org, log.id, 1);
  const signed = await cosignWith(latest, hub.witnessSigner);
  hub.store.addWitnessSignature(t.org, log.id, latest.body.size, signed.sigs.find((x) => x.role === 'witness'));
  const more = [agent.make(new Date().toISOString()), agent.make(new Date(Date.now() + 1000).toISOString())];
  assert.equal((await api('POST', '/v1/logs/payments/receipts', t.agent, { receipts: more })).status, 200);

  const bundle = (await api('GET', '/v1/logs/payments/bundle', t.agent)).json;
  assert.equal(bundle.partial, true);
  assert.ok(bundle.treeSize > latest.body.size, 'the log has grown past its witnessed checkpoint');
  assert.ok(Array.isArray(bundle.consistency[String(latest.body.size)]), 'the hub should ship a consistency proof');
  const trusted = { [hub.witnessSigner.kid]: hub.witnessSigner.publicKey };
  const v = verifyBundle(bundle, { minWitnesses: 1, trustedWitnesses: trusted });
  assert.ok(v.ok, JSON.stringify(v.issues));
  assert.equal(v.witnessedSize, latest.body.size);

  delete bundle.consistency;
  assert.equal(verifyBundle(bundle, { minWitnesses: 1, trustedWitnesses: trusted }).ok, false);
});
