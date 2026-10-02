import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ProofLog } from '../src/log.js';
import { Policy } from '../src/policy.js';
import { entryHash } from '../src/receipt.js';
import { findUnfinished } from '../src/unfinished.js';
import { Recorder, PolicyDenied, recordTools } from '../src/recorder.js';

function log() {
  return ProofLog.create(fs.mkdtempSync(path.join(os.tmpdir(), 'deedwrit-recorder-')));
}

/** @param {object} doc */
const pol = (doc) => new Policy({ version: 1, name: 'test', ...doc });

/** @param {any} over */
function recorder(over = {}) {
  return new Recorder({ log: log(), agent: 'support-bot', principal: 'ops@acme.test', ...over });
}

test('an allowed call gets an intent before it runs and a linked outcome after', async () => {
  const rec = recorder();
  let sizeWhenRunning = -1;
  const out = await rec.run('crm.lookup', { id: 42 }, () => {
    sizeWhenRunning = rec.log.size;
    return { name: 'Dana' };
  });
  assert.deepEqual(out, { name: 'Dana' });
  assert.equal(sizeWhenRunning, 1, 'the intent must be on disk before the tool runs');

  const [intent, outcome] = rec.log.entries;
  assert.equal(intent.phase, 'intent');
  assert.equal(intent.action.target, 'crm.lookup');
  assert.equal(intent.decision.policy, 'none', 'with no policy, the receipt says so');
  assert.match(intent.actor.runtime, /^deedwrit-js\//);
  assert.equal(outcome.phase, 'outcome');
  assert.equal(outcome.ref, entryHash(intent));
  assert.equal(outcome.result.status, 'ok');
  assert.ok(rec.log.audit().ok);
  assert.deepEqual(findUnfinished(rec.log.entries).unfinished, []);
});

test('a throwing tool is recorded as an error and the error still reaches the caller', async () => {
  const rec = recorder();
  const boom = Object.assign(new Error('upstream down'), { code: 'ECONNRESET' });
  await assert.rejects(rec.run('crm.lookup', {}, () => { throw boom; }), (e) => e === boom);
  const outcome = rec.log.entries[1];
  assert.equal(outcome.result.status, 'error');
  assert.equal(outcome.result.code, 'ECONNRESET');
  assert.equal(rec.pending.size, 0);
});

test('a denied call gets one receipt, never runs, and throws PolicyDenied', async () => {
  const rec = recorder({
    policy: pol({ rules: [{ id: 'no.drops', when: { target: 'db.drop*' }, then: 'deny', reason: 'destructive' }] }),
  });
  let ran = false;
  await assert.rejects(rec.run('db.drop_table', { table: 'users' }, () => { ran = true; }), (e) => {
    assert.ok(e instanceof PolicyDenied);
    assert.equal(/** @type {any} */ (e).receipt.decision.outcome, 'deny');
    return true;
  });
  assert.equal(ran, false);
  assert.equal(rec.log.size, 1);
  assert.equal(rec.log.entries[0].phase, 'atomic');
});

test('a budget holds across calls, counting what this log already recorded', async () => {
  const policy = pol({
    budgets: [{ id: 'refunds.daily', match: { target: 'stripe.*' }, field: 'metrics.amount_usd', limit: 100, window: '24h', then: 'deny' }],
  });
  const metrics = (/** @type {string} */ _t, /** @type {any} */ p) => ({ amount_usd: p.amount });
  const rec = recorder({ policy, metrics });
  const refund = rec.wrap('stripe.refund', async (/** @type {any} */ a) => ({ refunded: a.amount }));
  await refund({ amount: 45 });
  await refund({ amount: 30 });
  await assert.rejects(refund({ amount: 90 }), PolicyDenied);

  // A new recorder over the same log remembers the spend.
  const again = new Recorder({ log: rec.log, agent: 'support-bot', principal: 'ops@acme.test', policy, metrics });
  await assert.rejects(again.run('stripe.refund', { amount: 50 }, () => 0), PolicyDenied);
  await again.run('stripe.refund', { amount: 25 }, () => 0);
});

test('concurrent calls commit their spend on the intent, so they cannot all slip under a budget', async () => {
  const rec = recorder({
    policy: pol({ budgets: [{ id: 'cap', match: { target: 'pay' }, field: 'metrics.amount_usd', limit: 100, window: '1h', then: 'deny' }] }),
    metrics: (/** @type {string} */ _t, /** @type {any} */ p) => ({ amount_usd: p.amount }),
  });
  const slow = () => new Promise((r) => setTimeout(() => r('ok'), 20));
  const results = await Promise.allSettled([60, 60, 60].map((amount) => rec.run('pay', { amount }, slow)));
  assert.deepEqual(results.map((r) => r.status), ['fulfilled', 'rejected', 'rejected']);
});

test('an escalation goes to the approver with a redacted preview, and the receipt names who decided', async () => {
  const seen = [];
  const rec = recorder({
    policy: pol({ rules: [{ id: 'mail.external', when: { target: 'mail.send' }, then: 'escalate', reason: 'external mail' }] }),
    approver: async (/** @type {any} */ req) => {
      seen.push(req);
      return { approved: true, by: 'dana@acme.test', note: 'fine' };
    },
  });
  await rec.run('mail.send', { to: 'x@y.test', key: 'sk-ant-api03-Xk92mQvT1pLs8fR4nB6yH0jW' }, () => 'sent');
  assert.equal(seen.length, 1);
  assert.ok(!JSON.stringify(seen[0].params).includes('Xk92mQvT1pLs8fR4nB6yH0jW'), 'the approver must not see the secret');
  assert.equal(rec.log.entries[0].decision.approval.by, 'dana@acme.test');
});

test('with no approver, an escalation is refused as a fallback, never as a person', async () => {
  const rec = recorder({
    policy: pol({ rules: [{ id: 'x', when: { target: 'wire.send' }, then: 'escalate', reason: 'large transfer' }] }),
  });
  await assert.rejects(rec.run('wire.send', {}, () => 'sent'), PolicyDenied);
  assert.equal(rec.log.entries[0].decision.declined.by, 'policy:no-approver');
});

test('monitor mode runs every call and records what the policy would have done', async () => {
  const rec = recorder({
    policy: pol({ rules: [{ id: 'no.drops', when: { target: 'db.drop*' }, then: 'deny', reason: 'destructive' }] }),
    monitor: true,
  });
  assert.equal(await rec.run('db.drop_table', {}, () => 'dropped'), 'dropped');
  const d = rec.log.entries[0].decision;
  assert.equal(d.outcome, 'allow');
  assert.equal(d.enforced, false);
  assert.equal(d.wouldBe, 'deny');
});

test('finalize closes calls still out as unfinished; a crash leaves them open', async () => {
  const rec = recorder();
  /** @type {(v: any) => void} */
  let release = () => {};
  const hanging = rec.run('slow.export', {}, () => new Promise((r) => { release = r; }));
  await new Promise((r) => setImmediate(r));
  assert.equal(findUnfinished(rec.log.entries, { graceMs: 0 }).unfinished.length, 1, 'a crash now would leave this open');
  rec.finalize();
  const found = findUnfinished(rec.log.entries, { graceMs: 0 });
  assert.deepEqual(found.unfinished, []);
  assert.deepEqual(found.abandoned.map((u) => u.target), ['slow.export']);
  release('late');
  await hanging;
  assert.equal(rec.log.size, 2, 'a reply after finalize is not recorded twice');
});

test('awkward results and arguments are recorded without failing the call', async () => {
  const rec = recorder();
  class Thing { constructor() { this.n = 10n; } }
  const cyclic = /** @type {any} */ ({});
  cyclic.self = cyclic;
  assert.ok(await rec.run('t', { big: 1n }, () => new Thing()));
  assert.equal(await rec.run('t', {}, () => cyclic), cyclic);
  assert.equal(await rec.run('t', {}, () => undefined), undefined);
  assert.ok(rec.log.audit().ok);
});

test('recordTools wraps execute on every tool that has one, and leaves the rest alone', async () => {
  const rec = recorder({ namespace: 'app' });
  const clientSide = { description: 'rendered by the UI' };
  const tools = recordTools(rec, {
    weather: { description: 'weather', execute: async (/** @type {any} */ a, /** @type {any} */ o) => `${a.city} sunny ${o?.toolCallId}` },
    ui: clientSide,
  });
  assert.equal(tools.ui, clientSide);
  assert.equal(await tools.weather.execute({ city: 'Oslo' }, { toolCallId: 'c1' }), 'Oslo sunny c1');
  assert.equal(rec.log.entries[0].action.target, 'app.weather');
});

test('a recorder refuses to start without a log, an agent or a principal', () => {
  assert.throws(() => new Recorder(/** @type {any} */ ({ agent: 'a', principal: 'p' })), /needs a log/);
  assert.throws(() => new Recorder(/** @type {any} */ ({ log: log(), principal: 'p' })), /needs agent/);
  assert.throws(() => new Recorder(/** @type {any} */ ({ log: log(), agent: 'a', principal: '' })), /needs principal/);
});
