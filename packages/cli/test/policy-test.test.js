import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Policy } from '@vouchwell/core';
import { replay, recordedVerdict } from '../src/policy-test.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, '../src/bin.js');
const SERVER = path.resolve(HERE, '../../../examples/fake-mcp-server.js');

const ACTOR = { agent: 'a', runtime: 'r', session: 's', principal: 'p' };
let seq = 0;

/**
 * A receipt as the log stores it, reduced to what replay reads.
 *
 * @param {string} target
 * @param {object} [o]
 */
function rec(target, o = {}) {
  const { ts = '2026-09-01T10:00:00Z', phase = 'intent', params = {}, metrics, redacted, decision = { outcome: 'allow', rules: [] } } =
    /** @type {any} */ (o);
  return {
    seq: seq++,
    ts,
    phase,
    actor: ACTOR,
    action: { kind: 'tool_call', target, params: { hash: 'x', size: 1, preview: params, ...(redacted ? { redacted } : {}) }, ...(metrics ? { metrics } : {}) },
    decision,
  };
}

/** @param {object} doc */
const pol = (doc) => new Policy({ version: 1, name: 't', rules: [], ...doc });

test('a call the old policy denied and the new one allows is reported, and the reverse', () => {
  const entries = [
    rec('crm.refund', { phase: 'atomic', decision: { outcome: 'deny', rules: ['no-refunds'] } }),
    rec('crm.delete', {}),
  ];
  const { results, changed, transitions } = replay(entries, pol({ rules: [{ id: 'no-delete', match: { target: 'crm.delete' }, then: 'deny' }] }));
  assert.equal(changed, 2);
  assert.deepEqual(transitions, { 'deny → allow': 1, 'allow → deny': 1 });
  assert.deepEqual(results[1].rules, ['no-delete']);
});

test('outcome receipts are not judged a second time', () => {
  const entries = [rec('crm.query', { phase: 'intent' }), rec('crm.query', { phase: 'outcome' })];
  assert.equal(replay(entries, pol({})).results.length, 1);
});

test('a monitored call is compared on what the policy would have done, not on the fact that it ran', () => {
  const monitored = rec('crm.refund', { decision: { outcome: 'allow', enforced: false, wouldBe: 'deny', rules: ['no-refunds'] } });
  assert.equal(recordedVerdict(monitored), 'deny');
  const same = pol({ rules: [{ id: 'no-refunds', match: { target: 'crm.refund' }, then: 'deny' }] });
  assert.equal(replay([monitored], same).changed, 0);
});

test('an approved escalation is recorded as an escalation, not as the human\'s yes', () => {
  const approved = rec('crm.email', { decision: { outcome: 'allow', rules: ['mail'], approval: { by: 'dana', at: 'x' } } });
  assert.equal(recordedVerdict(approved), 'escalate');
  // And so is one a person, or a timeout, declined: the policy said escalate.
  const declined = rec('crm.email', { decision: { outcome: 'deny', rules: ['mail'], declined: { by: 'policy:timeout', at: 'x' } } });
  assert.equal(recordedVerdict(declined), 'escalate');
});

test('budgets are replayed against what the new policy would have let through', () => {
  const budget = { id: 'spend', match: { target: 'crm.refund' }, field: 'metrics.usd', limit: 100, window: '24h', then: 'deny' };
  const entries = [
    rec('crm.refund', { metrics: { usd: 80 }, params: { order: 'big' } }),
    rec('crm.refund', { metrics: { usd: 50 }, params: { order: 'small' } }),
  ];

  // Budget alone: the second refund breaches it.
  assert.deepEqual(replay(entries, pol({ budgets: [budget] })).results.map((r) => r.after), ['allow', 'deny']);

  // A policy that also refuses the big refund leaves room for the small one:
  // the $80 never ran, so it was never spent.
  const stricter = pol({ budgets: [budget], rules: [{ id: 'no-big', when: { 'params.order': 'big' }, then: 'deny' }] });
  assert.deepEqual(replay(entries, stricter).results.map((r) => r.after), ['deny', 'allow']);
});

test('rate limits are judged at each call\'s recorded time, not today', () => {
  const limit = { rateLimits: [{ id: 'burst', match: { target: 'mail.send' }, limit: 1, window: '1h' }] };
  const close = [rec('mail.send', { ts: '2026-01-01T10:00:00Z' }), rec('mail.send', { ts: '2026-01-01T10:20:00Z' })];
  assert.deepEqual(replay(close, pol(limit)).results.map((r) => r.after), ['allow', 'deny']);

  const apart = [rec('mail.send', { ts: '2026-01-01T10:00:00Z' }), rec('mail.send', { ts: '2026-01-01T12:00:00Z' })];
  assert.deepEqual(replay(apart, pol(limit)).results.map((r) => r.after), ['allow', 'allow']);
});

test('a call whose preview had values masked is flagged approximate', () => {
  const { results } = replay([rec('mail.send', { redacted: ['anthropic_key'] }), rec('mail.send')], pol({}));
  assert.deepEqual(results.map((r) => r.approximate), [true, false]);
});

// ── end to end ─────────────────────────────────────────────────────────────

/**
 * @param {string} cwd
 * @param {string[]} args
 * @param {string} [input]
 */
function pw(cwd, args, input) {
  const res = spawnSync(process.execPath, [BIN, ...args], {
    cwd,
    input,
    encoding: 'utf8',
    timeout: 20000,
    env: { ...process.env, HOME: cwd, USERPROFILE: cwd, NO_COLOR: '1' },
  });
  return { code: res.status, stdout: res.stdout, stderr: res.stderr };
}

test('vw policy test replays a monitored log, and --fail-on-change gates CI on it', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchwell-ptest-'));
  const write = (/** @type {string} */ name, /** @type {object} */ doc) =>
    fs.writeFileSync(path.join(cwd, name), JSON.stringify({ version: 1, name, ...doc }));
  write('vouchwell.policy.json', { rules: [{ id: 'no-refunds', match: { target: 'refund' }, then: 'deny' }] });
  write('open.json', { rules: [] });
  assert.equal(pw(cwd, ['init']).code, 0);

  const refund = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'refund', arguments: { order: 'o1', amount: 100 } } });
  assert.equal(pw(cwd, ['proxy', '--monitor', '--no-remote', '--', process.execPath, SERVER], refund + '\n').code, 0);

  // The policy that was observed: nothing changes.
  const same = pw(cwd, ['policy', 'test', '--fail-on-change']);
  assert.equal(same.code, 0, same.stdout + same.stderr);
  assert.match(same.stdout, /changed\s+0/);

  // A looser one: the refund it would now allow is listed, and CI fails.
  const looser = pw(cwd, ['policy', 'test', 'open.json', '--fail-on-change']);
  assert.equal(looser.code, 1);
  assert.match(looser.stdout, /deny → allow\s+1/);
  assert.match(looser.stdout, /refund\s+deny\s+allow/);

  const json = JSON.parse(pw(cwd, ['policy', 'test', 'open.json', '--json']).stdout);
  assert.equal(json.changed, 1);
  assert.equal(json.results[0].before, 'deny');

  // No hub was needed for any of it, and a broken policy is a usage error.
  fs.writeFileSync(path.join(cwd, 'broken.json'), '{ "version": 1, "rules": [{ "id": "x", "when": { "target": { "nope": 1 } } }] }');
  assert.equal(pw(cwd, ['policy', 'test', 'broken.json']).code, 2);
});
