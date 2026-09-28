import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ProofLog } from '../src/log.js';
import { entryHash } from '../src/receipt.js';
import { findUnfinished, DEFAULT_GRACE_MS } from '../src/unfinished.js';

const actor = { agent: 'claude', runtime: 'test', session: 'sess_a', principal: 'ops@acme.test' };
const allow = { outcome: 'allow', policy: 'p', rules: [] };
const NOW = Date.parse('2026-09-26T12:00:00.000Z');
const at = (/** @type {number} */ msAgo) => new Date(NOW - msAgo).toISOString();

function log() {
  return ProofLog.create(fs.mkdtempSync(path.join(os.tmpdir(), 'vouchwell-unfinished-')));
}

/**
 * @param {ProofLog} l
 * @param {string} target
 * @param {string} ts
 */
function intent(l, target, ts) {
  return l.append({ ts, phase: 'intent', actor, action: { kind: 'tool_call', target, params: {} }, decision: allow });
}

/**
 * @param {ProofLog} l
 * @param {any} of
 * @param {object} result
 */
function outcome(l, of, result) {
  return l.append({
    ts: at(0), phase: 'outcome', ref: entryHash(of), actor,
    action: { kind: 'tool_call', target: of.action.target, params: {} }, decision: allow,
    result: { payload: null, ...result },
  });
}

test('a finished call is not reported; one with no outcome is', () => {
  const l = log();
  const done = intent(l, 'crm.query', at(60_000));
  outcome(l, done, { status: 'ok' });
  intent(l, 'stripe.refund', at(DEFAULT_GRACE_MS + 1));

  const found = findUnfinished(l.entries, { now: NOW });
  assert.deepEqual(found.unfinished.map((u) => [u.seq, u.target, u.principal, u.session]), [[2, 'stripe.refund', 'ops@acme.test', 'sess_a']]);
  assert.equal(found.unfinished[0].intent, entryHash(l.entries[2]));
  assert.deepEqual(found.abandoned, []);
  assert.deepEqual(found.inFlight, []);
  assert.deepEqual(found.orphans, []);
});

test('a call younger than the grace period is in flight, not unfinished', () => {
  const l = log();
  intent(l, 'slow.export', at(30_000));
  const found = findUnfinished(l.entries, { now: NOW });
  assert.deepEqual(found.unfinished, []);
  assert.deepEqual(found.inFlight.map((u) => u.target), ['slow.export']);
  assert.equal(findUnfinished(l.entries, { now: NOW, graceMs: 1_000 }).unfinished.length, 1, 'the grace period is configurable');
});

test('an error is a finished call; a recorded give-up is abandoned', () => {
  const l = log();
  const failed = intent(l, 'mail.send', at(3_600_000));
  outcome(l, failed, { status: 'error', code: '-32000' });
  const cut = intent(l, 'db.migrate', at(3_600_000));
  outcome(l, cut, { status: 'error', code: 'unfinished' });

  const found = findUnfinished(l.entries, { now: NOW });
  assert.deepEqual(found.unfinished, [], 'both calls have outcomes');
  assert.deepEqual(found.abandoned.map((u) => [u.seq, u.target, u.outcomeSeq]), [[2, 'db.migrate', 3]]);
});

test('an outcome naming an intent the log does not hold is an orphan', () => {
  const l = log();
  const i = intent(l, 'crm.query', at(60_000));
  l.append({
    ts: at(0), phase: 'outcome', ref: 'ab'.repeat(32), actor,
    action: { kind: 'tool_call', target: 'crm.query', params: {} }, decision: allow, result: { status: 'ok', payload: null },
  });
  const found = findUnfinished(l.entries, { now: NOW });
  assert.deepEqual(found.orphans, [{ seq: 1, ref: 'ab'.repeat(32) }]);
  assert.equal(found.inFlight[0].seq, i.seq);
});

test('atomic receipts and refusals are never unfinished, and hostile input does not throw', () => {
  const l = log();
  l.append({ ts: at(DEFAULT_GRACE_MS * 2), actor, action: { kind: 'tool_call', target: 'x', params: {} }, decision: { outcome: 'deny', policy: 'p', rules: [], reason: 'no' } });
  assert.deepEqual(findUnfinished(l.entries, { now: NOW }).unfinished, []);
  const odd = /** @type {any[]} */ ([null, 7, { phase: 'outcome' }, { phase: 'intent', ts: 'not a date', action: {}, actor: {} }]);
  const found = findUnfinished(odd, { now: NOW });
  assert.equal(found.unfinished.length, 1, 'an unparseable time is not given the benefit of the doubt');
  assert.equal(found.orphans.length, 1);
});
