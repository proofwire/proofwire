import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ProofLog, entryHash } from '@deedwrit/core';

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/bin.js');
const actor = { agent: 'claude', runtime: 'test', session: 'sess_crash', principal: 'ops@acme.test' };
const allow = { outcome: 'allow', policy: 'p', rules: [] };

/** @param {string} cwd @param {string[]} args */
function pw(cwd, args) {
  const res = spawnSync(process.execPath, [BIN, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, HOME: cwd, USERPROFILE: cwd, NO_COLOR: '1' },
  });
  return { code: res.status, out: res.stdout + res.stderr };
}

/** A log where one call finished and one was cut off by a crash. */
function crashedLog() {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'deedwrit-unfinished-cli-'));
  const log = ProofLog.create(path.join(cwd, '.deedwrit'));
  const done = log.append({ ts: '2026-01-01T00:00:00.000Z', phase: 'intent', actor, action: { kind: 'tool_call', target: 'crm.query', params: {} }, decision: allow });
  log.append({ ts: '2026-01-01T00:00:01.000Z', phase: 'outcome', ref: entryHash(done), actor, action: { kind: 'tool_call', target: 'crm.query', params: {} }, decision: allow, result: { status: 'ok', payload: null } });
  log.append({ ts: '2026-01-01T00:00:02.000Z', phase: 'intent', actor, action: { kind: 'tool_call', target: 'stripe.refund', params: {} }, decision: allow });
  return cwd;
}

test('dw verify names a call that never finished, without calling the log tampered', () => {
  const cwd = crashedLog();
  const res = pw(cwd, ['verify']);
  assert.equal(res.code, 0, res.out);
  assert.match(res.out, /Every receipt verifies/);
  assert.match(res.out, /1 action\(s\) were authorised and sent, but never finished/);
  assert.match(res.out, /stripe\.refund/);
  assert.doesNotMatch(res.out, /crm\.query.*no result/);
});

test('--fail-on-unfinished turns it into exit code 3, and a clean log still exits 0', () => {
  assert.equal(pw(crashedLog(), ['verify', '--fail-on-unfinished']).code, 3);

  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'deedwrit-unfinished-clean-'));
  ProofLog.create(path.join(cwd, '.deedwrit'));
  const clean = pw(cwd, ['verify', '--fail-on-unfinished']);
  assert.equal(clean.code, 0, clean.out);
  assert.doesNotMatch(clean.out, /never finished/);
});

test('dw log --unfinished lists only the calls that never came back', () => {
  const res = pw(crashedLog(), ['log', '--unfinished', '--json']);
  assert.equal(res.code, 0, res.out);
  assert.deepEqual(JSON.parse(res.out).map((/** @type {any} */ r) => [r.seq, r.action.target]), [[2, 'stripe.refund']]);
});
