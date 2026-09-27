import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Policy, ProofLog, POLICY_TEMPLATES } from '@proof_wire/core';

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/bin.js');

/** @param {string} cwd @param {string[]} args */
function pw(cwd, args) {
  const res = spawnSync(process.execPath, [BIN, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, HOME: cwd, USERPROFILE: cwd, NO_COLOR: '1' },
  });
  return { code: res.status, out: res.stdout + res.stderr, stdout: res.stdout };
}

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'proofwire-templates-cli-'));

test('pw policy templates lists every template, and --json is machine-readable', () => {
  const cwd = tmp();
  const res = pw(cwd, ['policy', 'templates']);
  assert.equal(res.code, 0, res.out);
  for (const t of POLICY_TEMPLATES) assert.match(res.out, new RegExp(`\\b${t.id}\\b`));
  const json = JSON.parse(pw(cwd, ['policy', 'templates', '--json']).stdout);
  assert.deepEqual(json.map((/** @type {any} */ t) => t.id), POLICY_TEMPLATES.map((t) => t.id));
});

test('pw policy template prints a loadable policy, writes one with --out, and will not overwrite', () => {
  const cwd = tmp();
  const printed = pw(cwd, ['policy', 'template', 'secrets', 'destructive-sql,payments']);
  assert.equal(printed.code, 0, printed.out);
  const doc = JSON.parse(printed.stdout);
  assert.deepEqual(doc.templates, ['secrets', 'destructive-sql', 'payments']);
  assert.doesNotThrow(() => new Policy(doc));

  const file = path.join(cwd, 'p.json');
  assert.equal(pw(cwd, ['policy', 'template', 'loop-guard', '--out', file]).code, 0);
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).name, 'loop-guard');
  const again = pw(cwd, ['policy', 'template', 'secrets', '--out', file]);
  assert.equal(again.code, 1);
  assert.match(again.out, /already exists/);
  assert.equal(pw(cwd, ['policy', 'template', 'secrets', '--out', file, '--force']).code, 0);
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).name, 'secrets');
});

test('an unknown template, or none at all, is an error that says what exists', () => {
  const cwd = tmp();
  const unknown = pw(cwd, ['policy', 'template', 'nope']);
  assert.equal(unknown.code, 1);
  assert.match(unknown.out, /no policy template "nope"; available: secrets/);
  assert.equal(pw(cwd, ['policy', 'template']).code, 2);
});

test('pw init --template writes the composed policy; an unknown one creates nothing', () => {
  const cwd = tmp();
  const bad = pw(cwd, ['init', '--template', 'secrets,nope']);
  assert.equal(bad.code, 1);
  assert.ok(!fs.existsSync(path.join(cwd, '.proofwire')), 'no log should be created for a bad template');

  const res = pw(cwd, ['init', '--template', 'secrets,read-only']);
  assert.equal(res.code, 0, res.out);
  const doc = JSON.parse(fs.readFileSync(path.join(cwd, 'proofwire.policy.json'), 'utf8'));
  assert.deepEqual(doc.templates, ['secrets', 'read-only']);
  assert.equal(doc.defaults.outcome, 'deny');
});

test('a template policy replays against recorded traffic before it can block anything', () => {
  const cwd = tmp();
  const log = ProofLog.create(path.join(cwd, '.proofwire'));
  const actor = { agent: 'a', runtime: 'r', session: 's', principal: 'p@acme.test' };
  const allow = { outcome: 'allow', policy: 'none', rules: [] };
  log.append({ phase: 'intent', actor, action: { kind: 'tool_call', target: 'db.execute', params: { sql: 'DROP TABLE users' } }, decision: allow });
  log.append({ phase: 'intent', actor, action: { kind: 'tool_call', target: 'db.execute', params: { sql: 'SELECT 1' } }, decision: allow });
  assert.equal(pw(cwd, ['policy', 'template', 'destructive-sql', '--out', 'candidate.json']).code, 0);

  const res = pw(cwd, ['policy', 'test', 'candidate.json', '--fail-on-change']);
  assert.equal(res.code, 1, res.out);
  assert.match(res.out, /allow → deny/);
  assert.match(res.out, /destructive-sql\.schema\.sql/);
});
