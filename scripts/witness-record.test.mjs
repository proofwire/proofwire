import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateIdentity } from '@deedwrit/core';
import { validate, appendOnly, check, RECORD } from './witness-record.mjs';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = path.join(REPO, 'scripts/witness-record.mjs');

/** A well-formed entry for a fresh key. */
function entry(over = {}) {
  const { kid, publicKey } = generateIdentity().identity;
  return {
    kid, publicKey, operator: 'Deedwrit', node: 'https://witness1.example',
    addedAt: '2026-09-23', retiredAt: null, revokedAt: null, note: null, ...over,
  };
}

test('the published record is valid and has only ever been appended to', () => {
  const res = check(REPO);
  assert.deepEqual(res.problems, []);
  // CI fetches full history for exactly this, and says so, so a shallow
  // checkout there fails loudly instead of quietly checking one commit.
  const shallow = spawnSync('git', ['rev-parse', '--is-shallow-repository'], { cwd: REPO, encoding: 'utf8' }).stdout.trim();
  if (process.env.CI) assert.equal(shallow, 'false', 'CI checked out shallow history; the append-only check needs all of it');
  if (shallow === 'false') assert.ok(res.checkedHistory, 'history was available but not checked');
});

test('a sound record validates', () => {
  const a = entry();
  const b = entry({ addedAt: '2026-10-01', retiredAt: '2026-12-01', note: 'first node' });
  assert.deepEqual(validate([]), []);
  assert.deepEqual(validate([a, b]), []);
});

test('each entry is checked against what its key actually is', () => {
  const a = entry();
  const other = entry();
  // The same byte, spelled non-canonically: the verifier refuses it, so an
  // entry using it could never have pinned anything.
  const last = a.publicKey.at(-1);
  const respelled = a.publicKey.slice(0, -1) + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    .split('').find((c) => c !== last && Buffer.from(a.publicKey.slice(0, -1) + c, 'base64url').equals(Buffer.from(a.publicKey, 'base64url')));

  const cases = {
    'a kid that is not its key\'s': [{ ...a, kid: other.kid }],
    'a non-canonical key': [{ ...a, publicKey: respelled }],
    'not a key at all': [{ ...a, publicKey: 'nope' }],
    'the same kid twice': [a, { ...other, kid: a.kid }],
    'the same key twice': [a, { ...a }],
    'a date that does not exist': [{ ...a, addedAt: '2026-02-30' }],
    'retired before it was added': [{ ...a, retiredAt: '2026-01-01' }],
    'revoked before it was added': [{ ...a, revokedAt: '2026-01-01' }],
    'an unknown field': [{ ...a, trusted: true }],
    'a field left out rather than null': [(() => { const { note, ...rest } = a; return rest; })()],
    'a plain-http node': [{ ...a, node: 'http://witness1.example' }],
    'no operator': [{ ...a, operator: ' ' }],
    'added out of order': [{ ...a, addedAt: '2026-10-01' }, { ...other, addedAt: '2026-09-01' }],
  };
  for (const [label, record] of Object.entries(cases)) {
    assert.notDeepEqual(validate(record), [], `${label} was accepted`);
  }
  assert.notDeepEqual(validate({ entries: [] }), [], 'an object was accepted as the record');
});

test('only appending, and setting retiredAt or revokedAt once, is allowed', () => {
  const a = entry();
  const b = entry({ addedAt: '2026-10-01' });
  const retired = { ...a, retiredAt: '2026-11-01' };

  // Allowed.
  assert.deepEqual(appendOnly([], [a]), []);
  assert.deepEqual(appendOnly([a], [a, b]), []);
  assert.deepEqual(appendOnly([a], [retired]), []);
  assert.deepEqual(appendOnly([a], [{ ...a, revokedAt: '2026-11-01' }]), []);
  assert.deepEqual(appendOnly([retired], [{ ...retired, revokedAt: '2026-12-01' }]), [], 'a retired key can still be revoked');

  // Not.
  const refused = {
    'removing an entry': [[a, b], [a]],
    'reordering': [[a, b], [b, a]],
    'inserting in the middle': [[a, b], [a, entry({ addedAt: '2026-09-30' }), b]],
    'swapping a key': [[a], [{ ...a, publicKey: b.publicKey, kid: b.kid }]],
    'editing the operator': [[a], [{ ...a, operator: 'Someone else' }]],
    'editing the note': [[a], [{ ...a, note: 'rewritten' }]],
    'back-dating an addition': [[a], [{ ...a, addedAt: '2026-01-01' }]],
    'un-retiring': [[retired], [a]],
    'changing a retirement date': [[retired], [{ ...a, retiredAt: '2026-11-02' }]],
    'un-revoking': [[{ ...a, revokedAt: '2026-11-01' }], [a]],
  };
  for (const [label, [prev, next]] of Object.entries(refused)) {
    assert.notDeepEqual(appendOnly(prev, next), [], `${label} was allowed`);
  }
});

test('the history check catches a removal that was committed, and an uncommitted edit', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-record-'));
  const git = (...args) => {
    const r = spawnSync('git', args, { cwd: dir, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
  };
  git('init', '-q');
  git('config', 'user.email', 'test@deedwrit.test');
  git('config', 'user.name', 'test');
  fs.mkdirSync(path.join(dir, 'witnesses'));
  const write = (record) => fs.writeFileSync(path.join(dir, RECORD), `${JSON.stringify(record, null, 2)}\n`);
  const commit = (msg) => { git('add', '-A'); git('commit', '-q', '-m', msg); };

  const a = entry();
  const b = entry({ addedAt: '2026-10-01' });
  write([a]); commit('add a');
  write([a, b]); commit('add b');
  assert.deepEqual(check(dir).problems, []);

  // Committed, and valid on its own — only the history shows what happened.
  write([b]); commit('quietly drop a');
  assert.deepEqual(validate([b]), [], 'the tampered record should look fine in isolation');
  const res = check(dir);
  assert.ok(res.checkedHistory);
  assert.ok(res.problems.some((p) => /removed|edited or moved/.test(p)), res.problems.join('\n'));

  // Uncommitted edits are held to the same rules.
  const clean = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-record-'));
  spawnSync('git', ['init', '-q'], { cwd: clean });
  spawnSync('git', ['config', 'user.email', 'test@deedwrit.test'], { cwd: clean });
  spawnSync('git', ['config', 'user.name', 'test'], { cwd: clean });
  fs.mkdirSync(path.join(clean, 'witnesses'));
  fs.writeFileSync(path.join(clean, RECORD), `${JSON.stringify([a], null, 2)}\n`);
  spawnSync('git', ['add', '-A'], { cwd: clean });
  spawnSync('git', ['commit', '-q', '-m', 'a'], { cwd: clean });
  fs.writeFileSync(path.join(clean, RECORD), `${JSON.stringify([{ ...a, operator: 'Someone else' }], null, 2)}\n`);
  assert.ok(check(clean).problems.some((p) => /working copy/.test(p) && /edited/.test(p)));
});

test('the command line adds, retires and revokes, and refuses what the rules refuse', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-record-cli-'));
  spawnSync('git', ['init', '-q'], { cwd: dir });
  fs.mkdirSync(path.join(dir, 'witnesses'));
  fs.writeFileSync(path.join(dir, RECORD), '[]\n');
  const cli = (...args) => {
    const r = spawnSync(process.execPath, [SCRIPT, ...args], {
      encoding: 'utf8', env: { ...process.env, DEEDWRIT_RECORD_ROOT: dir },
    });
    return { status: r.status, out: r.stdout + r.stderr };
  };
  const read = () => JSON.parse(fs.readFileSync(path.join(dir, RECORD), 'utf8'));
  const { kid, publicKey } = generateIdentity().identity;

  assert.equal(cli('add', '--operator', 'Deedwrit').status, 2, 'add without a key');
  assert.equal(cli('add', '--operator', 'Deedwrit', '--public-key', 'nope').status, 1, 'add with a bad key');
  assert.equal(cli('add', '--operator', 'Deedwrit', '--public-key', publicKey, '--node', 'https://w1.example', '--date', '2026-09-23').status, 0);
  assert.deepEqual(read(), [{
    kid, publicKey, operator: 'Deedwrit', node: 'https://w1.example',
    addedAt: '2026-09-23', retiredAt: null, revokedAt: null, note: null,
  }]);
  // The same key twice is refused, and the file is left as it was.
  assert.equal(cli('add', '--operator', 'Deedwrit', '--public-key', publicKey).status, 1);
  assert.equal(read().length, 1);

  assert.equal(cli('retire', kid, '--date', '2026-10-01').status, 0);
  assert.equal(cli('retire', kid, '--date', '2026-10-02').status, 1, 'retiring twice');
  assert.equal(read()[0].retiredAt, '2026-10-01');
  assert.equal(cli('revoke', kid, '--date', '2026-10-05').status, 0);
  assert.equal(cli('revoke', 'pw1nothere').status, 2);
  assert.equal(cli('check').status, 0);
});

test('dw check never pins a revoked key from the record, and still pins a retired one', async () => {
  const { witnessKeysFrom } = await import('../packages/cli/src/witness-keys.js');
  const live = entry();
  const retired = entry({ retiredAt: '2026-10-01' });
  const revoked = entry({ revokedAt: '2026-10-01' });
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'pw-pins-')), 'keys.json');
  fs.writeFileSync(file, JSON.stringify([live, retired, revoked]));

  const pinned = witnessKeysFrom({ 'witness-keys': file });
  assert.deepEqual(Object.keys(pinned).sort(), [live.kid, retired.kid].sort());
  assert.equal(pinned[revoked.kid], undefined);

  // The empty published record pins nothing — and says so by returning nothing,
  // which `dw check --witnesses N` then refuses rather than counting anything.
  assert.equal(witnessKeysFrom({ 'witness-keys': path.join(REPO, RECORD) }), undefined);
});
