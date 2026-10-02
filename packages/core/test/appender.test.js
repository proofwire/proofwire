import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ProofLog } from '../src/log.js';
import { LogAppender } from '../src/appender.js';
import { randomBytes } from 'node:crypto';

const ACTOR = { agent: 'bot', runtime: 'test', session: 's1', principal: 'p@acme.test' };

/** @param {number} i @param {string} [ts] */
const action = (i, ts) => ({
  actor: ACTOR,
  action: { kind: 'tool_call', target: 'claude-code.Bash', params: { command: `echo ${i}` } },
  decision: { outcome: 'allow', policy: 'p', rules: [] },
  result: null,
  ...(ts ? { ts } : {}),
});

const fresh = () => {
  const dir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'vouchwell-appender-')), '.vouchwell');
  ProofLog.create(dir);
  return dir;
};

/** @param {string} dir */
const full = (dir) => ProofLog.open(dir, { readOnly: true });

test('appending through it gives the log ProofLog would have written', () => {
  const dir = fresh();
  for (let i = 0; i < 37; i++) {
    const a = LogAppender.open(dir);
    a.append(action(i));
    const log = full(dir);
    assert.equal(a.size, log.size);
    assert.equal(a.head, log.head);
    assert.equal(a.root, log.root, `root after ${i + 1}`);
  }
  LogAppender.open(dir).checkpoint();
  const log = full(dir);
  assert.ok(log.audit().ok, JSON.stringify(log.audit().issues));
  assert.equal(log.checkpoints().length, 1);
});

test('its frontier root matches the full tree at every size, across reopenings', () => {
  const dir = fresh();
  let a = LogAppender.open(dir);
  assert.equal(a.root, full(dir).root, 'empty');
  for (let i = 0; i < 70; i++) {
    a.append(action(i));
    if (i % 7 === 0) a = LogAppender.open(dir);
    assert.equal(a.root, full(dir).root, `size ${i + 1}`);
  }
});

test('opening reads only what was appended since the cache, not the whole file', () => {
  const dir = fresh();
  const a = LogAppender.open(dir);
  for (let i = 0; i < 20; i++) a.append(action(i));

  // Damage an early receipt without changing its length. ProofLog, which
  // reads everything, notices; the appender never reads that far back.
  const file = path.join(dir, 'entries.jsonl');
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  lines[3] = 'x'.repeat(lines[3].length);
  fs.writeFileSync(file, lines.join('\n'));
  assert.throws(() => full(dir), /not valid JSON/);
  const again = LogAppender.open(dir);
  assert.equal(again.size, 20);
  again.append(action(20));
  assert.equal(again.size, 21);
});

test('receipts another writer appended are picked up from the cached point', () => {
  const dir = fresh();
  const a = LogAppender.open(dir);
  for (let i = 0; i < 5; i++) a.append(action(i));
  const other = ProofLog.open(dir);
  for (let i = 5; i < 9; i++) other.append(action(i));

  const b = LogAppender.open(dir);
  assert.equal(b.size, 9);
  assert.equal(b.head, other.head);
  b.append(action(9));
  const log = full(dir);
  assert.equal(b.root, log.root);
  assert.ok(log.audit().ok);
});

test('a cache that does not match the file is rebuilt from the file', () => {
  const dir = fresh();
  const a = LogAppender.open(dir);
  for (let i = 0; i < 6; i++) a.append(action(i));
  const cacheFile = path.join(dir, 'append-state.json');
  const good = fs.readFileSync(cacheFile, 'utf8');

  const cases = {
    'wrong head': (/** @type {any} */ c) => ({ ...c, head: 'f'.repeat(64) }),
    'too many bytes': (/** @type {any} */ c) => ({ ...c, bytes: c.bytes + 10_000 }),
    'another log': (/** @type {any} */ c) => ({ ...c, log: 'lg_other' }),
    'not json': () => '{ broken',
  };
  for (const [name, mutate] of Object.entries(cases)) {
    const c = mutate(JSON.parse(good));
    fs.writeFileSync(cacheFile, typeof c === 'string' ? c : JSON.stringify(c));
    const b = LogAppender.open(dir);
    assert.equal(b.size, 6, name);
    assert.equal(b.root, full(dir).root, name);
  }

  // The file rewritten under the cache: a different chain of the same length.
  fs.writeFileSync(cacheFile, good);
  const entries = path.join(dir, 'entries.jsonl');
  fs.rmSync(dir, { recursive: true });
  ProofLog.create(dir);
  const config = JSON.parse(fs.readFileSync(path.join(dir, 'config.json'), 'utf8'));
  const c = JSON.parse(good);
  fs.writeFileSync(cacheFile, JSON.stringify({ ...c, log: config.log }));
  const rewritten = LogAppender.open(dir);
  for (let i = 0; i < 6; i++) rewritten.append(action(100 + i));
  assert.equal(rewritten.root, full(dir).root);
  assert.ok(fs.existsSync(entries));
});

test('a receipt cut short mid-write is left for the next reader', () => {
  const dir = fresh();
  const a = LogAppender.open(dir);
  for (let i = 0; i < 3; i++) a.append(action(i));
  const file = path.join(dir, 'entries.jsonl');
  fs.appendFileSync(file, '{"v":1,"log":"partial');
  const b = LogAppender.open(dir);
  assert.equal(b.size, 3);
});

test('reading in pieces of any size, a read starting on a newline included, finds every receipt', { timeout: 60_000 }, () => {
  const dir = fresh();
  const a = LogAppender.open(dir);
  for (let i = 0; i < 6; i++) a.append(action(i));
  // An empty line too, as a hand-edited file might have.
  fs.appendFileSync(path.join(dir, 'entries.jsonl'), '\n');
  const all = [0, 1, 2, 3, 4, 5];
  const lineLength = fs.readFileSync(path.join(dir, 'entries.jsonl'), 'utf8').split('\n')[0].length;
  const saved = LogAppender.chunkSize;
  try {
    for (let size = 1; size <= lineLength + 3; size++) {
      LogAppender.chunkSize = size;
      const b = LogAppender.open(dir);
      assert.deepEqual(b.recent(3600_000).map((r) => r.seq), all, `chunk ${size}`);
      fs.rmSync(path.join(dir, 'append-state.json'));
      const rebuilt = LogAppender.open(dir);
      assert.equal(rebuilt.size, 6, `chunk ${size}`);
      assert.equal(rebuilt.head, b.head, `chunk ${size}`);
    }
  } finally {
    LogAppender.chunkSize = saved;
  }
});

test('recent returns the receipts inside the window, oldest first, reading back only that far', () => {
  const dir = fresh();
  const a = LogAppender.open(dir);
  const now = Date.now();
  const at = (/** @type {number} */ msAgo) => new Date(now - msAgo).toISOString();
  // A long line, so the window spans more than one 64 KB read.
  a.append({ ...action(-1, at(10 * 3600_000)), action: { kind: 'tool_call', target: 'x', params: { blob: randomBytes(80_000).toString('hex') } } });
  for (let i = 0; i < 5; i++) a.append(action(i, at(3 * 3600_000 - i)));
  for (let i = 5; i < 9; i++) a.append(action(i, at(30 * 60_000 - i)));

  assert.deepEqual(a.recent(3600_000).map((r) => r.seq), [6, 7, 8, 9]);
  assert.deepEqual(a.recent(5 * 3600_000).map((r) => r.seq), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.equal(a.recent(24 * 3600_000).length, 10);
  assert.deepEqual(a.recent(0), []);
  assert.deepEqual(LogAppender.open(fresh()).recent(3600_000), []);
});
