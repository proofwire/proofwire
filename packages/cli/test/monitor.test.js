import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, '../src/bin.js');
const SERVER = path.resolve(HERE, '../../../examples/fake-mcp-server.js');

const REFUND = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'tools/call',
  params: { name: 'refund', arguments: { order: 'ord_1', amount: 100 } },
});

/** A project directory with a policy that denies every refund. */
function project() {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'deedwrit-cli-'));
  fs.writeFileSync(
    path.join(cwd, 'deedwrit.policy.json'),
    JSON.stringify({
      version: 1,
      name: 'frozen',
      rules: [{ id: 'no-refunds', match: { target: 'refund' }, then: 'deny', reason: 'refunds are frozen' }],
    }),
  );
  return cwd;
}

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
    // A private home: `dw` reads hub credentials from ~/.deedwrit, and a test
    // must neither pick up the developer's real ones nor write beside them.
    env: { ...process.env, HOME: cwd, USERPROFILE: cwd, NO_COLOR: '1' },
  });
  return { code: res.status, stdout: res.stdout, stderr: res.stderr };
}

/** @param {string} stdout */
const replies = (stdout) => stdout.split('\n').filter(Boolean).map((l) => JSON.parse(l));

test('dw proxy --monitor lets a call the policy denies through, loudly', () => {
  const cwd = project();
  assert.equal(pw(cwd, ['init']).code, 0);

  const run = pw(cwd, ['proxy', '--monitor', '--no-remote', '--', process.execPath, SERVER], REFUND + '\n');
  assert.equal(run.code, 0, run.stderr);
  assert.match(run.stderr, /MONITOR MODE — nothing will be blocked/);
  assert.match(run.stderr, /would deny refund — refunds are frozen/);
  assert.match(run.stderr, /1 would have been stopped \(monitor mode\)/);

  const [reply] = replies(run.stdout);
  assert.equal(reply.result.isError, undefined, 'the refund should have reached the server');

  const log = pw(cwd, ['log', '--would-block']);
  assert.match(log.stdout, /showing 1 of 1/);
  assert.match(log.stdout, /would deny/);

  const stats = pw(cwd, ['stats']);
  assert.match(stats.stdout, /not enforced\s+1 calls ran in monitor mode/);
  assert.match(stats.stdout, /Would have been stopped \(monitor mode\)[\s\S]*no-refunds\s+1/);
  assert.match(stats.stdout, /blocked\s+0/);

  assert.equal(pw(cwd, ['verify']).code, 0);
});

test('"monitor": true in the config is honoured, and --enforce overrides it', () => {
  const cwd = project();
  assert.equal(pw(cwd, ['init']).code, 0);
  const configFile = path.join(cwd, 'deedwrit.config.json');
  const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
  fs.writeFileSync(configFile, JSON.stringify({ ...config, monitor: true }));

  const monitored = pw(cwd, ['proxy', '--no-remote', '--', process.execPath, SERVER], REFUND + '\n');
  assert.match(monitored.stderr, /MONITOR MODE/);
  assert.equal(replies(monitored.stdout)[0].result.isError, undefined);

  const enforced = pw(cwd, ['proxy', '--enforce', '--no-remote', '--', process.execPath, SERVER], REFUND + '\n');
  assert.doesNotMatch(enforced.stderr, /MONITOR MODE/);
  const [reply] = replies(enforced.stdout);
  assert.equal(reply.result.isError, true);
  assert.match(reply.result.content[0].text, /Blocked by Deedwrit policy/);
});

test('without --monitor the same policy blocks', () => {
  const cwd = project();
  assert.equal(pw(cwd, ['init']).code, 0);
  const run = pw(cwd, ['proxy', '--no-remote', '--', process.execPath, SERVER], REFUND + '\n');
  assert.doesNotMatch(run.stderr, /MONITOR MODE/);
  assert.equal(replies(run.stdout)[0].result.isError, true);
});
