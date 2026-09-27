import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Hub } from '../../server/src/app.js';
import { Auth } from '../../server/src/auth.js';

/**
 * `pw witnesses` and `pw streams`: an admin configuring a hub's outside
 * witnesses and event streams from the command line.
 */

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, '../src/bin.js');
const fast = { capacity: 1e5, refillPerSec: 1e5 };

/** @type {Hub} */ let hub;
/** @type {Hub} */ let witness;
/** @type {http.Server} */ let sink;
let hubUrl = '';
let witnessUrl = '';
let witnessToken = '';
let sinkUrl = '';
let admin = '';
/** @type {string[]} */
const received = [];
let cwd = '';

before(async () => {
  witness = new Hub({ database: ':memory:', witnessOnly: true, apiRate: fast, authRate: fast });
  witnessUrl = (await witness.listen(0)).url.replace('0.0.0.0', '127.0.0.1');
  const wOrg = witness.store.createOrg({ slug: 'acme', name: 'Acme' });
  witnessToken = new Auth(witness.store).createKey({ orgId: wOrg.id, name: 'hub', scopes: ['witness:sign'] }).token;

  hub = new Hub({ database: ':memory:', egressAllowPrivate: true, apiRate: fast, authRate: fast });
  hubUrl = (await hub.listen(0)).url.replace('0.0.0.0', '127.0.0.1');
  const org = hub.store.createOrg({ slug: 'acme', name: 'Acme' });
  admin = new Auth(hub.store).createKey({ orgId: org.id, name: 'admin', scopes: ['admin', 'logs:read'] }).token;

  sink = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      received.push(body);
      res.writeHead(200).end('{}');
    });
  });
  await new Promise((r) => sink.listen(0, '127.0.0.1', () => r(null)));
  sinkUrl = `http://127.0.0.1:${/** @type {any} */ (sink.address()).port}`;

  cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'proofwire-integrations-cli-'));
  assert.equal((await pw(['init'])).code, 0);
  const added = await pw(['remote', 'add', '--url', hubUrl, '--token', admin, '--insecure']);
  assert.equal(added.code, 0, added.out);
});

after(async () => {
  await hub.close();
  await witness.close();
  await new Promise((r) => sink.close(r));
  fs.rmSync(cwd, { recursive: true, force: true });
});

/**
 * @param {string[]} args @param {Record<string, string>} [env]
 * @returns {Promise<{ code: number | null, out: string }>}
 */
function pw(args, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN, ...args], {
      cwd,
      env: { ...process.env, HOME: cwd, USERPROFILE: cwd, NO_COLOR: '1', ...env },
    });
    let out = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (out += d));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, out }));
    child.stdin.end();
  });
}

test('pw witnesses add, list and remove; the token comes from the environment', async () => {
  const add = await pw(['witnesses', 'add', 'notary', '--url', witnessUrl], { PROOFWIRE_WITNESS_TOKEN: witnessToken });
  assert.equal(add.code, 0, add.out);
  assert.match(add.out, new RegExp(witness.witnessSigner.kid));

  const list = await pw(['witnesses', 'list']);
  assert.match(list.out, /notary/);
  assert.ok(!list.out.includes(witnessToken));

  const gone = await pw(['witnesses', 'remove', 'notary']);
  assert.equal(gone.code, 0, gone.out);
  assert.match((await pw(['witnesses', 'list'])).out, /none/);
});

test('pw streams add, test, list and remove; a generated webhook secret is shown once', async () => {
  const add = await pw(['streams', 'add', 'soc', '--type', 'webhook', '--url', `${sinkUrl}/in`, '--receipts', 'blocked']);
  assert.equal(add.code, 0, add.out);
  assert.match(add.out, /whsec_[A-Za-z0-9_-]+/);

  const splunk = await pw(['streams', 'add', 'splunk', '--type', 'splunk', '--url', sinkUrl], { PROOFWIRE_STREAM_TOKEN: 'hec-1' });
  assert.equal(splunk.code, 0, splunk.out);
  assert.ok(!splunk.out.includes('whsec_'));

  const t = await pw(['streams', 'test']);
  assert.equal(t.code, 0, t.out);
  assert.match(t.out, /soc: delivered/);
  assert.match(t.out, /splunk: delivered/);
  assert.ok(received.some((b) => b.includes('"type":"test"')));

  assert.equal((await pw(['streams', 'flush'])).code, 0);
  const list = await pw(['streams', 'list']);
  assert.match(list.out, /soc\s+webhook/);
  assert.match(list.out, /receipts \(blocked\), audit/);
  assert.ok(!list.out.includes('hec-1'));

  // Adding again without the token keeps it (same URL).
  assert.equal((await pw(['streams', 'add', 'splunk', '--type', 'splunk', '--url', sinkUrl, '--no-audit'])).code, 0);
  assert.equal((await pw(['streams', 'remove', 'soc'])).code, 0);
  const after = await pw(['streams', 'list']);
  assert.ok(!/soc/.test(after.out), after.out);
  assert.match(after.out, /splunk/);

  assert.equal((await pw(['streams', 'add', 'x'])).code, 2);
  assert.equal((await pw(['streams', 'remove', 'nope'])).code, 1);
});
