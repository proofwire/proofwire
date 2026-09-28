import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ProofLog, verifyCheckpoint, signCheckpoint, generateIdentity, witnessCheckpoint, MerkleTree, leafHash } from '@vouchwell/core';
import { Hub, WITNESS_ONLY_ROUTES } from '../src/app.js';

/**
 * A witness-only node, driven the way an operator and a customer would drive
 * one: keys minted by the real `witness-key` command on the host, then
 * everything else over HTTP against a real socket.
 */

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/bin.js');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-witness-only-'));
const database = path.join(dir, 'witness.db');

/** @type {Hub} */
let hub;
let base = '';
/** What `witness-key` printed for each customer. */
const acme = { token: '', kid: '', publicKey: '' };
const globex = { token: '', kid: '', publicKey: '' };

/** @param {string[]} args @param {Record<string,string>} [env] */
function cli(args, env = {}) {
  const res = spawnSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    env: {
      ...process.env,
      VOUCHWELL_DB: database,
      VOUCHWELL_WITNESS_ONLY: '1',
      NODE_OPTIONS: '--no-warnings=ExperimentalWarning',
      ...env,
    },
  });
  // The CLI writes for people; strip the colour before reading it as data.
  const out = (res.stdout + res.stderr).replace(/\x1b\[[0-9;]*m/g, '');
  return { status: res.status, out };
}

/** @param {string} out */
function parseWitnessKey(out) {
  const token = out.match(/^\s*token\s+(pwk_\S+)/m)?.[1];
  const kid = out.match(/^\s*kid\s+(pw1\S+)/m)?.[1];
  const publicKey = out.match(/^\s*public key\s+(\S+)/m)?.[1];
  assert.ok(token && kid && publicKey, `witness-key output was not parseable:\n${out}`);
  return { token, kid, publicKey };
}

before(async () => {
  // Minted before the server starts, as an operator would on a fresh node.
  const a = cli(['witness-key', 'Acme']);
  assert.equal(a.status, 0, a.out);
  Object.assign(acme, parseWitnessKey(a.out));

  const g = cli(['witness-key', 'Globex']);
  assert.equal(g.status, 0, g.out);
  Object.assign(globex, parseWitnessKey(g.out));

  hub = new Hub({
    database,
    witnessOnly: true,
    apiRate: { capacity: 100000, refillPerSec: 100000 },
    ingestRate: { capacity: 100000, refillPerSec: 100000 },
    authRate: { capacity: 100000, refillPerSec: 100000 },
  });
  const { url } = await hub.listen(0);
  base = url.replace('0.0.0.0', '127.0.0.1');
});

after(async () => {
  await hub?.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

/** @param {string} method @param {string} p @param {{ token?: string, body?: unknown }} [opts] */
async function api(method, p, opts = {}) {
  const res = await fetch(base + p, {
    method,
    headers: {
      ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
      ...(opts.body !== undefined ? { 'content-type': 'application/json' } : {}),
    },
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    redirect: 'manual',
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* HTML or empty */ }
  return { status: res.status, json };
}

test('witness-key hands a customer a working key, and the node serves the key it printed', async () => {
  // Both customers were told the same witness key: it is the node's, not theirs.
  assert.equal(acme.kid, globex.kid);

  const served = await api('GET', '/v1/witness/key');
  assert.equal(served.status, 200);
  assert.equal(served.json.kid, acme.kid, 'the node serves a different key from the one the operator handed out');
  assert.equal(served.json.publicKey, acme.publicKey);

  // `vw remote add` proves a credential through /v1/me before storing it.
  const me = await api('GET', '/v1/me', { token: acme.token });
  assert.equal(me.status, 200);
  assert.deepEqual([...me.json.scopes].sort(), ['logs:read', 'witness:sign']);

  // Each customer has an organization of their own.
  const them = await api('GET', '/v1/me', { token: globex.token });
  assert.notEqual(them.json.org.id, me.json.org.id);
});

test('every route a full hub serves, except the witness\'s own, is gone', async () => {
  // Derived from a real hub's route table rather than listed by hand, so a
  // route added to the hub later is checked here without anyone remembering to.
  const full = new Hub({ database: ':memory:' });
  const routes = full.router.routes.map((r) => ({ method: r.method, raw: r.raw }));
  await full.close();

  const allowed = new Set(WITNESS_ONLY_ROUTES);
  const gone = routes.filter((r) => !allowed.has(`${r.method} ${r.raw}`));
  assert.ok(gone.length > 30, `expected the hub to have dozens of routes, found ${gone.length}`);

  for (const { method, raw } of gone) {
    const p = raw.replace(/:[^/]+/g, 'x');
    // A valid customer credential, so a 404 cannot be a permission failure in disguise.
    const res = await api(method, p, {
      token: acme.token,
      body: ['POST', 'PUT', 'PATCH'].includes(method) ? {} : undefined,
    });
    assert.equal(res.status, 404, `${method} ${raw} answered ${res.status} on a witness-only node`);
  }

  // And what it keeps, it still answers.
  assert.equal((await api('GET', '/health')).status, 200);
  assert.equal((await api('GET', '/ready')).status, 200);
});

test('.well-known names the witness key and nothing that could be mistaken for it', async () => {
  const res = await api('GET', '/.well-known/vouchwell');
  assert.equal(res.status, 200);
  assert.equal(res.json.service, 'vouchwell-witness');
  assert.equal('hub' in res.json, false, 'a witness-only node advertised a hub key');
  assert.equal(res.json.witness.kid, acme.kid);
  assert.ok(res.json.keys.length >= 1);
  for (const k of res.json.keys) assert.equal(k.role, 'witness');

  // No hub key was created at all — not merely hidden.
  assert.deepEqual(hub.store.serverKeys().map((k) => k.role), ['witness']);
});

test('identity, run on the host, prints the same witness key the node serves, and no hub key', async () => {
  const res = cli(['identity', '--json'], { VOUCHWELL_PUBLIC_URL: 'https://witness1.example' });
  assert.equal(res.status, 0, res.out);
  const printed = JSON.parse(res.out);
  const served = (await api('GET', '/.well-known/vouchwell')).json;
  assert.deepEqual(printed.witness, { kid: served.witness.kid, publicKey: served.witness.publicKey });
  assert.equal(printed.hub, null);
  assert.equal(printed.witnessOnly, true);
  assert.equal(printed.url, 'https://witness1.example');

  // The human form hands over the exact command that publishes the key.
  const human = cli(['identity'], { VOUCHWELL_PUBLIC_URL: 'https://witness1.example' });
  assert.ok(
    human.out.includes(
      `witness-record.mjs add --operator Vouchwell --public-key ${served.witness.publicKey} --node https://witness1.example`,
    ),
    human.out,
  );
});

test('it co-signs a real log\'s checkpoints, and an auditor pinning it can verify them', async () => {
  const logDir = path.join(dir, 'agent-log');
  const log = ProofLog.create(logDir);
  const append = () => log.append({
    actor: { agent: 'claude-opus-5', runtime: 'test', session: 'sess_w', principal: 'ops@acme.test' },
    action: { kind: 'tool_call', target: 'ops.refund', params: { n: log.size } },
    decision: { outcome: 'allow', policy: 'p0', rules: [] },
  });
  const cosign = async (checkpoint, consistencyProof) => api('POST', '/v1/witness/cosign', {
    token: acme.token,
    body: { checkpoint, consistencyProof, logPublicKey: log.identity.publicKey },
  });
  const trusted = { trustedWitnesses: { [acme.kid]: acme.publicKey }, minWitnesses: 1 };

  for (let i = 0; i < 3; i++) append();
  const first = log.checkpoint();
  const r1 = await cosign(first);
  assert.equal(r1.status, 200, JSON.stringify(r1.json));
  const witnessed1 = { body: first.body, sigs: [...first.sigs, r1.json.signature] };
  const v1 = verifyCheckpoint(witnessed1, log.keyring, trusted);
  assert.ok(v1.ok, v1.issues.join('; '));

  // Growth has to be proven: the consistency proof from 3 to 5, as `vw cosign` sends it.
  for (let i = 0; i < 2; i++) append();
  const second = log.checkpoint();
  const proof = log.tree.consistencyProof(first.body.size, second.body.size).map((b) => b.toString('hex'));
  const r2 = await cosign(second, proof);
  assert.equal(r2.status, 200, JSON.stringify(r2.json));
  const v2 = verifyCheckpoint({ body: second.body, sigs: [...second.sigs, r2.json.signature] }, log.keyring, trusted);
  assert.ok(v2.ok, v2.issues.join('; '));

  // The one thing a witness exists to refuse still gets refused — even signed
  // by the log's own key, which is exactly who would be forking it.
  const forked = signCheckpoint(log.identity, { ...second.body, root: 'cd'.repeat(32) });
  const r3 = await cosign(forked);
  assert.equal(r3.status, 409);
  assert.equal(r3.json.error.code, 'split_view');
});

test('two customers\' positions are independent, which is why each gets an organization', async () => {
  // A witness binds a log name to the first key that signs for it, per
  // organization. Two customers using the same log name, with different keys,
  // must not lock each other out — or block each other as a "split view" of
  // what are really two different logs.
  const globexKey = generateIdentity().identity;
  const acmeKey = generateIdentity().identity;
  const at = (identity, root) => signCheckpoint(identity, {
    v: 1, log: 'shared-name', size: 1, root, head: 'ab'.repeat(32), ts: new Date().toISOString(),
  });
  const cosign = (token, checkpoint, identity) => api('POST', '/v1/witness/cosign', {
    token, body: { checkpoint, logPublicKey: identity.publicKey },
  });

  const g1 = await cosign(globex.token, at(globexKey, '11'.repeat(32)), globexKey);
  assert.equal(g1.status, 200, JSON.stringify(g1.json));

  // Same log name, another customer, another key, another root: its own log.
  const a1 = await cosign(acme.token, at(acmeKey, '22'.repeat(32)), acmeKey);
  assert.equal(a1.status, 200, JSON.stringify(a1.json));

  // The same root change from the *same* customer is a split view.
  const g2 = await cosign(globex.token, at(globexKey, '22'.repeat(32)), globexKey);
  assert.equal(g2.status, 409);
  assert.equal(g2.json.error.code, 'split_view');
});

/** A fresh local log with `n` receipts. */
function localLog(/** @type {number} */ n) {
  const log = ProofLog.create(fs.mkdtempSync(path.join(dir, 'client-')));
  for (let i = 0; i < n; i++) grow(log, 1);
  return log;
}
/** @param {ProofLog} log @param {number} n */
function grow(log, n) {
  for (let i = 0; i < n; i++) {
    log.append({
      actor: { agent: 'a', runtime: 'test', session: 's', principal: 'p@acme.test' },
      action: { kind: 'tool_call', target: 'ops.x', params: { n: log.size } },
      decision: { outcome: 'allow', policy: 'p', rules: [] },
    });
  }
}
/** @param {ProofLog} log @param {string} [token] */
const witnessLog = (log, token = acme.token) => witnessCheckpoint({
  url: base, token, checkpoint: log.checkpoint(), tree: log.tree, logPublicKey: log.identity.publicKey,
});

test('the witness says what it last signed for a log, and only to that log\'s own organization', async () => {
  const log = localLog(3);
  const first = await api('GET', `/v1/witness/position/${log.logId}`, { token: acme.token });
  assert.equal(first.status, 404);
  assert.equal(first.json.error.code, 'no_position');

  const res = await witnessLog(log);
  assert.equal(res.from, null, 'a first signing proves nothing about growth');
  const pos = await api('GET', `/v1/witness/position/${log.logId}`, { token: acme.token });
  assert.equal(pos.status, 200);
  assert.deepEqual([pos.json.size, pos.json.root], [3, log.root]);
  assert.equal((await api('GET', `/v1/witness/position/${log.logId}`, { token: globex.token })).status, 404);
  assert.equal((await api('GET', `/v1/witness/position/${log.logId}`)).status, 401);
});

test('growth is proven from what the witness last signed, even when it missed a checkpoint', async () => {
  // Before the position endpoint, the client proved growth from its own
  // previous checkpoint. A witness that had not seen that one got a proof
  // from the wrong size and reported a rewritten history.
  const log = localLog(3);
  await witnessLog(log);            // witnessed at 3
  grow(log, 2);
  log.checkpoint();                 // checkpointed at 5, never shown to the witness
  grow(log, 3);
  const res = await witnessLog(log); // at 8
  assert.equal(res.from, 3);
  const v = verifyCheckpoint({ body: log.checkpoints().at(-1).body, sigs: [...log.checkpoints().at(-1).sigs, res.signature] }, log.keyring, {
    minWitnesses: 1, trustedWitnesses: { [acme.kid]: acme.publicKey },
  });
  assert.ok(v.ok, v.issues.join('; '));
});

test('a history that differs from what the witness signed is caught before anything is sent', async () => {
  const log = localLog(3);
  await witnessLog(log);
  grow(log, 2);
  // The same log, as someone who rewrote its first three entries would present it.
  const rewritten = new MerkleTree([leafHash(Buffer.from('forged')), ...log.tree.leaves.slice(1)]);
  await assert.rejects(
    witnessCheckpoint({ url: base, token: acme.token, checkpoint: log.checkpoint(), tree: rewritten, logPublicKey: log.identity.publicKey }),
    (/** @type {any} */ e) => e.code === 'diverged' && e.alarming === true,
  );
  // And a log shown to the witness at a size smaller than it already signed.
  const small = new MerkleTree(log.tree.leaves.slice(0, 2));
  const cp2 = signCheckpoint(log.identity, { ...log.checkpoint().body, size: 2, root: small.root.toString('hex') });
  await assert.rejects(
    witnessCheckpoint({ url: base, token: acme.token, checkpoint: cp2, tree: small, logPublicKey: log.identity.publicKey }),
    (/** @type {any} */ e) => e.code === 'log_shrank' && e.alarming === true,
  );
});

test('bootstrap refuses on a witness-only node and points at witness-key', () => {
  const res = cli(['bootstrap']);
  assert.equal(res.status, 1);
  assert.match(res.out, /witness-key/);
});

test('witness-key without a name is a usage error, not an organization called ""', () => {
  const res = cli(['witness-key']);
  assert.equal(res.status, 2);
  assert.match(res.out, /usage/);
});

test('a hub without the flag is unaffected', async () => {
  const full = new Hub({ database: ':memory:' });
  try {
    assert.ok(full.router.routes.some((r) => r.method === 'POST' && r.raw === '/v1/logs'));
    assert.ok(full.router.routes.some((r) => r.method === 'GET' && r.raw === '/'));
    assert.notEqual(full.hubSigner.kind, 'disabled');
  } finally {
    await full.close();
  }
});
