import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ProofLog, verifyBundle } from '@deedwrit/core';
import { Hub } from '../../server/src/app.js';
import { Auth } from '../../server/src/auth.js';

/**
 * Two independent witnesses, and a local log that has both sign its
 * checkpoints: by hand with `dw cosign`, and on its own when a `dw proxy`
 * session ends.
 */

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, '../src/bin.js');
const SERVER = path.resolve(HERE, '../../../examples/fake-mcp-server.js');

/** @type {{ hub: Hub, url: string, token: string, kid: string, publicKey: string }[]} */
const witnesses = [];

before(async () => {
  for (const name of ['one', 'two']) {
    const hub = new Hub({
      database: ':memory:',
      witnessOnly: true,
      apiRate: { capacity: 1e5, refillPerSec: 1e5 },
      authRate: { capacity: 1e5, refillPerSec: 1e5 },
    });
    const { url } = await hub.listen(0);
    const org = hub.store.createOrg({ slug: 'acme', name: 'Acme' });
    const { token } = new Auth(hub.store).createKey({ orgId: org.id, name: `witness ${name}`, scopes: ['witness:sign'] });
    witnesses.push({ hub, url: url.replace('0.0.0.0', '127.0.0.1'), token, kid: hub.witnessSigner.kid, publicKey: hub.witnessSigner.publicKey });
  }
});

after(async () => {
  for (const w of witnesses) await w.hub.close();
});

/**
 * Run the CLI without blocking: the witnesses live in this process, and a
 * synchronous spawn would stop them answering it.
 *
 * @param {string} cwd @param {string[]} args @param {string} [input]
 * @returns {Promise<{ code: number | null, out: string, stdout: string, stderr: string }>}
 */
function pw(cwd, args, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN, ...args], {
      cwd,
      env: { ...process.env, HOME: cwd, USERPROFILE: cwd, NO_COLOR: '1' },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, out: stdout + stderr, stdout, stderr }));
    child.stdin.end(input ?? '');
  });
}

/** A project with a log, and both witnesses added as remotes. */
async function project() {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'deedwrit-witness-cli-'));
  assert.equal((await pw(cwd, ['init'])).code, 0);
  for (const [i, name] of ['w1', 'w2'].entries()) {
    const added = await pw(cwd, ['remote', 'add', '--name', name, '--url', witnesses[i].url, '--token', witnesses[i].token]);
    assert.equal(added.code, 0, added.out);
  }
  return cwd;
}

const pinned = () => Object.fromEntries(witnesses.map((w) => [w.kid, w.publicKey]));

test('dw cosign --remote a,b has every named witness sign, and keeps each signature', async () => {
  const cwd = await project();
  const log = ProofLog.open(path.join(cwd, '.deedwrit'));
  log.append({
    actor: { agent: 'a', runtime: 'r', session: 's', principal: 'p@acme.test' },
    action: { kind: 'tool_call', target: 'crm.lookup', params: {} },
    decision: { outcome: 'allow', policy: 'p', rules: [] },
  });

  const res = await pw(cwd, ['cosign', '--remote', 'w1,w2']);
  assert.equal(res.code, 0, res.out);
  assert.match(res.out, /Checkpoint witnessed · w1/);
  assert.match(res.out, /Checkpoint witnessed · w2/);

  const bundle = ProofLog.open(path.join(cwd, '.deedwrit'), { readOnly: true }).bundle();
  const v = verifyBundle(bundle, { minWitnesses: 2, trustedWitnesses: pinned() });
  assert.ok(v.ok, v.issues.join('\n'));
});

test('a dw proxy session ends witnessed by every witness in the config, reported on stderr only', async () => {
  const cwd = await project();
  const configFile = path.join(cwd, 'deedwrit.config.json');
  const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
  fs.writeFileSync(configFile, JSON.stringify({ ...config, witnesses: ['w1', 'w2'] }, null, 2));

  const call = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'lookup', arguments: { id: 1 } } });
  const res = await pw(cwd, ['proxy', '--', process.execPath, SERVER], call + '\n');
  assert.equal(res.code, 0, res.out);
  assert.match(res.stderr, /witnessed by w1/);
  assert.match(res.stderr, /witnessed by w2/);
  assert.doesNotMatch(res.stdout, /witness/, 'stdout is the MCP channel and must carry nothing else');

  const bundle = ProofLog.open(path.join(cwd, '.deedwrit'), { readOnly: true }).bundle();
  const v = verifyBundle(bundle, { minWitnesses: 2, trustedWitnesses: pinned() });
  assert.ok(v.ok, v.issues.join('\n'));
  assert.equal(v.witnessedSize, bundle.treeSize, 'the whole session is witnessed');

  // A second session extends it, and both witnesses accept the growth.
  const again = await pw(cwd, ['proxy', '--', process.execPath, SERVER], call + '\n');
  assert.equal(again.code, 0, again.out);
  assert.match(again.stderr, /witnessed by w1/);
  assert.match(again.stderr, /witnessed by w2/);
});

test('a witness that is down costs a warning, never the session', async () => {
  const cwd = await project();
  const configFile = path.join(cwd, 'deedwrit.config.json');
  const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
  fs.writeFileSync(configFile, JSON.stringify({ ...config, witnesses: ['w1', 'nowhere'] }, null, 2));
  const call = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'lookup', arguments: {} } });
  const res = await pw(cwd, ['proxy', '--', process.execPath, SERVER], call + '\n');
  assert.equal(res.code, 0, res.out);
  assert.match(res.stderr, /witnessed by w1/);
  assert.match(res.stderr, /witness "nowhere" is not a configured remote/);
});
