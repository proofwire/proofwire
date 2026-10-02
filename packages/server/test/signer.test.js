import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { generateIdentity, verify, verifyCheckpoint } from '@deedwrit/core';
import {
  localSigner,
  commandSigner,
  normalizeSignature,
  selfTest,
  signerFor,
} from '../src/signer.js';
import { Hub } from '../src/app.js';
import { Auth } from '../src/auth.js';
import { openDatabase } from '../src/db.js';
import { Store } from '../src/store.js';

/**
 * The point of these tests is one property: **the hub can sign without ever
 * holding the key.** Everything else here exists to prove that the escape
 * hatches around it fail safely.
 */

/** A stand-in for a KMS CLI: reads a digest on stdin, prints a signature. */
function writeSignerScript(dir, privateKeyPem, opts = {}) {
  fs.mkdirSync(dir, { recursive: true });
  const keyFile = path.join(dir, 'key.pem');
  fs.writeFileSync(keyFile, privateKeyPem);
  const script = path.join(dir, 'sign.mjs');
  fs.writeFileSync(
    script,
    `import fs from 'node:fs';
import { createPrivateKey, sign } from 'node:crypto';
const key = createPrivateKey(fs.readFileSync(${JSON.stringify(keyFile)}, 'utf8'));
const chunks = [];
process.stdin.on('data', (c) => chunks.push(c));
process.stdin.on('end', () => {
  ${opts.exitCode ? `process.stderr.write('kms denied'); process.exit(${opts.exitCode});` : ''}
  const sig = sign(null, Buffer.concat(chunks), key);
  process.stdout.write(sig.toString(${JSON.stringify(opts.encoding ?? 'base64url')}));
});
`,
  );
  return script;
}

test('a local signer signs and verifies', async () => {
  const { privateKeyPem, identity } = generateIdentity();
  const signer = localSigner(privateKeyPem);

  assert.equal(signer.kid, identity.kid);
  assert.equal(signer.kind, 'local');

  const digest = randomBytes(32);
  assert.ok(verify(signer.publicKey, digest, await signer.sign(digest)));
  assert.deepEqual(await selfTest(signer), { ok: true });
});

test('an external command signs without the hub holding the key', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-signer-'));
  const { privateKeyPem, identity } = generateIdentity();
  const script = writeSignerScript(dir, privateKeyPem);

  const signer = commandSigner({
    command: process.execPath,
    args: [script],
    publicKey: identity.publicKey,
  });

  assert.equal(signer.kid, identity.kid, 'the kid is derived from the public key alone');
  assert.equal(signer.kind, 'command');
  // The signer object itself must carry nothing secret.
  assert.ok(!JSON.stringify(signer).includes('PRIVATE'));

  const digest = randomBytes(32);
  assert.ok(verify(signer.publicKey, digest, await signer.sign(digest)));
  assert.deepEqual(await selfTest(signer), { ok: true });
});

test('signatures are accepted in hex, base64 and base64url alike', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-signer-'));
  const { privateKeyPem, identity } = generateIdentity();

  for (const encoding of ['hex', 'base64', 'base64url']) {
    const script = writeSignerScript(path.join(dir, encoding), privateKeyPem, { encoding });
    const signer = commandSigner({
      command: process.execPath,
      args: [script],
      publicKey: identity.publicKey,
    });
    const digest = randomBytes(32);
    assert.ok(
      verify(signer.publicKey, digest, await signer.sign(digest)),
      `a ${encoding} signature was not accepted`,
    );
  }
});

test('a signer that returns junk is rejected rather than stored', () => {
  assert.throws(() => normalizeSignature(''), /empty signature/);
  assert.throws(() => normalizeSignature('not-a-signature'), /Ed25519 signature is 64/);
  // 32 bytes is a plausible-looking mistake: a hash, not a signature.
  assert.throws(() => normalizeSignature(randomBytes(32).toString('base64url')), /32 bytes/);
  // 64 bytes in any encoding is fine.
  assert.equal(normalizeSignature(randomBytes(64).toString('hex')).length, 86);
});

test('a failing external signer surfaces the error, and never a forged signature', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-signer-'));
  const { privateKeyPem, identity } = generateIdentity();
  const script = writeSignerScript(dir, privateKeyPem, { exitCode: 3 });

  const signer = commandSigner({
    command: process.execPath,
    args: [script],
    publicKey: identity.publicKey,
  });
  await assert.rejects(() => signer.sign(randomBytes(32)), /exited 3/);

  const res = await selfTest(signer);
  assert.equal(res.ok, false);
  assert.match(res.error, /exited 3/);
});

test('a signer that does not exist fails at self-test, not at the first checkpoint', async () => {
  const signer = commandSigner({
    command: path.join(os.tmpdir(), 'definitely-not-a-real-binary-xyz'),
    publicKey: generateIdentity().identity.publicKey,
  });
  const res = await selfTest(signer);
  assert.equal(res.ok, false);
});

test('a signer wired to the wrong key is caught by the self-test', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-signer-'));
  const script = writeSignerScript(dir, generateIdentity().privateKeyPem);

  // The command signs with key A; the config claims key B.
  const signer = commandSigner({
    command: process.execPath,
    args: [script],
    publicKey: generateIdentity().identity.publicKey,
  });

  const res = await selfTest(signer);
  assert.equal(res.ok, false);
  assert.match(res.error, /does not verify against its configured public key/);
});

test('a misconfigured backend disables signing rather than falling back to a local key', async () => {
  const db = openDatabase(':memory:');
  const store = new Store(db);

  const signer = signerFor(store, 'hub', { DEEDWRIT_SIGNER: 'command' });
  assert.equal(signer.kind, 'disabled');
  await assert.rejects(() => signer.sign(randomBytes(32)), /signing is disabled/);

  // Crucially, it did NOT quietly mint a local key to carry on with.
  assert.equal(store.holdsPrivateKeys(), false);
  assert.equal(signerFor(store, 'hub', { DEEDWRIT_SIGNER: 'nonsense' }).kind, 'disabled');
});

test('an external signer records the public key and stores no private half', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-signer-'));
  const { privateKeyPem, identity } = generateIdentity();
  const script = writeSignerScript(dir, privateKeyPem);

  const db = openDatabase(':memory:');
  const store = new Store(db);
  const signer = signerFor(store, 'hub', {
    DEEDWRIT_SIGNER: 'command',
    DEEDWRIT_SIGNER_COMMAND: process.execPath,
    DEEDWRIT_SIGNER_ARGS: script,
    DEEDWRIT_PUBLIC_KEY: identity.publicKey,
  });

  assert.equal(signer.kind, 'command');
  assert.ok(await selfTest(signer).then((r) => r.ok));

  const rows = store.serverKeys();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].public_key, identity.publicKey);
  assert.equal(rows[0].private_pem, null, 'the hub must not hold the private half');
  assert.equal(rows[0].backend, 'external');
  assert.equal(store.holdsPrivateKeys(), false);
});

test('a hub signs checkpoints through an external signer, end to end', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-signer-'));
  const hubKey = generateIdentity();
  const witnessKey = generateIdentity();
  const hubScript = writeSignerScript(path.join(dir, 'hub'), hubKey.privateKeyPem);
  const witScript = writeSignerScript(path.join(dir, 'wit'), witnessKey.privateKeyPem);

  const hub = new Hub({
    database: ':memory:',
    checkpointEvery: 0,
    apiRate: { capacity: 1e6, refillPerSec: 1e6 },
    ingestRate: { capacity: 1e6, refillPerSec: 1e6 },
    env: {
      DEEDWRIT_HUB_SIGNER: 'command',
      DEEDWRIT_HUB_SIGNER_COMMAND: process.execPath,
      DEEDWRIT_HUB_SIGNER_ARGS: hubScript,
      DEEDWRIT_HUB_PUBLIC_KEY: hubKey.identity.publicKey,
      DEEDWRIT_WITNESS_SIGNER: 'command',
      DEEDWRIT_WITNESS_SIGNER_COMMAND: process.execPath,
      DEEDWRIT_WITNESS_SIGNER_ARGS: witScript,
      DEEDWRIT_WITNESS_PUBLIC_KEY: witnessKey.identity.publicKey,
    },
  });

  assert.equal(hub.hubSigner.kind, 'command');
  assert.equal(hub.hubSigner.kid, hubKey.identity.kid);
  assert.equal(
    hub.store.holdsPrivateKeys(),
    false,
    'a hub configured with external signers must hold no key material',
  );

  const { url } = await hub.listen(0);
  const base = url.replace('0.0.0.0', '127.0.0.1');

  const auth = new Auth(hub.store);
  const org = hub.store.createOrg({ slug: 'kms', name: 'KMS' });
  const token = auth.createKey({
    orgId: org.id,
    name: 'agent',
    scopes: ['receipts:write', 'receipts:read', 'logs:write', 'logs:read', 'witness:sign'],
  }).token;
  const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };

  // Push a few receipts from a local agent.
  const { ProofLog } = await import('@deedwrit/core');
  const { RemoteSink } = await import('@deedwrit/proxy/remote');
  const logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-kms-log-'));
  const localLog = ProofLog.create(logDir);
  for (let i = 0; i < 4; i++) {
    localLog.append({
      actor: { agent: 'a', runtime: 'r', session: 's', principal: 'p' },
      action: { kind: 'tool_call', target: 'ops.q', params: { i } },
      decision: { outcome: 'allow', policy: 'p', rules: [] },
    });
  }
  const sink = new RemoteSink({ url: base, token, log: 'kms-log', localLog });
  assert.ok(await sink.connect());
  await sink.flush();

  // Checkpoint: signed by a key this process has never seen.
  const cp = await (await fetch(`${base}/v1/logs/kms-log/checkpoint`, { method: 'POST', headers })).json();
  assert.equal(cp.sigs[0].kid, hubKey.identity.kid);

  const keyring = Object.fromEntries(hub.store.serverKeys().map((k) => [k.kid, k.public_key]));
  assert.ok(verifyCheckpoint(cp, keyring).ok, 'an externally signed checkpoint must verify');

  // And the witness, also external.
  const signed = await (await fetch(`${base}/v1/witness/cosign`, {
    method: 'POST', headers, body: JSON.stringify({ checkpoint: cp, logPublicKey: hubKey.identity.publicKey }),
  })).json();
  assert.equal(signed.witness.kid, witnessKey.identity.kid);
  assert.equal(signed.logKey.kid, hubKey.identity.kid, 'the log is bound to the external hub key');
  const { checkpointDigest } = await import('@deedwrit/core');
  assert.ok(
    verify(witnessKey.identity.publicKey, checkpointDigest(cp.body), signed.signature.sig),
    'the witness countersignature must verify over the checkpoint body',
  );

  // The bundle an auditor gets must carry those public keys.
  const bundle = await (await fetch(`${base}/v1/logs/kms-log/bundle`, { headers })).json();
  assert.ok(bundle.keyring[hubKey.identity.kid], 'the external hub key must travel with the bundle');

  const { verifyBundle } = await import('@deedwrit/core');
  const res = verifyBundle(bundle);
  assert.ok(res.ok, JSON.stringify(res.issues));

  await hub.close();
});

test('a disabled signer stops checkpoints but never stops ingest', async () => {
  const hub = new Hub({
    database: ':memory:',
    checkpointEvery: 0,
    apiRate: { capacity: 1e6, refillPerSec: 1e6 },
    ingestRate: { capacity: 1e6, refillPerSec: 1e6 },
    // No command configured, so both signers disable themselves.
    env: { DEEDWRIT_SIGNER: 'command' },
  });
  assert.equal(hub.hubSigner.kind, 'disabled');

  const { url } = await hub.listen(0);
  const base = url.replace('0.0.0.0', '127.0.0.1');
  const auth = new Auth(hub.store);
  const org = hub.store.createOrg({ slug: 'nokey', name: 'NoKey' });
  const token = auth.createKey({
    orgId: org.id,
    name: 'agent',
    scopes: ['receipts:write', 'logs:write', 'logs:read'],
  }).token;
  const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };

  const { ProofLog } = await import('@deedwrit/core');
  const { RemoteSink } = await import('@deedwrit/proxy/remote');
  const logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-nokey-'));
  const localLog = ProofLog.create(logDir);
  localLog.append({
    actor: { agent: 'a', runtime: 'r', session: 's', principal: 'p' },
    action: { kind: 'tool_call', target: 'ops.q', params: {} },
    decision: { outcome: 'allow', policy: 'p', rules: [] },
  });

  const sink = new RemoteSink({ url: base, token, log: 'nokey-log', localLog });
  assert.ok(await sink.connect());
  assert.equal(await sink.flush(), 1, 'ingest must keep working without a usable signer');

  // The checkpoint fails, loudly, and does not take anything else down.
  const res = await fetch(`${base}/v1/logs/nokey-log/checkpoint`, { method: 'POST', headers });
  assert.equal(res.status, 500);

  await hub.close();
});

test('rotating a key retires the old one but keeps it verifiable', () => {
  const db = openDatabase(':memory:');
  const store = new Store(db);

  const first = generateIdentity().identity;
  store.recordServerKey({ kid: first.kid, role: 'hub', publicKey: first.publicKey, privatePem: null });
  assert.equal(store.activeServerKey('hub').kid, first.kid);

  const second = generateIdentity().identity;
  store.recordServerKey({ kid: second.kid, role: 'hub', publicKey: second.publicKey, privatePem: null });

  assert.equal(store.activeServerKey('hub').kid, second.kid, 'the new key is current');

  const all = store.serverKeys();
  assert.equal(all.length, 2, 'the old key is kept, not deleted');
  assert.ok(all.find((k) => k.kid === first.kid).retired_at, 'the old key is marked retired');

  // A checkpoint signed by the retired key must still be verifiable, or
  // rotating would silently invalidate history.
  const org = store.createOrg({ slug: 'o', name: 'o' });
  assert.equal(store.publicKeyFor(org.id, first.kid), first.publicKey);
});
