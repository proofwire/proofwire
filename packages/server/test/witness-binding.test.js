import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ProofLog, generateIdentity, signCheckpoint } from '@deedwrit/core';
import { Hub } from '../src/app.js';

/**
 * A witness binds each log to the key that signs its first checkpoint, and
 * holds every later checkpoint to that key. Rebinding after a rotation is an
 * operator action on the host, and never resets what the witness has already
 * attested to.
 *
 * Driven against a real socket, with keys minted and logs rebound by the real
 * CLI, in a separate process, while the server is running — as an operator
 * would.
 */

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/bin.js');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-witness-binding-'));
const database = path.join(dir, 'witness.db');

/** @type {Hub} */
let hub;
let base = '';
let token = '';
let orgId = '';

/** @param {string[]} args */
function cli(args) {
  const res = spawnSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    env: {
      ...process.env,
      DEEDWRIT_DB: database,
      DEEDWRIT_WITNESS_ONLY: '1',
      NODE_OPTIONS: '--no-warnings=ExperimentalWarning',
    },
  });
  return { status: res.status, out: (res.stdout + res.stderr).replace(/\x1b\[[0-9;]*m/g, '') };
}

before(async () => {
  const minted = cli(['witness-key', 'Acme']);
  assert.equal(minted.status, 0, minted.out);
  token = minted.out.match(/^\s*token\s+(pwk_\S+)/m)[1];

  hub = new Hub({
    database,
    witnessOnly: true,
    apiRate: { capacity: 100000, refillPerSec: 100000 },
  });
  const { url } = await hub.listen(0);
  base = url.replace('0.0.0.0', '127.0.0.1');
  orgId = hub.store.orgBySlug('acme').id;
});

after(async () => {
  await hub?.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

/** @param {object} body */
async function cosign(body) {
  const res = await fetch(`${base}/v1/witness/cosign`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: await res.json() };
}

const witnessKid = () => hub.witnessSigner.kid;
const bindingOf = (log) => hub.store.witnessBinding(witnessKid(), `${orgId}:${log}`);
const positionOf = (log) => hub.store.witnessPosition(witnessKid(), `${orgId}:${log}`);

/** A checkpoint body for `log`, signed by `identity`. */
function signed(identity, log, size, root) {
  return signCheckpoint(identity, {
    v: 1, log, size, root, head: 'ab'.repeat(32), ts: new Date().toISOString(),
  });
}

test('a first checkpoint that names no key is refused, and records nothing', async () => {
  const k = generateIdentity().identity;
  const res = await cosign({ checkpoint: signed(k, 'unnamed', 1, '11'.repeat(32)) });
  assert.equal(res.status, 400);
  assert.equal(res.json.error.code, 'missing_log_key');
  assert.equal(bindingOf('unnamed'), null);
  assert.equal(positionOf('unnamed'), null);
});

test('a first checkpoint not signed by the key it names binds nothing', async () => {
  const named = generateIdentity().identity;
  const actual = generateIdentity().identity;
  const res = await cosign({
    checkpoint: signed(actual, 'misnamed', 1, '11'.repeat(32)),
    logPublicKey: named.publicKey,
  });
  assert.equal(res.status, 422);
  assert.equal(res.json.error.code, 'bad_log_signature');
  // Above all, the named key must not have been bound on the strength of a
  // signature it never made.
  assert.equal(bindingOf('misnamed'), null);
  assert.equal(positionOf('misnamed'), null);

  // The log's real key can still claim it afterwards.
  const ok = await cosign({ checkpoint: signed(actual, 'misnamed', 1, '11'.repeat(32)), logPublicKey: actual.publicKey });
  assert.equal(ok.status, 200, JSON.stringify(ok.json));
  assert.equal(bindingOf('misnamed').kid, actual.kid);
});

test('a malformed log key is a 400, not a crash', async () => {
  const k = generateIdentity().identity;
  for (const bad of ['', 'not-base64!', k.publicKey + '=', k.publicKey.slice(0, -1), 'QQ']) {
    const res = await cosign({ checkpoint: signed(k, 'malformed', 1, '11'.repeat(32)), logPublicKey: bad });
    assert.equal(res.status, 400, `logPublicKey ${JSON.stringify(bad)} → ${res.status}`);
    assert.equal(res.json.error.code, 'bad_log_key');
  }
});

test('first use binds; after that the key need not be sent, and no other key is accepted', async () => {
  const k = generateIdentity().identity;
  const first = await cosign({ checkpoint: signed(k, 'bound', 1, '11'.repeat(32)), logPublicKey: k.publicKey });
  assert.equal(first.status, 200, JSON.stringify(first.json));
  assert.equal(first.json.logKey.kid, k.kid);
  assert.equal(first.json.logKey.newlyBound, true);
  assert.equal(first.json.logKey.boundBy, 'first-use');

  // Re-offering the same root at the same size is idempotent, and the bound key
  // is used without being named again.
  const again = await cosign({ checkpoint: signed(k, 'bound', 1, '11'.repeat(32)) });
  assert.equal(again.status, 200, JSON.stringify(again.json));
  assert.equal(again.json.logKey.newlyBound, false);

  // Another key, with a perfectly good signature of its own, gets nowhere —
  // not even to the split-view check.
  const other = generateIdentity().identity;
  const hijack = await cosign({ checkpoint: signed(other, 'bound', 1, '22'.repeat(32)), logPublicKey: other.publicKey });
  assert.equal(hijack.status, 409);
  assert.equal(hijack.json.error.code, 'log_key_mismatch');
  assert.equal(hijack.json.error.detail.bound, k.kid);

  // Without naming itself, the other key's checkpoint is simply unsigned as
  // far as this log is concerned.
  const quiet = await cosign({ checkpoint: signed(other, 'bound', 1, '22'.repeat(32)) });
  assert.equal(quiet.status, 422);
  assert.equal(quiet.json.error.code, 'bad_log_signature');

  assert.equal(positionOf('bound').root, '11'.repeat(32), 'a refused request moved the recorded position');
  assert.equal(bindingOf('bound').kid, k.kid);
});

test('the signature has to be the log\'s, over this body', async () => {
  const k = generateIdentity().identity;
  await cosign({ checkpoint: signed(k, 'strict', 1, '11'.repeat(32)), logPublicKey: k.publicKey });

  const good = signed(k, 'strict', 1, '11'.repeat(32));
  const cases = {
    'no signatures at all': { body: good.body, sigs: [] },
    'sigs is not an array': { body: good.body, sigs: 'nope' },
    'the right key, labelled as a witness': { body: good.body, sigs: [{ ...good.sigs[0], role: 'witness' }] },
    'a signature over a different body': { body: { ...good.body, head: 'cd'.repeat(32) }, sigs: good.sigs },
    'a garbled signature': { body: good.body, sigs: [{ ...good.sigs[0], sig: good.sigs[0].sig.slice(0, -4) + 'AAAA' }] },
    'a signature that is not a string': { body: good.body, sigs: [{ ...good.sigs[0], sig: 42 }] },
  };
  for (const [label, checkpoint] of Object.entries(cases)) {
    const res = await cosign({ checkpoint });
    assert.equal(res.status, 422, `${label} → ${res.status} ${JSON.stringify(res.json)}`);
    assert.equal(res.json.error.code, 'bad_log_signature', label);
  }
});

test('two first requests naming different keys: exactly one binds', async () => {
  const a = generateIdentity().identity;
  const b = generateIdentity().identity;
  const results = await Promise.all([
    cosign({ checkpoint: signed(a, 'race', 1, '11'.repeat(32)), logPublicKey: a.publicKey }),
    cosign({ checkpoint: signed(b, 'race', 1, '22'.repeat(32)), logPublicKey: b.publicKey }),
  ]);
  assert.deepEqual(results.map((r) => r.status).sort(), [200, 409]);
  const winner = results.find((r) => r.status === 200).json.logKey.kid;
  assert.equal(bindingOf('race').kid, winner);
  assert.equal(results.find((r) => r.status === 409).json.error.code, 'log_key_mismatch');
});

test('a position recorded before bindings existed is bound on its next successful co-signing', async () => {
  // As an upgraded witness would have it: a position, no binding.
  hub.db
    .prepare('INSERT INTO witness_state(witness_kid, log_id, size, root, updated_at) VALUES(?, ?, ?, ?, ?)')
    .run(witnessKid(), `${orgId}:legacy`, 2, '11'.repeat(32), new Date().toISOString());

  const k = generateIdentity().identity;
  // It still has to name a key...
  const unnamed = await cosign({ checkpoint: signed(k, 'legacy', 2, '11'.repeat(32)) });
  assert.equal(unnamed.status, 400);
  assert.equal(unnamed.json.error.code, 'missing_log_key');

  // ...and the old position still rules: a different root at size 2 is a
  // split view, and a refused request binds nothing.
  const forked = await cosign({ checkpoint: signed(k, 'legacy', 2, '22'.repeat(32)), logPublicKey: k.publicKey });
  assert.equal(forked.status, 409);
  assert.equal(forked.json.error.code, 'split_view');
  assert.equal(bindingOf('legacy'), null);

  const ok = await cosign({ checkpoint: signed(k, 'legacy', 2, '11'.repeat(32)), logPublicKey: k.publicKey });
  assert.equal(ok.status, 200, JSON.stringify(ok.json));
  assert.equal(ok.json.logKey.newlyBound, true);
  assert.equal(bindingOf('legacy').kid, k.kid);
});

test('a rotation is rebound on the host, and the new key must extend what was attested', async () => {
  // A real log, so growth can be proven with a real consistency proof.
  const log = ProofLog.create(path.join(dir, 'rotating'));
  const append = (n) => {
    for (let i = 0; i < n; i++) {
      log.append({
        actor: { agent: 'a', runtime: 'r', session: 's', principal: 'p' },
        action: { kind: 'tool_call', target: 't', params: { n: log.size } },
        decision: { outcome: 'allow', policy: 'p0', rules: [] },
      });
    }
  };
  const name = log.logId;
  const oldKey = log.identity;
  const newKey = generateIdentity().identity;

  append(3);
  const first = log.checkpoint();
  const bound = await cosign({ checkpoint: first, logPublicKey: oldKey.publicKey });
  assert.equal(bound.status, 200, JSON.stringify(bound.json));

  // The log's key is rotated. Its next checkpoint is signed by the new key.
  append(2);
  const body5 = log.checkpoint().body;
  const proof = log.tree.consistencyProof(3, 5).map((b) => b.toString('hex'));
  const rotated = signCheckpoint(newKey, body5);

  const refused = await cosign({ checkpoint: rotated, consistencyProof: proof, logPublicKey: newKey.publicKey });
  assert.equal(refused.status, 409, 'a new key must not be able to rebind itself over HTTP');
  assert.equal(refused.json.error.code, 'log_key_mismatch');

  // The operator rebinds on the host, with the server running.
  const rebind = cli(['witness-rebind', 'acme', name, newKey.publicKey]);
  assert.equal(rebind.status, 0, rebind.out);
  assert.match(rebind.out, new RegExp(`from\\s+${oldKey.kid}`));
  assert.match(rebind.out, new RegExp(`to\\s+${newKey.kid}`));
  assert.match(rebind.out, /size 3.*kept/);
  assert.equal(bindingOf(name).bound_by, 'operator');

  // Straight after a rebind is when a reset would bite: before anything
  // honest re-anchors the position, the new key tries to substitute a
  // different history. The recorded position must still be the old one.
  assert.deepEqual(
    { size: positionOf(name).size, root: positionOf(name).root },
    { size: 3, root: first.body.root },
    'the rebind changed what the witness remembers',
  );
  const substitute = await cosign({ checkpoint: signCheckpoint(newKey, { ...first.body, root: 'ee'.repeat(32) }) });
  assert.equal(substitute.status, 409);
  assert.equal(substitute.json.error.code, 'split_view');
  const unproven = await cosign({ checkpoint: rotated });
  assert.equal(unproven.status, 400, 'growth after a rebind was accepted without a consistency proof');
  assert.equal(unproven.json.error.code, 'missing_consistency_proof');

  // The new key now co-signs growth — with a proof, like anything else.
  const grown = await cosign({ checkpoint: rotated, consistencyProof: proof });
  assert.equal(grown.status, 200, JSON.stringify(grown.json));
  assert.equal(grown.json.logKey.kid, newKey.kid);

  // The old key is now the one refused.
  const stale = await cosign({ checkpoint: signCheckpoint(oldKey, body5), logPublicKey: oldKey.publicKey });
  assert.equal(stale.status, 409);
  assert.equal(stale.json.error.code, 'log_key_mismatch');

  // And the rebind reset nothing: the new key cannot rewrite what the witness
  // already attested to, at the same size or by shrinking.
  const fork = await cosign({ checkpoint: signCheckpoint(newKey, { ...body5, root: 'cd'.repeat(32) }) });
  assert.equal(fork.status, 409);
  assert.equal(fork.json.error.code, 'split_view');
  const shrink = await cosign({ checkpoint: signCheckpoint(newKey, first.body) });
  assert.equal(shrink.status, 409);
  assert.equal(shrink.json.error.code, 'log_shrank');

  // The rebind is in the control-plane audit trail, which still verifies.
  const event = hub.store.events(orgId).find((e) => e.action === 'witness.rebind' && e.subject === name);
  assert.ok(event, 'no witness.rebind event was recorded');
  assert.deepEqual(
    { from: JSON.parse(event.meta).from, to: JSON.parse(event.meta).to },
    { from: oldKey.kid, to: newKey.kid },
  );
  assert.ok(hub.store.auditEvents(orgId).ok, 'the control-plane audit chain no longer verifies');

  // Rebinding to the key already bound changes nothing.
  const same = cli(['witness-rebind', 'acme', name, newKey.publicKey]);
  assert.equal(same.status, 0, same.out);
  assert.match(same.out, /already bound/);
});

test('witness-rebind refuses what it cannot or should not do', () => {
  const k = generateIdentity().identity;
  const cases = [
    [[], 2, /usage/],
    [['acme', 'bound'], 2, /usage/],
    [['acme', 'bound', 'not-a-key'], 2, /not a raw 32-byte/],
    [['nobody', 'bound', k.publicKey], 1, /no customer "nobody"/],
    [['acme', 'never-seen', k.publicKey], 1, /never co-signed for never-seen/],
  ];
  for (const [args, status, pattern] of cases) {
    const res = cli(['witness-rebind', ...args]);
    assert.equal(res.status, status, `witness-rebind ${args.join(' ')}: ${res.out}`);
    assert.match(res.out, pattern);
  }
});
