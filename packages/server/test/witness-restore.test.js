import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ProofLog, signCheckpoint, MerkleTree, leafHash } from '@proof_wire/core';
import { Hub } from '../src/app.js';
import { Auth } from '../src/auth.js';
import { backup, restore } from '../src/backup.js';

/**
 * A witness restored from a backup must not forget what it signed.
 *
 * Each test: a witness signs a log at 5, is backed up, signs at 10, and is
 * restored to the backup. A fork that branches off the log at 5 is then
 * offered. A witness that forgot size 10 would sign it: a split view.
 */

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/bin.js');
const fast = { capacity: 1e5, refillPerSec: 1e5 };

/** A witness on a file database in a fresh directory, with one customer. */
async function setup(opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-witness-restore-'));
  const database = path.join(dir, 'witness.db');
  const start = async () => {
    const hub = new Hub({ database, witnessOnly: true, apiRate: fast, authRate: fast, ...opts });
    const url = (await hub.listen(0)).url.replace('0.0.0.0', '127.0.0.1');
    return { hub, url };
  };
  let { hub, url } = await start();
  const org = hub.store.createOrg({ slug: 'acme', name: 'Acme' });
  const token = new Auth(hub.store).createKey({ orgId: org.id, name: 'acme', scopes: ['witness:sign'] }).token;
  const log = ProofLog.create(path.join(dir, 'agent-log'));
  const grow = (/** @type {number} */ n) => {
    for (let i = 0; i < n; i++) {
      log.append({
        actor: { agent: 'bot', runtime: 'test', session: 's', principal: 'p@acme.test' },
        action: { kind: 'tool_call', target: 'ops.refund', params: { n: log.size } },
        decision: { outcome: 'allow', policy: 'p', rules: [] },
      });
    }
  };
  const t = {
    dir, database, org, token, log, grow,
    get hub() { return hub; },
    get url() { return url; },
    async restart() {
      await hub.close();
      ({ hub, url } = await start());
    },
    /** @param {any} checkpoint @param {Buffer[]} [proof] */
    async cosign(checkpoint, proof) {
      const res = await fetch(`${url}/v1/witness/cosign`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ checkpoint, consistencyProof: proof?.map((b) => b.toString('hex')), logPublicKey: log.identity.publicKey }),
      });
      return { status: res.status, json: await res.json() };
    },
    /** A history that agrees with the log up to `at`, then diverges, `size` long. */
    fork(at, size) {
      const leaves = log.tree.leaves.slice(0, at);
      while (leaves.length < size) leaves.push(leafHash(Buffer.from(`forged ${leaves.length}`)));
      const tree = new MerkleTree(leaves);
      const cp = signCheckpoint(log.identity, { ...log.checkpoint().body, size, root: tree.root.toString('hex') });
      return { cp, proofFrom: (/** @type {number} */ from) => tree.consistencyProof(from, size) };
    },
    async done() {
      await hub.close();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
  return t;
}

/** Sign at 5, back up, sign at 10. @returns {Promise<{ snapshot: string, signedAt10: any }>} */
async function history(/** @type {any} */ t) {
  t.grow(5);
  const at5 = t.log.checkpoint();
  assert.equal((await t.cosign(at5)).status, 200);
  const snapshot = path.join(t.dir, 'backup.db');
  backup({ database: t.database, out: snapshot });
  t.grow(5);
  const at10 = t.log.checkpoint();
  const r = await t.cosign(at10, t.log.tree.consistencyProof(5, 10));
  assert.equal(r.status, 200, JSON.stringify(r.json));
  return { snapshot, signedAt10: { body: at10.body, sigs: [...at10.sigs, r.json.signature] } };
}

/** Restore the snapshot over the live database, as `proofwire-hub restore` does. */
async function restoreTo(/** @type {any} */ t, /** @type {string} */ snapshot, /** @type {string|null} */ journal) {
  await t.hub.close();
  const res = restore({ from: snapshot, database: t.database, journal });
  return res;
}

test('without the journal, a restored witness would sign a fork: the attack this prevents', async () => {
  const t = await setup({ witnessJournal: false });
  try {
    const { snapshot } = await history(t);
    await restoreTo(t, snapshot, null);
    // Released by hand without evidence, the witness is back at 5 and signs
    // a fork of the history it already vouched for at 10.
    await t.restart();
    t.hub.store.releaseWitnessLog(t.hub.witnessSigner.kid, `${t.org.id}:${t.log.checkpoint().body.log}`);
    const fork = t.fork(5, 12);
    assert.equal((await t.cosign(fork.cp, fork.proofFrom(5))).status, 200);
  } finally {
    await t.done();
  }
});

test('with the journal, a restored witness catches up on start and refuses the fork', async () => {
  const t = await setup();
  try {
    const { snapshot } = await history(t);
    const journal = `${t.database}.witness-journal`;
    assert.ok(fs.existsSync(journal));
    const res = await restoreTo(t, snapshot, journal);
    assert.equal(res.witnessLogsHeld, 0);
    await t.restart();

    const logName = t.log.checkpoint().body.log;
    const pos = await (await fetch(`${t.url}/v1/witness/position/${logName}`, { headers: { authorization: `Bearer ${t.token}` } })).json();
    assert.equal(pos.size, 10, 'caught up from the journal');
    assert.equal(pos.held, undefined);

    const fork = t.fork(5, 12);
    const refused = await t.cosign(fork.cp, fork.proofFrom(5));
    assert.equal(refused.status, 409);
    assert.equal(refused.json.error.code, 'not_an_extension');
    assert.equal((await t.cosign(t.fork(5, 8).cp)).json.error.code, 'log_shrank');

    // The real log carries on.
    t.grow(2);
    const ok = await t.cosign(t.log.checkpoint(), t.log.tree.consistencyProof(10, 12));
    assert.equal(ok.status, 200, JSON.stringify(ok.json));

    const events = t.hub.store.events(t.org.id).map((e) => e.action);
    assert.ok(events.includes('hub.restore') && events.includes('witness.caught_up'), events.join());
  } finally {
    await t.done();
  }
});

test('a backup copied into place by hand is caught, too', async () => {
  const t = await setup();
  try {
    const { snapshot } = await history(t);
    await t.hub.close();
    for (const sfx of ['', '-wal', '-shm']) fs.rmSync(t.database + sfx, { force: true });
    fs.copyFileSync(snapshot, t.database);
    await t.restart();
    const fork = t.fork(5, 12);
    assert.equal((await t.cosign(fork.cp, fork.proofFrom(5))).json.error.code, 'not_an_extension');
  } finally {
    await t.done();
  }
});

test('restored without the journal, every log is held until the operator releases it with evidence', async () => {
  const t = await setup();
  try {
    const { snapshot, signedAt10 } = await history(t);
    const journal = `${t.database}.witness-journal`;
    fs.rmSync(journal); // lost with the disk
    const res = await restoreTo(t, snapshot, journal);
    assert.equal(res.witnessLogsHeld, 1);
    await t.restart();

    const fork = t.fork(5, 12);
    const held = await t.cosign(fork.cp, fork.proofFrom(5));
    assert.equal(held.status, 409);
    assert.equal(held.json.error.code, 'witness_restored');
    // The honest log is held too; nobody is signed for until released.
    assert.equal((await t.cosign(t.log.checkpoint(), t.log.tree.consistencyProof(5, 10))).json.error.code, 'witness_restored');
    const logName = t.log.checkpoint().body.log;
    const pos = await (await fetch(`${t.url}/v1/witness/position/${logName}`, { headers: { authorization: `Bearer ${t.token}` } })).json();
    assert.equal(pos.held.reason, 'restored_without_journal');

    // The operator gets the customer's latest witnessed checkpoint, which
    // carries this witness's own signature at 10, and releases with it.
    await t.hub.close();
    const evidence = path.join(t.dir, 'checkpoint.json');
    fs.writeFileSync(evidence, JSON.stringify(signedAt10));
    const env = { ...process.env, PROOFWIRE_DB: t.database, PROOFWIRE_WITNESS_ONLY: '1', NODE_OPTIONS: '--no-warnings=ExperimentalWarning' };
    const forged = path.join(t.dir, 'forged.json');
    fs.writeFileSync(forged, JSON.stringify({ ...signedAt10, body: { ...signedAt10.body, size: 11 } }));
    const bad = spawnSync(process.execPath, [BIN, 'witness-release', 'acme', logName, '--checkpoint', forged], { env, encoding: 'utf8' });
    assert.equal(bad.status, 1, 'a checkpoint whose witness signature does not verify is not evidence');
    const rel = spawnSync(process.execPath, [BIN, 'witness-release', 'acme', logName, '--checkpoint', evidence], { env, encoding: 'utf8' });
    assert.equal(rel.status, 0, rel.stderr);
    assert.match(rel.stderr, /co-signing again from size 10/);
    await t.restart();

    assert.equal((await t.cosign(fork.cp, fork.proofFrom(5))).json.error.code, 'not_an_extension');
    t.grow(1);
    assert.equal((await t.cosign(t.log.checkpoint(), t.log.tree.consistencyProof(10, 11))).status, 200);
    const events = t.hub.store.events(t.org.id).map((e) => e.action);
    assert.ok(events.includes('witness.released'), events.join());
  } finally {
    await t.done();
  }
});

test('release without evidence is explicit, and --all needs it', async () => {
  const t = await setup();
  try {
    const { snapshot } = await history(t);
    fs.rmSync(`${t.database}.witness-journal`);
    await restoreTo(t, snapshot, `${t.database}.witness-journal`);
    const env = { ...process.env, PROOFWIRE_DB: t.database, PROOFWIRE_WITNESS_ONLY: '1', NODE_OPTIONS: '--no-warnings=ExperimentalWarning' };
    const run = (/** @type {string[]} */ args) => spawnSync(process.execPath, [BIN, 'witness-release', ...args], { env, encoding: 'utf8' });
    assert.equal(run(['acme', t.log.checkpoint().body.log]).status, 2, 'neither evidence nor --no-evidence');
    assert.equal(run(['acme', '--all']).status, 2);
    const r = run(['acme', '--all', '--no-evidence']);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stderr, /from size 5[\s\S]*without evidence/);
  } finally {
    // Nothing is listening; setup's hub was closed by restoreTo.
    fs.rmSync(t.dir, { recursive: true, force: true });
  }
});

test('if the journal can\'t be written, nothing is signed', async () => {
  const t = await setup();
  try {
    t.grow(3);
    t.hub.witnessJournal.file = path.join(t.dir, 'no-such-dir', 'journal');
    const res = await t.cosign(t.log.checkpoint());
    assert.equal(res.status, 503);
    assert.equal(res.json.error.code, 'witness_journal_unavailable');
    assert.equal(res.json.signature, undefined);
  } finally {
    await t.done();
  }
});

test('a journal and database that disagree at one size put the log on hold', async () => {
  const t = await setup();
  try {
    t.grow(3);
    assert.equal((await t.cosign(t.log.checkpoint())).status, 200);
    await t.hub.close();
    // Someone edits the database's memory of that root.
    const tamper = new Hub({ database: t.database, witnessOnly: true, witnessJournal: false });
    tamper.db.prepare('UPDATE witness_state SET root = ?').run('ab'.repeat(32));
    await tamper.close();
    await t.restart();
    const r = await t.cosign(t.log.checkpoint());
    assert.equal(r.json.error.code, 'witness_restored');
    assert.equal(r.json.error.detail.reason, 'journal_conflict');
  } finally {
    await t.done();
  }
});
