import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ProofLog } from '@vouchwell/core';
import { RemoteSink } from '@vouchwell/proxy/remote';
import { Hub } from '../src/app.js';
import { Auth } from '../src/auth.js';
import { backup, verifyBackup, restore, reconcile, prune } from '../src/backup.js';

/**
 * Backup and restore, exercised rather than documented.
 *
 * The test that matters most is the last one: a restore from a stale backup
 * produces exactly the evidence a truncation attack would, and the system has
 * to (a) still say so, loudly, and (b) tell the operator how to close the gap
 * from the agents' own logs.
 */

/** @returns {string} */
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'pw-backup-'));

/**
 * Stand up a hub with a log in it, driven the way a real agent does.
 *
 * @param {object} [opts]
 */
async function seed(opts = {}) {
  const dir = tmp();
  const dbFile = path.join(dir, 'hub.db');
  const hub = new Hub({
    database: dbFile,
    checkpointEvery: 0,
    apiRate: { capacity: 1e6, refillPerSec: 1e6 },
    ingestRate: { capacity: 1e6, refillPerSec: 1e6 },
  });
  const { url } = await hub.listen(0);
  const base = url.replace('0.0.0.0', '127.0.0.1');

  const auth = new Auth(hub.store);
  const org = hub.store.createOrg({ slug: 'acme', name: 'Acme' });
  const token = auth.createKey({
    orgId: org.id,
    name: 'agent',
    scopes: ['receipts:write', 'receipts:read', 'logs:write', 'logs:read'],
  }).token;

  const agentDir = tmp();
  const localLog = ProofLog.create(agentDir);
  for (let i = 0; i < (opts.receipts ?? 10); i++) {
    localLog.append({
      actor: { agent: 'claude-opus-5', runtime: 'r', session: 's', principal: 'ops@acme.test' },
      action: { kind: 'tool_call', target: 'ops.refund', params: { i }, metrics: { amount_usd: 1 } },
      decision: { outcome: 'allow', policy: 'p', rules: [] },
      result: { status: 'ok', payload: { i } },
    });
  }

  const sink = new RemoteSink({ url: base, token, log: 'payments', localLog });
  assert.ok(await sink.connect());
  await sink.flush();

  return { hub, base, token, org, dbFile, dir, localLog, sink };
}

test('a backup is consistent, digested, and re-verifies', async () => {
  const { hub, org, dbFile, dir } = await seed({ receipts: 12 });
  await hub.store.checkpoint(org.id, hub.store.logBySlug(org.id, 'payments').id, hub.hubSigner);
  await hub.close();

  const out = path.join(dir, 'snap.db');
  const res = backup({ database: dbFile, out });

  assert.equal(res.receipts, 12);
  assert.equal(res.logs, 1);
  assert.ok(res.bytes > 0);
  assert.match(res.sha256, /^[0-9a-f]{64}$/);
  assert.ok(fs.existsSync(out + '.json'), 'a manifest travels with the backup');

  const check = verifyBackup(out);
  assert.ok(check.ok, JSON.stringify(check.issues));
  assert.equal(check.receipts, 12);
});

test('a backup will not silently overwrite another', async () => {
  const { hub, dbFile, dir } = await seed({ receipts: 3 });
  await hub.close();

  const out = path.join(dir, 'once.db');
  backup({ database: dbFile, out });
  assert.throws(() => backup({ database: dbFile, out }), /refusing to overwrite/);
});

test('a corrupted backup fails verification instead of being restored', async () => {
  const { hub, dbFile, dir } = await seed({ receipts: 5 });
  await hub.close();

  const out = path.join(dir, 'corrupt.db');
  backup({ database: dbFile, out });

  // Flip bytes in the middle of the file, as a bad disk would. Filling with
  // 0xff rather than 0x00 matters: a freshly vacuumed page is often already
  // zeroed, so zeroing it changes nothing and the "corruption" is a no-op.
  const bytes = fs.readFileSync(out);
  const mid = Math.floor(bytes.length / 2);
  bytes.fill(0xff, mid, mid + 256);
  fs.writeFileSync(out, bytes);


  const check = verifyBackup(out);
  assert.equal(check.ok, false);
  assert.ok(check.issues.some((i) => /does not match its manifest digest/.test(i)));

  // And restoring it is refused rather than attempted.
  assert.throws(
    () => restore({ from: out, database: path.join(dir, 'target.db') }),
    /does not verify/,
  );
});

test('restore keeps the database it replaces', async () => {
  const { hub, dbFile, dir } = await seed({ receipts: 6 });
  await hub.close();

  const out = path.join(dir, 'good.db');
  backup({ database: dbFile, out });

  const res = restore({ from: out, database: dbFile });
  assert.ok(res.displaced, 'the previous database must be kept, not deleted');
  assert.ok(fs.existsSync(res.displaced));
  assert.ok(res.verified.ok);
});

test('a restore is recorded in the hub\'s own hash-chained audit trail', async () => {
  const { hub, dbFile, dir, org } = await seed({ receipts: 4 });
  await hub.close();

  const out = path.join(dir, 'audited.db');
  backup({ database: dbFile, out });
  restore({ from: out, database: dbFile });

  const reopened = new Hub({ database: dbFile });
  const events = reopened.store.events(org.id, 50);
  const restoreEvent = events.find((e) => e.action === 'hub.restore');

  assert.ok(restoreEvent, 'the restore should be recorded');
  assert.match(JSON.parse(restoreEvent.meta).sha256, /^[0-9a-f]{64}$/);
  // The claim is contemporaneous and chained — it cannot be inserted later.
  assert.ok(reopened.store.auditEvents(org.id).ok);
  await reopened.close();
});

test('a restored hub cannot detect its own staleness — only an outside party can', async () => {
  // The single most important property in this file, and the one that is
  // easiest to assume away.
  const { hub, token, org, dbFile, dir, localLog } = await seed({ receipts: 10 });
  const logId = hub.store.logBySlug(org.id, 'payments').id;

  // Back up at 10 entries, with a signed checkpoint covering them.
  await hub.store.checkpoint(org.id, logId, hub.hubSigner);
  await hub.close();
  const snapshot = path.join(dir, 'at-10.db');
  backup({ database: dbFile, out: snapshot });

  // The agent keeps working; the hub reaches 18 and checkpoints again.
  const hub2 = new Hub({
    database: dbFile,
    checkpointEvery: 0,
    apiRate: { capacity: 1e6, refillPerSec: 1e6 },
    ingestRate: { capacity: 1e6, refillPerSec: 1e6 },
  });
  const { url } = await hub2.listen(0);
  const base2 = url.replace('0.0.0.0', '127.0.0.1');
  for (let i = 0; i < 8; i++) {
    localLog.append({
      actor: { agent: 'claude-opus-5', runtime: 'r', session: 's', principal: 'ops@acme.test' },
      action: { kind: 'tool_call', target: 'ops.refund', params: { late: i } },
      decision: { outcome: 'allow', policy: 'p', rules: [] },
    });
  }
  const sink2 = new RemoteSink({ url: base2, token, log: 'payments', localLog });
  await sink2.connect();
  await sink2.flush();
  const laterCheckpoint = await hub2.store.checkpoint(org.id, logId, hub2.hubSigner);
  assert.equal(hub2.store.log(org.id, logId).size, 18);
  await hub2.close();

  // Disaster. Restore the older snapshot.
  restore({ from: snapshot, database: dbFile, force: true });

  // The restored hub is perfectly self-consistent and has NO WAY to know
  // otherwise: the proof that 18 entries ever existed was in the data the
  // restore discarded. Asserting this explicitly, because a future change
  // that appears to "fix" it is almost certainly fooling itself.
  const after = new Hub({ database: dbFile });
  const selfAudit = after.store.audit(org.id, after.store.logBySlug(org.id, 'payments').id);
  assert.ok(selfAudit.ok, 'a rolled-back hub is internally consistent — this is the hazard');
  await after.close();

  const blind = reconcile(dbFile);
  assert.ok(blind.ok, 'and self-reconciliation cannot see the gap either');
  assert.equal(blind.selfReferential, true, 'but it must say that it only checked itself');

  // Given the later checkpoint — from a witness, an auditor, or an export —
  // the gap is immediately visible and correctly classified.
  const sighted = reconcile(dbFile, { reference: [laterCheckpoint] });
  const payments = sighted.logs.find((l) => l.log === 'payments');

  assert.equal(sighted.ok, false);
  assert.equal(sighted.selfReferential, false);
  assert.equal(payments.state, 'recoverable');
  assert.equal(payments.size, 10);
  assert.equal(payments.checkpointed, 18);
  assert.equal(payments.missing, 8);
  assert.match(payments.remedy, /vw push --name payments/);
});

test('the agent detects the rollback by itself and heals it', async () => {
  // The path that matters in practice: nobody has to notice anything.
  const { hub, base, token, org, localLog } = await seed({ receipts: 12 });
  const logId = hub.store.logBySlug(org.id, 'payments').id;

  // Roll the hub back, as a stale restore would.
  hub.db.prepare('DELETE FROM receipts WHERE log_id = ? AND seq >= 5').run(logId);
  const last = hub.db
    .prepare('SELECT hash FROM receipts WHERE log_id = ? ORDER BY seq DESC LIMIT 1')
    .get(logId);
  hub.db.prepare('UPDATE logs SET size = 5, head = ? WHERE id = ?').run(last.hash, logId);
  hub.store.forgetTree(logId);
  hub.db
    .prepare('UPDATE logs SET root = ? WHERE id = ?')
    .run(hub.store.tree(logId).root.toString('hex'), logId);

  // The agent reconnects and simply notices the hub is behind.
  const sink = new RemoteSink({ url: base, token, log: 'payments', localLog });
  assert.ok(await sink.connect());
  assert.equal(sink.cursor, 5, 'the sink resumes from what the hub actually holds');
  assert.equal(await sink.flush(), 7, 'and re-sends exactly what is missing');

  assert.ok(hub.store.audit(org.id, logId).ok);
  assert.equal(hub.store.log(org.id, logId).root, localLog.root, 'roots agree again');
  await hub.close();
});

test('re-pushing from the agent closes the gap completely', async () => {
  const { hub, token, org, dbFile, localLog, base } = await seed({ receipts: 6 });
  const logId = hub.store.logBySlug(org.id, 'payments').id;
  await hub.store.checkpoint(org.id, logId, hub.hubSigner);

  // Simulate a restore that lost the last three entries.
  hub.db.prepare('DELETE FROM receipts WHERE log_id = ? AND seq >= 3').run(logId);
  const remaining = hub.db
    .prepare('SELECT hash FROM receipts WHERE log_id = ? ORDER BY seq DESC LIMIT 1')
    .get(logId);
  hub.db
    .prepare('UPDATE logs SET size = 3, head = ? WHERE id = ?')
    .run(remaining.hash, logId);
  hub.store.forgetTree(logId);
  hub.db
    .prepare('UPDATE logs SET root = ? WHERE id = ?')
    .run(hub.store.tree(logId).root.toString('hex'), logId);

  assert.equal(hub.store.log(org.id, logId).size, 3);
  assert.equal(hub.store.audit(org.id, logId).ok, false, 'the gap is visible');

  // The agent still holds all six. Re-push.
  const sink = new RemoteSink({ url: base, token, log: 'payments', localLog });
  assert.ok(await sink.connect());
  assert.equal(sink.cursor, 3, 'the sink resumes from what the hub actually has');
  assert.equal(await sink.flush(), 3);

  const healed = hub.store.audit(org.id, logId);
  assert.ok(healed.ok, JSON.stringify(healed.issues));
  assert.equal(hub.store.log(org.id, logId).size, 6);
  assert.equal(hub.store.log(org.id, logId).root, localLog.root);

  await hub.close();
  assert.ok(reconcile(dbFile).ok, 'reconcile should now be clean');
});

test('reconcile distinguishes a recoverable gap from a rewrite', async () => {
  const { hub, org, dbFile } = await seed({ receipts: 8 });
  const logId = hub.store.logBySlug(org.id, 'payments').id;
  await hub.store.checkpoint(org.id, logId, hub.hubSigner);

  // Not a gap: an entry altered in place. No re-push fixes this.
  const row = hub.db.prepare('SELECT body FROM receipts WHERE log_id = ? AND seq = 2').get(logId);
  const doctored = JSON.parse(row.body);
  doctored.action.target = 'ops.something-else';
  hub.db
    .prepare('UPDATE receipts SET body = ? WHERE log_id = ? AND seq = 2')
    .run(JSON.stringify(doctored), logId);
  await hub.close();

  const rec = reconcile(dbFile);
  const payments = rec.logs.find((l) => l.log === 'payments');
  assert.equal(rec.ok, false);
  assert.equal(payments.state, 'divergent', 'an edit is not a gap and must not be called recoverable');
  assert.equal(payments.missing, 0);
  assert.ok(!payments.remedy, 're-pushing must not be offered as a fix for a rewrite');
});

test('a healthy hub reconciles clean', async () => {
  const { hub, org, dbFile } = await seed({ receipts: 5 });
  await hub.store.checkpoint(org.id, hub.store.logBySlug(org.id, 'payments').id, hub.hubSigner);
  await hub.close();

  const rec = reconcile(dbFile);
  assert.ok(rec.ok, JSON.stringify(rec.logs, null, 2));
  assert.equal(rec.logs[0].state, 'ok');
});

test('pruning keeps the newest backups and removes their manifests too', async () => {
  const { hub, dbFile, dir } = await seed({ receipts: 2 });
  await hub.close();

  const backupDir = path.join(dir, 'backups');
  for (let i = 0; i < 5; i++) {
    backup({ database: dbFile, out: path.join(backupDir, `b-${i}.db`) });
    // Space them out so mtime ordering is deterministic.
    const f = path.join(backupDir, `b-${i}.db`);
    const t = new Date(Date.now() + i * 1000);
    fs.utimesSync(f, t, t);
  }

  const removed = prune(backupDir, 2);
  assert.equal(removed.length, 3);

  const left = fs.readdirSync(backupDir);
  assert.deepEqual(left.filter((f) => f.endsWith('.db')).sort(), ['b-3.db', 'b-4.db']);
  assert.equal(left.filter((f) => f.endsWith('.json')).length, 2, 'manifests go with their backups');
});
