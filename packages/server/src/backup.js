import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { canonicalBytes } from '@proof_wire/core';
import { openDatabase, openReadOnly, now } from './db.js';
import { Store } from './store.js';

/**
 * Backup, restore, and the awkward truth in between.
 *
 * The awkward truth: **a restore from a stale backup is indistinguishable from
 * malicious truncation.** An auditor holding a checkpoint at size 10,000 who
 * is shown a log of 9,400 sees the same evidence either way — entries covered
 * by a signed root are gone. No amount of honesty in the restore procedure
 * changes what the cryptography says, and it should not: a system where the
 * operator can say "that gap was a restore, not a deletion" and be believed is
 * a system with no integrity guarantee at all.
 *
 * So this module does three things, in order of importance:
 *
 *   1. Makes consistent backups, so the situation arises less often.
 *   2. Records restores in the hub's own hash-chained audit trail, so the
 *      claim is at least contemporaneous and tamper-evident rather than an
 *      assertion made afterwards.
 *   3. Reports the gap precisely and tells the operator how to *close* it —
 *      by re-pushing from the agents, whose local logs are authoritative and
 *      hold the missing receipts.
 *
 * Point 3 is the real remedy. The hub is a replica; the agents are the source.
 * A gap is a synchronisation problem with a known fix, not a lost record —
 * provided the agents' logs still exist, which is precisely why the local log
 * is never optional.
 */

/**
 * Take a consistent snapshot.
 *
 * `VACUUM INTO` is the right tool: it reads through SQLite's own MVCC, so it
 * produces a coherent single-file copy of a live database without stopping
 * writes and without the WAL and shm sidecars that make naive `cp` backups
 * subtly wrong.
 *
 * @param {object} args
 * @param {string} args.database   Path to the live database.
 * @param {string} args.out        Destination file.
 * @returns {{ file: string, bytes: number, sha256: string, at: string, logs: number, receipts: number }}
 */
export function backup(args) {
  const outPath = path.resolve(args.out);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  if (fs.existsSync(outPath)) {
    throw new Error(`refusing to overwrite an existing backup at ${outPath}`);
  }

  const db = openDatabase(args.database);
  try {
    // SQLite has no parameter binding for VACUUM INTO's target.
    db.exec(`VACUUM INTO '${outPath.replace(/'/g, "''")}'`);
  } finally {
    db.close();
  }

  // Read the copy, not the original: this both confirms the snapshot opens
  // and reports what is actually in the file an operator will later restore.
  // Read-only, so inspecting it does not change the bytes we are about to
  // digest.
  const copy = openReadOnly(outPath);
  let logs = 0;
  let receipts = 0;
  try {
    logs = copy.prepare('SELECT count(*) AS n FROM logs').get().n;
    receipts = copy.prepare('SELECT count(*) AS n FROM receipts').get().n;
  } finally {
    copy.close();
  }

  const bytes = fs.readFileSync(outPath);
  const digest = createHash('sha256').update(bytes).digest('hex');

  const manifest = {
    kind: 'proofwire.backup',
    v: 1,
    at: now(),
    file: path.basename(outPath),
    bytes: bytes.length,
    sha256: digest,
    logs,
    receipts,
  };
  fs.writeFileSync(outPath + '.json', JSON.stringify(manifest, null, 2) + '\n');

  return { ...manifest, file: outPath };
}

/**
 * Check a backup before trusting it.
 *
 * A backup nobody has verified is a hope. This opens the file, checks its
 * digest against the manifest, and re-verifies every log inside it — so the
 * failure is found on a quiet afternoon rather than during an incident.
 *
 * @param {string} file
 * @returns {{ ok: boolean, issues: string[], logs: number, receipts: number }}
 */
export function verifyBackup(file) {
  /** @type {string[]} */
  const issues = [];
  const resolved = path.resolve(file);

  if (!fs.existsSync(resolved)) {
    return { ok: false, issues: [`no such backup: ${resolved}`], logs: 0, receipts: 0 };
  }

  const manifestPath = resolved + '.json';
  if (fs.existsSync(manifestPath)) {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const digest = createHash('sha256').update(fs.readFileSync(resolved)).digest('hex');
    if (digest !== manifest.sha256) {
      issues.push(
        `the backup file does not match its manifest digest — it is corrupt or was modified`,
      );
    }
  } else {
    issues.push('no manifest beside this backup; its integrity cannot be checked');
  }

  let logs = 0;
  let receipts = 0;
  const db = openReadOnly(resolved);
  try {
    const store = new Store(db);
    for (const org of db.prepare('SELECT id, slug FROM orgs').all()) {
      for (const log of store.logs(org.id)) {
        logs++;
        receipts += log.size;
        const res = store.audit(org.id, log.id);
        if (!res.ok) {
          issues.push(
            `${org.slug}/${log.slug}: ${res.issues.length} problem(s) — ${res.issues[0].message}`,
          );
        }
      }
    }
  } catch (err) {
    issues.push(`could not open the backup: ${/** @type {Error} */ (err).message}`);
  } finally {
    db.close();
  }

  return { ok: issues.length === 0, issues, logs, receipts };
}

/**
 * Restore a backup over a database path.
 *
 * The existing database is moved aside rather than deleted. Restoring onto a
 * live hub is exactly the moment someone discovers they restored the wrong
 * file, and an unrecoverable mistake there is unforgivable.
 *
 * @param {object} args
 * @param {string} args.from
 * @param {string} args.database
 * @param {boolean} [args.force]  Skip the pre-verification. Never in an incident.
 * @param {string | null} [args.journal]  The witness journal's path, if the hub has one.
 * @returns {{ restored: string, displaced: string|null, verified: object, witnessLogsHeld: number }}
 */
export function restore(args) {
  const source = path.resolve(args.from);
  const target = path.resolve(args.database);

  const verified = verifyBackup(source);
  if (!verified.ok && !args.force) {
    throw new Error(
      `this backup does not verify, so restoring it would install a log that cannot be ` +
        `trusted:\n  ${verified.issues.join('\n  ')}\n` +
        `Pass --force only if you have decided to accept that.`,
    );
  }

  /** @type {string|null} */
  let displaced = null;
  if (fs.existsSync(target)) {
    displaced = `${target}.displaced-${Date.now()}`;
    fs.renameSync(target, displaced);
    // The WAL and shm sidecars belong to the file we just moved; leaving them
    // beside the restored database would corrupt it.
    for (const suffix of ['-wal', '-shm']) {
      if (fs.existsSync(target + suffix)) fs.renameSync(target + suffix, displaced + suffix);
    }
  }

  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(source, target);

  // Record the restore inside the restored database itself, in the
  // hash-chained control-plane trail. This does not make a gap legitimate —
  // nothing could — but it does make the claim contemporaneous and
  // tamper-evident rather than an assertion produced after the fact.
  const db = openDatabase(target);
  let held = 0;
  try {
    const store = new Store(db);
    // With a witness journal the witness catches up from it when it starts.
    // Without one, nothing says what it signed after this backup was taken,
    // so it signs nothing until its operator releases each log.
    const journalSurvived = Boolean(args.journal && fs.existsSync(args.journal));
    /** @type {Map<string, number>} */
    const heldByOrg = new Map();
    if (!journalSurvived) {
      for (const row of db.prepare('SELECT witness_kid, log_id FROM witness_state').all()) {
        store.holdWitnessLog(String(row.witness_kid), String(row.log_id), 'restored_without_journal');
        const orgId = String(row.log_id).slice(0, String(row.log_id).indexOf(':'));
        heldByOrg.set(orgId, (heldByOrg.get(orgId) ?? 0) + 1);
        held++;
      }
    }
    for (const org of db.prepare('SELECT id FROM orgs').all()) {
      store.recordEvent({
        orgId: org.id,
        actor: 'operator',
        actorKind: 'system',
        action: 'hub.restore',
        subject: path.basename(source),
        meta: {
          sha256: createHash('sha256').update(fs.readFileSync(source)).digest('hex'),
          backupVerified: verified.ok,
          ...(heldByOrg.has(String(org.id)) ? { witnessLogsHeld: heldByOrg.get(String(org.id)) } : {}),
        },
      });
    }
  } finally {
    db.close();
  }

  return { restored: target, displaced, verified, witnessLogsHeld: held };
}

/**
 * Work out what each log is missing relative to its own signed checkpoints,
 * and say precisely how to fix it.
 *
 * This is the command to run immediately after a restore, and the one to run
 * when `hub check` reports entries removed. It distinguishes the two cases
 * that matter:
 *
 *   **recoverable** — the hub is behind a checkpoint it signed, and the agent
 *   that owns the log can re-push the difference from its local copy.
 *
 *   **divergent** — the hub holds entries that contradict a signed root rather
 *   than merely lacking some. No re-push fixes that; it means the history was
 *   rewritten, and it should be treated as an incident.
 *
 * **A restored hub cannot detect its own staleness.** This is not an oversight
 * and cannot be engineered away: the proof that the log once reached 18
 * entries lived in the data the restore discarded. A hub rolled back to 10
 * entries holds a checkpoint at 10, is perfectly self-consistent, and has no
 * way to know anything else ever happened.
 *
 * Only a party holding the later evidence can see the gap:
 *
 *   - **the agent**, whose local log is longer. This is the normal path and it
 *     self-heals: `pw push` detects the shortfall and re-sends the difference.
 *   - **a witness or auditor** holding a later checkpoint. Pass it as
 *     `reference` and the gap is reported here.
 *
 * Which is why the agents' local logs are never optional, and why a restore
 * runbook that does not end in "re-push from every agent" is incomplete.
 *
 * @param {string} database
 * @param {object} [opts]
 * @param {import('@proof_wire/core').Checkpoint[]} [opts.reference]
 *   Checkpoints obtained from outside this database — from a witness, an
 *   auditor, or a previous export.
 * @returns {{ ok: boolean, logs: object[], selfReferential: boolean }}
 */
export function reconcile(database, opts = {}) {
  const db = openDatabase(database);
  try {
    const store = new Store(db);
    /** @type {object[]} */
    const report = [];
    const reference = opts.reference ?? [];

    for (const org of db.prepare('SELECT id, slug FROM orgs').all()) {
      for (const log of store.logs(org.id)) {
        const checkpoints = [
          ...store.checkpoints(org.id, log.id, 1000),
          // External checkpoints for this log count too, and are the only
          // thing that can reveal a rollback.
          ...reference.filter((cp) => cp?.body?.log === log.slug || cp?.body?.log === log.canonical),
        ];
        const highest = checkpoints.reduce(
          (max, cp) => (cp.body.size > (max?.body.size ?? -1) ? cp : max),
          /** @type {any} */ (null),
        );
        const audit = store.audit(org.id, log.id);

        if (!highest) {
          report.push({
            org: org.slug, log: log.slug, state: audit.ok ? 'ok' : 'divergent',
            size: log.size, checkpointed: 0, missing: 0,
            detail: audit.ok ? 'no checkpoints yet' : audit.issues[0]?.message,
          });
          continue;
        }

        const missing = Math.max(0, highest.body.size - log.size);

        if (missing > 0) {
          report.push({
            org: org.slug, log: log.slug, state: 'recoverable',
            size: log.size, checkpointed: highest.body.size, missing,
            detail:
              `${missing} receipt(s) covered by a signed checkpoint are not stored. ` +
              `The agent that owns this log still holds them.`,
            remedy: `On the agent: pw push --name ${log.slug}`,
          });
          continue;
        }

        report.push({
          org: org.slug, log: log.slug,
          state: audit.ok ? 'ok' : 'divergent',
          size: log.size, checkpointed: highest.body.size, missing: 0,
          detail: audit.ok
            ? 'consistent with every checkpoint'
            : audit.issues[0]?.message ??
              'the stored history contradicts a signed root — this is not a gap, it is a rewrite',
        });
      }
    }

    return {
      ok: report.every((r) => r.state === 'ok'),
      logs: report,
      // True when nothing outside this database was consulted, and therefore
      // when a clean result proves only internal consistency — not that the
      // hub is up to date.
      selfReferential: reference.length === 0,
    };
  } finally {
    db.close();
  }
}

/**
 * Prune old backups, keeping the most recent `keep`.
 *
 * @param {string} dir
 * @param {number} keep
 * @returns {string[]} Files removed.
 */
export function prune(dir, keep) {
  const resolved = path.resolve(dir);
  if (!fs.existsSync(resolved)) return [];

  const backups = fs
    .readdirSync(resolved)
    .filter((f) => f.endsWith('.db'))
    .map((f) => ({ f, at: fs.statSync(path.join(resolved, f)).mtimeMs }))
    .sort((a, b) => b.at - a.at);

  /** @type {string[]} */
  const removed = [];
  for (const { f } of backups.slice(Math.max(keep, 1))) {
    fs.rmSync(path.join(resolved, f), { force: true });
    fs.rmSync(path.join(resolved, f + '.json'), { force: true });
    removed.push(f);
  }
  return removed;
}

/**
 * Digest of a value, for the manifest. Exported so tests can reproduce it.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function digestOf(value) {
  return createHash('sha256').update(canonicalBytes(value)).digest('hex');
}
