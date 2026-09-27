import fs from 'node:fs';
import path from 'node:path';
import { DEFAULT_CONFIG } from './app.js';
import { backup, verifyBackup, restore, reconcile, prune } from './backup.js';
import { witnessJournalPath } from './witness-journal.js';

/**
 * The operator-facing half of backup and restore.
 *
 * Split out of `bin.js` because the wording here is load-bearing: the whole
 * hazard of a restore is that the operator does not realise it leaves the hub
 * looking, to an auditor, exactly like a log somebody truncated. These
 * commands say so, every time, and then say what to do about it.
 */

const B = (s) => `[1m${s}[0m`;
const DIM = (s) => `[90m${s}[0m`;
const GREEN = (s) => `[32m${s}[0m`;
const RED = (s) => `[31m${s}[0m`;
const YELLOW = (s) => `[33m${s}[0m`;
const CYAN = (s) => `[36m${s}[0m`;

/** @returns {string} */
function databasePath() {
  return process.env.PROOFWIRE_DB ?? DEFAULT_CONFIG.database;
}

/** @returns {string} */
function defaultBackupName() {
  const dir = process.env.PROOFWIRE_BACKUP_DIR ?? './backups';
  return path.join(dir, `proofwire-${new Date().toISOString().replace(/[:.]/g, '-')}.db`);
}

/** Take a snapshot now. */
export async function cmdBackup() {
  const out = process.argv[3] ?? defaultBackupName();
  const res = backup({ database: databasePath(), out });

  console.log('');
  console.log(B('  Backup written'));
  console.log(DIM('  ─────────────────────────────────────────────'));
  console.log(`  file       ${res.file}`);
  console.log(`  size       ${(res.bytes / 1024 / 1024).toFixed(2)} MB`);
  console.log(`  contents   ${res.logs} log(s), ${res.receipts.toLocaleString()} receipts`);
  console.log(`  sha256     ${res.sha256}`);
  console.log('');
  console.log(DIM('  Verify it now, not during an incident:'));
  console.log(`    ${CYAN(`proofwire-hub verify-backup ${res.file}`)}`);
  console.log('');
}

/** Check that a backup opens, matches its digest, and verifies. */
export async function cmdVerifyBackup() {
  const file = process.argv[3];
  if (!file) {
    console.error('usage: proofwire-hub verify-backup <file.db>');
    process.exitCode = 2;
    return;
  }

  const res = verifyBackup(file);
  console.log('');
  if (res.ok) {
    console.log(
      `  ${GREEN('✓')} ${res.logs} log(s), ${res.receipts.toLocaleString()} receipts — every one verifies`,
    );
  } else {
    console.log(`  ${RED('✗')} ${res.issues.length} problem(s):`);
    for (const i of res.issues) console.log(`      ${DIM(i)}`);
    console.log('');
    console.log(DIM('  Do not restore this file expecting a sound log.'));
  }
  console.log('');
  process.exitCode = res.ok ? 0 : 1;
}

/** Put a backup back, keeping whatever was there. */
export async function cmdRestore() {
  const file = process.argv[3];
  if (!file) {
    console.error('usage: proofwire-hub restore <file.db> [--force]');
    process.exitCode = 2;
    return;
  }

  let res;
  try {
    const journalEnv = process.env.PROOFWIRE_WITNESS_JOURNAL;
    res = restore({
      from: file,
      database: databasePath(),
      force: process.argv.includes('--force'),
      journal: witnessJournalPath({
        database: databasePath(),
        witnessJournal: journalEnv === 'off' ? false : journalEnv ?? null,
      }),
    });
  } catch (err) {
    console.error('');
    console.error(`  ${RED('✗')} ${/** @type {Error} */ (err).message}`);
    console.error('');
    process.exitCode = 1;
    return;
  }

  console.log('');
  console.log(B('  Restored'));
  console.log(DIM('  ─────────────────────────────────────────────'));
  console.log(`  database   ${res.restored}`);
  if (res.displaced) {
    console.log(`  previous   ${DIM(res.displaced)}  ${DIM('(kept, not deleted)')}`);
  }
  console.log('');
  if (res.witnessLogsHeld > 0) {
    console.log(YELLOW(`  The witness journal was not found, so this witness has put ${res.witnessLogsHeld} log(s) on hold.`));
    console.log(YELLOW('  It may have signed checkpoints after this backup that it no longer remembers, and'));
    console.log(YELLOW('  will not co-sign for them until you release each one, ideally with the latest'));
    console.log(YELLOW('  checkpoint it signed, from the customer:'));
    console.log('');
    console.log(`    ${CYAN('proofwire-hub witness-release <customer> <log> --checkpoint checkpoint.json')}`);
    console.log('');
  } else {
    console.log(DIM('  The witness catches up from its journal when the hub starts.'));
    console.log('');
  }
  console.log(YELLOW('  A restore can leave the hub behind a checkpoint it already signed.'));
  console.log(YELLOW('  To an auditor that is indistinguishable from deletion, so close the gap:'));
  console.log('');
  console.log(`    ${CYAN('proofwire-hub reconcile')}`);
  console.log('');
}

/** Say exactly what is missing, and how to get it back. */
export async function cmdReconcile() {
  // An auditor's or witness's checkpoints, if the operator has them. This is
  // the only thing that can reveal a hub rolled back to an earlier state.
  const refFlag = process.argv.indexOf('--against');
  /** @type {object[]} */
  let reference = [];
  if (refFlag !== -1 && process.argv[refFlag + 1]) {
    const raw = JSON.parse(fs.readFileSync(process.argv[refFlag + 1], 'utf8'));
    reference = Array.isArray(raw) ? raw : (raw.checkpoints ?? [raw]);
  }

  const res = reconcile(databasePath(), { reference });

  console.log('');
  console.log(B('  Reconciliation'));
  console.log(DIM('  ─────────────────────────────────────────────────────────────'));

  for (const l of res.logs) {
    const mark = l.state === 'ok' ? GREEN('✓') : l.state === 'recoverable' ? YELLOW('!') : RED('✗');
    console.log(
      `  ${mark} ${`${l.org}/${l.log}`.padEnd(30)} ` +
        DIM(`${l.size} stored · ${l.checkpointed} checkpointed`),
    );
    if (l.state !== 'ok') {
      console.log(`      ${l.detail}`);
      if (l.remedy) console.log(`      ${CYAN(l.remedy)}`);
    }
  }

  const recoverable = res.logs.filter((l) => l.state === 'recoverable');
  const divergent = res.logs.filter((l) => l.state === 'divergent');

  console.log('');
  if (res.ok) {
    console.log(`  ${GREEN('Every log is consistent with every checkpoint it has signed.')}`);
    if (res.selfReferential) {
      console.log('');
      console.log(DIM('  Note: this compared the hub against its own checkpoints only, so it'));
      console.log(DIM('  proves internal consistency — not that the hub is up to date. A hub'));
      console.log(DIM('  restored to an earlier state looks exactly like this, because the'));
      console.log(DIM('  evidence of the later state was in the data the restore discarded.'));
      console.log('');
      console.log(DIM('  After any restore, re-push from every agent — their logs are the'));
      console.log(DIM('  authoritative copy and the push is idempotent:'));
      console.log(`    ${CYAN('pw push')}   ${DIM('(on each agent)')}`);
      console.log('');
      console.log(DIM('  Or compare against a checkpoint held outside this database:'));
      console.log(`    ${CYAN('proofwire-hub reconcile --against witness-checkpoints.json')}`);
    }
  } else {
    if (recoverable.length) {
      console.log(`  ${YELLOW(`${recoverable.length} log(s) can be repaired by re-pushing from the agent.`)}`);
      console.log(DIM('  The agents hold the authoritative copy; the hub is only a replica.'));
    }
    if (divergent.length) {
      console.log(`  ${RED(`${divergent.length} log(s) contradict a signed root.`)}`);
      console.log(DIM('  That is not a gap, and re-pushing will not fix it. Treat it as an incident.'));
    }
  }
  console.log('');
  process.exitCode = res.ok ? 0 : 1;
}

/**
 * Periodic backups while the hub is serving.
 *
 * @param {string} database
 * @returns {NodeJS.Timeout|null}
 */
export function scheduleBackups(database) {
  const dir = process.env.PROOFWIRE_BACKUP_DIR;
  const hours = Number(process.env.PROOFWIRE_BACKUP_HOURS ?? 6);
  const keep = Number(process.env.PROOFWIRE_BACKUP_KEEP ?? 14);
  if (!dir || hours <= 0) return null;

  const run = () => {
    try {
      const res = backup({ database, out: defaultBackupName() });
      const removed = prune(dir, keep);
      console.error(
        JSON.stringify({
          level: 'info',
          event: 'backup.written',
          file: res.file,
          bytes: res.bytes,
          receipts: res.receipts,
          pruned: removed.length,
        }),
      );
    } catch (err) {
      // A failed backup is worth an alert, not a crash: the hub's job is to
      // keep accepting receipts.
      console.error(
        JSON.stringify({
          level: 'error',
          event: 'backup.failed',
          message: /** @type {Error} */ (err).message,
        }),
      );
    }
  };

  const timer = setInterval(run, hours * 3_600_000);
  timer.unref();
  return timer;
}
