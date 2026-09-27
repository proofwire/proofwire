import fs from 'node:fs';
import path from 'node:path';

/**
 * A witness's memory of what it signed, kept outside its database.
 *
 * A witness refuses to sign two histories of a log because it remembers the
 * last root it signed. That memory is in the database, and a database can be
 * restored from a backup. A witness restored to last Tuesday has forgotten
 * everything it signed since, and would sign a history that conflicts with
 * one it has already vouched for: exactly the split view it exists to stop.
 * No amount of care in the database can prevent that, because the evidence
 * is what the restore discarded.
 *
 * So every co-signature is also written here, and forced to disk, before it
 * is returned. Backups copy only the database, so after a restore this file
 * still holds everything signed since the backup, and the witness catches up
 * from it before signing anything (`Hub._catchUpWitness`). Put it on a
 * different volume from the database, so the two are not lost together; if
 * both are, a restore puts every log on hold instead (see `restore`).
 *
 * One JSON object per line:
 *   { "t": "sign", "witness": kid, "log": "<org id>:<log>", "size": n, "root": hex,
 *     "logKid": kid, "logPublicKey": key, "at": iso }
 *   { "t": "bind", "witness": kid, "log": ..., "logKid": kid, "logPublicKey": key, "by": "operator", "at": iso }
 */

/**
 * @typedef {{ t: 'sign', witness: string, log: string, size: number, root: string,
 *   logKid: string, logPublicKey: string, at: string }} SignEntry
 * @typedef {{ t: 'bind', witness: string, log: string, logKid: string, logPublicKey: string,
 *   by: string, at: string }} BindEntry
 * @typedef {{ position: SignEntry | null, binding: { logKid: string, logPublicKey: string, by: string } | null }} LogMemory
 */

/**
 * Where the journal is, or null when there is none: an in-memory database,
 * or `witnessJournal: false` (PROOFWIRE_WITNESS_JOURNAL=off).
 *
 * @param {{ database?: string, witnessJournal?: string | false | null }} config
 * @returns {string | null}
 */
export function witnessJournalPath(config) {
  if (config.witnessJournal === false) return null;
  if (typeof config.witnessJournal === 'string' && config.witnessJournal) return path.resolve(config.witnessJournal);
  if (!config.database || config.database === ':memory:') return null;
  return path.resolve(`${config.database}.witness-journal`);
}

export class WitnessJournal {
  /** @param {string} file */
  constructor(file) {
    this.file = file;
    fs.mkdirSync(path.dirname(file), { recursive: true });
  }

  /**
   * Append one entry and force it to disk. Throws if it can't: a signature
   * the journal doesn't hold must not be issued.
   *
   * @param {SignEntry | BindEntry} entry
   */
  append(entry) {
    const fd = fs.openSync(this.file, 'a', 0o600);
    try {
      fs.writeSync(fd, JSON.stringify(entry) + '\n');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  }

  /** Whether the file exists at all. */
  exists() {
    return fs.existsSync(this.file);
  }

  /**
   * The latest position and binding per (witness, log). A torn last line,
   * from a crash mid-write, is skipped: its signature was never returned.
   *
   * @returns {Map<string, LogMemory>}  keyed by `${witness} ${log}`
   */
  read() {
    /** @type {Map<string, LogMemory>} */
    const out = new Map();
    if (!this.exists()) return out;
    for (const line of fs.readFileSync(this.file, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      let e;
      try {
        e = JSON.parse(line);
      } catch {
        continue;
      }
      if (!e || typeof e.witness !== 'string' || typeof e.log !== 'string') continue;
      const key = `${e.witness} ${e.log}`;
      const mem = out.get(key) ?? { position: null, binding: null };
      if (e.t === 'sign' && Number.isInteger(e.size) && typeof e.root === 'string') {
        // Sizes only grow; a smaller one later in the file is an older entry
        // re-seeded after compaction, never a newer position.
        if (!mem.position || e.size >= mem.position.size) mem.position = e;
        if (!mem.binding) mem.binding = { logKid: e.logKid, logPublicKey: e.logPublicKey, by: 'first-use' };
      } else if (e.t === 'bind') {
        mem.binding = { logKid: e.logKid, logPublicKey: e.logPublicKey, by: e.by };
      }
      out.set(key, mem);
    }
    return out;
  }

  /**
   * Rewrite the file as one position (and binding, if it was rebound) per
   * log, atomically. The file otherwise grows by a line per signature.
   *
   * @param {Map<string, LogMemory>} memory
   */
  compact(memory) {
    const tmp = `${this.file}.compact-${process.pid}`;
    const lines = [];
    for (const mem of memory.values()) {
      if (mem.position) lines.push(JSON.stringify(mem.position));
      if (mem.binding && mem.position && mem.binding.logKid !== mem.position.logKid) {
        lines.push(JSON.stringify({
          t: 'bind', witness: mem.position.witness, log: mem.position.log,
          logKid: mem.binding.logKid, logPublicKey: mem.binding.logPublicKey, by: mem.binding.by, at: mem.position.at,
        }));
      }
    }
    const fd = fs.openSync(tmp, 'w', 0o600);
    try {
      fs.writeSync(fd, lines.length ? lines.join('\n') + '\n' : '');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, this.file);
  }
}
