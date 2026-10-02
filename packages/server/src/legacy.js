import fs from 'node:fs';
import path from 'node:path';

/**
 * The hub's database file, allowing for the project's old name.
 *
 * Until 0.5.0 the default was `proofwire.db` (the Docker image used
 * /data/proofwire.db), and then briefly `vouchwell.db`. A hub upgraded in place
 * must keep its data, keys and witness positions, not start a new empty
 * database beside them: so when the new default doesn't exist and an old one
 * does, the old one is used (the more recent name first).
 *
 * @param {string} file
 * @returns {{ file: string, legacy: boolean }}
 */
export function resolveDatabase(file) {
  if (file === ':memory:' || fs.existsSync(file) || path.basename(file) !== 'deedwrit.db') return { file, legacy: false };
  for (const name of ['vouchwell.db', 'proofwire.db']) {
    const old = path.join(path.dirname(file), name);
    if (fs.existsSync(old)) return { file: old, legacy: true };
  }
  return { file, legacy: false };
}
