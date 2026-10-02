import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * Where a file lives, allowing for the project's old name.
 *
 * Until 0.5.0 the project was called Proofwire, and its files were named for
 * it: the `.proofwire/` log, `proofwire.config.json`, `proofwire.policy.json`
 * and `~/.proofwire/credentials.json`. A project set up then keeps working:
 * the new name is used whenever it exists or nothing does, and the old one
 * only when it is the only one there.
 *
 * @param {string} current  The name to use, e.g. `.vouchwell`.
 * @param {string} legacy   What the same thing was called before, e.g. `.proofwire`.
 */
export function current(current, legacy) {
  return !fs.existsSync(current) && fs.existsSync(legacy) ? legacy : current;
}

export const LOG_DIR = () => current('.vouchwell', '.proofwire');
export const CONFIG_FILE = () => current('vouchwell.config.json', 'proofwire.config.json');
export const POLICY_FILE = () => current('vouchwell.policy.json', 'proofwire.policy.json');

/** The credentials file to read: ~/.vouchwell, or ~/.proofwire from before the rename. */
export function credentialsToRead() {
  return current(path.join(os.homedir(), '.vouchwell', 'credentials.json'), path.join(os.homedir(), '.proofwire', 'credentials.json'));
}
