import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * Where a file lives, allowing for the project's old name.
 *
 * Until 0.5.0 the project was called Proofwire, and its files were named for
 * it: the `.proofwire/` log, `proofwire.config.json`, `proofwire.policy.json`
 * and `~/.proofwire/credentials.json`. It was briefly Vouchwell after that,
 * with `.vouchwell/` and `vouchwell.*` files. A project set up under either
 * keeps working: the new name is used whenever it exists or nothing does, and
 * an old one only when it is all there is (the more recent name first).
 *
 * @param {string} current     The name to use, e.g. `.deedwrit`.
 * @param {...string} legacy   What the same thing was called before, newest first.
 */
export function current(current, ...legacy) {
  if (fs.existsSync(current)) return current;
  return legacy.find((name) => fs.existsSync(name)) ?? current;
}

export const LOG_DIR = () => current('.deedwrit', '.vouchwell', '.proofwire');
export const CONFIG_FILE = () => current('deedwrit.config.json', 'vouchwell.config.json', 'proofwire.config.json');
export const POLICY_FILE = () => current('deedwrit.policy.json', 'vouchwell.policy.json', 'proofwire.policy.json');

/** The credentials file to read: ~/.deedwrit, or the one an earlier name left. */
export function credentialsToRead() {
  const at = (/** @type {string} */ dir) => path.join(os.homedir(), dir, 'credentials.json');
  return current(at('.deedwrit'), at('.vouchwell'), at('.proofwire'));
}
