/**
 * The project was called Proofwire until 0.5.0. Settings written for it keep
 * working: this reads every `PROOFWIRE_*` environment variable as its
 * `VOUCHWELL_*` counterpart when that isn't set, and says so once, so an
 * existing deployment or script doesn't silently lose its configuration.
 *
 * @param {Record<string, string | undefined>} [env]
 * @param {((message: string) => void) | null} [notice]  Where to say it; stderr by default.
 * @returns {string[]}  The old names that were read.
 */
export function adoptLegacyEnv(env = process.env, notice = (m) => process.stderr.write(m)) {
  /** @type {string[]} */
  const adopted = [];
  for (const [key, value] of Object.entries(env)) {
    if (!key.startsWith('PROOFWIRE_') || value === undefined) continue;
    const current = `VOUCHWELL_${key.slice('PROOFWIRE_'.length)}`;
    if (env[current] === undefined) {
      env[current] = value;
      adopted.push(key);
    }
  }
  if (adopted.length && notice) {
    notice(`vouchwell: read ${adopted.join(', ')} from the project's old name; rename to VOUCHWELL_… (the old names still work for now)\n`);
  }
  return adopted;
}
