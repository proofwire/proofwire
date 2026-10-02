/**
 * The project was called Proofwire until 0.5.0, and briefly Vouchwell after
 * that. Settings written for either keep working: this reads every
 * `PROOFWIRE_*` and `VOUCHWELL_*` environment variable as its `DEEDWRIT_*`
 * counterpart when that isn't set (the more recent name first), and says so
 * once, so an existing deployment or script doesn't silently lose its
 * configuration.
 *
 * @param {Record<string, string | undefined>} [env]
 * @param {((message: string) => void) | null} [notice]  Where to say it; stderr by default.
 * @returns {string[]}  The old names that were read.
 */
/** Most recent first: a VOUCHWELL_ setting wins over a PROOFWIRE_ one. */
const LEGACY_PREFIXES = ['VOUCHWELL_', 'PROOFWIRE_'];

export function adoptLegacyEnv(env = process.env, notice = (m) => process.stderr.write(m)) {
  /** @type {string[]} */
  const adopted = [];
  for (const prefix of LEGACY_PREFIXES) {
    for (const [key, value] of Object.entries(env)) {
      if (!key.startsWith(prefix) || value === undefined) continue;
      const current = `DEEDWRIT_${key.slice(prefix.length)}`;
      if (env[current] === undefined) {
        env[current] = value;
        adopted.push(key);
      }
    }
  }
  if (adopted.length && notice) {
    notice(`deedwrit: read ${adopted.join(', ')} from the project's old name; rename to DEEDWRIT_… (the old names still work for now)\n`);
  }
  return adopted;
}
