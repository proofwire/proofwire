#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { identityFromPublicKey } from '@vouchwell/core';

/**
 * The published record of Vouchwell-operated witness keys: witnesses/keys.json.
 *
 * A witness vouching for its own key over its own API is worth nothing — that
 * is the self-vouching the verifier's witness pinning exists to refuse. So
 * the keys an auditor pins come from here instead, where a key cannot be
 * swapped or quietly withdrawn without it showing: the file is append-only,
 * and that is enforced against its own git history, not promised.
 *
 * Each entry is added once and never edited, reordered or removed. Two fields
 * may change, once each, from null to a date:
 *
 *   retiredAt  the key stopped signing. What it signed before stays good, so
 *              auditors keep pinning it.
 *   revokedAt  the key must not be trusted at all — compromised, or lost to
 *              someone else. `vw check --witness-keys` skips it.
 *
 * The file is a plain JSON list so `vw check --witness-keys witnesses/keys.json`
 * reads it as it stands.
 *
 *   node scripts/witness-record.mjs check
 *   node scripts/witness-record.mjs add --operator <name> --public-key <key> [--node <https url>] [--note <text>] [--date YYYY-MM-DD]
 *   node scripts/witness-record.mjs retire <kid> [--date YYYY-MM-DD]
 *   node scripts/witness-record.mjs revoke <kid> [--date YYYY-MM-DD]
 */

// Overridable only so the tests can drive the command line against a scratch
// repository instead of this one's real record.
export const ROOT = process.env.VOUCHWELL_RECORD_ROOT ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const RECORD = 'witnesses/keys.json';

const FIELDS = ['kid', 'publicKey', 'operator', 'node', 'addedAt', 'retiredAt', 'revokedAt', 'note'];
/** Everything about an entry that is fixed the moment it is added. */
const FIXED = ['kid', 'publicKey', 'operator', 'node', 'addedAt', 'note'];

/** @param {unknown} s */
function isDate(s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
}

/**
 * Problems with one version of the record, as messages; empty when sound.
 *
 * @param {unknown} record
 * @returns {string[]}
 */
export function validate(record) {
  if (!Array.isArray(record)) return ['the record must be a JSON list'];
  /** @type {string[]} */
  const problems = [];
  const kids = new Set();
  const keys = new Set();
  let lastAdded = '';

  record.forEach((entry, i) => {
    const at = `entry ${i}`;
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      problems.push(`${at} is not an object`);
      return;
    }
    const extra = Object.keys(entry).filter((k) => !FIELDS.includes(k));
    const missing = FIELDS.filter((k) => !(k in entry));
    if (extra.length) problems.push(`${at} has unknown field(s): ${extra.join(', ')}`);
    if (missing.length) problems.push(`${at} is missing: ${missing.join(', ')} (use null, not absence)`);

    // The kid must be the one the key actually derives to, and the key must be
    // the one canonical spelling — the verifier refuses anything else, so an
    // entry that fails here could never have pinned anything.
    let derived = null;
    try {
      derived = identityFromPublicKey(String(entry.publicKey));
    } catch {
      problems.push(`${at}: publicKey is not a raw 32-byte Ed25519 key in canonical base64url`);
    }
    if (derived && derived.kid !== entry.kid) {
      problems.push(`${at}: kid ${entry.kid} is not the id of its publicKey (${derived.kid})`);
    }
    if (kids.has(entry.kid)) problems.push(`${at}: kid ${entry.kid} appears twice`);
    if (keys.has(entry.publicKey)) problems.push(`${at}: publicKey appears twice`);
    kids.add(entry.kid);
    keys.add(entry.publicKey);

    if (typeof entry.operator !== 'string' || !entry.operator.trim()) problems.push(`${at}: operator is required`);
    if (entry.node !== null && !(typeof entry.node === 'string' && /^https:\/\/[^\s/]+/.test(entry.node))) {
      problems.push(`${at}: node must be an https URL or null`);
    }
    if (entry.note !== null && typeof entry.note !== 'string') problems.push(`${at}: note must be text or null`);

    if (!isDate(entry.addedAt)) {
      problems.push(`${at}: addedAt must be a real YYYY-MM-DD date`);
    } else {
      if (entry.addedAt < lastAdded) problems.push(`${at}: added ${entry.addedAt}, before the entry above it`);
      lastAdded = entry.addedAt;
    }
    for (const field of ['retiredAt', 'revokedAt']) {
      if (entry[field] === null) continue;
      if (!isDate(entry[field])) problems.push(`${at}: ${field} must be a real YYYY-MM-DD date or null`);
      else if (isDate(entry.addedAt) && entry[field] < entry.addedAt) problems.push(`${at}: ${field} is before addedAt`);
    }
  });
  return problems;
}

/**
 * Problems with `next` as a successor of `prev`: what may never happen to a
 * published record, whatever else is true of it.
 *
 * @param {any[]} prev
 * @param {any[]} next
 * @returns {string[]}
 */
export function appendOnly(prev, next) {
  /** @type {string[]} */
  const problems = [];
  if (next.length < prev.length) {
    problems.push(`${prev.length - next.length} entr${prev.length - next.length === 1 ? 'y was' : 'ies were'} removed`);
  }
  prev.forEach((before, i) => {
    const after = next[i];
    if (!after) return;
    const label = `entry ${i} (${before.kid})`;
    const changed = FIXED.filter((k) => JSON.stringify(after[k]) !== JSON.stringify(before[k]));
    if (changed.length) {
      problems.push(`${label} was edited or moved: ${changed.join(', ')} changed`);
      return;
    }
    for (const field of ['retiredAt', 'revokedAt']) {
      if (before[field] !== null && after[field] !== before[field]) {
        problems.push(`${label}: ${field} was ${before[field]} and cannot change (now ${after[field]})`);
      }
    }
  });
  return problems;
}

/**
 * Every committed version of the record, oldest first, then the working copy.
 * `null` when there is no history to check (not a git checkout, or a shallow
 * one — CI fetches full history for this).
 *
 * @param {string} [root]
 * @returns {{ label: string, record: any }[]|null}
 */
export function history(root = ROOT) {
  const git = (...args) => spawnSync('git', args, { cwd: root, encoding: 'utf8' });
  const shallow = git('rev-parse', '--is-shallow-repository');
  if (shallow.status !== 0 || shallow.stdout.trim() !== 'false') return null;

  const commits = git('log', '--reverse', '--format=%H', '--', RECORD).stdout.split('\n').filter(Boolean);
  /** @type {{ label: string, record: any }[]} */
  const versions = [];
  for (const sha of commits) {
    const blob = git('show', `${sha}:${RECORD}`);
    // A commit that deleted the file shows up in the log too; its absence is
    // itself a removal, which the next comparison reports.
    versions.push({ label: sha.slice(0, 7), record: blob.status === 0 ? JSON.parse(blob.stdout) : [] });
  }
  const file = path.join(root, RECORD);
  versions.push({ label: 'working copy', record: fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : [] });
  return versions;
}

/**
 * Validate the record now, and every step of its history.
 *
 * @param {string} [root]
 * @returns {{ problems: string[], checkedHistory: boolean, entries: number }}
 */
export function check(root = ROOT) {
  const file = path.join(root, RECORD);
  if (!fs.existsSync(file)) return { problems: [`${RECORD} does not exist`], checkedHistory: false, entries: 0 };
  const current = JSON.parse(fs.readFileSync(file, 'utf8'));
  const problems = validate(current).map((p) => `now: ${p}`);

  const versions = history(root);
  if (versions) {
    for (let i = 1; i < versions.length; i++) {
      for (const p of appendOnly(versions[i - 1].record, versions[i].record)) {
        problems.push(`${versions[i - 1].label} → ${versions[i].label}: ${p}`);
      }
    }
  }
  return { problems, checkedHistory: Boolean(versions), entries: Array.isArray(current) ? current.length : 0 };
}

// ── command line ──────────────────────────────────────────────────────────

/** @param {string[]} argv */
function flags(argv) {
  /** @type {Record<string, string>} */
  const out = {};
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) out[argv[i].slice(2)] = argv[++i];
    else rest.push(argv[i]);
  }
  return { out, rest };
}

function write(record) {
  const problems = validate(record);
  if (problems.length) throw new Error(problems.join('\n'));
  fs.writeFileSync(path.join(ROOT, RECORD), `${JSON.stringify(record, null, 2)}\n`);
}

function main(argv) {
  const [command, ...args] = argv;
  const { out, rest } = flags(args);
  const today = new Date().toISOString().slice(0, 10);
  const record = () => JSON.parse(fs.readFileSync(path.join(ROOT, RECORD), 'utf8'));

  if (command === 'check') {
    const res = check();
    if (res.problems.length) {
      for (const p of res.problems) console.error(`  ✗ ${p}`);
      return 1;
    }
    console.log(`  ✓ ${RECORD}: ${res.entries} entr${res.entries === 1 ? 'y' : 'ies'}, valid` +
      (res.checkedHistory ? ', append-only through its whole history' : ' (history not checked: shallow or no git)'));
    return 0;
  }

  if (command === 'add') {
    if (!out['operator'] || !out['public-key']) {
      console.error('  usage: witness-record.mjs add --operator <name> --public-key <key> [--node <https url>] [--note <text>] [--date YYYY-MM-DD]');
      return 2;
    }
    const { kid, publicKey } = identityFromPublicKey(out['public-key']);
    const next = [...record(), {
      kid, publicKey, operator: out.operator, node: out.node ?? null,
      addedAt: out.date ?? today, retiredAt: null, revokedAt: null, note: out.note ?? null,
    }];
    write(next);
    console.log(`  added ${kid} (${out.operator}). Commit it; the record is the commit history.`);
    return 0;
  }

  if (command === 'retire' || command === 'revoke') {
    const field = command === 'retire' ? 'retiredAt' : 'revokedAt';
    const next = record();
    const entry = next.find((e) => e.kid === rest[0]);
    if (!entry) {
      console.error(`  no entry with kid ${rest[0] ?? '(none given)'}`);
      return 2;
    }
    if (entry[field] !== null) {
      console.error(`  ${entry.kid} already has ${field} ${entry[field]}; it cannot change`);
      return 1;
    }
    entry[field] = out.date ?? today;
    write(next);
    console.log(`  ${entry.kid}: ${field} ${entry[field]}. Commit it.`);
    return 0;
  }

  console.error('  usage: witness-record.mjs check | add | retire <kid> | revoke <kid>');
  return 2;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (err) {
    console.error(`  ✗ ${err.message}`);
    process.exitCode = 1;
  }
}
