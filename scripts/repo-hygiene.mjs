#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/**
 * What must never be committed to this public repository, checked on every CI
 * run and before every release.
 *
 * `.gitignore` keeps these out of an ordinary `git add`, but not out of a
 * `git add -f`, a renamed file, or a secret pasted into source. Once pushed,
 * deleting it is not enough: forks and clones already have it. So the check
 * runs before the push can matter, and fails loudly.
 */

/** Paths that are secrets, local state or build output by their name alone. */
const FORBIDDEN_PATHS = [
  // The current names and the ones used under the project's earlier names.
  [/(^|\/)\.(deedwrit|vouchwell|proofwire)\/(key\.pem|salts\.jsonl)$/, "a Deedwrit log's signing key or commitment salts"],
  [/(^|\/)\.(deedwrit|vouchwell|proofwire)-witness\//, "a witness's private state"],
  [/\.(pem|key|p12|pfx)$/i, 'a private key or certificate bundle'],
  [/(^|\/)\.env(\..*)?$/, 'an environment file'],
  [/\.(db|db-wal|db-shm|sqlite|sqlite3)$/i, 'a database file'],
  [/(^|\/)credentials\.json$/, 'a credentials file'],
  [/(^|\/)\.npmrc$/, 'an npm config, which can hold an auth token'],
  [/(^|\/)node_modules\//, 'installed dependencies'],
  [/(^|\/)data\//, "a hub's data directory"],
];

/** Secret shapes to look for inside text files. */
const SECRET_PATTERNS = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'a PEM private key'],
  [/\bnpm_[A-Za-z0-9]{36}\b/, 'an npm token'],
  [/\bgh[pousr]_[A-Za-z0-9]{36,}\b/, 'a GitHub token'],
  [/\bgithub_pat_[A-Za-z0-9_]{22,}\b/, 'a GitHub fine-grained token'],
  [/\bAKIA[0-9A-Z]{16}\b/, 'an AWS access key id'],
  [/\bsk-ant-[A-Za-z0-9_-]{16,}\b/, 'an Anthropic API key'],
  [/\bsk-(proj-)?[A-Za-z0-9]{32,}\b/, 'an OpenAI API key'],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, 'a Slack token'],
];

/**
 * Deliberately fake values the tests use to prove redaction works. Listed
 * exactly, so a real key never passes by resembling one.
 */
const KNOWN_FIXTURES = new Set([
  'AKIAIOSFODNN7EXAMPLE', // AWS's own documentation example
  'sk-ant-api03-Xk92mQvT1pLs8fR4nB6yH0jW',
  'sk-ant-api03-abcdefghijklmnop12345',
]);

const MAX_BYTES = 1024 * 1024;
const BINARY = /\.(woff2?|ttf|otf|png|jpe?g|gif|ico|webp|pdf|zip|gz)$/i;

/**
 * @param {string} root   Repository root.
 * @param {string[]} files Tracked paths, relative to `root`, with `/` separators.
 * @returns {string[]} One message per problem; empty means clean.
 */
export function hygieneProblems(root, files) {
  /** @type {string[]} */
  const problems = [];
  for (const file of files) {
    for (const [pattern, what] of FORBIDDEN_PATHS) {
      if (pattern.test(file)) problems.push(`${file}: ${what} must not be committed`);
    }

    let bytes;
    try {
      bytes = fs.readFileSync(path.join(root, file));
    } catch {
      continue; // Deleted in the working tree; git will say so.
    }
    if (bytes.length > MAX_BYTES) {
      problems.push(`${file}: ${(bytes.length / 1024 / 1024).toFixed(1)} MB; nothing here should be over 1 MB`);
    }
    if (BINARY.test(file)) continue;

    const text = bytes.toString('utf8');
    for (const [pattern, what] of SECRET_PATTERNS) {
      const global = new RegExp(pattern.source, 'g');
      for (const m of text.matchAll(global)) {
        if (KNOWN_FIXTURES.has(m[0])) continue;
        const line = text.slice(0, m.index).split('\n').length;
        problems.push(`${file}:${line}: looks like ${what}`);
      }
    }
  }
  return problems;
}

/** @param {string} root */
export function trackedFiles(root) {
  return execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' }).split('\0').filter(Boolean);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const problems = hygieneProblems(root, trackedFiles(root));
  if (problems.length) {
    for (const p of problems) console.error(`✗ ${p}`);
    console.error(`\n${problems.length} problem(s). If one is a real secret, rotate it: removing it from the tree does not un-publish it.`);
    process.exit(1);
  }
  console.log('✓ repo hygiene: no secrets, keys, local state or oversized files tracked');
}
