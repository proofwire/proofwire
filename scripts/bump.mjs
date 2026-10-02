#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { launchSpec } from '../packages/proxy/src/proxy.js';

/**
 * Move every version in the repository to a new release, in one step:
 *
 *     npm run bump -- 0.4.0
 *
 * The five npm packages release together, pin each other exactly, and the
 * Python SDK follows the same number. Bumping them by hand is how a release
 * ends up re-running the last one: `npm run release` found 0.3.0 already on
 * the registry and skipped everything. This changes, together:
 *
 *   - "version" in the root package.json and each packages/<name>/package.json
 *   - every "@deedwrit/<name>" dependency pin between them
 *   - sdk/python/pyproject.toml and deedwrit/__init__.py
 *   - CHANGELOG.md: the "Unreleased" section becomes "<version> — <date>",
 *     with a fresh empty "Unreleased" above it
 *   - package-lock.json, via npm, so the lockfile agrees
 */

export const PACKAGES = ['packages/core', 'packages/proxy', 'packages/cli', 'packages/dashboard', 'packages/server'];
const SEMVER = /^(\d+)\.(\d+)\.(\d+)$/;

/**
 * @param {string} a
 * @param {string} b
 * @returns {number} negative, zero or positive, as a sort comparator
 */
export function compareVersions(a, b) {
  const pa = SEMVER.exec(a);
  const pb = SEMVER.exec(b);
  if (!pa || !pb) throw new Error(`not a version: ${!pa ? a : b}`);
  for (let i = 1; i <= 3; i++) {
    const d = Number(pa[i]) - Number(pb[i]);
    if (d) return d;
  }
  return 0;
}

/**
 * Whether the CHANGELOG has a heading for exactly this version, as in
 * "## 0.4.0 — 2026-09-25". A line comparison, not a regex built from the
 * version, so nothing in the version is ever read as pattern syntax.
 *
 * @param {string} log
 * @param {string} version
 */
export function hasSection(log, version) {
  const heading = `## ${version}`;
  return log.split(/\r?\n/).some((line) => line === heading || line.startsWith(`${heading} `));
}

/**
 * @param {string} file
 * @param {(json: any) => void} change
 */
function editJson(file, change) {
  const text = fs.readFileSync(file, 'utf8');
  const json = JSON.parse(text);
  change(json);
  fs.writeFileSync(file, JSON.stringify(json, null, 2) + (text.endsWith('\n') ? '\n' : ''));
}

/**
 * @param {string} file
 * @param {RegExp} pattern  Must match exactly once.
 * @param {string} replacement
 */
function editText(file, pattern, replacement) {
  const text = fs.readFileSync(file, 'utf8');
  const matches = text.match(new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g'));
  if (!matches || matches.length !== 1) {
    throw new Error(`${path.basename(file)}: expected one match for ${pattern}, found ${matches?.length ?? 0}`);
  }
  fs.writeFileSync(file, text.replace(pattern, replacement));
}

/**
 * Rewrite every version-bearing file under `root`. Pure file edits, no npm;
 * tests call this on a fixture.
 *
 * @param {string} root
 * @param {string} version
 * @param {string} date  YYYY-MM-DD, for the CHANGELOG heading
 * @returns {{ from: string, to: string, files: string[] }}
 */
export function bumpFiles(root, version, date) {
  if (!SEMVER.test(version)) throw new Error(`"${version}" is not a version like 0.4.0`);
  const current = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
  if (compareVersions(version, current) <= 0) {
    throw new Error(`${version} is not newer than the current ${current}`);
  }

  const changelog = path.join(root, 'CHANGELOG.md');
  const log = fs.readFileSync(changelog, 'utf8');
  if (hasSection(log, version)) {
    throw new Error(`CHANGELOG.md already has a ${version} section`);
  }
  const unreleased = /^## Unreleased[ \t]*\r?\n([\s\S]*?)(?=^## )/m.exec(log);
  if (!unreleased || !unreleased[1].trim()) {
    throw new Error('CHANGELOG.md has nothing under "## Unreleased": say what this release changes first');
  }

  const files = [];
  const internal = new Set(PACKAGES.map((p) => JSON.parse(fs.readFileSync(path.join(root, p, 'package.json'), 'utf8')).name));

  for (const rel of ['.', ...PACKAGES]) {
    const file = path.join(root, rel, 'package.json');
    editJson(file, (pkg) => {
      pkg.version = version;
      for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
        for (const dep of Object.keys(pkg[field] ?? {})) {
          if (internal.has(dep)) pkg[field][dep] = version;
        }
      }
    });
    files.push(path.relative(root, file).split(path.sep).join('/'));
  }

  const pyproject = path.join(root, 'sdk/python/pyproject.toml');
  if (fs.existsSync(pyproject)) {
    editText(pyproject, /^version = "[^"]+"$/m, `version = "${version}"`);
    editText(path.join(root, 'sdk/python/src/deedwrit/__init__.py'), /^__version__ = "[^"]+"$/m, `__version__ = "${version}"`);
    files.push('sdk/python/pyproject.toml', 'sdk/python/src/deedwrit/__init__.py');
  }

  fs.writeFileSync(changelog, log.replace(/^## Unreleased[ \t]*\r?\n/m, `## Unreleased\n\n## ${version} — ${date}\n`));
  files.push('CHANGELOG.md');

  return { from: current, to: version, files };
}

/**
 * Why the files under `root` are not ready to release at their current
 * version; empty when they are. The release script refuses to publish
 * while this has anything in it.
 *
 * @param {string} root
 * @returns {{ version: string, problems: string[] }}
 */
export function versionProblems(root) {
  const read = (/** @type {string} */ rel) => JSON.parse(fs.readFileSync(path.join(root, rel, 'package.json'), 'utf8'));
  const version = read('.').version;
  const problems = [];
  const internal = new Set(PACKAGES.map((p) => read(p).name));

  for (const rel of PACKAGES) {
    const pkg = read(rel);
    if (pkg.version !== version) problems.push(`${pkg.name} is at ${pkg.version}, the workspace at ${version}`);
    for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
      for (const [dep, want] of Object.entries(pkg[field] ?? {})) {
        if (internal.has(dep) && want !== version) {
          problems.push(`${pkg.name} depends on ${dep}@${want}, not ${version}: it would install the old one`);
        }
      }
    }
  }

  const log = fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8');
  if (!hasSection(log, version)) {
    problems.push(`CHANGELOG.md has no "## ${version}" section`);
  }

  const pyproject = path.join(root, 'sdk/python/pyproject.toml');
  if (fs.existsSync(pyproject)) {
    const py = /^version = "([^"]+)"$/m.exec(fs.readFileSync(pyproject, 'utf8'))?.[1];
    const init = /^__version__ = "([^"]+)"$/m.exec(fs.readFileSync(path.join(root, 'sdk/python/src/deedwrit/__init__.py'), 'utf8'))?.[1];
    if (py !== version || init !== version) problems.push(`the Python SDK is at ${py} / ${init}, not ${version}`);
  }
  return { version, problems };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const version = process.argv[2];
  if (!version) {
    console.error('usage: npm run bump -- <version>      e.g. npm run bump -- 0.4.0');
    process.exit(2);
  }
  try {
    // The maintainer's own date, not UTC's: a release cut on the morning of
    // the 25th in India is dated the 25th.
    const now = new Date();
    const local = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
    const { from, to, files } = bumpFiles(root, version, local);
    // The lockfile records each workspace's version; npm keeps it consistent.
    const spec = launchSpec('npm', ['install', '--package-lock-only', '--no-audit', '--no-fund']);
    execFileSync(spec.command, spec.args, { cwd: root, stdio: 'inherit', shell: spec.shell });
    console.log(`\n  ${from} → ${to}\n`);
    for (const f of [...files, 'package-lock.json']) console.log(`    ${f}`);
    console.log('\n  Next: review the diff, commit it, then `npm run release`.\n');
  } catch (err) {
    console.error(`\n  ✗ ${/** @type {Error} */ (err).message}\n`);
    process.exit(1);
  }
}
