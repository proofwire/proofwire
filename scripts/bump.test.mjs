import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { bumpFiles, versionProblems, compareVersions, hasSection, PACKAGES } from './bump.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** A copy of just the files a bump touches, taken from this repository. */
function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-bump-'));
  const copy = (/** @type {string} */ rel) => {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.copyFileSync(path.join(ROOT, rel), path.join(dir, rel));
  };
  for (const rel of ['package.json', 'CHANGELOG.md', 'sdk/python/pyproject.toml', 'sdk/python/src/vouchwell/__init__.py']) copy(rel);
  for (const p of PACKAGES) copy(`${p}/package.json`);
  return dir;
}

/** The version one minor above the repository's, whatever it is today. */
function nextMinor() {
  const [a, b] = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version.split('.').map(Number);
  return `${a}.${b + 1}.0`;
}

test('this repository is ready to release at its current version', () => {
  assert.deepEqual(versionProblems(ROOT).problems, []);
});

test('a bump moves every version, every internal pin, the Python SDK and the CHANGELOG together', () => {
  const dir = fixture();
  // Something to release, whatever state the real CHANGELOG is in.
  const log = path.join(dir, 'CHANGELOG.md');
  fs.writeFileSync(log, fs.readFileSync(log, 'utf8').replace(/^## Unreleased[ \t]*\n/m, '## Unreleased\n\n### Added\n\n- something\n\n'));
  const to = nextMinor();

  const { files } = bumpFiles(dir, to, '2030-01-02');
  assert.ok(files.includes('CHANGELOG.md'));
  assert.deepEqual(versionProblems(dir).problems, []);
  assert.equal(versionProblems(dir).version, to);
  for (const p of PACKAGES) {
    const pkg = JSON.parse(fs.readFileSync(path.join(dir, p, 'package.json'), 'utf8'));
    assert.equal(pkg.version, to, p);
    for (const [dep, v] of Object.entries(pkg.dependencies ?? {})) {
      if (dep.startsWith('@vouchwell/')) assert.equal(v, to, `${p} → ${dep}`);
    }
  }
  const changelog = fs.readFileSync(log, 'utf8');
  assert.match(changelog, new RegExp(`## Unreleased\\n\\n## ${to.replace(/\./g, '\\.')} — 2030-01-02\\n\\n### Added\\n\\n- something`));
  assert.match(fs.readFileSync(path.join(dir, 'sdk/python/pyproject.toml'), 'utf8'), new RegExp(`^version = "${to}"$`, 'm'));
});

test('a bump refuses to go backwards, to repeat itself, or to release nothing', () => {
  const dir = fixture();
  const current = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).version;
  assert.throws(() => bumpFiles(dir, current, '2030-01-01'), /not newer/);
  assert.throws(() => bumpFiles(dir, '0.0.1', '2030-01-01'), /not newer/);
  assert.throws(() => bumpFiles(dir, 'v1', '2030-01-01'), /not a version/);

  // An empty Unreleased section: nothing to say, so nothing to release.
  const log = path.join(dir, 'CHANGELOG.md');
  fs.writeFileSync(log, fs.readFileSync(log, 'utf8').replace(/^## Unreleased[\s\S]*?(?=^## \d)/m, '## Unreleased\n\n'));
  assert.throws(() => bumpFiles(dir, nextMinor(), '2030-01-01'), /nothing under "## Unreleased"/);
});

test('the release preflight names each kind of mismatch', () => {
  const dir = fixture();
  const cli = path.join(dir, 'packages/cli/package.json');
  const pkg = JSON.parse(fs.readFileSync(cli, 'utf8'));
  pkg.dependencies['@vouchwell/core'] = '0.0.1';
  fs.writeFileSync(cli, JSON.stringify(pkg, null, 2));
  const pyinit = path.join(dir, 'sdk/python/src/vouchwell/__init__.py');
  fs.writeFileSync(pyinit, fs.readFileSync(pyinit, 'utf8').replace(/__version__ = "[^"]+"/, '__version__ = "0.0.1"'));
  const problems = versionProblems(dir).problems.join('\n');
  assert.match(problems, /depends on @vouchwell\/core@0\.0\.1/);
  assert.match(problems, /Python SDK/);
});

test('a CHANGELOG section is matched by its exact version, nothing near it', () => {
  const log = '# Changelog\n\n## Unreleased\n\n## 0.4.0 — 2026-09-25\n\n## 0.40.1 — 2030-01-01\n## 1.0.0\r\n';
  assert.ok(hasSection(log, '0.4.0'));
  assert.ok(hasSection(log, '1.0.0'), 'a bare heading, with CRLF, counts');
  assert.equal(hasSection(log, '0.4'), false);
  assert.equal(hasSection(log, '0.40'), false);
  assert.equal(hasSection(log, '0x4y0'), false, 'dots are not wildcards');
});

test('versions compare numerically, not as text', () => {
  assert.ok(compareVersions('0.10.0', '0.9.0') > 0);
  assert.ok(compareVersions('1.0.0', '0.99.99') > 0);
  assert.equal(compareVersions('0.4.0', '0.4.0'), 0);
});
