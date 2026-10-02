import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { hygieneProblems, trackedFiles } from './repo-hygiene.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * A throwaway tree with exactly these files.
 *
 * @param {Record<string, string | Buffer>} files
 */
function fixture(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-hygiene-'));
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), body);
  }
  return { dir, list: Object.keys(files) };
}

/** @param {Record<string, string | Buffer>} files */
const problemsIn = (files) => {
  const { dir, list } = fixture(files);
  return hygieneProblems(dir, list);
};

// Assembled at runtime so this file does not itself look like it holds keys.
const PEM = '-----BEGIN ' + 'PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEI\n-----END PRIVATE KEY-----\n';
const NPM = 'npm_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8';
const GH = 'ghp_' + 'A'.repeat(36);

test('this repository is clean', () => {
  assert.deepEqual(hygieneProblems(ROOT, trackedFiles(ROOT)), []);
});

test("a log's signing key and salts are refused by path", () => {
  // Including a log made before the rename, in .proofwire/.
  const found = problemsIn({ '.vouchwell/key.pem': 'x', 'examples/.vouchwell/salts.jsonl': '', '.proofwire/key.pem': 'x' });
  assert.equal(found.filter((p) => /signing key or commitment salts/.test(p)).length, 3);
});

test('any private key or certificate bundle is refused by path, wherever it sits', () => {
  const found = problemsIn({ 'certs/server.pem': 'x', 'deploy/hub.key': 'x', 'signing.p12': 'x' });
  assert.equal(found.filter((p) => /private key or certificate bundle/.test(p)).length, 3, found.join('\n'));
});

test('environment, database, credential and npm config files are refused by path', () => {
  const found = problemsIn({
    '.env': 'A=1',
    '.env.production': 'A=1',
    'data/vouchwell.db': 'x',
    'hub.sqlite': 'x',
    'credentials.json': '{}',
    '.npmrc': '//registry.npmjs.org/:_authToken=x',
  });
  for (const f of ['.env', '.env.production', 'data/vouchwell.db', 'hub.sqlite', 'credentials.json', '.npmrc']) {
    assert.ok(found.some((p) => p.startsWith(`${f}:`)), `${f} should be refused`);
  }
});

test('secrets pasted into source are found, with the line they are on', () => {
  const found = problemsIn({ 'src/config.js': `const a = 1;\nconst key = \`${PEM}\`;\nconst t = '${NPM}';\nconst g = '${GH}';\n` });
  assert.ok(found.includes('src/config.js:2: looks like a PEM private key'), found.join('\n'));
  assert.ok(found.some((p) => p.startsWith('src/config.js:6:') && /npm token/.test(p)), found.join('\n'));
  assert.ok(found.some((p) => /GitHub token/.test(p)));
});

test("the tests' documented fake keys pass, and a real-looking neighbour does not", () => {
  assert.deepEqual(problemsIn({ 't.js': "'AKIAIOSFODNN7EXAMPLE'; 'sk-ant-api03-Xk92mQvT1pLs8fR4nB6yH0jW'" }), []);
  // One character off each fixture, assembled here for the same reason as PEM.
  const found = problemsIn({ 't.js': `'${'AKIA' + 'IOSFODNN7EXAMPLF'}'; '${'sk-ant-' + 'api03-Xk92mQvT1pLs8fR4nB6yH0jX'}'` });
  assert.equal(found.length, 2, found.join('\n'));
});

test('oversized files are refused, and binaries are not scanned as text', () => {
  const big = problemsIn({ 'dump.json': Buffer.alloc(1024 * 1024 + 1, 0x20) });
  assert.match(big[0], /over 1 MB/);
  assert.deepEqual(problemsIn({ 'site/fonts/x.woff2': Buffer.from(PEM) }), []);
});
