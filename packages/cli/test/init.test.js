import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/bin.js');

test('vw init never overwrites an existing policy or config', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchwell-init-'));
  fs.writeFileSync(path.join(cwd, 'vouchwell.policy.json'), 'MINE');
  fs.writeFileSync(path.join(cwd, 'vouchwell.config.json'), 'MINE TOO');
  const res = spawnSync(process.execPath, [BIN, 'init'], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, HOME: cwd, USERPROFILE: cwd, NO_COLOR: '1' },
  });
  assert.equal(res.status, 0, res.stderr);
  assert.equal(fs.readFileSync(path.join(cwd, 'vouchwell.policy.json'), 'utf8'), 'MINE');
  assert.equal(fs.readFileSync(path.join(cwd, 'vouchwell.config.json'), 'utf8'), 'MINE TOO');
  assert.match(fs.readFileSync(path.join(cwd, '.gitignore'), 'utf8'), /\.vouchwell\/key\.pem/);
});
