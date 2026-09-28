import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/**
 * A project set up before the rename from Proofwire: `.proofwire/`,
 * `proofwire.config.json`, `proofwire.policy.json` and
 * `~/.proofwire/credentials.json`. It keeps working without being touched.
 */

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, '../src/bin.js');
const SERVER = path.resolve(HERE, '../../../examples/fake-mcp-server.js');

/** @param {string} cwd @param {string[]} args @param {string} [input] */
function vw(cwd, args, input) {
  const clean = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(VOUCHWELL|PROOFWIRE)_/.test(k)));
  const res = spawnSync(process.execPath, [BIN, ...args], {
    cwd, input, encoding: 'utf8', env: { ...clean, HOME: cwd, USERPROFILE: cwd, NO_COLOR: '1' },
  });
  return { status: res.status, out: res.stdout + res.stderr };
}

/** Lay a fresh project out the way 0.5.0 named things. */
function oldProject() {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'vw-legacy-cli-'));
  assert.equal(vw(cwd, ['init']).status, 0);
  fs.renameSync(path.join(cwd, '.vouchwell'), path.join(cwd, '.proofwire'));
  fs.renameSync(path.join(cwd, 'vouchwell.policy.json'), path.join(cwd, 'proofwire.policy.json'));
  const config = JSON.parse(fs.readFileSync(path.join(cwd, 'vouchwell.config.json'), 'utf8'));
  fs.rmSync(path.join(cwd, 'vouchwell.config.json'));
  fs.writeFileSync(path.join(cwd, 'proofwire.config.json'), JSON.stringify({ ...config, log: '.proofwire', policy: 'proofwire.policy.json' }));
  return cwd;
}

test('a project from before the rename records, verifies and stays in its own folder', () => {
  const cwd = oldProject();
  try {
    const call = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'lookup', arguments: { id: 1 } } });
    const proxied = vw(cwd, ['proxy', '--namespace', 'ops', '--', process.execPath, SERVER], call + '\n');
    assert.equal(proxied.status, 0, proxied.out);
    const verified = vw(cwd, ['verify']);
    assert.equal(verified.status, 0, verified.out);
    assert.match(verified.out, /entries\s+2/, 'the call was recorded in .proofwire: its intent and its outcome');
    assert.ok(!fs.existsSync(path.join(cwd, '.vouchwell')), 'a second log was started beside the old one');

    // The same holds with no config file at all: the old folder is found.
    fs.rmSync(path.join(cwd, 'proofwire.config.json'));
    assert.equal(vw(cwd, ['verify']).status, 0);
    const again = vw(cwd, ['init']);
    assert.equal(again.status, 1);
    assert.match(again.out, /already exists at \.proofwire/);
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});

test('hubs saved in ~/.proofwire are still known, and new saves go to ~/.vouchwell', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'vw-legacy-creds-'));
  try {
    fs.mkdirSync(path.join(cwd, '.proofwire'), { recursive: true });
    fs.writeFileSync(path.join(cwd, '.proofwire', 'credentials.json'), JSON.stringify({ acme: { url: 'https://hub.acme.test', token: 'pwk_legacy' } }));
    const list = vw(cwd, ['remote', 'list']);
    assert.equal(list.status, 0, list.out);
    assert.match(list.out, /acme/);
    assert.match(list.out, /hub\.acme\.test/);
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});
