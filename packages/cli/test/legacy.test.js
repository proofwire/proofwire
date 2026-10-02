import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/**
 * A project set up under an earlier name, Proofwire (0.5.0 and before) or the
 * interim Vouchwell: `.<name>/`, `<name>.config.json`, `<name>.policy.json`
 * and `~/.<name>/credentials.json`. It keeps working without being touched.
 */
const EARLIER = ['proofwire', 'vouchwell'];

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, '../src/bin.js');
const SERVER = path.resolve(HERE, '../../../examples/fake-mcp-server.js');

/** @param {string} cwd @param {string[]} args @param {string} [input] */
function dw(cwd, args, input) {
  const clean = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(DEEDWRIT|VOUCHWELL|PROOFWIRE)_/.test(k)));
  const res = spawnSync(process.execPath, [BIN, ...args], {
    cwd, input, encoding: 'utf8', env: { ...clean, HOME: cwd, USERPROFILE: cwd, NO_COLOR: '1' },
  });
  return { status: res.status, out: res.stdout + res.stderr };
}

/** Lay a fresh project out the way an earlier name named things. @param {string} name */
function oldProject(name) {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'dw-legacy-cli-'));
  assert.equal(dw(cwd, ['init']).status, 0);
  fs.renameSync(path.join(cwd, '.deedwrit'), path.join(cwd, `.${name}`));
  fs.renameSync(path.join(cwd, 'deedwrit.policy.json'), path.join(cwd, `${name}.policy.json`));
  const config = JSON.parse(fs.readFileSync(path.join(cwd, 'deedwrit.config.json'), 'utf8'));
  fs.rmSync(path.join(cwd, 'deedwrit.config.json'));
  fs.writeFileSync(path.join(cwd, `${name}.config.json`), JSON.stringify({ ...config, log: `.${name}`, policy: `${name}.policy.json` }));
  return cwd;
}

for (const name of EARLIER) test(`a ${name} project records, verifies and stays in its own folder`, () => {
  const cwd = oldProject(name);
  try {
    const call = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'lookup', arguments: { id: 1 } } });
    const proxied = dw(cwd, ['proxy', '--namespace', 'ops', '--', process.execPath, SERVER], call + '\n');
    assert.equal(proxied.status, 0, proxied.out);
    const verified = dw(cwd, ['verify']);
    assert.equal(verified.status, 0, verified.out);
    assert.match(verified.out, /entries\s+2/, `the call was recorded in .${name}: its intent and its outcome`);
    assert.ok(!fs.existsSync(path.join(cwd, '.deedwrit')), 'a second log was started beside the old one');

    // The same holds with no config file at all: the old folder is found.
    fs.rmSync(path.join(cwd, `${name}.config.json`));
    assert.equal(dw(cwd, ['verify']).status, 0);
    const again = dw(cwd, ['init']);
    assert.equal(again.status, 1);
    assert.match(again.out, new RegExp(`already exists at \\.${name}`));
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});

for (const name of EARLIER) test(`hubs saved in ~/.${name} are still known`, () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'dw-legacy-creds-'));
  try {
    fs.mkdirSync(path.join(cwd, `.${name}`), { recursive: true });
    fs.writeFileSync(path.join(cwd, `.${name}`, 'credentials.json'), JSON.stringify({ acme: { url: 'https://hub.acme.test', token: 'pwk_legacy' } }));
    const list = dw(cwd, ['remote', 'list']);
    assert.equal(list.status, 0, list.out);
    assert.match(list.out, /acme/);
    assert.match(list.out, /hub\.acme\.test/);
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});
