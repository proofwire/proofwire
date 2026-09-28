import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { urlProblem } from '../src/remote-cmds.js';

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/bin.js');

/** @param {string[]} args */
function pw(args) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchwell-remote-'));
  const res = spawnSync(process.execPath, [BIN, ...args], {
    cwd: home,
    encoding: 'utf8',
    timeout: 20000,
    env: { ...process.env, HOME: home, USERPROFILE: home, NO_COLOR: '1' },
  });
  return { code: res.status, stderr: res.stderr + res.stdout, home };
}

test('a hub URL over plain HTTP to another machine is refused, and nothing is stored', () => {
  const res = pw(['remote', 'add', '--url', 'http://hub.example.com', '--token', 'pk_live_secret']);
  assert.equal(res.code, 2);
  assert.match(res.stderr, /plain HTTP/);
  assert.equal(fs.existsSync(path.join(res.home, '.vouchwell', 'credentials.json')), false);
});

test('which URLs may carry a token', () => {
  for (const ok of ['https://hub.acme.com', 'http://localhost:8787', 'http://127.0.0.1:8787', 'http://[::1]:8787', 'http://app.localhost']) {
    assert.equal(urlProblem(ok), null, ok);
  }
  for (const clear of ['http://hub.acme.com', 'http://10.0.0.5:8787', 'http://127.0.0.1.evil.example', 'http://localhost.evil.example']) {
    assert.equal(urlProblem(clear), 'cleartext', clear);
  }
  for (const junk of ['hub.acme.com', 'ftp://hub.acme.com', 'javascript:alert(1)']) {
    assert.equal(urlProblem(junk), 'invalid', junk);
  }
});

test('--insecure lets an operator choose plain HTTP knowingly', () => {
  // Nothing listens there, so the credential check fails, but it fails at
  // the network, past the refusal.
  const res = pw(['remote', 'add', '--url', 'http://192.0.2.1:9', '--token', 'pk', '--insecure']);
  assert.doesNotMatch(res.stderr, /plain HTTP/);
});
