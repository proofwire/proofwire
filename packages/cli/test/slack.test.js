import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Hub } from '../../server/src/app.js';
import { Auth } from '../../server/src/auth.js';

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/bin.js');
const SECRET = 'e3b0c44298fc1c149afbf4c8996fb924';

/** @type {any[]} */
const posted = [];
/** @type {http.Server} */
let slack;
/** @type {Hub} */
let hub;
let home = '';
let slackUrl = '';

before(async () => {
  slack = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      posted.push(JSON.parse(body));
      res.end('ok');
    });
  });
  await new Promise((r) => slack.listen(0, '127.0.0.1', r));
  const slackHost = `127.0.0.1:${/** @type {any} */ (slack.address()).port}`;
  slackUrl = `http://${slackHost}/services/T0/B0/x`;

  hub = new Hub({ database: ':memory:', checkpointEvery: 0, slackHosts: [slackHost] });
  const base = (await hub.listen(0)).url.replace('0.0.0.0', '127.0.0.1');
  const org = hub.store.createOrg({ slug: 'acme', name: 'Acme' });
  const token = new Auth(hub.store).createKey({ orgId: org.id, name: 'admin', scopes: ['admin', 'logs:read'] }).token;

  // A private home, so the stored credential goes nowhere real.
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'deedwrit-slack-cli-'));
  const add = await pw(['remote', 'add', '--url', base, '--token', token]);
  assert.equal(add.code, 0, add.out);
});

after(async () => {
  await hub.close();
  slack.close();
});

/**
 * Async, not spawnSync: the hub answering these requests runs in this process.
 *
 * @param {string[]} args
 * @param {Record<string, string>} [env]
 * @returns {Promise<{ code: number | null, out: string }>}
 */
function pw(args, env = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [BIN, ...args], {
      cwd: home,
      env: { ...process.env, HOME: home, USERPROFILE: home, NO_COLOR: '1', ...env },
    });
    let out = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (out += d));
    child.on('close', (code) => resolve({ code, out }));
  });
}

test('dw slack connects from the environment, reports without secrets, tests and disconnects', async () => {
  assert.match((await pw(['slack', 'status'])).out, /not connected/);

  const missing = await pw(['slack', 'connect']);
  assert.equal(missing.code, 2);
  assert.match(missing.out, /DEEDWRIT_SLACK_WEBHOOK_URL/);

  const connect = await pw(['slack', 'connect', '--approver', 'U024BE7LH'], {
    DEEDWRIT_SLACK_WEBHOOK_URL: slackUrl,
    DEEDWRIT_SLACK_SIGNING_SECRET: SECRET,
  });
  assert.equal(connect.code, 0, connect.out);
  assert.match(connect.out, /\/v1\/integrations\/slack\/interactions/);

  const status = await pw(['slack', 'status']);
  assert.match(status.out, /connected/);
  assert.match(status.out, /U024BE7LH/);
  assert.ok(!status.out.includes(SECRET) && !status.out.includes('/services/'), 'status printed a credential');

  assert.equal((await pw(['slack', 'test'])).code, 0);
  assert.match(posted.at(-1).text, /Deedwrit is connected/);

  const bad = await pw(['slack', 'connect', '--webhook-url', 'https://example.com/x', '--signing-secret', SECRET]);
  assert.equal(bad.code, 1);
  assert.match(bad.out, /webhookUrl must be on/);

  assert.match((await pw(['slack', 'disconnect'])).out, /Slack disconnected/);
  assert.match((await pw(['slack', 'status'])).out, /not connected/);
});
