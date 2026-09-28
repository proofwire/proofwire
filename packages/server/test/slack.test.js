import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHmac } from 'node:crypto';
import { generateIdentity } from '@vouchwell/core';
import { Hub } from '../src/app.js';
import { Auth } from '../src/auth.js';
import { verifySlackSignature, slackUrlProblem, approvalMessage, slackActor } from '../src/slack.js';
import { hubApprover } from '../../proxy/src/remote.js';

/**
 * Slack approvals, end to end against a real socket: the hub posts to a fake
 * Slack, and "Slack" clicks back with requests signed the way Slack signs
 * them. Nothing here talks to slack.com.
 */

/** A signing secret in Slack's format: 32 hex characters. */
const SECRET = 'e3b0c44298fc1c149afbf4c8996fb924';

/** Everything the fake Slack received, by path. */
const inbox = { webhook: /** @type {any[]} */ ([]), response: /** @type {any[]} */ ([]) };
/** @type {http.Server} */
let slack;
let slackHost = '';

/** @type {Hub} */
let hub;
let base = '';
const acme = { admin: '', agent: '', org: '' };
const globex = { admin: '', org: '' };

before(async () => {
  slack = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const which = req.url?.startsWith('/webhook') ? 'webhook' : 'response';
      inbox[which].push(JSON.parse(body));
      res.writeHead(req.url?.includes('fail') ? 500 : 200).end('ok');
    });
  });
  await new Promise((r) => slack.listen(0, '127.0.0.1', r));
  slackHost = `127.0.0.1:${/** @type {any} */ (slack.address()).port}`;

  hub = new Hub({
    database: ':memory:',
    checkpointEvery: 0,
    slackHosts: [slackHost],
    apiRate: { capacity: 100000, refillPerSec: 100000 },
    ingestRate: { capacity: 100000, refillPerSec: 100000 },
    authRate: { capacity: 100000, refillPerSec: 100000 },
  });
  base = (await hub.listen(0)).url.replace('0.0.0.0', '127.0.0.1');

  const auth = new Auth(hub.store);
  for (const [tenant, slug] of [[acme, 'acme'], [globex, 'globex']]) {
    const org = hub.store.createOrg({ slug, name: slug });
    tenant.org = org.id;
    tenant.admin = auth.createKey({ orgId: org.id, name: 'admin', scopes: ['admin', 'approvals:read', 'approvals:write'] }).token;
  }
  acme.agent = auth.createKey({
    orgId: acme.org,
    name: 'agent',
    scopes: ['receipts:write', 'logs:write', 'logs:read', 'approvals:read'],
  }).token;
  const id = generateIdentity().identity;
  const log = await api('POST', '/v1/logs', { token: acme.agent, body: { slug: 'payments', kid: id.kid, publicKey: id.publicKey } });
  assert.equal(log.status, 200);
});

after(async () => {
  await hub.close();
  slack.close();
});

/**
 * @param {string} method
 * @param {string} path
 * @param {{ token?: string, body?: any }} [opts]
 */
async function api(method, path, opts = {}) {
  const res = await fetch(base + path, {
    method,
    headers: {
      ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
      ...(opts.body !== undefined ? { 'content-type': 'application/json' } : {}),
    },
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

/**
 * A click, as Slack sends it: form-encoded `payload`, signed over the raw body.
 *
 * @param {object} payload
 * @param {{ secret?: string, ts?: number, tamper?: (raw: string) => string }} [opts]
 */
async function click(payload, opts = {}) {
  const raw = new URLSearchParams({ payload: JSON.stringify(payload) }).toString();
  const ts = String(opts.ts ?? Math.floor(Date.now() / 1000));
  const sig = 'v0=' + createHmac('sha256', opts.secret ?? SECRET).update(`v0:${ts}:${raw}`).digest('hex');
  const res = await fetch(base + '/v1/integrations/slack/interactions', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'x-slack-request-timestamp': ts,
      'x-slack-signature': sig,
    },
    body: opts.tamper ? opts.tamper(raw) : raw,
  });
  return res.status;
}

/** @param {string} approvalId @param {'vouchwell_approve'|'vouchwell_deny'|'proofwire_approve'|'proofwire_deny'} actionId @param {string} [user] */
const payloadFor = (approvalId, actionId, user = 'U024BE7LH') => ({
  type: 'block_actions',
  user: { id: user, username: 'dana' },
  team: { id: 'T0001' },
  actions: [{ action_id: actionId, value: approvalId, type: 'button' }],
  response_url: `http://${slackHost}/response/1`,
});

async function escalate(target = 'crm.refund') {
  const res = await api('POST', '/v1/approvals', {
    token: acme.agent,
    body: { log: 'payments', target, params: { amount: 12000, card: '[REDACTED:card]' }, reason: 'refund over $100', rules: ['refunds.large'], principal: 'ops@acme.test', agent: 'claude' },
  });
  assert.equal(res.status, 200);
  return res.json.id;
}

/** Wait for the fire-and-forget post to land. */
async function settle(list, n) {
  for (let i = 0; i < 100 && list.length < n; i++) await new Promise((r) => setTimeout(r, 10));
}

// ── the signature ──────────────────────────────────────────────────────────

test("Slack's documented signature example verifies, and any change to it does not", () => {
  // The worked example from https://api.slack.com/authentication/verifying-requests-from-slack
  const signingSecret = '8f742231b10e8888abcd99yyyzzz85a5';
  const timestamp = '1531420618';
  const rawBody =
    'token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c';
  const signature = 'v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503';
  const nowMs = 1531420618 * 1000;

  assert.ok(verifySlackSignature({ signingSecret, timestamp, signature, rawBody, nowMs }));
  assert.equal(verifySlackSignature({ signingSecret, timestamp, signature, rawBody: rawBody + 'x', nowMs }), false);
  assert.equal(verifySlackSignature({ signingSecret: signingSecret.replace('8', '9'), timestamp, signature, rawBody, nowMs }), false);
  // Six minutes later the same request is a replay.
  assert.equal(verifySlackSignature({ signingSecret, timestamp, signature, rawBody, nowMs: nowMs + 360_000 }), false);
  assert.equal(verifySlackSignature({ signingSecret, timestamp: undefined, signature, rawBody, nowMs }), false);
});

test('webhook URLs are limited to Slack, over HTTPS, with no credentials', () => {
  assert.equal(slackUrlProblem('https://hooks.slack.com/services/T0/B0/xyz'), null);
  assert.match(slackUrlProblem('http://hooks.slack.com/services/x') ?? '', /https/);
  assert.match(slackUrlProblem('https://169.254.169.254/latest/meta-data') ?? '', /hooks\.slack\.com/);
  assert.match(slackUrlProblem('https://hooks.slack.com.evil.example/x') ?? '', /hooks\.slack\.com/);
  assert.match(slackUrlProblem('https://user:pw@hooks.slack.com/x') ?? '', /credentials/);
  assert.match(slackUrlProblem('not a url') ?? '', /not a URL/);
});

test('the message escapes what it shows, and a Slack user is recorded by id', () => {
  const m = approvalMessage(
    { id: 'approval_1', target: 'crm.<b>', log: 'l', params: { note: '```<!channel>```' }, reason: '<!here> & more', rules: [], principal: '', agent: '', expiresAt: new Date().toISOString() },
    'https://hub.example/approvals',
  );
  const text = JSON.stringify(m);
  assert.ok(!text.includes('<!here>') && !text.includes('<!channel>'), 'a mention smuggled through the arguments would ping the channel');
  assert.ok(text.includes('&lt;!here&gt; &amp; more'));
  assert.equal(slackActor({ id: 'U024BE7LH', username: 'dana' }), 'slack:U024BE7LH (dana)');
  assert.equal(slackActor({ id: 'U1<script>', username: 'x y' }), 'slack:U1script (xy)');
});

// ── configuration ──────────────────────────────────────────────────────────

test('connecting Slack is for admins, validates what it stores, and never echoes the secrets', async () => {
  const body = { webhookUrl: `http://${slackHost}/webhook/acme`, signingSecret: SECRET, approvers: ['U024BE7LH', 'W0123ABC'] };
  assert.equal((await api('PUT', '/v1/integrations/slack', { token: acme.agent, body })).status, 403);
  assert.equal((await api('PUT', '/v1/integrations/slack', { token: acme.admin, body: { ...body, webhookUrl: 'https://example.com/x' } })).json.error.code, 'bad_webhook_url');
  assert.equal((await api('PUT', '/v1/integrations/slack', { token: acme.admin, body: { ...body, signingSecret: 'short' } })).json.error.code, 'bad_signing_secret');
  assert.equal((await api('PUT', '/v1/integrations/slack', { token: acme.admin, body: { ...body, approvers: ['dana'] } })).json.error.code, 'bad_approver');

  const set = await api('PUT', '/v1/integrations/slack', { token: acme.admin, body });
  assert.equal(set.status, 200);
  assert.match(set.json.interactionsUrl, /\/v1\/integrations\/slack\/interactions$/);

  const shown = await api('GET', '/v1/integrations/slack', { token: acme.admin });
  assert.equal(shown.json.configured, true);
  assert.equal(shown.json.webhookHost, slackHost);
  assert.ok(!JSON.stringify(shown.json).includes(SECRET), 'the signing secret was returned');
  assert.ok(!JSON.stringify(shown.json).includes('/webhook/acme'), 'the webhook URL was returned');

  const events = hub.store.events(acme.org, 50);
  const ev = events.find((e) => e.action === 'integration.slack.set');
  assert.ok(ev);
  assert.ok(!JSON.stringify(ev).includes(SECRET), 'the audit trail recorded the secret');

  // Another tenant's Slack is its own business.
  assert.equal((await api('GET', '/v1/integrations/slack', { token: globex.admin })).json.configured, false);

  const test_ = await api('POST', '/v1/integrations/slack/test', { token: acme.admin });
  assert.equal(test_.status, 200);
  assert.match(inbox.webhook.at(-1).text, /Vouchwell is connected/);
});

test("the console's settings show Slack as connected, and never the credentials", async () => {
  const auth = new Auth(hub.store);
  const user = auth.createUser({ email: 'owner@acme.test', password: 'a-long-enough-password' });
  auth.addMember(acme.org, user.id, 'owner');
  const login = await fetch(base + '/login', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ email: 'owner@acme.test', password: 'a-long-enough-password' }),
    redirect: 'manual',
  });
  const cookie = (login.headers.getSetCookie?.() ?? []).map((c) => c.split(';')[0]).join('; ');
  const html = await (await fetch(base + '/settings/integrations', { headers: { cookie } })).text();
  assert.match(html, /Slack approvals/);
  assert.match(html, /connected/);
  assert.match(html, /U024BE7LH/);
  assert.ok(!html.includes(SECRET), 'the signing secret is on the page');
  assert.ok(!html.includes('/webhook/acme'), 'the webhook URL is on the page');
  // Retention stays on the general tab.
  const general = await (await fetch(base + '/settings', { headers: { cookie } })).text();
  assert.match(general, /<h2>Retention<\/h2>/);
  assert.match(general, /kept on the hub<\/dt><dd><b>forever<\/b>/);
  assert.match(general, /href="\/settings\/integrations"/);
});

// ── the flow ───────────────────────────────────────────────────────────────

test('an escalation posts to Slack, a signed click approves it, and the agent sees who approved', async () => {
  const before_ = inbox.webhook.length;
  const approver = hubApprover({ url: base, token: acme.agent, log: 'payments', timeoutMs: 10_000 });
  const verdict = approver({
    target: 'crm.refund',
    params: { amount: 12000 },
    reason: 'refund over $100',
    rules: ['refunds.large'],
    actor: { principal: 'ops@acme.test', agent: 'claude', session: 's1' },
  });

  await settle(inbox.webhook, before_ + 1);
  const posted = inbox.webhook.at(-1);
  assert.match(posted.text, /Approval needed: crm\.refund/);
  const buttons = posted.blocks.find((b) => b.type === 'actions').elements;
  assert.deepEqual(buttons.map((b) => b.action_id), ['vouchwell_approve', 'vouchwell_deny']);
  const approvalId = buttons[0].value;

  const responses = inbox.response.length;
  assert.equal(await click(payloadFor(approvalId, 'vouchwell_approve')), 200);

  const result = await verdict;
  assert.equal(result.approved, true);
  assert.equal(result.by, 'slack:U024BE7LH (dana)');
  assert.equal(result.note, 'approved in Slack');

  // The Slack message is replaced with the outcome.
  await settle(inbox.response, responses + 1);
  assert.equal(inbox.response.at(-1).replace_original, true);
  assert.match(JSON.stringify(inbox.response.at(-1)), /Approved by slack:U024BE7LH/);

  const ev = hub.store.events(acme.org, 50).find((e) => e.action === 'approval.approved');
  assert.equal(ev.actor, 'slack:U024BE7LH (dana)');
});

test('buttons on messages posted before the rename still decide the right way', async () => {
  // Slack keeps old messages, and their buttons carry proofwire_* ids. Anything
  // that isn't an approve button is a denial, so an old Approve must approve.
  const approve = await escalate('crm.old-approve');
  assert.equal(await click(payloadFor(approve, 'proofwire_approve')), 200);
  assert.equal((await api('GET', `/v1/approvals/${approve}`, { token: acme.agent })).json.status, 'approved');
  const deny = await escalate('crm.old-deny');
  assert.equal(await click(payloadFor(deny, 'proofwire_deny')), 200);
  assert.equal((await api('GET', `/v1/approvals/${deny}`, { token: acme.agent })).json.status, 'denied');
});

test('a second click, or a click after the console decided, changes nothing and says who got there first', async () => {
  const id = await escalate();
  const first = inbox.response.length;
  assert.equal(await click(payloadFor(id, 'vouchwell_deny')), 200);
  await settle(inbox.response, first + 1);
  const n = inbox.response.length;
  assert.equal(await click(payloadFor(id, 'vouchwell_approve', 'W0123ABC')), 200);
  await settle(inbox.response, n + 1);
  assert.match(JSON.stringify(inbox.response.at(-1)), /Denied by slack:U024BE7LH.*before this click/);
  const row = (await api('GET', `/v1/approvals/${id}`, { token: acme.admin })).json;
  assert.equal(row.status, 'denied');
});

test('an unsigned, mis-signed, stale or altered click is refused and decides nothing', async () => {
  const id = await escalate();
  const ok = payloadFor(id, 'vouchwell_approve');
  assert.equal(await click(ok, { secret: 'f'.repeat(32) }), 401);
  assert.equal(await click(ok, { ts: Math.floor(Date.now() / 1000) - 3600 }), 401);
  assert.equal(await click(ok, { tamper: (raw) => raw.replace('vouchwell_approve', 'vouchwell_deny') }), 401);
  const unsigned = await fetch(base + '/v1/integrations/slack/interactions', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ payload: JSON.stringify(ok) }).toString(),
  });
  assert.equal(unsigned.status, 401);
  // A made-up id gets the same answer as a bad signature: no probing for ids.
  assert.equal(await click(payloadFor('approval_nope', 'vouchwell_approve')), 401);
  assert.equal((await api('GET', `/v1/approvals/${id}`, { token: acme.admin })).json.status, 'pending');
});

test("one org's signing secret cannot decide another org's approvals", async () => {
  // Globex connects its own Slack app, with its own secret.
  const globexSecret = 'a'.repeat(32);
  await api('PUT', '/v1/integrations/slack', { token: globex.admin, body: { webhookUrl: `http://${slackHost}/webhook/globex`, signingSecret: globexSecret } });
  const id = await escalate();
  assert.equal(await click(payloadFor(id, 'vouchwell_approve'), { secret: globexSecret }), 401);
  assert.equal((await api('GET', `/v1/approvals/${id}`, { token: acme.admin })).json.status, 'pending');
});

test('someone outside the approver list is told so, and the request stays pending', async () => {
  const id = await escalate();
  const n = inbox.response.length;
  assert.equal(await click(payloadFor(id, 'vouchwell_approve', 'U999OUTSIDER')), 200);
  await settle(inbox.response, n + 1);
  assert.equal(inbox.response.at(-1).response_type, 'ephemeral');
  assert.equal((await api('GET', `/v1/approvals/${id}`, { token: acme.admin })).json.status, 'pending');
  assert.ok(hub.store.events(acme.org, 50).some((e) => e.action === 'approval.refused' && e.actor.startsWith('slack:U999OUTSIDER')));
});

test('a response_url off Slack is not called, even on a validly signed click', async () => {
  const id = await escalate();
  const n = inbox.response.length;
  const p = { ...payloadFor(id, 'vouchwell_deny'), response_url: 'http://169.254.169.254/latest/meta-data' };
  assert.equal(await click(p), 200);
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(inbox.response.length, n);
  assert.equal((await api('GET', `/v1/approvals/${id}`, { token: acme.admin })).json.status, 'denied');
});

test('Slack being down never blocks an escalation', async () => {
  await api('PUT', '/v1/integrations/slack', { token: acme.admin, body: { webhookUrl: `http://${slackHost}/webhook/fail`, signingSecret: SECRET } });
  const warn = console.error;
  console.error = () => {};
  try {
    const t = performance.now();
    const id = await escalate();
    assert.ok(id);
    assert.ok(performance.now() - t < 1000);
    assert.equal((await api('POST', '/v1/integrations/slack/test', { token: acme.admin })).status, 502);
  } finally {
    console.error = warn;
  }
});

test('disconnecting stops the posts', async () => {
  assert.equal((await api('DELETE', '/v1/integrations/slack', { token: acme.admin })).json.removed, true);
  const n = inbox.webhook.length;
  await escalate();
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(inbox.webhook.length, n);
});

test('a witness-only node has no Slack routes at all', () => {
  const w = new Hub({ database: ':memory:', witnessOnly: true });
  assert.equal(w.router.routes.some((r) => r.raw.includes('slack')), false);
  w.close();
});
