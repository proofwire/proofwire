import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { generateIdentity, buildReceipt, signReceipt, entryHash, GENESIS_PREV } from '@proof_wire/core';
import { Hub } from '../src/app.js';
import { Auth } from '../src/auth.js';

/**
 * The console's Integrations tab: an admin adds and removes outside witnesses
 * and event-stream destinations from the browser, with the same checks as the
 * API, and never sees a credential again once it's saved.
 */

const fast = { capacity: 1e5, refillPerSec: 1e5 };
/** @type {Hub} */ let hub;
/** @type {Hub} */ let witness;
/** @type {http.Server} */ let sink;
let base = '';
let witnessUrl = '';
let witnessToken = '';
let sinkUrl = '';
let sinkStatus = 200;
/** @type {string[]} */
const received = [];
let orgId = '';
let ownerCookie = '';
let auditorCookie = '';

/** @param {string} email */
async function signIn(email) {
  const res = await fetch(base + '/login', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ email, password: 'a-long-enough-password' }),
    redirect: 'manual',
  });
  return (res.headers.getSetCookie?.() ?? []).map((c) => c.split(';')[0]).join('; ');
}

before(async () => {
  witness = new Hub({ database: ':memory:', witnessOnly: true, apiRate: fast, authRate: fast });
  witnessUrl = (await witness.listen(0)).url.replace('0.0.0.0', '127.0.0.1');
  const wOrg = witness.store.createOrg({ slug: 'acme', name: 'Acme' });
  witnessToken = new Auth(witness.store).createKey({ orgId: wOrg.id, name: 'hub', scopes: ['witness:sign'] }).token;

  sink = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      received.push(body);
      res.writeHead(sinkStatus).end('{}');
    });
  });
  await new Promise((r) => sink.listen(0, '127.0.0.1', () => r(null)));
  sinkUrl = `http://127.0.0.1:${/** @type {any} */ (sink.address()).port}`;

  hub = new Hub({ database: ':memory:', checkpointEvery: 3, egressAllowPrivate: true, apiRate: fast, ingestRate: fast, authRate: fast });
  base = (await hub.listen(0)).url.replace('0.0.0.0', '127.0.0.1');
  const org = hub.store.createOrg({ slug: 'acme', name: 'Acme' });
  orgId = org.id;
  const auth = new Auth(hub.store);
  for (const [email, role] of [['owner@acme.test', 'owner'], ['auditor@acme.test', 'auditor']]) {
    const user = auth.createUser({ email, password: 'a-long-enough-password' });
    auth.addMember(org.id, user.id, role);
  }
  ownerCookie = await signIn('owner@acme.test');
  auditorCookie = await signIn('auditor@acme.test');

  // A log with a checkpoint, so there is something to witness.
  const agent = auth.createKey({ orgId: org.id, name: 'agent', scopes: ['receipts:write', 'logs:write'] }).token;
  const { identity } = generateIdentity();
  const call = (/** @type {string} */ m, /** @type {string} */ p, /** @type {any} */ body) => fetch(base + p, {
    method: m, headers: { authorization: `Bearer ${agent}`, 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  assert.equal((await call('POST', '/v1/logs', { slug: 'payments', kid: identity.kid, publicKey: identity.publicKey })).status, 200);
  let prev = GENESIS_PREV;
  const receipts = [0, 1, 2].map((seq) => {
    const { body } = buildReceipt({
      log: 'payments', seq, prev,
      actor: { agent: 'bot', runtime: 't', session: 's', principal: 'p' },
      action: { kind: 'tool_call', target: 'stripe.refund', params: { seq } },
      decision: { outcome: seq === 1 ? 'deny' : 'allow', policy: 'p', rules: [] }, result: null,
    });
    const r = signReceipt(identity, body);
    prev = entryHash(r);
    return r;
  });
  assert.equal((await call('POST', '/v1/logs/payments/receipts', { receipts })).status, 200);
  for (let i = 0; i < 50 && hub.store.checkpoints(orgId, hub.store.logBySlug(orgId, 'payments').id, 1).length === 0; i++) {
    await new Promise((r) => setTimeout(r, 20));
  }
});

after(async () => {
  await hub.close();
  await witness.close();
  await new Promise((r) => sink.close(r));
});

/** @param {string} path @param {string} [cookie] */
async function view(path, cookie = ownerCookie) {
  const res = await fetch(base + path, { headers: { cookie } });
  return { status: res.status, html: await res.text() };
}

/**
 * Submit a console form, as the browser would: same origin, with the session.
 * @param {string} path @param {Record<string, string>} [fields] @param {{ cookie?: string, origin?: string }} [opts]
 */
async function submit(path, fields = {}, opts = {}) {
  const res = await fetch(base + path, {
    method: 'POST',
    headers: { cookie: opts.cookie ?? ownerCookie, origin: opts.origin ?? base, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields),
    redirect: 'manual',
  });
  return { status: res.status, location: res.headers.get('location'), html: await res.text() };
}

test('settings has a General and an Integrations tab; Slack and SSO live on the second', async () => {
  const general = await view('/settings');
  assert.match(general.html, /href="\/settings\/integrations"/);
  assert.ok(!general.html.includes('Slack approvals'));
  const page = await view('/settings/integrations');
  assert.equal(page.status, 200);
  for (const h of ['Outside witnesses', 'Event streams', 'Slack approvals', 'Single sign-on']) assert.match(page.html, new RegExp(h));
  assert.match(page.html, /No outside witnesses/);
});

test('an admin adds a witness from the form; it signs at once, and its key is never shown back', async () => {
  const added = await submit('/settings/integrations/witnesses/add', { name: 'notary', url: witnessUrl, token: witnessToken });
  assert.equal(added.status, 303, added.html.slice(0, 300));
  assert.equal(added.location, '/settings/integrations?done=witness-added');
  const page = await view(added.location);
  assert.match(page.html, /Witness added/);
  assert.match(page.html, /<b>notary<\/b>/);
  assert.match(page.html, /payments at 3/, 'the latest checkpoint was sent and signed');
  assert.match(page.html, /pill allow">signing/);
  assert.ok(!page.html.includes(witnessToken), 'the witness token is on the page');

  // Refusals show on the page, not as JSON, and what was typed is escaped.
  const bad = await submit('/settings/integrations/witnesses/add', { name: 'x<script>', url: witnessUrl, token: 't' });
  assert.equal(bad.status, 400);
  assert.match(bad.html, /banner bad/);
  assert.match(bad.html, /x&lt;script&gt;/);
  assert.ok(!bad.html.includes('x<script>'));
  const gone = await submit('/settings/integrations/witnesses/add', { name: 'gone', url: 'http://127.0.0.1:1', token: 't' });
  assert.equal(gone.status, 422);
  assert.match(gone.html, /no witness answered/);
  // The first witness is untouched by the failed additions.
  assert.match((await view('/settings/integrations')).html, /<b>notary<\/b>/);

  assert.equal((await submit('/settings/integrations/witnesses/send')).location, '/settings/integrations?done=witnesses-sent');
  const removed = await submit('/settings/integrations/witnesses/notary/remove');
  assert.equal(removed.location, '/settings/integrations?done=witness-removed');
  assert.match((await view('/settings/integrations')).html, /No outside witnesses/);
  const events = hub.store.events(orgId).map((e) => e.action);
  assert.ok(events.includes('integration.witnesses.set') && events.includes('integration.witnesses.removed'));
});

test('a webhook destination shows its generated secret once; tokens never', async () => {
  const hook = await submit('/settings/integrations/streams/add', { name: 'soc', type: 'webhook', url: `${sinkUrl}/in`, receipts: 'blocked', audit: '1' });
  assert.equal(hook.status, 200);
  const secret = hook.html.match(/whsec_[A-Za-z0-9_-]+/)?.[0];
  assert.ok(secret, 'the generated secret is shown on the page it was made on');
  assert.ok(!(await view('/settings/integrations')).html.includes(secret), 'and never again');

  const splunk = await submit('/settings/integrations/streams/add', { name: 'splunk', type: 'splunk', url: sinkUrl, token: 'hec-secret-1', audit: '1' });
  assert.equal(splunk.location, '/settings/integrations?done=stream-added');
  const page = (await view('/settings/integrations')).html;
  assert.ok(!page.includes('hec-secret-1'));
  assert.match(page, /<b>soc<\/b>[\s\S]*receipts \(blocked\), audit/);

  const tested = await submit('/settings/integrations/streams/test');
  assert.equal(tested.status, 200);
  assert.match(tested.html, /<b>soc<\/b>: delivered a test event/);
  assert.match(tested.html, /<b>splunk<\/b>: delivered a test event/);
  assert.equal((await submit('/settings/integrations/streams/flush')).location, '/settings/integrations?done=streams-flushed');
  assert.match((await view('/settings/integrations')).html, /pill allow">delivering/);

  // A destination that fails says so, with the reason.
  sinkStatus = 503;
  await hub.streams.poke(orgId);
  await submit('/settings/integrations/streams/add', { name: 'dd', type: 'datadog', url: sinkUrl, token: 'k', backfill: '1' });
  await submit('/settings/integrations/streams/flush');
  const failing = (await view('/settings/integrations')).html;
  assert.match(failing, /pill deny">retrying[\s\S]*HTTP 503/);
  sinkStatus = 200;

  assert.equal((await submit('/settings/integrations/streams/dd/remove')).location, '/settings/integrations?done=stream-removed');
  const missing = await submit('/settings/integrations/streams/nope/remove');
  assert.equal(missing.status, 404);
  assert.match(missing.html, /no destination named/);
});

test('a log this hub\'s witness holds after a restore is shown, with the operator\'s command, and no button', async () => {
  hub.store.holdWitnessLog(hub.witnessSigner.kid, `${orgId}:payments`, 'restored_without_journal');
  const page = (await view('/settings/integrations')).html;
  assert.match(page, /holding 1 log\(s\)/);
  assert.match(page, /proofwire-hub witness-release/);
  assert.ok(!/action="[^"]*release/.test(page), 'releasing is the witness operator\'s, not the log owner\'s');
  hub.store.releaseWitnessLog(hub.witnessSigner.kid, `${orgId}:payments`);
});

test('only admins see or change integrations, and only from the console itself', async () => {
  const page = await view('/settings/integrations', auditorCookie);
  assert.match(page.html, /Only admins/);
  assert.ok(!page.html.includes('Event streams'));
  const denied = await submit('/settings/integrations/streams/add', { name: 'x', type: 'webhook', url: sinkUrl }, { cookie: auditorCookie });
  assert.equal(denied.status, 403);

  const forged = await submit('/settings/integrations/streams/add', { name: 'x', type: 'webhook', url: sinkUrl }, { origin: 'https://evil.example' });
  assert.equal(forged.status, 403, 'a cross-site form post is refused');
  assert.ok(!hub.streams.destinations(orgId).some((d) => d.name === 'x'));

  // A done code the page doesn't know is ignored, not reflected.
  const odd = await view('/settings/integrations?done=%3Cscript%3Ealert(1)%3C%2Fscript%3E');
  assert.ok(!odd.html.includes('<script>'));
  assert.ok(!/banner" role="status"/.test(odd.html));
});
