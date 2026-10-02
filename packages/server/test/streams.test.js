import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHmac } from 'node:crypto';
import { generateIdentity, buildReceipt, signReceipt, entryHash, GENESIS_PREV } from '@deedwrit/core';
import { Hub } from '../src/app.js';
import { Auth } from '../src/auth.js';

/**
 * Event streaming, end to end: a hub sends to a local server that plays a
 * webhook receiver, Splunk's HEC, Datadog's intake and an OTLP collector.
 */

const fast = { capacity: 1e5, refillPerSec: 1e5 };
/** @type {{ path: string, headers: http.IncomingHttpHeaders, body: string }[]} */
let seen = [];
let failWith = 0;
let sink = '';
/** @type {http.Server} */
let server;

before(async () => {
  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      if (failWith) {
        res.writeHead(failWith).end('{"error":"down for maintenance"}');
        return;
      }
      seen.push({ path: String(req.url), headers: req.headers, body });
      res.writeHead(req.url?.startsWith('/api/v2/logs') ? 202 : 200, { 'content-type': 'application/json' }).end('{}');
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', () => r(null)));
  sink = `http://127.0.0.1:${/** @type {any} */ (server.address()).port}`;
});
after(() => new Promise((r) => server.close(r)));

/** @param {object} [opts] */
async function startHub(opts = {}) {
  const hub = new Hub({ database: ':memory:', checkpointEvery: 0, egressAllowPrivate: true, apiRate: fast, ingestRate: fast, authRate: fast, ...opts });
  const base = (await hub.listen(0)).url.replace('0.0.0.0', '127.0.0.1');
  let org = hub.store.orgBySlug('acme');
  const fresh = !org;
  if (!org) org = hub.store.createOrg({ slug: 'acme', name: 'Acme' });
  const auth = new Auth(hub.store);
  const admin = auth.createKey({ orgId: org.id, name: 'admin', scopes: ['admin'] }).token;
  const agent = auth.createKey({ orgId: org.id, name: 'agent', scopes: ['receipts:write', 'logs:write', 'logs:read'] }).token;
  /** @param {string} method @param {string} p @param {string} token @param {any} [body] */
  const api = async (method, p, token, body) => {
    const res = await fetch(base + p, {
      method,
      headers: { authorization: `Bearer ${token}`, ...(body ? { 'content-type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, json: await res.json().catch(() => null) };
  };
  return { hub, api, admin, agent, fresh };
}

/** An agent with a log on the hub. */
async function agentLog(/** @type {any} */ h, slug = 'payments') {
  const identity = generateIdentity().identity;
  const a = { identity, seq: 0, prev: GENESIS_PREV };
  assert.equal((await h.api('POST', '/v1/logs', h.agent, { slug, kid: identity.kid, publicKey: identity.publicKey })).status, 200);
  /** @param {('allow'|'deny'|'escalate')[]} outcomes */
  return async (outcomes) => {
    const receipts = outcomes.map((outcome) => {
      const { body } = buildReceipt({
        log: slug, seq: a.seq, prev: a.prev,
        actor: { agent: 'bot', runtime: 'test', session: 's1', principal: 'p@acme.test' },
        action: { kind: 'tool_call', target: 'stripe.refund', params: { card: '4242 4242 4242 4242', amount: a.seq } },
        decision: { outcome, policy: 'pol', rules: outcome === 'allow' ? [] : ['payments.big'], reason: outcome === 'allow' ? undefined : 'over the limit' },
        result: null,
      });
      const r = signReceipt(identity, body);
      a.seq++;
      a.prev = entryHash(r);
      return r;
    });
    const res = await h.api('POST', `/v1/logs/${slug}/receipts`, h.agent, { receipts });
    assert.equal(res.status, 200, JSON.stringify(res.json));
  };
}

const all = (/** @type {string} */ name) => ({
  webhook: { name, type: 'webhook', url: `${sink}/hooks/${name}` },
  splunk: { name, type: 'splunk', url: sink, token: 'hec-token-1' },
  datadog: { name, type: 'datadog', url: sink, token: 'dd-key-1' },
  otlp: { name, type: 'otlp', url: sink, headers: { authorization: 'Bearer otel-1' } },
});

test('each destination gets receipts and audit events in its own format, without the action\'s parameters', async () => {
  seen = [];
  const h = await startHub();
  try {
    const set = await h.api('PUT', '/v1/integrations/streams', h.admin, {
      destinations: [all('hook').webhook, all('splunk').splunk, all('dd').datadog, all('otel').otlp],
    });
    assert.equal(set.status, 200, JSON.stringify(set.json));
    const secret = set.json.secrets.hook;
    assert.match(secret, /^whsec_/);

    const push = await agentLog(h);
    await push(['allow', 'deny', 'escalate']);
    const flushed = await h.api('POST', '/v1/integrations/streams/flush', h.admin);
    for (const d of flushed.json.destinations) assert.equal(d.pending, 0, `${d.name}: ${d.lastError}`);

    // The card number as written, spaces included: hashes and nanosecond
    // timestamps are hex and digits, so plain '4242' turns up in them by chance.
    assert.ok(!seen.some((s) => s.body.includes('4242 4242')), 'parameters must never leave the hub');

    // Events can arrive over several requests (the audit event of adding the
    // destinations may go out before the receipts exist), so gather them all.
    const at = (/** @type {string} */ p) => seen.filter((s) => s.path === p);

    // Webhook: {events}, each request signed over the timestamp and the exact body.
    const hooks = at('/hooks/hook');
    assert.ok(hooks.length);
    for (const hook of hooks) {
      const [, t, v1] = /** @type {RegExpMatchArray} */ (String(hook.headers['deedwrit-signature']).match(/^t=(\d+),v1=([0-9a-f]{64})$/));
      assert.equal(v1, createHmac('sha256', secret).update(`${t}.${hook.body}`).digest('hex'));
    }
    const events = hooks.flatMap((h) => JSON.parse(h.body).events);
    const receipts = events.filter((/** @type {any} */ e) => e.type === 'receipt');
    assert.deepEqual(receipts.map((/** @type {any} */ e) => e.outcome), ['allow', 'deny', 'escalate']);
    assert.deepEqual(receipts[1].rules, ['payments.big']);
    assert.equal(receipts[1].reason, 'over the limit');
    assert.equal(receipts[1].org, 'acme');
    assert.equal(receipts[1].id, 'payments:1');
    assert.ok(events.some((/** @type {any} */ e) => e.type === 'audit' && e.action === 'integration.streams.set'));

    // Splunk: HEC path and scheme, events back to back.
    const splunk = at('/services/collector/event');
    assert.ok(splunk.length && splunk.every((r) => r.headers.authorization === 'Splunk hec-token-1'));
    const hec = splunk.flatMap((r) => r.body.split('\n').map((l) => JSON.parse(l)));
    assert.ok(hec.every((e) => e.source === 'deedwrit' && typeof e.time === 'number' && e.event.type));
    assert.ok(hec.some((e) => e.sourcetype === 'deedwrit:receipt'));

    // Datadog: logs intake v2, a JSON array, key in the header.
    const dd = at('/api/v2/logs');
    assert.ok(dd.length && dd.every((r) => r.headers['dd-api-key'] === 'dd-key-1'));
    const logs = dd.flatMap((r) => JSON.parse(r.body));
    const denied = logs.find((/** @type {any} */ l) => l.outcome === 'deny');
    assert.equal(denied.ddsource, 'deedwrit');
    assert.equal(denied.status, 'warn');
    assert.match(denied.ddtags, /outcome:deny/);
    assert.equal(denied.message, 'deny tool_call stripe.refund by bot (payments#1)');

    // OpenTelemetry: OTLP/HTTP JSON, with the collector's own headers.
    const otel = at('/v1/logs');
    assert.ok(otel.length && otel.every((r) => r.headers.authorization === 'Bearer otel-1'));
    const records = otel.flatMap((r) => JSON.parse(r.body).resourceLogs[0].scopeLogs[0].logRecords);
    const warn = records.find((/** @type {any} */ r) => r.severityText === 'WARN');
    assert.match(warn.timeUnixNano, /^\d{19}$/);
    assert.ok(warn.attributes.some((/** @type {any} */ a) => a.key === 'deedwrit.outcome' && a.value.stringValue === 'deny'));
    assert.ok(warn.attributes.some((/** @type {any} */ a) => a.key === 'deedwrit.seq' && a.value.intValue === '1'));

    // Nothing sent twice once delivered.
    const before = seen.length;
    assert.equal((await h.api('POST', '/v1/integrations/streams/flush', h.admin)).status, 200);
    assert.equal(seen.length, before);
  } finally {
    await h.hub.close();
  }
});

test('credentials are write-only, and changing a filter keeps them', async () => {
  seen = [];
  const h = await startHub();
  try {
    const first = await h.api('PUT', '/v1/integrations/streams', h.admin, { destinations: [all('s').splunk, { ...all('h').webhook, secret: 'a-secret-of-sixteen+' }] });
    assert.equal(first.status, 200);
    assert.equal(first.json.secrets, undefined, 'a secret the admin chose is not echoed');
    const got = await h.api('GET', '/v1/integrations/streams', h.admin);
    const text = JSON.stringify(got.json);
    assert.ok(!text.includes('hec-token-1') && !text.includes('a-secret-of-sixteen+'), text);
    assert.equal(got.json.destinations[0].token, 'set');
    assert.equal((await h.api('GET', '/v1/integrations/streams', h.agent)).status, 403);

    // Same name and type, no token: the old one stays.
    const again = await h.api('PUT', '/v1/integrations/streams', h.admin, {
      destinations: [{ name: 's', type: 'splunk', url: sink, receipts: 'blocked' }, { name: 'h', type: 'webhook', url: `${sink}/hooks/h` }],
    });
    assert.equal(again.status, 200, JSON.stringify(again.json));
    assert.equal((await h.api('POST', '/v1/integrations/streams/test', h.admin)).json.results.every((/** @type {any} */ r) => r.ok), true);
    assert.equal(seen.find((s) => s.path === '/services/collector/event')?.headers.authorization, 'Splunk hec-token-1');

    for (const [bad, code] of /** @type {[any, string][]} */ ([
      [{ name: 'x', type: 'kafka', url: sink }, 'bad_destination_type'],
      [{ name: 'x', type: 'splunk', url: sink }, 'missing_token'],
      [{ name: 'X!', type: 'webhook', url: sink }, 'bad_destination_name'],
      [{ name: 'x', type: 'webhook', url: sink, secret: 'short' }, 'weak_secret'],
      [{ name: 'x', type: 'otlp', url: sink, headers: { host: 'evil' } }, 'bad_headers'],
      [{ name: 'x', type: 'otlp', url: sink, headers: { 'x-a': 'b\r\nx-c: d' } }, 'bad_headers'],
      [{ name: 'x', type: 'webhook', url: sink, receipts: 'some' }, 'bad_destination_filter'],
    ])) {
      assert.equal((await h.api('PUT', '/v1/integrations/streams', h.admin, { destinations: [bad] })).json.error.code, code, JSON.stringify(bad));
    }
  } finally {
    await h.hub.close();
  }
});

test('a hub that may not reach private addresses refuses them as destinations', async () => {
  const h = await startHub({ egressAllowPrivate: false });
  try {
    for (const url of [sink, 'https://169.254.169.254/latest', 'https://10.1.2.3', 'https://collector.internal', 'http://splunk.example.com']) {
      const res = await h.api('PUT', '/v1/integrations/streams', h.admin, { destinations: [{ name: 'x', type: 'webhook', url }] });
      assert.equal(res.json.error.code, 'bad_destination_url', url);
    }
  } finally {
    await h.hub.close();
  }
});

test('a blocked-only destination gets denials and escalations; the stream sends new events on its own', async () => {
  seen = [];
  const h = await startHub();
  try {
    await h.api('PUT', '/v1/integrations/streams', h.admin, {
      destinations: [{ ...all('soc').webhook, secret: 'x'.repeat(16), receipts: 'blocked', audit: false }],
    });
    const push = await agentLog(h);
    await push(['allow', 'allow', 'deny', 'allow', 'escalate', 'allow']);
    for (let i = 0; i < 100 && seen.length === 0; i++) await new Promise((r) => setTimeout(r, 20));
    const events = seen.flatMap((s) => JSON.parse(s.body).events);
    assert.deepEqual(events.map((/** @type {any} */ e) => `${e.type}:${e.outcome}`), ['receipt:deny', 'receipt:escalate']);
  } finally {
    await h.hub.close();
  }
});

test('while a destination is down nothing is lost; it catches up, after a restart too', async () => {
  seen = [];
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-streams-'));
  const database = path.join(dir, 'hub.db');
  try {
    let h = await startHub({ database });
    await h.api('PUT', '/v1/integrations/streams', h.admin, { destinations: [{ ...all('siem').webhook, secret: 'y'.repeat(16), audit: false }] });
    const push = await agentLog(h);
    failWith = 503;
    await push(['allow', 'deny']);
    let status = (await h.api('POST', '/v1/integrations/streams/flush', h.admin)).json.destinations[0];
    assert.equal(status.pending, 2);
    assert.match(status.lastError, /HTTP 503/);
    assert.equal(status.retrying, true);
    await h.hub.close();

    // Back up, on a fresh process: the backlog is in the database, not in memory.
    failWith = 0;
    h = await startHub({ database });
    for (let i = 0; i < 100 && seen.length === 0; i++) await new Promise((r) => setTimeout(r, 20));
    status = (await h.api('GET', '/v1/integrations/streams', h.admin)).json.destinations[0];
    assert.equal(status.pending, 0);
    const ids = seen.flatMap((s) => JSON.parse(s.body).events).map((/** @type {any} */ e) => e.id);
    assert.deepEqual(ids, ['payments:0', 'payments:1']);
    await h.hub.close();
  } finally {
    failWith = 0;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a new destination starts at the present unless asked to backfill', async () => {
  seen = [];
  const h = await startHub();
  try {
    const push = await agentLog(h);
    await push(['allow', 'deny']);
    await h.api('PUT', '/v1/integrations/streams', h.admin, {
      destinations: [
        { ...all('now').webhook, secret: 'z'.repeat(16), audit: false },
        { ...all('history').webhook, secret: 'z'.repeat(16), audit: false, backfill: true },
      ],
    });
    await push(['escalate']);
    await h.api('POST', '/v1/integrations/streams/flush', h.admin);
    const ids = (/** @type {string} */ name) => seen.filter((s) => s.path === `/hooks/${name}`)
      .flatMap((s) => JSON.parse(s.body).events).map((/** @type {any} */ e) => e.id);
    assert.deepEqual(ids('now'), ['payments:2']);
    assert.deepEqual(ids('history'), ['payments:0', 'payments:1', 'payments:2']);

    assert.equal((await h.api('DELETE', '/v1/integrations/streams', h.admin)).json.removed, true);
    assert.deepEqual((await h.api('GET', '/v1/integrations/streams', h.admin)).json.destinations, []);
  } finally {
    await h.hub.close();
  }
});

test('a stored credential is never sent to a URL other than the one it was given for', async () => {
  const h = await startHub();
  try {
    await h.api('PUT', '/v1/integrations/streams', h.admin, { destinations: [all('s').splunk] });
    const moved = await h.api('PUT', '/v1/integrations/streams', h.admin, {
      destinations: [{ name: 's', type: 'splunk', url: 'http://127.0.0.2:9' }],
    });
    assert.equal(moved.json.error.code, 'missing_token');
  } finally {
    await h.hub.close();
  }
});

test('several logs, more than a batch: every receipt arrives once, each log in order', async () => {
  seen = [];
  const h = await startHub();
  try {
    // Both logs exist before the destination does, so no automatic send can
    // go out with only one of them; backfill makes it deliver both.
    const a = await agentLog(h, 'alpha');
    const b = await agentLog(h, 'beta');
    await a(Array(260).fill('allow'));
    await b(Array(30).fill('deny'));
    await h.api('PUT', '/v1/integrations/streams', h.admin, {
      destinations: [{ ...all('bulk').webhook, secret: 'q'.repeat(16), audit: false, backfill: true }],
    });
    const status = (await h.api('POST', '/v1/integrations/streams/flush', h.admin)).json.destinations[0];
    assert.equal(status.pending, 0);
    const ids = seen.flatMap((s) => JSON.parse(s.body).events).map((/** @type {any} */ e) => e.id);
    assert.equal(new Set(ids).size, 290);
    assert.equal(ids.length, 290);
    for (const log of ['alpha', 'beta']) {
      const seqs = ids.filter((i) => i.startsWith(`${log}:`)).map((i) => Number(i.split(':')[1]));
      assert.deepEqual(seqs, [...seqs].sort((x, y) => x - y));
    }
    // The first batch carried both logs, not 200 of one.
    const first = JSON.parse(seen[0].body).events.map((/** @type {any} */ e) => e.log);
    assert.ok(first.includes('beta'));
  } finally {
    await h.hub.close();
  }
});
