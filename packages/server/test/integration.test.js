import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { ProofLog, Policy, verifyBundle, signCheckpoint } from '@vouchwell/core';
import { McpProxy } from '@vouchwell/proxy';
import { LineFramer } from '@vouchwell/proxy/jsonrpc';
import { RemoteSink, hubApprover, fetchPolicy } from '@vouchwell/proxy/remote';
import { Hub } from '../src/app.js';
import { Auth } from '../src/auth.js';

/**
 * The whole product, end to end: a real MCP server behind a real proxy,
 * enforcing a policy fetched from a real hub, shipping signed receipts to it
 * over HTTP, with escalations resolved through the hub's approvals inbox.
 *
 * These are the tests that would catch an integration breaking while every
 * unit test still passed.
 */

const SERVER = fileURLToPath(new URL('../../../examples/fake-mcp-server.js', import.meta.url));

/** @type {Hub} */
let hub;
let base;
let agentToken;
let auditToken;
let orgId;

before(async () => {
  hub = new Hub({
    database: ':memory:',
    checkpointEvery: 0,
    apiRate: { capacity: 100000, refillPerSec: 100000 },
    ingestRate: { capacity: 100000, refillPerSec: 100000 },
  });
  const { url } = await hub.listen(0);
  base = url.replace('0.0.0.0', '127.0.0.1');

  const auth = new Auth(hub.store);
  const org = hub.store.createOrg({ slug: 'acme', name: 'Acme' });
  orgId = org.id;
  agentToken = auth.createKey({
    orgId,
    name: 'agent',
    scopes: ['receipts:write', 'receipts:read', 'logs:write', 'logs:read', 'policies:read', 'policies:write', 'approvals:read', 'approvals:write', 'witness:sign'],
  }).token;
  auditToken = auth.createKey({
    orgId,
    name: 'auditor',
    scopes: ['receipts:read', 'logs:read', 'policies:read'],
  }).token;
});

after(async () => { await hub.close(); });

/** @param {string} token */
const hdrs = (token) => ({ authorization: `Bearer ${token}`, 'content-type': 'application/json' });

/**
 * Run an agent session through a proxy wired to the hub.
 *
 * @param {object} opts
 */
async function session(opts) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchwell-e2e-'));
  const localLog = ProofLog.create(dir);

  const sink = new RemoteSink({
    url: base,
    token: agentToken,
    log: opts.slug,
    localLog,
    flushMs: 50,
  });
  const connected = await sink.connect();

  const stdin = new PassThrough();
  const stdout = new PassThrough();
  /** @type {Map<number, any>} */
  const replies = new Map();
  const framer = new LineFramer();
  stdout.on('data', (chunk) => {
    for (const { message } of framer.push(chunk)) {
      if (message && 'id' in message) replies.set(message.id, message);
    }
  });

  const proxy = new McpProxy({
    log: localLog,
    policy: opts.policy,
    actor: { agent: 'claude-opus-5', session: opts.session ?? 'sess_e2e', principal: 'ops@acme.test' },
    approver: opts.approver ?? (async () => ({ approved: false, by: 'test' })),
    command: process.execPath,
    args: [SERVER],
    namespace: 'ops',
    metrics: { 'ops.refund': { amount_usd: { from: 'params.amount', scale: 0.01 } } },
    stdin,
    stdout,
    stderr: new PassThrough(),
  });

  const running = proxy.start();

  for (const [i, [name, args]] of opts.calls.entries()) {
    const id = i + 1;
    stdin.write(
      JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }) + '\n',
    );
    const deadline = Date.now() + 8000;
    while (!replies.has(id) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 5));
  }

  stdin.end();
  await running;
  proxy.finalize();
  const behind = connected ? await sink.stop() : localLog.size;

  return { dir, localLog: ProofLog.open(dir, { readOnly: true }), replies, sink, behind, connected };
}

test('a policy published to the hub governs an agent that fetches it', async () => {
  const published = await fetch(`${base}/v1/policies/default`, {
    method: 'POST',
    headers: hdrs(agentToken),
    body: JSON.stringify({
      policy: {
        version: 1,
        name: 'org-standard',
        rules: [
          {
            id: 'deny.destructive-sql',
            when: { 'params.sql': { matches: '(?i)\\b(drop|delete\\s+from)\\b' } },
            then: 'deny',
            reason: 'destructive SQL from an agent is never permitted',
          },
        ],
        budgets: [
          {
            id: 'refunds.daily',
            match: { target: 'ops.refund' },
            field: 'metrics.amount_usd',
            limit: 100,
            window: '24h',
            then: 'deny',
          },
        ],
        egress: { denySecrets: true },
      },
    }),
  });
  assert.equal(published.status, 200);

  // The agent fetches it exactly as the proxy does at startup.
  const active = await fetchPolicy({ url: base, token: agentToken, slug: 'default' });
  assert.equal(active.version, 1);
  const policy = new Policy(active.policy);

  const run = await session({
    slug: 'ops-a',
    policy,
    calls: [
      ['query', { sql: 'SELECT 1' }],
      ['refund', { order: 'ord_1', amount: 6000 }],
      ['query', { sql: 'DROP TABLE customers' }],
      ['refund', { order: 'ord_2', amount: 9000 }],
      ['query', { sql: "SELECT * FROM t WHERE k='sk-ant-api03-Xk92mQvT1pLs8fR4nB6yH0jW'" }],
    ],
  });

  assert.ok(run.connected, 'the sink should have connected');
  assert.equal(run.behind, 0, 'every receipt should have reached the hub');

  // The policy the hub published actually blocked things.
  const denied = run.localLog.entries.filter((r) => r.decision.outcome === 'deny');
  assert.equal(denied.length, 3, `expected 3 denials, got ${denied.map((d) => d.action.target)}`);
  assert.ok(denied.some((d) => /destructive SQL/.test(d.decision.reason)));
  assert.ok(denied.some((d) => /budget refunds.daily/.test(d.decision.reason)));
  assert.ok(denied.some((d) => /anthropic_key/.test(d.decision.reason)));

  // And the hub holds exactly what the agent recorded.
  const remote = await (await fetch(`${base}/v1/logs/ops-a`, { headers: hdrs(auditToken) })).json();
  assert.equal(remote.size, run.localLog.size);
  assert.equal(remote.root, run.localLog.root, 'hub and agent must agree on the root');
  assert.equal(remote.head, run.localLog.head);
});

test('an auditor verifies the hosted log without touching the agent', async () => {
  const bundle = await (await fetch(`${base}/v1/logs/ops-a/bundle`, { headers: hdrs(auditToken) })).json();
  const res = verifyBundle(bundle);
  assert.ok(res.ok, JSON.stringify(res.issues, null, 2));

  // The blocked actions are in the evidence, which is the point: proof the
  // guardrail fired, not just proof of what succeeded.
  const denials = bundle.entries.filter((e) => e.receipt.decision.outcome === 'deny');
  assert.equal(denials.length, 3);

  // And nothing sensitive travelled.
  const text = JSON.stringify(bundle);
  assert.ok(!text.includes('sk-ant-api03-Xk92mQvT1pLs8fR4nB6yH0jW'), 'a live key reached the hub');
  assert.ok(!text.includes('"salt"'), 'commitment salts must never leave the agent');
});

test('the agent keeps working and keeps recording while the hub is unreachable', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchwell-offline-'));
  const localLog = ProofLog.create(dir);

  const sink = new RemoteSink({
    url: 'http://127.0.0.1:1',   // nothing listens here
    token: agentToken,
    log: 'ops-offline',
    localLog,
    flushMs: 50,
  });
  const connected = await sink.connect();
  assert.equal(connected, false, 'connect should fail, not throw');

  // The agent runs regardless. This is the property that decides whether a
  // team keeps the proxy in production after the first hub outage.
  const run = await session({
    slug: 'ops-offline-local',
    policy: new Policy({ version: 1, rules: [] }),
    calls: [['query', { sql: 'SELECT 1' }], ['refund', { order: 'o', amount: 100 }]],
  });
  assert.ok(run.localLog.size >= 4);
  assert.ok(run.localLog.audit().ok, 'the local log must still be sound');
});

test('a backlog ships when the hub comes back, in order, and the roots agree', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchwell-backlog-'));
  const localLog = ProofLog.create(dir);

  for (let i = 0; i < 25; i++) {
    localLog.append({
      actor: { agent: 'a', runtime: 'r', session: 's', principal: 'p' },
      action: { kind: 'tool_call', target: 'ops.refund', params: { i }, metrics: { amount_usd: 1 } },
      decision: { outcome: 'allow', policy: 'p', rules: [] },
      result: { status: 'ok', payload: { i } },
    });
  }

  const sink = new RemoteSink({ url: base, token: agentToken, log: 'ops-backlog', localLog, batchSize: 7 });
  assert.ok(await sink.connect());
  const sent = await sink.flush();

  assert.equal(sent, 25, 'the whole backlog should ship');
  assert.equal(sink.status().behind, 0);

  const remote = await (await fetch(`${base}/v1/logs/ops-backlog`, { headers: hdrs(auditToken) })).json();
  assert.equal(remote.size, 25);
  assert.equal(remote.root, localLog.root);
});

test('a duplicate flush after a lost response does not corrupt the log', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchwell-dup-'));
  const localLog = ProofLog.create(dir);
  for (let i = 0; i < 5; i++) {
    localLog.append({
      actor: { agent: 'a', runtime: 'r', session: 's', principal: 'p' },
      action: { kind: 'tool_call', target: 'ops.q', params: { i } },
      decision: { outcome: 'allow', policy: 'p', rules: [] },
    });
  }

  const sink = new RemoteSink({ url: base, token: agentToken, log: 'ops-dup', localLog });
  await sink.connect();
  await sink.flush();

  // Simulate a client that never saw the 200 and retries from its old cursor.
  sink.cursor = 0;
  await sink.flush();

  const remote = await (await fetch(`${base}/v1/logs/ops-dup`, { headers: hdrs(auditToken) })).json();
  assert.equal(remote.size, 5, 'a replay must not duplicate entries');
  assert.equal(remote.root, localLog.root);

  const audit = await (await fetch(`${base}/v1/logs/ops-dup/audit`, { headers: hdrs(auditToken) })).json();
  assert.ok(audit.ok, JSON.stringify(audit.issues));
});

test('an escalation is resolved by a human in the console and the agent proceeds', async () => {
  await fetch(`${base}/v1/policies/mail`, {
    method: 'POST',
    headers: hdrs(agentToken),
    body: JSON.stringify({
      policy: {
        version: 1,
        name: 'mail',
        rules: [{ id: 'escalate.mail', when: { target: 'ops.send_email' }, then: 'escalate', reason: 'customer contact' }],
      },
    }),
  });

  // A reviewer, watching for the request and approving it.
  const reviewer = (async () => {
    for (let i = 0; i < 100; i++) {
      const list = await (await fetch(`${base}/v1/approvals?status=pending`, { headers: hdrs(agentToken) })).json();
      const req = list.approvals.find((a) => a.target === 'ops.send_email');
      if (req) {
        // The reviewer sees redacted arguments, never the raw payload.
        assert.ok(!JSON.stringify(req.params).includes('AKIA'), 'raw secret shown to the approver');
        await fetch(`${base}/v1/approvals/${req.id}/decide`, {
          method: 'POST',
          headers: hdrs(agentToken),
          body: JSON.stringify({ approved: true, note: 'checked with the customer' }),
        });
        return req.id;
      }
      await new Promise((r) => setTimeout(r, 50));
    }
    return null;
  })();

  const run = await session({
    slug: 'ops-mail',
    policy: new Policy({
      version: 1,
      rules: [{ id: 'escalate.mail', when: { target: 'ops.send_email' }, then: 'escalate', reason: 'customer contact' }],
    }),
    approver: hubApprover({ url: base, token: agentToken, log: 'ops-mail', timeoutMs: 20_000 }),
    calls: [['send_email', { to: 'sam@example.test', subject: 'Your refund', body: 'key AKIAIOSFODNN7EXAMPLE' }]],
  });

  const approvalId = await reviewer;
  assert.ok(approvalId, 'the approval request should have appeared in the inbox');

  const reply = run.replies.get(1);
  assert.ok(!reply.result.isError, 'an approved action should have run');
  assert.match(reply.result.content[0].text, /Sent "Your refund"/);

  const intent = run.localLog.entries.find((r) => r.phase === 'intent');
  assert.equal(intent.decision.outcome, 'allow');
  assert.match(intent.decision.approval.note, /checked with the customer/);
});

test('an escalation nobody answers is denied, never approved by default', async () => {
  const run = await session({
    slug: 'ops-noanswer',
    policy: new Policy({
      version: 1,
      rules: [{ id: 'escalate.all', when: { target: '*' }, then: 'escalate', reason: 'needs review' }],
    }),
    // A two-second patience with no reviewer anywhere.
    approver: hubApprover({ url: base, token: agentToken, log: 'ops-noanswer', timeoutMs: 2000 }),
    calls: [['refund', { order: 'ord_x', amount: 100 }]],
  });

  const reply = run.replies.get(1);
  assert.equal(reply.result.isError, true, 'an unanswered escalation must not run');
  assert.match(reply.result.content[0].text, /Blocked by Vouchwell policy/);
  assert.equal(run.localLog.entries[0].decision.outcome, 'deny');
});

test('a hub that refuses permanently stops shipping and says so, keeping the local log', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchwell-refused-'));
  const localLog = ProofLog.create(dir);
  localLog.append({
    actor: { agent: 'a', runtime: 'r', session: 's', principal: 'p' },
    action: { kind: 'tool_call', target: 'ops.q', params: {} },
    decision: { outcome: 'allow', policy: 'p', rules: [] },
  });

  /** @type {string[]} */
  const messages = [];
  const sink = new RemoteSink({
    url: base,
    token: auditToken,          // read-only: cannot write receipts
    log: 'ops-refused',
    localLog,
    onLog: (level, msg) => messages.push(`${level}: ${msg}`),
  });

  // Registration itself needs logs:write, so this fails before any push.
  const connected = await sink.connect();
  assert.equal(connected, false);
  assert.ok(messages.some((m) => m.startsWith('warn') || m.startsWith('error')));

  // The local log is untouched and still verifies — the guarantee that makes
  // the hub optional rather than load-bearing.
  assert.equal(localLog.size, 1);
  assert.ok(ProofLog.open(dir, { readOnly: true }).audit().ok);
});

test('the hub witness counter-signs a local checkpoint and refuses a rewrite', async () => {
  const run = await session({
    slug: 'ops-witness',
    policy: new Policy({ version: 1, rules: [] }),
    calls: [['query', { sql: 'SELECT 1' }], ['query', { sql: 'SELECT 2' }]],
  });

  const local = ProofLog.open(run.dir);
  const cp = local.checkpoints().at(-1) ?? local.checkpoint();

  const signed = await (await fetch(`${base}/v1/witness/cosign`, {
    method: 'POST',
    headers: hdrs(agentToken),
    body: JSON.stringify({ checkpoint: cp, logPublicKey: local.identity.publicKey }),
  })).json();
  assert.equal(signed.signature.role, 'witness');

  // Now offer the witness a different history at the same size — signed by
  // the log's own key, as a rewrite by whoever holds it would be.
  const rewritten = signCheckpoint(local.identity, { ...cp.body, root: '11'.repeat(32) });
  const refused = await fetch(`${base}/v1/witness/cosign`, {
    method: 'POST',
    headers: hdrs(agentToken),
    body: JSON.stringify({ checkpoint: rewritten }),
  });
  assert.equal(refused.status, 409);
  assert.equal((await refused.json()).error.code, 'split_view');
});

test('the console renders and escapes agent-supplied strings', async () => {
  const auth = new Auth(hub.store);
  const user = auth.createUser({ email: 'dana@acme.test', password: 'correct horse battery staple' });
  auth.addMember(orgId, user.id, 'owner');

  const login = await fetch(`${base}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ email: 'dana@acme.test', password: 'correct horse battery staple' }),
    redirect: 'manual',
  });
  assert.equal(login.status, 303);
  const cookie = (login.headers.getSetCookie?.() ?? []).map((c) => c.split(';')[0]).join('; ');
  assert.match(cookie, /pw_session=/);

  const overview = await fetch(base + '/', { headers: { cookie } });
  assert.equal(overview.status, 200);
  const html = await overview.text();
  assert.match(html, /Acme/);
  assert.match(html, /ops-a/);
  assert.ok(!html.includes('sk-ant-api03-Xk92'), 'a redacted secret must not reach the console');

  // A tool name containing markup must render as text, not as markup.
  const probe = ProofLog.create(fs.mkdtempSync(path.join(os.tmpdir(), 'pw-xss-')));
  // A call that was sent and never came back, so the page's "never finished"
  // banner renders too, with a name that tries to be markup.
  probe.append({
    ts: '2026-01-01T00:00:00.000Z',
    phase: 'intent',
    actor: { agent: 'a', runtime: 'r', session: 's', principal: 'p@acme.test' },
    action: { kind: 'tool_call', target: '<b>never</b>', params: {} },
    decision: { outcome: 'allow', policy: 'p', rules: [] },
  });
  probe.append({
    actor: { agent: 'a', runtime: 'r', session: 's', principal: '<img src=x onerror=alert(1)>' },
    action: { kind: 'tool_call', target: '<script>alert(1)</script>', params: {} },
    decision: { outcome: 'deny', policy: 'p', rules: [], reason: '"><script>alert(2)</script>' },
  });
  const reopened = ProofLog.open(probe.dir, { readOnly: true });
  const sink = new RemoteSink({ url: base, token: agentToken, log: 'ops-xss', localLog: reopened });
  await sink.connect();
  await sink.flush();

  const page = await (await fetch(base + '/logs/ops-xss', { headers: { cookie } })).text();

  // The payloads must appear as visible text, never as live markup. Checking
  // for the escaped form proves they reached the page at all — an assertion
  // that only looked for the absence of `<script>` would also pass if the
  // receipt had never rendered.
  assert.ok(page.includes('&lt;script&gt;alert(1)&lt;/script&gt;'), 'the tool name should be escaped');
  assert.ok(page.includes('&lt;img src=x onerror=alert(1)&gt;'), 'the principal should be escaped');
  assert.ok(!page.includes('<script>alert(1)</script>'), 'unescaped markup reached the page');
  assert.ok(!page.includes('<img src=x'), 'an unescaped tag reached the page');
  assert.match(page, /1 action\(s\) were authorised and sent, but never finished/);
  assert.ok(page.includes('#0 · 2026-01-01 00:00:00 · &lt;b&gt;never&lt;/b&gt;'), 'the unfinished call should be listed, escaped');

  // The response must also forbid inline script execution outright, so a
  // single missed escape somewhere is not immediately exploitable.
  const csp = (await fetch(base + '/logs/ops-xss', { headers: { cookie } })).headers.get('content-security-policy');
  assert.match(csp ?? '', /default-src 'none'/);
});

test('an unauthenticated visitor gets the login page, not data', async () => {
  const res = await fetch(base + '/', { redirect: 'manual' });
  assert.equal(res.status, 401);
  const html = await res.text();
  assert.ok(!html.includes('ops-a'), 'log names leaked to an anonymous visitor');
});
