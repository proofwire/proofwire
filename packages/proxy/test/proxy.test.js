import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { ProofLog, Policy, entryHash } from '@deedwrit/core';
import { McpProxy, extractMetrics } from '../src/proxy.js';
import { LineFramer, isRequest, isResponse, toolRefusal } from '../src/jsonrpc.js';
import { denyingApprover } from '../src/approve.js';

const SERVER = fileURLToPath(new URL('../../../examples/fake-mcp-server.js', import.meta.url));

/**
 * Drive a proxy over in-memory streams and collect what the client sees.
 *
 * @param {object} opts
 * @param {object} opts.policy
 * @param {object[]} opts.send
 * @param {any} [opts.approver]
 * @param {Record<string, any>} [opts.metrics]
 * @param {boolean} [opts.monitor]
 * @param {(proxy: McpProxy) => void} [opts.onProxy]
 */
async function run(opts) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deedwrit-proxy-'));
  const log = ProofLog.create(dir);
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();

  /** @type {any[]} */
  const received = [];
  const framer = new LineFramer();
  stdout.on('data', (chunk) => {
    for (const { message } of framer.push(chunk)) if (message) received.push(message);
  });

  const proxy = new McpProxy({
    log,
    policy: new Policy({ version: 1, name: 'test', ...opts.policy }),
    actor: { agent: 'claude-opus-5', session: 'sess_test', principal: 'ops@acme.test' },
    approver: opts.approver ?? denyingApprover(),
    command: process.execPath,
    args: [SERVER],
    namespace: 'ops',
    metrics: opts.metrics,
    monitor: opts.monitor,
    stdin,
    stdout,
    stderr,
  });

  opts.onProxy?.(proxy);
  const done = proxy.start();
  for (const msg of opts.send) stdin.write(JSON.stringify(msg) + '\n');

  // Wait until every request we sent has been answered, or we give up.
  const wanted = opts.send.filter((m) => 'id' in m).length;
  const deadline = Date.now() + 8000;
  while (received.length < wanted && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 10));
  }

  stdin.end();
  await done;
  proxy.finalize();

  const byId = new Map(received.filter((m) => 'id' in m).map((m) => [m.id, m]));
  return { received, byId, log: ProofLog.open(dir, { readOnly: true }), proxy, dir };
}

/**
 * @param {number} id
 * @param {string} name
 * @param {object} args
 */
const call = (id, name, args) => ({
  jsonrpc: '2.0',
  id,
  method: 'tools/call',
  params: { name, arguments: args },
});

test('framing survives chunk boundaries in the wrong places', () => {
  const f = new LineFramer();
  assert.deepEqual(f.push('{"a":1}\n{"b'), [{ message: { a: 1 }, raw: '{"a":1}' }]);
  assert.deepEqual(f.push('":2}\n'), [{ message: { b: 2 }, raw: '{"b":2}' }]);
  assert.equal(f.pending, '');

  // Three messages in one chunk, and CRLF line endings.
  const g = new LineFramer();
  const msgs = g.push('{"x":1}\r\n{"y":2}\r\n{"z":3}\r\n');
  assert.deepEqual(msgs.map((m) => m.message), [{ x: 1 }, { y: 2 }, { z: 3 }]);
});

test('a malformed line is reported, not thrown', () => {
  const f = new LineFramer();
  const [entry] = f.push('not json at all\n');
  assert.ok(entry.error instanceof Error);
  assert.equal(entry.raw, 'not json at all');
});

test('request, response and notification are told apart', () => {
  assert.ok(isRequest({ method: 'tools/call', id: 1 }));
  assert.equal(isRequest({ method: 'notifications/initialized' }), false);
  assert.equal(isRequest({ id: 1, result: {} }), false);
  assert.ok(isResponse({ id: 1, result: {} }));
  assert.ok(isResponse({ id: 1, error: { code: -1 } }));
  assert.equal(isResponse({ method: 'x', id: 1 }), false);
});

test('a refusal reaches the model as tool output, not a protocol error', () => {
  const r = toolRefusal(7, 'nope');
  assert.equal(r.id, 7);
  assert.equal(r.result.isError, true);
  assert.equal(r.result.content[0].text, 'nope');
  assert.ok(!('error' in r), 'must not be a JSON-RPC error: the model would never see it');
});

test('an allowed call is recorded before it runs, then again when it returns', async () => {
  const { received, log } = await run({
    policy: { rules: [] },
    send: [call(1, 'query', { sql: 'SELECT count(*) FROM orders' })],
  });

  assert.equal(received.length, 1);
  assert.equal(received[0].result.isError, undefined);
  assert.match(received[0].result.content[0].text, /"count":128/);

  // Two receipts, in this order, on purpose: the intent is durable before the
  // call goes out, so a crash mid-call still leaves evidence it was attempted.
  assert.equal(log.size, 2);

  const intent = log.entries[0];
  assert.equal(intent.phase, 'intent');
  assert.equal(intent.action.target, 'ops.query');
  assert.equal(intent.decision.outcome, 'allow');
  assert.equal(intent.result, null);

  const outcome = log.entries[1];
  assert.equal(outcome.phase, 'outcome');
  assert.equal(outcome.result.status, 'ok');
  assert.ok(typeof outcome.result.latencyMs === 'number');
  assert.equal(outcome.ref, entryHash(intent), 'the outcome must point at its intent');

  assert.ok(log.audit().ok);
});

test('a denied call produces exactly one receipt, because nothing ran', async () => {
  const { log } = await run({
    policy: { defaults: { outcome: 'deny' }, rules: [] },
    send: [call(1, 'refund', { order: 'ord_1', amount: 100 })],
  });
  assert.equal(log.size, 1);
  assert.equal(log.entries[0].phase, 'atomic');
  assert.equal(log.entries[0].result, null);
});

test('a denied call never reaches the upstream server', async () => {
  const { received, log } = await run({
    policy: {
      rules: [
        {
          id: 'deny.destructive-sql',
          when: { 'params.sql': { matches: '(?i)\\b(drop|delete|truncate)\\b' } },
          then: 'deny',
          reason: 'destructive SQL is not permitted from an agent',
        },
      ],
    },
    send: [call(1, 'query', { sql: 'DROP TABLE customers' })],
  });

  assert.equal(received[0].result.isError, true);
  assert.match(received[0].result.content[0].text, /Blocked by Deedwrit policy/);
  assert.match(received[0].result.content[0].text, /destructive SQL/);
  // The upstream server would have reported rows affected. It never ran.
  assert.ok(!/rows affected/.test(received[0].result.content[0].text));

  const r = log.entries[0];
  assert.equal(r.decision.outcome, 'deny');
  assert.equal(r.result, null, 'a blocked action has no result, because it did not happen');
  assert.deepEqual(r.decision.rules, ['deny.destructive-sql']);
});

test('the refusal tells the agent where the evidence lives', async () => {
  const { received, log } = await run({
    policy: { defaults: { outcome: 'deny' }, rules: [] },
    send: [call(1, 'refund', { order: 'ord_1', amount: 500 })],
  });
  assert.match(received[0].result.content[0].text, new RegExp(`receipt 0 in log ${log.logId}`));
});

test('non-tool traffic is forwarded untouched', async () => {
  const { received, log } = await run({
    policy: { defaults: { outcome: 'deny' }, rules: [] },
    send: [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
      { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    ],
  });

  assert.equal(received.length, 2);
  assert.equal(received[0].result.serverInfo.name, 'fake-ops-server');
  assert.equal(received[1].result.tools.length, 3);
  assert.equal(log.size, 0, 'listing tools is not an action and should not be logged');
});

test('an unknown future method is forwarded rather than swallowed', async () => {
  const { received } = await run({
    policy: { rules: [] },
    send: [{ jsonrpc: '2.0', id: 1, method: 'resources/subscribe', params: {} }],
  });
  assert.equal(received[0].error.code, -32601, 'the upstream server answered, so we forwarded it');
});

test('escalation with no approver configured denies, and says why', async () => {
  const { received, log } = await run({
    policy: {
      rules: [{ id: 'escalate.mail', when: { target: 'ops.send_email' }, then: 'escalate' }],
    },
    send: [call(1, 'send_email', { to: 'customer@example.test', subject: 'Hi' })],
  });

  assert.equal(received[0].result.isError, true);
  assert.match(received[0].result.content[0].text, /no approver is configured/);
  assert.equal(log.entries[0].decision.outcome, 'deny');
  // A fallback is recorded as one, not as a person.
  assert.match(log.entries[0].decision.declined.by, /^policy:/);
  assert.equal(log.entries[0].decision.approval, undefined);
});

test('an escalation a person declines records who declined it, inside the signature', async () => {
  const { log } = await run({
    policy: { rules: [{ id: 'escalate.mail', when: { target: 'ops.send_email' }, then: 'escalate' }] },
    approver: async () => ({ approved: false, by: 'slack:U024BE7LH (dana)', note: 'wrong customer' }),
    send: [call(1, 'send_email', { to: 'customer@example.test', subject: 'Hi' })],
  });
  const d = log.entries[0].decision;
  assert.equal(d.outcome, 'deny');
  assert.equal(d.declined.by, 'slack:U024BE7LH (dana)');
  assert.equal(d.declined.note, 'wrong customer');
  assert.ok(Date.parse(d.declined.at));
  assert.ok(log.audit().ok);
});

test('an approved escalation runs and records who approved it', async () => {
  const { received, log } = await run({
    policy: {
      rules: [{ id: 'escalate.mail', when: { target: 'ops.send_email' }, then: 'escalate' }],
    },
    approver: async () => ({ approved: true, by: 'dana@acme.test', note: 'confirmed by phone' }),
    send: [call(1, 'send_email', { to: 'customer@example.test', subject: 'Your refund' })],
  });

  assert.match(received[0].result.content[0].text, /Sent "Your refund"/);
  const r = log.entries[0];
  assert.equal(r.decision.outcome, 'allow');
  assert.equal(r.decision.approval.by, 'dana@acme.test');
  assert.equal(r.decision.approval.note, 'confirmed by phone');
  assert.ok(r.decision.approval.at);
});

test('the approver is shown redacted arguments, never raw secrets', async () => {
  /** @type {any} */
  let seen;
  await run({
    policy: { rules: [{ id: 'esc', when: { target: '*' }, then: 'escalate' }] },
    approver: async (req) => {
      seen = req;
      return { approved: false, by: 'nobody' };
    },
    send: [call(1, 'send_email', { to: 'x@y.test', subject: 'k', body: 'key AKIAIOSFODNN7EXAMPLE' })],
  });

  assert.ok(seen, 'the approver should have been consulted');
  const text = JSON.stringify(seen.params);
  assert.ok(!text.includes('AKIAIOSFODNN7EXAMPLE'), 'a raw key was shown to the approver');
  assert.ok(text.includes('[redacted:aws_access_key'));
});

test('a budget denies the call that would breach it, mid-session', async () => {
  const { byId, log } = await run({
    policy: {
      budgets: [
        {
          id: 'spend.daily',
          match: { target: 'ops.refund' },
          field: 'metrics.amount_usd',
          limit: 100,
          window: '24h',
          then: 'deny',
        },
      ],
    },
    metrics: { 'ops.refund': { amount_usd: { from: 'params.amount', scale: 0.01 } } },
    send: [
      call(1, 'refund', { order: 'ord_1', amount: 6000 }), // $60 — fine
      call(2, 'refund', { order: 'ord_2', amount: 3000 }), // $30 — $90 total, fine
      call(3, 'refund', { order: 'ord_3', amount: 5000 }), // $50 — would hit $140
    ],
  });
  // All three are pipelined before any reply arrives, which is exactly the
  // case that defeats a ledger written on completion.

  assert.equal(byId.size, 3);
  assert.equal(byId.get(1).result.isError, undefined, '$60 should be allowed');
  assert.equal(byId.get(2).result.isError, undefined, '$30 should be allowed');
  assert.equal(byId.get(3).result.isError, true, 'the third refund should have been blocked');
  assert.match(byId.get(3).result.content[0].text, /budget spend.daily would be exceeded/);

  // The ledger the budget read from is the log itself.
  assert.equal(log.entries[0].action.metrics.amount_usd, 60);
  const denials = log.entries.filter((r) => r.decision.outcome === 'deny');
  assert.equal(denials.length, 1);
  assert.match(denials[0].decision.reason, /90 already committed plus 50 proposed/);
});

test('the egress guard stops a credential from reaching a tool', async () => {
  const { received, log } = await run({
    policy: { egress: { denySecrets: true } },
    send: [
      call(1, 'send_email', {
        to: 'partner@example.test',
        subject: 'creds',
        body: 'use sk-ant-api03-Xk92mQvT1pLs8fR4nB6yH0jW',
      }),
    ],
  });

  assert.equal(received[0].result.isError, true);
  assert.match(received[0].result.content[0].text, /anthropic_key/);
  assert.deepEqual(log.entries[0].decision.rules, ['egress.guard']);
  // And the log itself does not contain the key it blocked.
  assert.ok(!JSON.stringify(log.entries[0]).includes('Xk92mQvT1pLs8fR4nB6yH0jW'));
});

test('monitor mode forwards a call the policy would deny, and says so in the signed receipt', async () => {
  /** @type {any[]} */
  const events = [];
  const { byId, log, proxy } = await run({
    monitor: true,
    policy: { rules: [{ id: 'no-refunds', match: { target: 'ops.refund' }, then: 'deny', reason: 'refunds are frozen' }] },
    send: [call(1, 'refund', { order: 'ord_1', amount: 100 })],
    onProxy: (p) => p.on('monitored', ({ target, wouldBe, reason }) => events.push({ target, wouldBe, reason })),
  });

  // It ran: the client got the upstream's real answer, not a refusal.
  assert.equal(byId.get(1).result.isError, undefined);
  assert.doesNotMatch(JSON.stringify(byId.get(1)), /Blocked by Deedwrit/);

  // And the record says it ran — intent then outcome, never an atomic "deny"
  // for an action that happened.
  assert.deepEqual(log.entries.map((r) => r.phase), ['intent', 'outcome']);
  for (const r of log.entries) {
    assert.equal(r.decision.outcome, 'allow');
    assert.equal(r.decision.enforced, false);
    assert.equal(r.decision.wouldBe, 'deny');
    assert.deepEqual(r.decision.rules, ['no-refunds']);
    assert.match(r.decision.reason, /^not enforced \(monitor mode\): would deny — /);
  }
  assert.equal(proxy.stats.wouldDeny, 1);
  assert.deepEqual(events, [{ target: 'ops.refund', wouldBe: 'deny', reason: 'refunds are frozen' }]);
  assert.equal(proxy.stats.denied, 0);
  // The monitor fields are inside the signature, not decoration beside it.
  assert.ok(log.audit().ok);
});

test('monitor mode marks even allowed calls as unenforced', async () => {
  const { log } = await run({
    monitor: true,
    policy: { rules: [] },
    send: [call(1, 'query', { sql: 'SELECT 1' })],
  });
  assert.equal(log.entries[0].decision.outcome, 'allow');
  assert.equal(log.entries[0].decision.enforced, false);
  assert.equal(log.entries[0].decision.wouldBe, undefined);
});

test('enforcing mode writes no monitor fields', async () => {
  const { log } = await run({ policy: { rules: [] }, send: [call(1, 'query', { sql: 'SELECT 1' })] });
  assert.equal('enforced' in log.entries[0].decision, false);
  assert.equal('wouldBe' in log.entries[0].decision, false);
});

test('monitor mode never asks a human to approve a call that will run anyway', async () => {
  let asked = 0;
  const { byId, log, proxy } = await run({
    monitor: true,
    policy: { rules: [{ id: 'big', match: { target: 'ops.refund' }, then: 'escalate' }] },
    approver: async () => {
      asked++;
      return { approved: false, by: 'nobody' };
    },
    send: [call(1, 'refund', { order: 'ord_1', amount: 100 })],
  });
  assert.equal(asked, 0);
  assert.equal(byId.get(1).result.isError, undefined);
  assert.equal(log.entries[0].decision.wouldBe, 'escalate');
  assert.equal(log.entries[0].decision.approval, undefined);
  assert.equal(proxy.stats.wouldEscalate, 1);
  assert.equal(proxy.stats.escalated, 0);
});

test('monitor mode counts spend that really happened against the budget', async () => {
  const { byId, log } = await run({
    monitor: true,
    policy: {
      budgets: [
        { id: 'spend.daily', match: { target: 'ops.refund' }, field: 'metrics.amount_usd', limit: 100, window: '24h', then: 'deny' },
      ],
    },
    metrics: { 'ops.refund': { amount_usd: { from: 'params.amount', scale: 0.01 } } },
    send: [
      call(1, 'refund', { order: 'ord_1', amount: 6000 }),
      call(2, 'refund', { order: 'ord_2', amount: 5000 }), // $110 — would breach
      call(3, 'refund', { order: 'ord_3', amount: 1000 }), // $120 — still over
    ],
  });
  for (const id of [1, 2, 3]) assert.equal(byId.get(id).result.isError, undefined, `call ${id} should have run`);
  const intents = log.entries.filter((r) => r.phase === 'intent');
  assert.deepEqual(intents.map((r) => r.decision.wouldBe), [undefined, 'deny', 'deny']);
  // The third is over budget only because the second's $50 was counted: it
  // ran, so it was spent.
  assert.match(intents[2].decision.reason, /110 already committed plus 10 proposed/);
});

test('a call left unanswered at shutdown is recorded as unfinished', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deedwrit-proxy-'));
  const log = ProofLog.create(dir);
  const proxy = new McpProxy({
    log,
    policy: new Policy({ version: 1, rules: [] }),
    actor: { agent: 'a', session: 's', principal: 'p' },
    approver: denyingApprover(),
    command: process.execPath,
    args: [SERVER],
    stdin: new PassThrough(),
    stdout: new PassThrough(),
    stderr: new PassThrough(),
  });

  // Simulate a forwarded call whose reply never arrived.
  proxy._pending.set(9, {
    target: 'ops.refund',
    params: { order: 'ord_9', amount: 100 },
    metrics: {},
    actor: { agent: 'a', runtime: 'test', session: 's', principal: 'p' },
    decision: { outcome: 'allow', policy: 'p', rules: [] },
    startedAt: Date.now() - 50,
  });
  proxy.finalize();

  const reopened = ProofLog.open(dir, { readOnly: true });
  assert.equal(reopened.size, 1);
  assert.equal(reopened.entries[0].result.status, 'error');
  assert.equal(reopened.entries[0].result.code, 'unfinished');
});

test('metric extraction scales units and ignores tools it does not match', () => {
  const config = {
    'stripe.*': { amount_usd: { from: 'params.amount', scale: 0.01 } },
    'invoice.*': { amount_usd: 'params.total' },
  };
  assert.deepEqual(extractMetrics(config, 'stripe.refund', { amount: 2500 }), { amount_usd: 25 });
  assert.deepEqual(extractMetrics(config, 'invoice.create', { total: 40 }), { amount_usd: 40 });
  assert.deepEqual(extractMetrics(config, 'crm.lookup', { amount: 99 }), {});
  assert.deepEqual(extractMetrics(config, 'stripe.refund', {}), {}, 'a missing field yields nothing');
});

test('a full session leaves an audit that verifies and a bundle that travels', async () => {
  const { log } = await run({
    policy: {
      rules: [
        { id: 'deny.sql', when: { 'params.sql': { matches: '(?i)drop' } }, then: 'deny' },
      ],
    },
    send: [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
      call(2, 'query', { sql: 'SELECT 1' }),
      call(3, 'query', { sql: 'DROP TABLE t' }),
      call(4, 'refund', { order: 'ord_5', amount: 1200 }),
    ],
  });

  const audit = log.audit();
  assert.ok(audit.ok, JSON.stringify(audit.issues));
  // Two allowed calls (intent + outcome each) plus one denial.
  assert.equal(log.size, 5);
  assert.equal(log.entries.filter((r) => r.phase === 'intent').length, 2);
  assert.equal(log.entries.filter((r) => r.phase === 'outcome').length, 2);
  assert.equal(log.entries.filter((r) => r.decision.outcome === 'deny').length, 1);

  const { verifyBundle } = await import('@deedwrit/core');
  const bundle = JSON.parse(JSON.stringify(log.bundle()));
  const res = verifyBundle(bundle);
  assert.ok(res.ok, JSON.stringify(res.issues));
  assert.equal(res.checked, 5);
});

test('off Windows, the command and its argv pass through untouched', async () => {
  const { launchSpec } = await import('../src/proxy.js');
  assert.deepEqual(launchSpec('npx', ['-y', 'a b'], 'linux'), { command: 'npx', args: ['-y', 'a b'], shell: false });
  assert.deepEqual(launchSpec(process.execPath, ['server.js'], 'darwin'), {
    command: process.execPath,
    args: ['server.js'],
    shell: false,
  });
});

test('on Windows, an executable is spawned directly and a batch shim through one quoted command line', async () => {
  const { launchSpec } = await import('../src/proxy.js');
  const node = String.raw`C:\Program Files\nodejs\node.exe`;
  const npx = String.raw`C:\Program Files\nodejs\npx.cmd`;
  const which = (/** @type {string} */ n) => ({ node, npx })[/** @type {'node'|'npx'} */ (n)] ?? null;

  // A path to an executable, or a name that resolves to one: no shell, real
  // argv. cmd.exe would split "C:\Program Files" at the space.
  assert.deepEqual(launchSpec(node, ['server.js', 'a b'], 'win32', which), { command: node, args: ['server.js', 'a b'], shell: false });
  assert.deepEqual(launchSpec('node', ['a b'], 'win32', which), { command: node, args: ['a b'], shell: false });

  // A shim: through the shell as one finished line, never shell plus argv,
  // which is what Node flags as DEP0190.
  const shim = launchSpec('npx', ['-y', '@acme/mcp server'], 'win32', which);
  assert.equal(shim.shell, true);
  assert.deepEqual(shim.args, []);
  assert.ok(shim.command.startsWith(String.raw`C:\Program^ Files\nodejs\npx.cmd `), shim.command);

  // A name nothing on PATH provides is left for cmd.exe to report.
  assert.equal(launchSpec('nosuchtool', [], 'win32', () => null).shell, true);
});

test('Windows quoting escapes for the C runtime and for cmd.exe, and twice for a batch file', async () => {
  const { winQuote } = await import('../src/proxy.js');
  // Every character cmd.exe interprets, the quotes included, is ^-escaped.
  assert.equal(winQuote('a b'), '^"a^ b^"');
  assert.equal(winQuote('x&y|z'), '^"x^&y^|z^"');
  assert.equal(winQuote('100%PATH%'), '^"100^%PATH^%^"');
  // A quote is escaped for the C runtime, then its escape for cmd.exe.
  assert.equal(winQuote('a"b'), String.raw`^"a\^"b^"`);
  // A trailing backslash is doubled so it cannot escape the closing quote.
  assert.equal(winQuote(String.raw`C:\dir\ `.trim()), String.raw`^"C:\dir\\^"`);
  // A batch file re-parses %* through cmd.exe: one more layer of ^.
  assert.equal(winQuote('a b', true), '^^^"a^^^ b^^^"');
});

test('hostile arguments reach a real batch shim exactly, run nothing, and raise no DEP0190', { skip: process.platform !== 'win32' }, async () => {
  const { launchSpec, whichWindows } = await import('../src/proxy.js');
  const { spawnSync } = await import('node:child_process');

  // A shim in a directory with a space in it, like C:\Program Files\nodejs.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dw shim '));
  fs.writeFileSync(path.join(dir, 'echo.js'), 'process.stdout.write(JSON.stringify(process.argv.slice(2)))');
  fs.writeFileSync(path.join(dir, 'echoargs.cmd'), '@node "%~dp0echo.js" %*\r\n');
  const env = { ...process.env, PATH: `${dir};${process.env.PATH}`, PW_SECRET: 'must-not-expand' };

  const args = [
    'plain', 'a b', 'q"uote', 'x"&echo INJECTED', 'amp&whoami', '%PW_SECRET%', 'caret^', 'bang!',
    'trail\\', 'dir with space\\', 'lt<gt>', 'paren(x)', '', 'semi;colon', 'a\\"b', 'star*?', 'pipe|x', 'back`tick',
  ];
  for (const command of ['echoargs', 'node']) {
    const argv = command === 'node' ? ['-e', 'process.stdout.write(JSON.stringify(process.argv.slice(1)))', ...args] : args;
    const spec = launchSpec(command, argv, 'win32', (n) => whichWindows(n, env));
    assert.equal(spec.shell, command === 'echoargs', `${command} should ${command === 'echoargs' ? '' : 'not '}need a shell`);

    // Spawned from a child so its stderr, where DEP0190 would land, is ours.
    const probe =
      `const r = require('node:child_process').spawnSync(${JSON.stringify(spec.command)}, ${JSON.stringify(spec.args)}, ` +
      `{ shell: ${spec.shell}, encoding: 'utf8', env: ${JSON.stringify(env)} });` +
      `process.stdout.write(r.stdout); process.stderr.write(r.stderr);`;
    const res = spawnSync(process.execPath, ['-e', probe], { encoding: 'utf8' });
    assert.deepEqual(JSON.parse(res.stdout), args, `${command}: arguments must arrive exactly as given`);
    assert.doesNotMatch(res.stderr, /DEP0190/);
  }
});

test('a budget with no metric extractor behind it is reported, not silently inert', async () => {
  const { auditPolicyMetrics } = await import('../src/proxy.js');

  const policy = new Policy({
    version: 1,
    budgets: [
      { id: 'refunds.daily', match: { target: '*' }, field: 'metrics.amount_usd', limit: 100 },
      { id: 'calls.daily', match: { target: '*' }, field: 'metrics.tokens', limit: 10 },
    ],
  });

  const unwired = auditPolicyMetrics(policy, { 'stripe.*': { other_number: 'params.x' } });
  assert.equal(unwired.length, 2, 'both budgets are inert and both should be named');
  assert.match(unwired[0], /budget "refunds.daily" caps metrics.amount_usd/);
  assert.match(unwired[0], /will never fire/);

  const wired = auditPolicyMetrics(policy, {
    'ops.*': { amount_usd: { from: 'params.amount', scale: 0.01 } },
    'llm.*': { tokens: 'params.n' },
  });
  assert.deepEqual(wired, [], 'a fully wired policy should produce no warnings');

  // A budget over a clear-text param, rather than a metric, needs no extractor.
  const direct = new Policy({
    version: 1,
    budgets: [{ id: 'b', match: { target: '*' }, field: 'params.amount', limit: 1 }],
  });
  assert.deepEqual(auditPolicyMetrics(direct, {}), []);
});

test('trailing slashes are trimmed in linear time', async () => {
  const { trimSlashes } = await import('../src/remote.js');
  assert.equal(trimSlashes('https://hub.example///'), 'https://hub.example');
  assert.equal(trimSlashes('https://hub.example'), 'https://hub.example');
  assert.equal(trimSlashes('///'), '');
  const hostile = '/'.repeat(200000) + 'x';
  const t = performance.now();
  assert.equal(trimSlashes(hostile), hostile);
  assert.ok(performance.now() - t < 200, 'a long run of slashes must not be slow');
});
