#!/usr/bin/env node
/**
 * Regenerate site/sample.bundle.json.
 *
 * The website lets a visitor verify a real evidence bundle in their browser, so
 * the sample has to be real: this runs an agent session through the actual
 * proxy against the example MCP server, checkpoints the log twice, has two
 * independent witnesses counter-sign, and exports the result.
 *
 *     node scripts/make-sample-bundle.js
 *
 * Everything in it is fictional (Acme, a made-up customer, a made-up key), and
 * the signing keys are throwaways that are deleted as soon as the run ends.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { ProofLog, Policy, generateIdentity, cosign, verifyBundle } from '@deedwrit/core';
import { McpProxy } from '@deedwrit/proxy';
import { LineFramer } from '@deedwrit/proxy/jsonrpc';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SERVER = path.join(ROOT, 'examples', 'fake-mcp-server.js');
const OUT = path.join(ROOT, 'site', 'sample.bundle.json');

const POLICY = {
  version: 1,
  name: 'finance-ops',
  rules: [
    {
      id: 'deny.destructive-sql',
      when: { 'params.sql': { matches: '(?i)\\b(drop|truncate|delete\\s+from)\\b' } },
      then: 'deny',
      reason: 'destructive SQL from an agent is never permitted',
    },
    {
      id: 'escalate.customer-mail',
      when: { target: 'ops.send_email' },
      then: 'escalate',
      reason: 'anything that reaches a customer gets a human first',
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
};

const CALLS = [
  ['query', { sql: 'SELECT count(*) FROM orders WHERE status = $1' }],
  ['refund', { order: 'ord_8821', amount: 4500 }],
  ['refund', { order: 'ord_8822', amount: 3000 }],
  ['refund', { order: 'ord_8823', amount: 9000 }],
  ['query', { sql: 'DELETE FROM customers WHERE churn_risk > 0.8' }],
  ['send_email', { to: 'sam@example.test', subject: 'Your refund', body: 'On its way.' }],
  ['query', { sql: "SELECT * FROM logs WHERE token = 'sk-ant-api03-Xk92mQvT1pLs8fR4nB6yH0jW'" }],
];

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deedwrit-sample-'));

try {
  const log = ProofLog.create(dir);

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
    log,
    policy: new Policy(POLICY),
    actor: { agent: 'claude-opus-5', session: 'sess_sample', principal: 'ops@acme.test' },
    approver: async (req) => ({
      approved: req.target === 'ops.send_email',
      by: 'dana@acme.test',
      note: 'reviewed in the approvals channel',
    }),
    command: process.execPath,
    args: [SERVER],
    namespace: 'ops',
    metrics: { 'ops.refund': { amount_usd: { from: 'params.amount', scale: 0.01 } } },
    stdin,
    stdout,
    stderr: new PassThrough(),
  });

  const running = proxy.start();

  for (const [i, [name, args]] of CALLS.entries()) {
    const id = i + 1;
    stdin.write(
      JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }) + '\n',
    );
    const deadline = Date.now() + 8000;
    while (!replies.has(id) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 5));
    if (!replies.has(id)) throw new Error(`no reply to call ${id}`);

    // An earlier checkpoint partway through, so the sample shows a log that
    // has been signed more than once rather than only at the very end.
    if (i === 2) log.checkpoint();
  }

  stdin.end();
  await running;
  proxy.finalize(); // signs the final checkpoint

  // Two independent witnesses. The earlier checkpoint gets one, the final one
  // gets both, so a visitor can ask for "at least 2" and watch it fail on the
  // older root and pass on the newer.
  const w1 = generateIdentity().identity;
  const w2 = generateIdentity().identity;
  log.trustKey(w1.kid, w1.publicKey);
  log.trustKey(w2.kid, w2.publicKey);

  const [first, last] = log.checkpoints();
  const witnessSig = (cp, w) => cosign(cp, w).sigs.find((s) => s.kid === w.kid);
  log.addSignature(first.body.size, witnessSig(first, w1));
  log.addSignature(last.body.size, witnessSig(last, w1));
  log.addSignature(last.body.size, witnessSig(last, w2));

  const bundle = log.bundle();

  // Never write a sample that does not verify: it would be the first thing a
  // visitor tries.
  const check = verifyBundle(JSON.parse(JSON.stringify(bundle)), {
    minWitnesses: 1,
    trustedWitnesses: { [w1.kid]: w1.publicKey, [w2.kid]: w2.publicKey },
  });
  if (!check.ok) throw new Error(`the sample bundle does not verify: ${check.issues.join('; ')}`);

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(bundle, null, 2) + '\n');

  const denied = bundle.entries.filter((e) => e.receipt.decision.outcome === 'deny').length;
  console.log(`wrote ${path.relative(ROOT, OUT)}`);
  console.log(
    `  ${bundle.entries.length} receipts · ${denied} blocked · ` +
      `${bundle.checkpoints.length} checkpoints · witnesses per checkpoint: ` +
      bundle.checkpoints.map((c) => c.sigs.filter((s) => s.role === 'witness').length).join(', '),
  );
  console.log(`  root ${bundle.root}`);
} finally {
  // The signing keys were throwaways; do not leave them lying around.
  fs.rmSync(dir, { recursive: true, force: true });
}
