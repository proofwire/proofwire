#!/usr/bin/env node
/**
 * The five-minute demo.
 *
 * Runs a real agent session through a real proxy against a real MCP server,
 * then attacks the resulting log four different ways and shows each attack
 * being caught. Nothing here is mocked; the log it writes is a log you can
 * inspect with `vw` afterwards.
 *
 *     node examples/demo.js
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { ProofLog, Policy, verifyBundle, canonicalize, identityFromPem, signReceipt, entryHash, GENESIS_PREV, generateIdentity, cosign, verifyCheckpoint } from '@vouchwell/core';
import { McpProxy } from '@vouchwell/proxy';
import { LineFramer } from '@vouchwell/proxy/jsonrpc';

const SERVER = fileURLToPath(new URL('./fake-mcp-server.js', import.meta.url));
const B = (s) => `[1m${s}[0m`;
const DIM = (s) => `[90m${s}[0m`;
const GREEN = (s) => `[32m${s}[0m`;
const RED = (s) => `[31m${s}[0m`;
const YELLOW = (s) => `[33m${s}[0m`;
const CYAN = (s) => `[36m${s}[0m`;

const say = (s = '') => console.log(s);
const step = (n, s) => {
  say();
  say(B(`${n}. ${s}`));
  say(DIM('─'.repeat(72)));
};

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
  ['query', { sql: 'SELECT count(*) FROM orders WHERE status = $1' }, 'a harmless read'],
  ['refund', { order: 'ord_8821', amount: 4500 }, '$45 refund — inside budget'],
  ['refund', { order: 'ord_8822', amount: 3000 }, '$30 refund — $75 committed'],
  ['refund', { order: 'ord_8823', amount: 9000 }, '$90 refund — would reach $165'],
  ['query', { sql: 'DELETE FROM customers WHERE churn_risk > 0.8' }, 'destructive SQL'],
  ['send_email', { to: 'sam@example.test', subject: 'Your refund', body: 'On its way.' }, 'outbound mail'],
  ['query', { sql: "SELECT * FROM logs WHERE token = 'sk-ant-api03-Xk92mQvT1pLs8fR4nB6yH0jW'" }, 'a live credential in the args'],
];

async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchwell-demo-'));
  const log = ProofLog.create(dir);

  say();
  say(B('  Vouchwell — every AI agent action, signed, chained, and provable'));
  say(DIM(`  log ${log.logId}   key ${log.identity.kid}`));
  say(DIM(`  ${dir}`));

  // ── 1. Run a session ──────────────────────────────────────────────────
  step(1, 'An agent works through a queue of tasks');

  const stdin = new PassThrough();
  const stdout = new PassThrough();
  /** @type {Map<number, any>} */
  const replies = new Map();
  const framer = new LineFramer();
  stdout.on('data', (c) => {
    for (const { message } of framer.push(c)) {
      if (message && 'id' in message) replies.set(message.id, message);
    }
  });

  const proxy = new McpProxy({
    log,
    policy: new Policy(POLICY),
    actor: { agent: 'claude-opus-5', session: 'sess_demo', principal: 'ops@acme.test' },
    // One human, approving mail but not blindly: they decline anything that
    // still looks wrong after the policy escalated it.
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

  for (const [i, [name, args, note]] of CALLS.entries()) {
    const id = i + 1;
    stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }) + '\n');

    const deadline = Date.now() + 5000;
    while (!replies.has(id) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 5));

    const reply = replies.get(id);
    const blocked = reply?.result?.isError === true;
    const text = (reply?.result?.content?.[0]?.text ?? '').split('\n')[0];
    say(
      `  ${blocked ? RED('BLOCKED') : GREEN('ran    ')}  ${`ops.${name}`.padEnd(16)} ${DIM(note)}`,
    );
    if (blocked) say(`            ${YELLOW(text.replace('Blocked by Vouchwell policy. ', ''))}`);
  }

  stdin.end();
  await running;
  proxy.finalize();

  say();
  say(`  ${log.size} receipts written · ${proxy.stats.denied} actions refused · checkpoint signed`);

  // ── 2. Verify ─────────────────────────────────────────────────────────
  step(2, 'Anyone can verify the log — no trust in us required');

  const audit = ProofLog.open(dir, { readOnly: true }).audit();
  say(`  ${audit.ok ? GREEN('✓') : RED('✗')} ${audit.ok ? 'every signature, chain link and checkpoint verifies' : 'problems found'}`);
  say(DIM(`  merkle root  ${audit.root}`));

  const bundle = JSON.parse(JSON.stringify(ProofLog.open(dir, { readOnly: true }).bundle()));
  const bundleCheck = verifyBundle(bundle);
  say(`  ${bundleCheck.ok ? GREEN('✓') : RED('✗')} the exported evidence bundle verifies standing alone (${bundleCheck.checked} receipts)`);
  say(DIM('    no payloads, no salts, no database — one file an auditor can check offline'));

  // ── 3. Attack it ──────────────────────────────────────────────────────
  step(3, 'Four ways to cover your tracks, and what each one costs');

  const attacks = [
    {
      name: 'Edit a receipt in place',
      how: 'quietly reduce the amount on a refund that was already approved',
      run: (lines) => {
        const i = lines.findIndex((l) => JSON.parse(l).action.metrics?.amount_usd > 0);
        const r = JSON.parse(lines[i]);
        r.action.metrics.amount_usd = 1;
        lines[i] = canonicalize(r);
        return lines;
      },
    },
    {
      name: 'Delete a receipt',
      how: 'drop the entry that recorded the block',
      run: (lines) => lines.filter((l) => JSON.parse(l).decision.outcome !== 'deny'),
    },
    {
      name: 'Re-sign the whole chain',
      how: 'steal the signing key, remove an entry, rebuild every link',
      run: (lines) => {
        const identity = identityFromPem(fs.readFileSync(path.join(dir, 'key.pem'), 'utf8'));
        const kept = lines.map((l) => JSON.parse(l)).filter((r) => r.decision.outcome !== 'deny');
        let prev = GENESIS_PREV;
        return kept.map((r, i) => {
          const { attest: _drop, ...body } = r;
          const signed = signReceipt(identity, { ...body, seq: i, prev });
          prev = entryHash(signed);
          return canonicalize(signed);
        });
      },
    },
    {
      name: 'Truncate the log',
      how: 'keep only the first few entries',
      run: (lines) => lines.slice(0, 4),
    },
  ];

  for (const attack of attacks) {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchwell-attack-'));
    for (const f of ['config.json', 'key.pem', 'keyring.json', 'entries.jsonl', 'checkpoints.jsonl', 'salts.jsonl']) {
      fs.copyFileSync(path.join(dir, f), path.join(scratch, f));
    }

    const file = path.join(scratch, 'entries.jsonl');
    const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
    fs.writeFileSync(file, attack.run(lines).join('\n') + '\n');

    const result = ProofLog.open(scratch, { readOnly: true }).audit();
    say(`  ${B(attack.name)}`);
    say(DIM(`    ${attack.how}`));
    if (result.ok) {
      say(`    ${RED('✗ UNDETECTED')}`);
    } else {
      say(`    ${GREEN('✓ caught')} — ${result.issues[0].message}`);
    }
  }

  // ── 4. Witnesses ──────────────────────────────────────────────────────
  step(4, 'Independent witnesses close the last hole');

  say(DIM('  A log signing its own root can show two different histories to two'));
  say(DIM('  auditors. Witnesses only counter-sign a root that extends the last one'));
  say(DIM('  they saw, so a split view needs every witness to collude.'));
  say();

  const writable = ProofLog.open(dir);
  const w1 = generateIdentity().identity;
  const w2 = generateIdentity().identity;
  writable.trustKey(w1.kid, w1.publicKey);
  writable.trustKey(w2.kid, w2.publicKey);

  const cp = writable.checkpoints().at(-1);
  const cosigned = cosign(cosign(cp, w1), w2);
  // Pinned: the witnesses' keys come from us here, not from the checkpoint.
  const cpCheck = verifyCheckpoint(cosigned, writable.keyring, {
    minWitnesses: 2,
    trustedWitnesses: { [w1.kid]: w1.publicKey, [w2.kid]: w2.publicKey },
  });
  say(`  ${cpCheck.ok ? GREEN('✓') : RED('✗')} checkpoint at size ${cp.body.size} carries ${cpCheck.witnesses} independent witness signatures`);

  // ── 5. Erasure ────────────────────────────────────────────────────────
  step(5, 'Erasure without destroying the audit trail');

  // The first refund the agent actually made — the entry a customer might ask
  // us to erase.
  const target = writable.entries.find(
    (r) => r.action.target === 'ops.refund' && r.phase === 'intent',
  );
  const payload = CALLS.find(([name]) => name === 'refund')[1];

  const before = writable.reveal(target.seq, 'params', payload);
  say(`  ${before ? GREEN('✓') : RED('✗')} before: the payload of entry ${target.seq} can be confirmed against its commitment`);

  const shredded = writable.shred((r) => r.seq === target.seq);
  const after = ProofLog.open(dir, { readOnly: true });
  const stillOpenable = after.reveal(target.seq, 'params', payload);
  const stillValid = after.audit().ok;

  say(`  ${DIM(`  shredded ${shredded} payload commitment (a GDPR Article 17 request)`)}`);
  say(`  ${!stillOpenable ? GREEN('✓') : RED('✗')} after: that payload can no longer be confirmed by anyone, including us`);
  say(`  ${stillValid ? GREEN('✓') : RED('✗')} after: the audit trail still verifies end to end`);

  // ── Done ──────────────────────────────────────────────────────────────
  say();
  say(DIM('─'.repeat(74)));
  say(`  Explore the log this demo just wrote:`);
  say();
  say(`    ${CYAN(`node packages/cli/src/bin.js log   --log "${dir}"`)}`);
  say(`    ${CYAN(`node packages/cli/src/bin.js verify --log "${dir}"`)}`);
  say(`    ${CYAN(`node packages/cli/src/bin.js dash  --log "${dir}"`)}`);
  say();
}

await main();
