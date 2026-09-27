import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ProofLog, generateIdentity, cosign, verifyBundle, entryHash } from '@proof_wire/core';
import { summarise, frameworkMap, renderHtml } from '../src/report.js';

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/bin.js');

const actor = (principal = 'ops@acme.test') => ({ agent: 'claude-opus-5', runtime: 'test', session: 's1', principal });

/**
 * A log with one of everything a report has to account for, spread over two
 * days so a date filter has something to cut.
 */
function fixtureLog() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'proofwire-report-'));
  const log = ProofLog.create(dir);
  const add = (/** @type {any} */ a) => log.append(a);
  const allow = { outcome: 'allow', policy: 'p1', rules: [] };

  // Day one: a normal call, with its outcome.
  const intent = add({ ts: '2026-09-01T10:00:00.000Z', phase: 'intent', actor: actor(), action: { kind: 'tool_call', target: 'crm.query', params: { q: 1 } }, decision: allow });
  add({ ts: '2026-09-01T10:00:01.000Z', phase: 'outcome', ref: entryHash(intent), actor: actor(), action: { kind: 'tool_call', target: 'crm.query', params: { q: 1 } }, decision: allow, result: { status: 'ok', latencyMs: 12, payload: {} } });
  // A refusal, whose target tries to be markup.
  add({ ts: '2026-09-01T11:00:00.000Z', actor: actor(), action: { kind: 'tool_call', target: 'crm.<script>alert(1)</script>', params: {} }, decision: { outcome: 'deny', policy: 'p1', rules: ['no-scripts'], reason: 'destructive <b>SQL</b>' } });
  // Day two, under a new policy version: an approval by a person, a decline
  // by a person, and one nobody answered. The approved refund never comes
  // back: the process was killed while it was out.
  add({ ts: '2026-09-02T09:00:00.000Z', phase: 'intent', actor: actor('cfo@acme.test'), action: { kind: 'tool_call', target: 'stripe.refund', params: {}, metrics: { amount_usd: 250 } }, decision: { ...allow, policy: 'p2', rules: ['refunds.large'], approval: { by: 'slack:U024BE7LH (dana)', at: '2026-09-02T09:00:05.000Z', note: 'ok' } } });
  add({ ts: '2026-09-02T09:30:00.000Z', actor: actor(), action: { kind: 'tool_call', target: 'mail.send', params: {} }, decision: { outcome: 'deny', policy: 'p2', rules: ['mail.external'], reason: 'external mail — wrong customer', declined: { by: 'dana@acme.test', at: '2026-09-02T09:31:00.000Z', note: 'wrong customer' } } });
  add({ ts: '2026-09-02T10:00:00.000Z', actor: actor(), action: { kind: 'tool_call', target: 'mail.send', params: {} }, decision: { outcome: 'deny', policy: 'p2', rules: ['mail.external'], reason: 'external mail — nobody answered', declined: { by: 'policy:timeout', at: '2026-09-02T10:15:00.000Z' } } });
  // Monitor mode: ran, but the policy would have stopped it.
  const drop = add({ ts: '2026-09-02T11:00:00.000Z', phase: 'intent', actor: actor(), action: { kind: 'tool_call', target: 'db.drop', params: {} }, decision: { outcome: 'allow', policy: 'p2', rules: ['no-drop'], enforced: false, wouldBe: 'deny', reason: 'not enforced' } });
  // Still out when the proxy shut down, which recorded that it gave up.
  add({ ts: '2026-09-02T12:00:00.000Z', phase: 'outcome', ref: entryHash(drop), actor: actor(), action: { kind: 'tool_call', target: 'crm.query', params: {} }, decision: allow, result: { status: 'error', code: 'unfinished', payload: null } });
  assert.ok(intent);
  return { dir, log };
}

/**
 * @param {string} cwd
 * @param {string[]} args
 */
function pw(cwd, args) {
  const res = spawnSync(process.execPath, [BIN, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, HOME: cwd, USERPROFILE: cwd, NO_COLOR: '1' },
  });
  return { code: res.status, out: res.stdout + res.stderr };
}

test('the summary counts what happened, including who approved, who declined, and who never answered', () => {
  const { log } = fixtureLog();
  const s = /** @type {any} */ (summarise(log.entries));
  assert.equal(s.receipts, 8);
  assert.equal(s.calls, 6, 'outcome receipts are not calls');
  assert.equal(s.allowed, 3);
  assert.equal(s.denied, 3);
  assert.equal(s.approvedByPerson, 1);
  assert.equal(s.declinedByPerson, 1);
  assert.equal(s.unanswered, 1);
  assert.deepEqual(
    s.decisions.map((/** @type {any} */ d) => [d.decision, d.by, d.human]),
    [['approved', 'slack:U024BE7LH (dana)', true], ['declined', 'dana@acme.test', true], ['declined', 'policy:timeout', false]],
  );
  assert.equal(s.monitor.unenforced, 1);
  assert.deepEqual(s.monitor.wouldBlock, [{ name: 'no-drop', count: 1 }]);
  assert.equal(s.errors, 0, 'a call that never returned is not a tool error');
  assert.equal(s.unfinished, 2);
  assert.deepEqual(
    s.unfinishedActions.map((/** @type {any} */ u) => [u.target, u.why]),
    [['stripe.refund', 'no result recorded'], ['db.drop', 'recorder stopped before the reply']],
  );
  assert.deepEqual(s.spend, { amount_usd: 250 });
  assert.deepEqual(s.policies.map((/** @type {any} */ p) => [p.hash, p.calls]), [['p1', 2], ['p2', 4]]);
  assert.equal(s.period.days, 2);
});

test('the report escapes everything taken from the log, and runs no script', () => {
  const { log } = fixtureLog();
  const html = renderHtml({
    generatedAt: 'now', generator: 'test', log: { id: log.logId, kid: 'k' }, filter: {}, frameworks: ['ai-act', 'soc2'],
    integrity: { ok: true, issues: [], treeSize: 8, partial: false, root: 'r', checkpoints: 0, witnessSignatures: 0, pinned: false, pinnedWitnesses: 0 },
    summary: summarise(log.entries), files: ['a'],
  });
  assert.ok(!html.includes('<script>'), 'markup from a tool name reached the page');
  assert.ok(html.includes('crm.&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(html.includes('destructive &lt;b&gt;SQL&lt;/b&gt;'));
  assert.match(html, /Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"/);
  assert.match(html, /policy:timeout \(no person\)/);
});

test('the framework mapping says "supports", never that anything complies', () => {
  const { log } = fixtureLog();
  const text = JSON.stringify(frameworkMap(summarise(log.entries)));
  assert.doesNotMatch(text, /\bcomplies\b|\bcompliant\b|\bcertif/i);
  assert.match(text, /Art\. 12\(1\)/);
  assert.match(text, /Art\. 14/);
  assert.match(text, /CC7\.2/);
});

test('pw report writes a pack an auditor can verify on their own, with checksums', () => {
  const { dir, log } = fixtureLog();
  // A witness countersigns the latest checkpoint; the auditor pins it.
  const cp = log.checkpoint();
  const witness = generateIdentity().identity;
  // As `pw cosign` does: keep the witness's key with the log, then its signature.
  log.trustKey(witness.kid, witness.publicKey);
  log.addSignature(cp.body.size, cosign(cp, witness).sigs.find((x) => x.role === 'witness'));

  const cwd = path.dirname(dir);
  const out = path.join(cwd, `pack-${path.basename(dir)}`);
  const res = pw(cwd, ['report', '--log', dir, '--out', out, '--witness-key', `${witness.kid}=${witness.publicKey}`]);
  assert.equal(res.code, 0, res.out);
  assert.match(res.out, /Evidence pack written/);
  assert.match(res.out, /1 on the latest checkpoint, 1 pinned/);

  for (const f of ['evidence.bundle.json', 'report.html', 'summary.json', 'SHA256SUMS']) assert.ok(fs.existsSync(path.join(out, f)), f);

  // The checksums match the files.
  for (const line of fs.readFileSync(path.join(out, 'SHA256SUMS'), 'utf8').trim().split('\n')) {
    const [sum, name] = line.split(/\s+/);
    assert.equal(createHash('sha256').update(fs.readFileSync(path.join(out, name))).digest('hex'), sum, name);
  }

  // The bundle verifies independently, with the witness pinned, and matches the report.
  const bundle = JSON.parse(fs.readFileSync(path.join(out, 'evidence.bundle.json'), 'utf8'));
  assert.ok(verifyBundle(bundle, { minWitnesses: 1, trustedWitnesses: { [witness.kid]: witness.publicKey } }).ok);
  const summary = JSON.parse(fs.readFileSync(path.join(out, 'summary.json'), 'utf8'));
  assert.equal(summary.integrity.root, bundle.root);
  assert.equal(summary.integrity.pinnedWitnesses, 1);

  const html = fs.readFileSync(path.join(out, 'report.html'), 'utf8');
  assert.match(html, /Verified: all 8 receipts/);
  assert.match(html, /EU AI Act/);
  assert.match(html, /SOC 2/);
  assert.match(html, /1 verified against keys the report&#39;s author pinned|1 verified against keys the report's author pinned/);

  assert.equal(pw(cwd, ['check', path.join(out, 'evidence.bundle.json'), '--witnesses', '1', '--witness-key', `${witness.kid}=${witness.publicKey}`]).code, 0);
});

test('a date range narrows the pack, and says it is a filtered export', () => {
  const { dir } = fixtureLog();
  const cwd = path.dirname(dir);
  const out = path.join(cwd, `pack-range-${path.basename(dir)}`);
  const res = pw(cwd, ['report', '--log', dir, '--out', out, '--since', '2026-09-02', '--framework', 'soc2']);
  assert.equal(res.code, 0, res.out);
  const summary = JSON.parse(fs.readFileSync(path.join(out, 'summary.json'), 'utf8'));
  assert.equal(summary.summary.receipts, 5);
  assert.equal(summary.integrity.partial, true);
  assert.deepEqual(summary.frameworks, ['soc2']);
  const html = fs.readFileSync(path.join(out, 'report.html'), 'utf8');
  assert.doesNotMatch(html, /EU AI Act/);
  assert.match(html, /a filtered export/);
  assert.match(res.out, /No witness has countersigned/);
});

test('a tampered log produces a pack that says so, and exits non-zero', () => {
  const { dir } = fixtureLog();
  // Rewrite history on disk: the refusal becomes a harmless-looking query.
  const file = path.join(dir, 'entries.jsonl');
  const text = fs.readFileSync(file, 'utf8');
  assert.ok(text.includes('crm.<script>'), 'fixture layout changed');
  fs.writeFileSync(file, text.replace('crm.<script>alert(1)</script>', 'crm.query'));

  const cwd = path.dirname(dir);
  const out = path.join(cwd, `pack-tampered-${path.basename(dir)}`);
  const res = pw(cwd, ['report', '--log', dir, '--out', out]);
  assert.equal(res.code, 1, res.out);
  assert.match(res.out, /FAILED/);
  const html = fs.readFileSync(path.join(out, 'report.html'), 'utf8');
  assert.match(html, /Verification FAILED/);
  assert.doesNotMatch(html, /Verified: all/);
  assert.equal(JSON.parse(fs.readFileSync(path.join(out, 'summary.json'), 'utf8')).integrity.ok, false);
});

test('bad options are refused before anything is written', () => {
  const { dir } = fixtureLog();
  const cwd = path.dirname(dir);
  assert.equal(pw(cwd, ['report', '--log', dir, '--framework', 'hipaa']).code, 2);
  assert.equal(pw(cwd, ['report', '--log', dir, '--since', 'last tuesday']).code, 2);
});
