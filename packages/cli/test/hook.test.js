import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ProofLog, entryHash, verifyBundle, composePolicy } from '@vouchwell/core';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, '../src/bin.js');

/** A project with the coding-agent and shell-safety templates as its policy. */
function project() {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchwell-hook-'));
  fs.writeFileSync(path.join(cwd, 'vouchwell.policy.json'), JSON.stringify(composePolicy(['coding-agent', 'shell-safety'])));
  return cwd;
}

/**
 * @param {string} cwd
 * @param {string[]} args
 * @param {string} [input]
 * @param {Record<string, string>} [env]
 */
function vw(cwd, args, input, env = {}) {
  const res = spawnSync(process.execPath, [BIN, ...args], {
    cwd,
    input,
    encoding: 'utf8',
    timeout: 20000,
    env: { ...process.env, HOME: cwd, USERPROFILE: cwd, NO_COLOR: '1', VOUCHWELL_HOOK: '', ...env },
  });
  return { code: res.status, stdout: res.stdout, stderr: res.stderr };
}

/** One Claude Code hook event, as JSON. @param {string} name @param {object} fields */
const event = (name, fields) => JSON.stringify({ hook_event_name: name, session_id: 's1', cwd: '/repo', ...fields });

/** @param {string} cwd @param {string} name @param {object} fields @param {string[]} [flags] */
const fire = (cwd, name, fields, flags = []) => vw(cwd, ['hook', ...flags], event(name, fields));

/** @param {string} cwd */
const entries = (cwd) => ProofLog.open(path.join(cwd, '.vouchwell'), { readOnly: true }).entries;

/** @param {string} stdout */
const decision = (stdout) => (stdout.trim() ? JSON.parse(stdout).hookSpecificOutput : null);

const BASH = (/** @type {string} */ command, id = 't1') => ({ tool_name: 'Bash', tool_use_id: id, tool_input: { command } });

test('an allowed call gets an intent before it runs and an outcome linked to it after', () => {
  const cwd = project();
  const pre = fire(cwd, 'PreToolUse', BASH('npm test'));
  assert.equal(pre.code, 0, pre.stderr);
  assert.equal(decision(pre.stdout), null, 'allowed: the hook says nothing, so Claude Code prompts as usual');
  assert.equal(entries(cwd).length, 1, 'durable before the tool runs');

  fire(cwd, 'PostToolUse', { ...BASH('npm test'), tool_response: { stdout: 'ok' }, duration_ms: 42 });
  const [intent, outcome] = entries(cwd);
  assert.equal(intent.phase, 'intent');
  assert.equal(intent.action.target, 'claude-code.Bash');
  assert.equal(intent.actor.agent, 'claude-code');
  assert.equal(intent.actor.session, 'cc_s1');
  assert.equal(outcome.phase, 'outcome');
  assert.equal(outcome.ref, entryHash(intent));
  assert.equal(outcome.result.status, 'ok');
  assert.equal(outcome.result.latencyMs, 42);
  assert.equal(vw(cwd, ['verify']).code, 0);
});

test('a refused call is denied to Claude Code and recorded once', () => {
  const cwd = project();
  const res = fire(cwd, 'PreToolUse', { tool_name: 'Read', tool_use_id: 't1', tool_input: { file_path: '/repo/.env' } });
  const out = decision(res.stdout);
  assert.equal(out.hookEventName, 'PreToolUse');
  assert.equal(out.permissionDecision, 'deny');
  assert.match(out.permissionDecisionReason, /secret files/);
  const [r] = entries(cwd);
  assert.equal(entries(cwd).length, 1);
  assert.equal(r.phase, 'atomic');
  assert.equal(r.decision.outcome, 'deny');
  assert.deepEqual(r.decision.rules.includes('coding-agent.secret-files'), true);
});

test('an escalation asks Claude Code’s user; running means approved, never running means declined', () => {
  const cwd = project();
  const ask = fire(cwd, 'PreToolUse', BASH('git commit -m x --no-verify', 'a1'));
  assert.equal(decision(ask.stdout).permissionDecision, 'ask');
  assert.equal(entries(cwd).length, 0, 'nothing is recorded until it is known whether it ran');

  fire(cwd, 'PostToolUse', { ...BASH('git commit -m x --no-verify', 'a1'), tool_response: {}, duration_ms: 5 });
  const [intent, outcome] = entries(cwd);
  assert.equal(intent.decision.outcome, 'allow');
  assert.equal(intent.decision.approval.by, 'claude-code:user');
  assert.match(intent.decision.reason, /approved in Claude Code/);
  assert.equal(outcome.ref, entryHash(intent));

  // Asked again, and this time the session ends without it running.
  fire(cwd, 'PreToolUse', BASH('git push --no-verify origin x', 'a2'));
  fire(cwd, 'SessionEnd', { reason: 'exit' });
  const declined = entries(cwd).at(-1);
  assert.equal(declined.decision.outcome, 'deny');
  assert.equal(declined.decision.declined.by, 'claude-code:user');
});

test('a call that never reports back is closed as not run when the session ends, and the log is checkpointed', () => {
  const cwd = project();
  fire(cwd, 'PreToolUse', { tool_name: 'Edit', tool_use_id: 'e1', tool_input: { file_path: '/repo/a.js' } });
  fire(cwd, 'SessionEnd', { reason: 'exit' });
  const [intent, outcome] = entries(cwd);
  assert.equal(outcome.ref, entryHash(intent));
  assert.equal(outcome.result.code, 'not_run');
  const log = ProofLog.open(path.join(cwd, '.vouchwell'), { readOnly: true });
  assert.equal(log.checkpoints().length, 1);
  assert.equal(JSON.parse(fs.readFileSync(path.join(cwd, '.vouchwell', 'hook-pending.json'), 'utf8'))['e1'], undefined);
});

test("another session's open calls are left for its own SessionEnd", () => {
  const cwd = project();
  fire(cwd, 'PreToolUse', BASH('npm test', 'mine'));
  vw(cwd, ['hook'], JSON.stringify({ hook_event_name: 'SessionEnd', session_id: 'other', reason: 'exit' }));
  assert.equal(entries(cwd).length, 1);
});

test('failures, interruptions and permission refusals are recorded as errors', () => {
  const cwd = project();
  fire(cwd, 'PreToolUse', BASH('npm run build', 'f1'));
  fire(cwd, 'PostToolUseFailure', { ...BASH('npm run build', 'f1'), error: 'exit 1', is_interrupt: false, duration_ms: 9 });
  fire(cwd, 'PreToolUse', BASH('sleep 100', 'f2'));
  fire(cwd, 'PostToolUseFailure', { ...BASH('sleep 100', 'f2'), error: 'interrupted', is_interrupt: true });
  fire(cwd, 'PreToolUse', BASH('ls', 'f3'));
  fire(cwd, 'PermissionDenied', { ...BASH('ls', 'f3'), reason: 'the auto-mode classifier refused it' });
  const outcomes = entries(cwd).filter((r) => r.phase === 'outcome');
  assert.deepEqual(outcomes.map((r) => r.result.code), ['tool_error', 'interrupted', 'permission_denied']);
});

test('monitor mode blocks nothing and records what the policy would have done', () => {
  const cwd = project();
  const res = fire(cwd, 'PreToolUse', { tool_name: 'Read', tool_use_id: 'm1', tool_input: { file_path: '/repo/.env' } }, ['--monitor']);
  assert.equal(decision(res.stdout), null);
  const [r] = entries(cwd);
  assert.equal(r.decision.outcome, 'allow');
  assert.equal(r.decision.wouldBe, 'deny');
  assert.equal(r.decision.enforced, false);
});

test('tool arguments are previewed and tool output is not, by default; "none" keeps only commitments', () => {
  const cwd = project();
  fire(cwd, 'PreToolUse', BASH('npm test', 'p1'));
  fire(cwd, 'PostToolUse', { ...BASH('npm test', 'p1'), tool_response: { stdout: 'the whole output' } });
  const [intent, outcome] = entries(cwd);
  assert.deepEqual(intent.action.params.preview, { command: 'npm test' });
  assert.equal(outcome.result.payload.preview, undefined);

  const bare = project();
  fs.writeFileSync(path.join(bare, 'vouchwell.config.json'), JSON.stringify({ hook: { previews: 'none', principal: 'maintainers' } }));
  fire(bare, 'PreToolUse', BASH('npm test', 'p2'));
  const [r] = entries(bare);
  assert.equal(r.action.params.preview, undefined);
  assert.equal(r.actor.principal, 'maintainers');
  assert.ok(!JSON.stringify(r).includes('npm test'), 'nothing of the command is in the receipt');
});

test('parallel tool calls from one session, each its own process, keep one unbroken chain', async () => {
  const cwd = project();
  const n = 8;
  await Promise.all(Array.from({ length: n }, (_, i) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN, 'hook'], { cwd, env: { ...process.env, HOME: cwd, NO_COLOR: '1', VOUCHWELL_HOOK: '' } });
    child.on('error', reject);
    child.on('close', resolve);
    child.stdin.end(event('PreToolUse', BASH(`echo ${i}`, `par${i}`)));
  })));
  assert.equal(entries(cwd).length, n);
  const verify = vw(cwd, ['verify']);
  assert.equal(verify.code, 0, verify.stdout + verify.stderr);
  assert.ok(!fs.existsSync(path.join(cwd, '.vouchwell', 'hook.lock')), 'the lock is released');
});

test("a lock left by a writer that died is taken over; a live writer's is waited for", () => {
  const cwd = project();
  fire(cwd, 'PreToolUse', BASH('npm test'));
  const lock = path.join(cwd, '.vouchwell', 'hook.lock');
  const dead = spawnSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'], { encoding: 'utf8' }).stdout;
  fs.writeFileSync(lock, dead);
  const res = fire(cwd, 'PostToolUse', { ...BASH('npm test'), tool_response: {} });
  assert.equal(res.code, 0, res.stderr);
  assert.equal(entries(cwd).length, 2);
  assert.ok(!fs.existsSync(lock));

  // This test's own process is alive: the hook waits it out and gives up.
  fs.writeFileSync(lock, String(process.pid));
  const held = vw(cwd, ['hook'], event('PreToolUse', BASH('npm test', 't2')), { VOUCHWELL_HOOK_LOCK_WAIT_MS: '300' });
  assert.equal(decision(held.stdout).permissionDecision, 'deny', 'when enforcing, unrecordable means refused');
  assert.match(decision(held.stdout).permissionDecisionReason, /stayed locked/);
  fs.rmSync(lock);
});

test('when enforcing, a call that cannot be recorded is refused; VOUCHWELL_HOOK=off turns recording off', () => {
  const cwd = project();
  fire(cwd, 'PreToolUse', BASH('npm test'));
  fs.writeFileSync(path.join(cwd, '.vouchwell', 'config.json'), '{ not json');
  const res = fire(cwd, 'PreToolUse', BASH('npm test', 't2'));
  assert.equal(decision(res.stdout).permissionDecision, 'deny');
  assert.match(decision(res.stdout).permissionDecisionReason, /could not record/);

  const monitor = fire(cwd, 'PreToolUse', BASH('npm test', 't3'), ['--monitor']);
  assert.equal(monitor.stdout, '', 'in monitor mode a broken log blocks nothing');

  const off = project();
  const skipped = vw(off, ['hook'], event('PreToolUse', BASH('cat .env')), { VOUCHWELL_HOOK: 'off' });
  assert.equal(skipped.stdout, '');
  assert.ok(!fs.existsSync(path.join(off, '.vouchwell')));
});

test('events it does not handle, and input that is not an event, change nothing', () => {
  const cwd = project();
  assert.equal(vw(cwd, ['hook'], event('Stop', {})).code, 0);
  assert.equal(vw(cwd, ['hook'], 'not json').code, 2);
  assert.ok(!fs.existsSync(path.join(cwd, '.vouchwell')));
});

test('install adds the hooks beside existing ones, is idempotent, and uninstall removes only its own', () => {
  const cwd = project();
  const file = path.join(cwd, '.claude', 'settings.json');
  fs.mkdirSync(path.dirname(file));
  const theirs = { type: 'command', command: '~/stop-check.sh' };
  fs.writeFileSync(file, JSON.stringify({ permissions: { allow: ['Read'] }, hooks: { Stop: [{ hooks: [theirs] }], PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'lint.sh' }] }] } }));

  assert.equal(vw(cwd, ['hook', 'install']).code, 0);
  assert.equal(vw(cwd, ['hook', 'install']).code, 0);
  const installed = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(installed.permissions, { allow: ['Read'] });
  assert.deepEqual(installed.hooks.Stop, [{ hooks: [theirs] }]);
  for (const name of ['PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'PermissionDenied', 'SessionEnd']) {
    const ours = installed.hooks[name].flatMap((/** @type {any} */ g) => g.hooks).filter((/** @type {any} */ h) => h.command === 'vw hook');
    assert.equal(ours.length, 1, `${name}: installed once, however many times install runs`);
  }
  assert.equal(installed.hooks.PreToolUse[0].hooks[0].command, 'lint.sh', 'their PreToolUse hook is kept, first');
  assert.equal(installed.hooks.PreToolUse[1].matcher, '*');
  assert.equal(installed.hooks.SessionEnd[0].matcher, undefined);

  assert.equal(vw(cwd, ['hook', 'uninstall']).code, 0);
  const after = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(after.hooks, { Stop: [{ hooks: [theirs] }], PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'lint.sh' }] }] });

  assert.equal(vw(cwd, ['hook', 'install', '--user', '--monitor']).code, 0);
  const user = JSON.parse(fs.readFileSync(path.join(cwd, '.claude', 'settings.json'), 'utf8'));
  assert.ok(user.hooks.PostToolUse, '--user writes ~/.claude/settings.json (HOME is the project here)');

  const nowhere = project();
  assert.equal(vw(nowhere, ['hook', 'uninstall']).code, 0);
  assert.ok(!fs.existsSync(path.join(nowhere, '.claude')), 'uninstall creates nothing');

  fs.writeFileSync(file, '{ broken');
  const refused = vw(cwd, ['hook', 'install']);
  assert.equal(refused.code, 1);
  assert.equal(fs.readFileSync(file, 'utf8'), '{ broken', 'a settings file it cannot read is left alone');
});

test('rate limits still count past calls, read back only as far as their window', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchwell-hook-'));
  fs.writeFileSync(path.join(cwd, 'vouchwell.policy.json'), JSON.stringify({
    version: 1, name: 'slow-down',
    rateLimits: [{ id: 'bash.burst', match: { target: 'claude-code.Bash' }, limit: 2, window: '1h', then: 'deny' }],
  }));
  for (const id of ['r1', 'r2']) {
    assert.equal(decision(fire(cwd, 'PreToolUse', BASH('ls', id)).stdout), null);
    fire(cwd, 'PostToolUse', { ...BASH('ls', id), tool_response: {} });
  }
  const third = decision(fire(cwd, 'PreToolUse', BASH('ls', 'r3')).stdout);
  assert.equal(third.permissionDecision, 'deny');
  assert.match(third.permissionDecisionReason, /bash\.burst|rate|limit/i);

  // Two intents written two hours ago no longer count against a 1h window.
  const old = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchwell-hook-'));
  fs.copyFileSync(path.join(cwd, 'vouchwell.policy.json'), path.join(old, 'vouchwell.policy.json'));
  const log = ProofLog.create(path.join(old, '.vouchwell'));
  const twoHoursAgo = new Date(Date.now() - 2 * 3600_000).toISOString();
  for (let i = 0; i < 2; i++) {
    log.append({ actor: { agent: 'claude-code', session: 'cc_s1', principal: 'p' }, action: { kind: 'tool_call', target: 'claude-code.Bash', params: {} },
      decision: { outcome: 'allow', policy: 'p', rules: [] }, result: null, phase: 'intent', ts: twoHoursAgo });
  }
  assert.equal(decision(fire(old, 'PreToolUse', BASH('ls', 'r4')).stdout), null);
});

test('with an evidence folder set, the session end writes the bundle there', () => {
  const cwd = project();
  fs.writeFileSync(path.join(cwd, 'vouchwell.config.json'), JSON.stringify({ hook: { evidence: 'proof' } }));
  fire(cwd, 'PreToolUse', BASH('npm test'));
  fire(cwd, 'PostToolUse', { ...BASH('npm test'), tool_response: {} });
  assert.ok(!fs.existsSync(path.join(cwd, 'proof')), 'written at the end of the session, not on every call');
  fire(cwd, 'SessionEnd', { reason: 'exit' });
  const [name] = fs.readdirSync(path.join(cwd, 'proof'));
  const bundle = JSON.parse(fs.readFileSync(path.join(cwd, 'proof', name), 'utf8'));
  assert.equal(bundle.entries.length, 2);
  assert.equal(bundle.checkpoints.length, 1, 'the checkpoint the session end just made is in it');
  assert.ok(verifyBundle(bundle).ok);

  const without = project();
  fire(without, 'PreToolUse', BASH('npm test'));
  fire(without, 'SessionEnd', { reason: 'exit' });
  assert.ok(!fs.existsSync(path.join(without, 'evidence')), 'nothing is written unless asked for');
});

test('evidence checkpoints the log and writes a bundle anyone can verify', () => {
  const cwd = project();
  fire(cwd, 'PreToolUse', BASH('npm test'));
  fire(cwd, 'PostToolUse', { ...BASH('npm test'), tool_response: { stdout: 'ok' } });
  const res = vw(cwd, ['hook', 'evidence']);
  assert.equal(res.code, 0, res.stderr);
  const [name] = fs.readdirSync(path.join(cwd, 'evidence'));
  const bundle = JSON.parse(fs.readFileSync(path.join(cwd, 'evidence', name), 'utf8'));
  assert.equal(name, `${bundle.log}.json`);
  assert.equal(bundle.entries.length, 2);
  assert.ok(verifyBundle(bundle).ok);
  assert.equal(vw(cwd, ['check', path.join('evidence', name)]).code, 0);

  const empty = project();
  assert.equal(vw(empty, ['hook', 'evidence']).code, 1);
});

test('a --config that names a missing file is an error, never a fresh log in the default place', () => {
  const cwd = project();
  const res = fire(cwd, 'PreToolUse', BASH('npm test'), ['--config', 'gone/vouchwell.config.json']);
  assert.equal(decision(res.stdout).permissionDecision, 'deny', 'when enforcing, unrecordable means refused');
  assert.match(decision(res.stdout).permissionDecisionReason, /no config file at/);
  const monitored = fire(cwd, 'PostToolUse', { ...BASH('npm test'), tool_response: {} }, ['--monitor', '--config', 'gone/vouchwell.config.json']);
  assert.equal(monitored.code, 0);
  assert.match(monitored.stderr, /no config file at/);
  assert.ok(!fs.existsSync(path.join(cwd, '.vouchwell')), 'no log was started');
});
