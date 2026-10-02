import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ProofLog, LogAppender, History, parseWindow, entryHash, canonicalize } from '@deedwrit/core';
import { c, out, err, ok, bad, info, heading, kv } from './ui.js';

/**
 * `dw hook`: record, and gate, what a coding agent does with its own tools.
 *
 * `dw proxy` sees an agent's MCP servers. A coding agent does most of its work
 * with built-in tools instead: it runs shell commands, reads and edits files,
 * fetches pages. Claude Code runs a command before and after every one of
 * those (its hooks), and this is that command. Claude Code writes one JSON
 * event to stdin per call:
 *
 *   PreToolUse          the policy decides. Allowed: an `intent` receipt,
 *                       durable before the tool runs. Refused: one receipt,
 *                       and Claude Code is told to deny the call. Escalated:
 *                       Claude Code asks its user, who is the approver.
 *   PostToolUse         the `outcome` receipt, linked to its intent.
 *   PostToolUseFailure  the same, as an error.
 *   PermissionDenied    Claude Code's own permission check refused it.
 *   SessionEnd          anything still open is closed as not run, and the log
 *                       is checkpointed.
 *
 * Each event is a separate process, so what one event leaves for the next (the
 * intent a tool call's outcome links to) is kept beside the log, and every
 * process takes a lock first: Claude Code runs the hooks of parallel tool calls
 * at the same time, and two writers would fork the chain.
 *
 * Claude Code's own permission prompts still apply. An allowed call is
 * recorded, not approved: the hook says nothing and the prompt, if any, is
 * shown as usual.
 */

const EVENTS = ['PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'PermissionDenied', 'SessionEnd'];
const TOOL_EVENTS = new Set(['PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'PermissionDenied']);
const PENDING = 'hook-pending.json';
const LOCK = 'hook.lock';

/**
 * @param {any} args
 * @param {{ loadConfig: (args: any) => { dir: string, config: any }, loadPolicy: (config: any, args: any) => any, version: string }} deps
 */
export async function cmdHook(args, deps) {
  const sub = args._[1];
  if (sub === 'install') return install(args);
  if (sub === 'uninstall') return uninstall(args);
  if (sub === 'evidence') return evidence(args, deps);
  if (sub !== undefined) {
    bad(`unknown hook command "${sub}"; try install, uninstall, evidence, or no argument to handle an event from stdin`);
    return 2;
  }
  return handleEvent(args, deps, fs.readFileSync(0, 'utf8'));
}

// ─────────────────────────────────────────────────────────────── events ──

/**
 * Handle one event. Exported for tests, which pass the event text directly.
 *
 * Returns the exit code. Anything Claude Code should act on is written to
 * stdout as its hook JSON; everything else goes to stderr.
 *
 * @param {any} args
 * @param {{ loadConfig: (args: any) => { dir: string, config: any }, loadPolicy: (config: any, args: any) => any, version: string }} deps
 * @param {string} text
 */
export function handleEvent(args, deps, text) {
  // For the person at the keyboard, never the agent: the agent's shell
  // cannot change the environment Claude Code starts hooks with.
  if (process.env.DEEDWRIT_HOOK === 'off') return 0;

  /** @type {any} */
  let event;
  try {
    event = JSON.parse(text);
  } catch {
    err('deedwrit hook: expected one JSON event on stdin, from a Claude Code hook');
    return 2;
  }
  const name = event?.hook_event_name;
  if (!EVENTS.includes(name)) return 0; // Not one this handles: say nothing.

  const { dir, config } = deps.loadConfig(args);
  const settings = { ...(config.hook ?? {}) };
  const monitor = !args.enforce && (args.monitor === true || (settings.monitor ?? config.monitor) === true);

  try {
    return withLock(dir, () => {
      const log = openOrCreate(dir);
      const ctx = {
        log,
        dir,
        monitor,
        actor: {
          agent: args.agent ?? settings.agent ?? 'claude-code',
          runtime: `deedwrit-hook/${deps.version}`,
          session: `cc_${event.session_id ?? 'unknown'}`,
          principal: args.principal ?? settings.principal ?? config.actor?.principal ?? 'unknown',
        },
        namespace: args.namespace ?? settings.namespace ?? 'claude-code',
        previews: previewsFor(args.previews ?? settings.previews ?? 'params'),
        // Where SessionEnd writes the log as a bundle, if anywhere.
        evidence: typeof (args.evidence ?? settings.evidence) === 'string' ? (args.evidence ?? settings.evidence) : null,
      };
      if (name === 'PreToolUse') return pre(ctx, event, deps.loadPolicy(config, args));
      if (name === 'SessionEnd') return sessionEnd(ctx);
      return after(ctx, name, event);
    });
  } catch (e) {
    const message = /** @type {Error} */ (e).message;
    // Refuse what cannot be recorded, when enforcing: a gate that opens
    // whenever the log is unwritable is not one. Everything else carries on.
    if (name === 'PreToolUse' && !monitor) {
      respond('deny', `Deedwrit could not record this call, so it is refused: ${message}. ` +
        'Fix the log, or start Claude Code with DEEDWRIT_HOOK=off to turn recording off.');
      return 0;
    }
    err(`deedwrit hook: ${message}`);
    return 0;
  }
}

/**
 * @param {any} ctx
 * @param {any} event
 * @param {any} policy
 */
function pre(ctx, event, policy) {
  const target = `${ctx.namespace}.${event.tool_name}`;
  const params = event.tool_input ?? {};
  let decision = policy.decide(
    { kind: 'tool_call', target, params, metrics: {}, actor: ctx.actor },
    new History(ctx.log.recent(historyWindow(policy))),
  );
  if (ctx.monitor) decision = monitored(decision);

  const pending = readPending(ctx.dir);
  const key = callKey(event);

  if (decision.outcome === 'deny') {
    append(ctx, { target, params, decision, result: null, phase: 'atomic' });
    respond('deny', `Refused by Deedwrit policy: ${decision.reason}`);
    return 0;
  }
  if (decision.outcome === 'escalate') {
    // Claude Code's user is the approver: they are asked, and the receipts
    // are written once it is known whether the call ran.
    pending[key] = { session: ctx.actor.session, target, decision, asked: true, at: new Date().toISOString() };
    writePending(ctx.dir, pending);
    respond('ask', `Deedwrit policy asks for a person: ${decision.reason}`);
    return 0;
  }
  const intent = append(ctx, { target, params, decision, result: null, phase: 'intent' });
  pending[key] = { session: ctx.actor.session, target, decision, intent: entryHash(intent), at: new Date().toISOString() };
  writePending(ctx.dir, pending);
  return 0;
}

/**
 * PostToolUse, PostToolUseFailure and PermissionDenied: the call is over.
 *
 * @param {any} ctx
 * @param {string} name
 * @param {any} event
 */
function after(ctx, name, event) {
  const pending = readPending(ctx.dir);
  const key = callKey(event);
  const call = pending[key];
  delete pending[key];
  const target = call?.target ?? `${ctx.namespace}.${event.tool_name}`;
  const params = event.tool_input ?? {};

  if (name === 'PermissionDenied') {
    if (call?.intent) {
      append(ctx, {
        target, params, decision: call.decision, phase: 'outcome', ref: call.intent,
        result: { status: 'error', code: 'permission_denied', payload: { reason: String(event.reason ?? '') } },
      });
    } else {
      const decision = call?.decision ?? { outcome: 'deny', policy: 'none', rules: [], reason: 'refused by Claude Code' };
      append(ctx, {
        target, params, phase: 'atomic', result: null,
        decision: { ...decision, outcome: 'deny', declined: { by: 'claude-code', at: new Date().toISOString(), note: String(event.reason ?? 'permission denied') } },
      });
    }
    writePending(ctx.dir, pending);
    return 0;
  }

  const result = name === 'PostToolUse'
    ? { status: 'ok', latencyMs: event.duration_ms, payload: event.tool_response ?? null }
    : { status: 'error', code: event.is_interrupt ? 'interrupted' : 'tool_error', latencyMs: event.duration_ms, payload: { error: String(event.error ?? '').slice(0, 2000) } };

  let ref = call?.intent;
  let decision = call?.decision;
  if (call?.asked) {
    // It ran, so the person Claude Code asked said yes.
    const at = new Date().toISOString();
    decision = {
      ...call.decision,
      outcome: 'allow',
      reason: `${call.decision.reason} — approved in Claude Code`,
      approval: { by: 'claude-code:user', at },
    };
    ref = entryHash(append(ctx, { target, params, decision, result: null, phase: 'intent' }));
  }
  if (ref) {
    append(ctx, { target, params, decision, result, phase: 'outcome', ref });
  } else {
    // No record of it starting: the hook was installed mid-call, or the
    // PreToolUse hook is not configured. Recorded as what it is.
    append(ctx, {
      target, params, result, phase: 'atomic',
      decision: { outcome: 'allow', policy: 'none', rules: [], reason: 'recorded after it ran: there was no PreToolUse record of it' },
    });
  }
  writePending(ctx.dir, pending);
  return 0;
}

/**
 * Close this session's calls that never reported back, then checkpoint.
 *
 * @param {any} ctx
 */
function sessionEnd(ctx) {
  const pending = readPending(ctx.dir);
  for (const [key, call] of Object.entries(pending)) {
    if (call.session !== ctx.actor.session) continue;
    if (call.intent) {
      append(ctx, {
        target: call.target, params: null, decision: call.decision, phase: 'outcome', ref: call.intent,
        result: { status: 'error', code: 'not_run', payload: { reason: 'no result was reported before the session ended: declined at a prompt, or interrupted' } },
      });
    } else if (call.asked) {
      append(ctx, {
        target: call.target, params: null, phase: 'atomic', result: null,
        decision: { ...call.decision, outcome: 'deny', declined: { by: 'claude-code:user', at: new Date().toISOString(), note: 'not approved before the session ended' } },
      });
    }
    delete pending[key];
  }
  writePending(ctx.dir, pending);
  if (ctx.log.size === 0) return 0;
  ctx.log.checkpoint();
  if (ctx.evidence) writeEvidence(ctx.dir, path.resolve(ctx.evidence));
  return 0;
}

// ──────────────────────────────────────────────────────────── commands ──

/** Where Claude Code's settings for this install live. @param {any} args */
function settingsPath(args) {
  if (args.user) return path.join(os.homedir(), '.claude', 'settings.json');
  return path.resolve('.claude', args.local ? 'settings.local.json' : 'settings.json');
}

/** @param {any} args */
function hookCommand(args) {
  return typeof args.command === 'string' ? args.command : `dw hook${args.monitor === true ? ' --monitor' : ''}`;
}

/** @param {string} file */
function readSettings(file) {
  const text = readIfPresent(file);
  if (text === null) return {};
  try {
    return text.trim() ? JSON.parse(text) : {};
  } catch {
    throw new Error(`${file} is not valid JSON; fix it by hand first, so nothing in it is lost`);
  }
}

/**
 * Take this command's entries out of a settings object, leaving everything
 * else as it was.
 *
 * @param {any} settings
 * @param {string} command
 */
function withoutOurs(settings, command) {
  const hooks = { ...(settings.hooks ?? {}) };
  for (const event of EVENTS) {
    if (!Array.isArray(hooks[event])) continue;
    const kept = hooks[event]
      .map((/** @type {any} */ group) => ({ ...group, hooks: (group.hooks ?? []).filter((/** @type {any} */ h) => h?.command !== command) }))
      .filter((/** @type {any} */ group) => group.hooks.length > 0);
    if (kept.length) hooks[event] = kept;
    else delete hooks[event];
  }
  return hooks;
}

/** @param {any} args */
function install(args) {
  const file = settingsPath(args);
  const command = hookCommand(args);
  const settings = readSettings(file);
  const hooks = withoutOurs(settings, command);
  for (const event of EVENTS) {
    const entry = { type: 'command', command, timeout: 30 };
    hooks[event] = [...(hooks[event] ?? []), TOOL_EVENTS.has(event) ? { matcher: '*', hooks: [entry] } : { hooks: [entry] }];
  }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify({ ...settings, hooks }, null, 2) + '\n');

  ok(`Claude Code will run ${c.cyan(command)} around every tool call`);
  info(`settings: ${file}`);
  info('It takes effect in the next Claude Code session.');
  out('');
  out(`  ${c.bold('Next')}`);
  out(`    ${c.cyan('dw policy template coding-agent shell-safety secrets --out deedwrit.policy.json')}`);
  out(`      ${c.grey('a starting policy for a coding agent')}`);
  out(`    ${c.cyan('dw log')}   ${c.grey('what the agent did')}      ${c.cyan('dw hook evidence')}   ${c.grey('a bundle to share')}`);
  out('');
  return 0;
}

/** @param {any} args */
function uninstall(args) {
  const file = settingsPath(args);
  const command = hookCommand(args);
  // No settings file: nothing was installed, and nothing is created.
  if (readIfPresent(file) === null) {
    ok(`${file} does not exist; nothing to remove`);
    return 0;
  }
  const settings = readSettings(file);
  const hooks = withoutOurs(settings, command);
  const next = { ...settings, hooks };
  if (Object.keys(hooks).length === 0) delete next.hooks;
  fs.writeFileSync(file, JSON.stringify(next, null, 2) + '\n');
  ok(`removed ${c.cyan(command)} from ${file}`);
  return 0;
}

/**
 * Checkpoint the log and write it as an evidence bundle, named for the log so
 * the same log always lands in the same file.
 *
 * @param {any} args
 * @param {{ loadConfig: (args: any) => { dir: string, config: any } }} deps
 */
function evidence(args, deps) {
  const { dir } = deps.loadConfig(args);
  const outDir = path.resolve(args._[2] ?? 'evidence');
  const { file, bundle } = withLock(dir, () => {
    const log = LogAppender.open(dir);
    if (log.size === 0) throw new Error('the log is empty: nothing to put in a bundle yet');
    log.checkpoint();
    return writeEvidence(dir, outDir);
  });
  heading('Evidence written');
  kv([
    ['file', path.relative(process.cwd(), file) || file],
    ['entries', String(bundle.entries.length)],
    ['root', bundle.root],
  ]);
  out('');
  info('No payloads and no salts: safe to publish. Anyone can check it with');
  info(`  ${c.cyan(`dw check ${path.relative(process.cwd(), file)}`)}`);
  out('');
  return 0;
}

// ─────────────────────────────────────────────────────────────── helpers ──

/**
 * Write the log, as of its last checkpoint, as `<outDir>/<log id>.json`.
 * The one step here that reads the whole log: it proves every receipt.
 *
 * @param {string} dir
 * @param {string} outDir
 */
function writeEvidence(dir, outDir) {
  const log = ProofLog.open(dir, { readOnly: true });
  const bundle = log.bundle();
  fs.mkdirSync(outDir, { recursive: true });
  const file = path.join(outDir, `${log.logId}.json`);
  fs.writeFileSync(file, JSON.stringify(bundle, null, 2) + '\n');
  return { file, bundle };
}

/**
 * How far back the policy looks: its longest budget or rate-limit window,
 * with the defaults it applies itself. Nothing older can change a decision,
 * so nothing older is read.
 *
 * @param {any} policy
 */
function historyWindow(policy) {
  const windows = [
    ...(policy.budgets ?? []).map((/** @type {any} */ b) => parseWindow(b.window ?? '24h')),
    ...(policy.rateLimits ?? []).map((/** @type {any} */ r) => parseWindow(r.window ?? '1h')),
  ];
  return windows.length ? Math.max(...windows) : 0;
}

/** @param {'deny'|'ask'} decision @param {string} reason */
function respond(decision, reason) {
  out(JSON.stringify({
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: decision, permissionDecisionReason: reason },
  }));
}

/**
 * @param {any} ctx
 * @param {{ target: string, params: unknown, decision: any, result: any, phase: 'atomic'|'intent'|'outcome', ref?: string }} a
 */
function append(ctx, a) {
  return ctx.log.append({
    actor: ctx.actor,
    action: { kind: 'tool_call', target: a.target, params: a.params },
    decision: a.decision,
    result: a.result,
    phase: a.phase,
    ref: a.ref,
    previews: ctx.previews,
  });
}

/**
 * What goes into a receipt besides the commitment. Tool output is off by
 * default: it is whole files and command output, too large to copy into
 * every receipt, and the commitment still proves what it was.
 *
 * @param {string} mode
 */
function previewsFor(mode) {
  if (mode === 'all') return { params: true, result: true };
  if (mode === 'none') return { params: false, result: false };
  if (mode === 'params') return { params: true, result: false };
  throw new Error(`previews must be all, params or none; got ${JSON.stringify(mode)}`);
}

/** The proxy's monitor-mode rule: the call ran, so the receipt says allow. @param {any} decision */
function monitored(decision) {
  if (decision.outcome === 'allow') return { ...decision, enforced: false };
  return {
    ...decision,
    outcome: 'allow',
    enforced: false,
    wouldBe: decision.outcome,
    reason: `not enforced (monitor mode): would ${decision.outcome} — ${decision.reason}`,
  };
}

/**
 * Which call an event is about. Claude Code gives each one an id; without it,
 * the session, tool and arguments stand in.
 *
 * @param {any} event
 */
function callKey(event) {
  if (event.tool_use_id) return String(event.tool_use_id);
  const digest = createHash('sha256').update(canonicalize(event.tool_input ?? null)).digest('hex').slice(0, 16);
  return `${event.session_id}:${event.tool_name}:${digest}`;
}

/** @param {string} dir */
function openOrCreate(dir) {
  // Opened or created in one step each, never "check, then act": the hook
  // lock is held, but a log is a directory anyone can write to.
  if (readIfPresent(path.join(dir, 'config.json')) !== null) return LogAppender.open(dir);
  const log = ProofLog.create(dir);
  err(`deedwrit hook: started a new log at ${dir} (${log.logId})`);
  return LogAppender.open(dir);
}

/** @param {string} dir @returns {Record<string, any>} */
function readPending(dir) {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, PENDING), 'utf8'));
  } catch {
    return {};
  }
}

/** @param {string} dir @param {Record<string, any>} pending */
function writePending(dir, pending) {
  const file = path.join(dir, PENDING);
  const tmp = `${file}.${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(pending) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
}

/** @param {string} file @returns {string | null} */
function readIfPresent(file) {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch (e) {
    if (/** @type {NodeJS.ErrnoException} */ (e).code === 'ENOENT') return null;
    throw e;
  }
}

/**
 * Whether the process a lock file names is still running. A lock that is gone,
 * or not yet written, is treated as held: the next attempt settles it.
 *
 * @param {string | null} text
 */
function holderAlive(text) {
  const pid = Number(text);
  if (text === null || !Number.isInteger(pid) || pid <= 0) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    // EPERM: it exists and belongs to someone else.
    return /** @type {NodeJS.ErrnoException} */ (e).code !== 'ESRCH';
  }
}

/**
 * Run `fn` holding the log's hook lock: one writer at a time.
 *
 * @template T
 * @param {string} dir
 * @param {() => T} fn
 * @returns {T}
 */
export function withLock(dir, fn) {
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, LOCK);
  const waitMs = Number(process.env.DEEDWRIT_HOOK_LOCK_WAIT_MS) || 15_000;
  const deadline = Date.now() + waitMs;
  const nap = new Int32Array(new SharedArrayBuffer(4));
  for (;;) {
    try {
      fs.writeFileSync(file, String(process.pid), { flag: 'wx' });
      break;
    } catch (e) {
      if (/** @type {NodeJS.ErrnoException} */ (e).code !== 'EEXIST') throw e;
      // A writer that died holding the lock must not stop every later one.
      // The lock names its holder, so a dead holder's lock is taken over.
      if (!holderAlive(readIfPresent(file))) fs.rmSync(file, { force: true });
      if (Date.now() > deadline) throw new Error(`the log at ${dir} stayed locked for ${waitMs / 1000}s`);
      Atomics.wait(nap, 0, 0, 20);
    }
  }
  try {
    return fn();
  } finally {
    fs.rmSync(file, { force: true });
  }
}
