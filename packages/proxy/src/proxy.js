import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { createRequire } from 'node:module';
import { LineFramer, encode, isRequest, isResponse, toolRefusal } from './jsonrpc.js';
import { History, redact, entryHash, globMatch } from '@deedwrit/core';

/**
 * A transparent MCP proxy that enforces policy and writes receipts.
 *
 * It sits between an agent and an MCP server, speaking the same protocol to
 * both, so adopting it is a change to one line of configuration:
 *
 *     "command": "npx", "args": ["-y", "@acme/mcp-crm"]
 *     "command": "dw",  "args": ["proxy", "--", "npx", "-y", "@acme/mcp-crm"]
 *
 * Everything that is not a `tools/call` is forwarded untouched. That matters
 * more than it sounds: MCP gains methods faster than any proxy can track, and
 * a proxy that only forwards what it recognises breaks on the next release.
 */

// Stamped into every receipt's actor.runtime, so it must name the version that
// actually produced the receipt — read from the package, never typed here.
const RUNTIME = `deedwrit-proxy/${createRequire(import.meta.url)('../package.json').version}`;

/**
 * Pull a dotted path out of an object.
 *
 * @param {unknown} obj
 * @param {string} dotted
 * @returns {unknown}
 */
function pluck(obj, dotted) {
  let cur = obj;
  for (const part of dotted.split('.')) {
    if (cur === null || cur === undefined) return undefined;
    cur = /** @type {Record<string, unknown>} */ (cur)[part];
  }
  return cur;
}

/**
 * Extract the clear-text numbers budgets aggregate over.
 *
 * Configured per tool pattern, because only the operator knows that their
 * payments tool reports cents and their invoicing tool reports dollars:
 *
 *     "metrics": {
 *       "stripe.*": { "amount_usd": { "from": "params.amount", "scale": 0.01 } }
 *     }
 *
 * @param {Record<string, any>} config
 * @param {string} target
 * @param {unknown} params
 * @returns {Record<string, number>}
 */
export function extractMetrics(config, target, params) {
  /** @type {Record<string, number>} */
  const out = {};
  for (const [pattern, spec] of Object.entries(config ?? {})) {
    if (!globMatch(pattern, target)) continue;
    for (const [name, rule] of Object.entries(/** @type {Record<string, any>} */ (spec))) {
      const from = typeof rule === 'string' ? rule : rule.from;
      const scale = typeof rule === 'string' ? 1 : (rule.scale ?? 1);
      const raw = Number(pluck({ params }, from));
      if (Number.isFinite(raw)) out[name] = raw * scale;
    }
  }
  return out;
}

/**
 * Cross-check a policy's budgets against the metrics this runtime can actually
 * produce.
 *
 * A budget over `metrics.amount_usd` is inert unless something extracts that
 * number from the tool's arguments. Nothing errors, nothing logs, and the cap
 * simply never fires — the guardrail exists on paper and not in production.
 * This is the same failure the policy loader refuses to allow for a typo'd
 * operator, and it deserves the same treatment.
 *
 * @param {import('@deedwrit/core').Policy} policy
 * @param {Record<string, any>} metricsConfig
 * @returns {string[]} Human-readable warnings; empty when the policy is wired up.
 */
export function auditPolicyMetrics(policy, metricsConfig) {
  /** @type {Set<string>} */
  const produced = new Set();
  for (const spec of Object.values(metricsConfig ?? {})) {
    for (const name of Object.keys(/** @type {object} */ (spec) ?? {})) produced.add(name);
  }

  /** @type {string[]} */
  const warnings = [];
  for (const budget of policy.budgets ?? []) {
    const field = String(budget.field ?? '');
    if (!field.startsWith('metrics.')) continue;
    const name = field.slice('metrics.'.length);
    if (produced.has(name)) continue;
    warnings.push(
      `budget "${budget.id}" caps ${field}, but nothing here produces "${name}". ` +
        `This budget will never fire. Add a metrics extractor for the tools it covers.`,
    );
  }
  return warnings;
}

/** Every character cmd.exe gives meaning to, quotes included. */
const CMD_META = /([()\][%!^"`<>&|;, *?])/g;

/**
 * Quote one argument for a command line that cmd.exe parses first and the
 * program's C runtime parses second.
 *
 * Two parsers, two sets of rules, so two layers:
 *
 *   1. For the C runtime (how every Windows program splits its command line):
 *      wrap in quotes; escape a quote as `\"`; and double any backslashes
 *      that precede a quote or the closing quote, since `\"` would otherwise
 *      read as a literal quote. Without that, `C:\dir\` swallows its closing
 *      quote and merges with the next argument.
 *   2. For cmd.exe, which knows nothing of backslash escapes: prefix every
 *      metacharacter with `^`, quotes included. cmd.exe's own idea of "inside
 *      quotes" then never comes into play, so `a"&calc` cannot close a quote
 *      and start a second command.
 *
 * A `.cmd` or `.bat` shim (npx, npm, yarn) passes its arguments through cmd.exe
 * once more when it runs `%*`, so those get the second layer twice.
 *
 * @param {string} arg
 * @param {boolean} [shim]  The target is a batch file.
 * @returns {string}
 */
export function winQuote(arg, shim = false) {
  let s = '';
  let slashes = 0;
  for (const ch of String(arg)) {
    if (ch === '\\') {
      slashes++;
      continue;
    }
    // Backslashes are only special in front of a quote: double them there,
    // then escape the quote itself.
    s += ch === '"' ? '\\'.repeat(slashes * 2 + 1) + '"' : '\\'.repeat(slashes) + ch;
    slashes = 0;
  }
  // ...and in front of the closing quote.
  s += '\\'.repeat(slashes * 2);
  s = `"${s}"`.replace(CMD_META, '^$1');
  return shim ? s.replace(CMD_META, '^$1') : s;
}

/**
 * Find what a bare command name will actually run, the way cmd.exe would:
 * each directory on PATH in turn, each extension in PATHEXT in turn.
 *
 * @param {string} name
 * @param {Record<string, string | undefined>} env
 * @returns {string | null}
 */
export function whichWindows(name, env) {
  const pathVar = env.PATH ?? env.Path ?? '';
  const exts = (env.PATHEXT ?? '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean);
  const hasExt = /\.[^\\/.]+$/.test(name);
  for (const dir of pathVar.split(';').filter(Boolean)) {
    for (const ext of hasExt ? [''] : exts) {
      const candidate = path.join(dir, name + ext.toLowerCase());
      try {
        if (fs.statSync(candidate).isFile()) return candidate;
      } catch {
        // Not here; keep looking.
      }
    }
  }
  return null;
}

/**
 * Decide how to launch the upstream server.
 *
 * Windows makes this a genuine fork in the road. Since the fix for
 * CVE-2024-27980, Node refuses to spawn `.cmd` and `.bat` files without a
 * shell — and `npx`, `npm` and `yarn`, which is how nearly every MCP server is
 * launched, are exactly that. But a shell is a second parser with its own
 * metacharacters, and every argument must survive it.
 *
 * So the command is resolved first, as cmd.exe would resolve it:
 *
 *   - An executable (`.exe`, `.com`) is spawned directly, with a real argv,
 *     and no shell anywhere. Node's own quoting is then all that applies.
 *   - A batch file goes through cmd.exe as one command line with everything
 *     quoted by `winQuote`, and no separate argv. Handing Node args together
 *     with `shell: true` is what it warns about as DEP0190, because it would
 *     join them unescaped.
 *   - A name that cannot be found is left for cmd.exe to report.
 *
 * @param {string} command
 * @param {string[]} args
 * @param {NodeJS.Platform} [platform]  For tests; defaults to this machine's.
 * @param {(name: string) => string | null} [which]  For tests; defaults to a PATH search.
 * @returns {{ command: string, args: string[], shell: boolean }}
 */
export function launchSpec(command, args, platform = process.platform, which = (n) => whichWindows(n, process.env)) {
  if (platform !== 'win32') return { command, args, shell: false };

  const namesAPath = /[\\/]/.test(command);
  const resolved = namesAPath ? command : which(command);
  const target = resolved ?? command;

  if (resolved && !/\.(bat|cmd)$/i.test(resolved)) return { command: resolved, args, shell: false };

  const shim = /\.(bat|cmd)$/i.test(target);
  const line = [target.replace(CMD_META, '^$1'), ...args.map((a) => winQuote(a, shim))].join(' ');
  return { command: line, args: [], shell: true };
}

/**
 * @typedef {object} ProxyOptions
 * @property {import('@deedwrit/core').ProofLog} log
 * @property {import('@deedwrit/core').Policy} policy
 * @property {{ agent: string, session: string, principal: string }} actor
 * @property {(req: any) => Promise<{approved: boolean, by: string, note?: string}>} approver
 * @property {string} command
 * @property {string[]} args
 * @property {string} [namespace]  Prefix for tool names in receipts, e.g. `stripe`.
 * @property {Record<string, any>} [metrics]
 * @property {NodeJS.ReadableStream} [stdin]
 * @property {NodeJS.WritableStream} [stdout]
 * @property {NodeJS.WritableStream} [stderr]
 * @property {Record<string,string>} [env]
 * @property {boolean} [monitor]  Evaluate policy and record what it would have
 *   done, but forward every call. See `_monitor`.
 */

export class McpProxy extends EventEmitter {
  /** @param {ProxyOptions} opts */
  constructor(opts) {
    super();
    this.opts = opts;
    this.log = opts.log;
    this.policy = opts.policy;
    this.namespace = opts.namespace ?? '';
    this.history = new History([...opts.log.entries]);

    /** In-flight upstream calls, keyed by JSON-RPC id. */
    this._pending = new Map();
    /** @type {import('node:child_process').ChildProcessWithoutNullStreams|null} */
    this.child = null;
    this.monitor = opts.monitor === true;
    this.stats = { forwarded: 0, denied: 0, escalated: 0, approved: 0, errors: 0, wouldDeny: 0, wouldEscalate: 0 };
  }

  /**
   * @param {string} name
   * @returns {string}
   */
  _qualify(name) {
    return this.namespace ? `${this.namespace}.${name}` : name;
  }

  /**
   * Start the upstream server and wire the two directions together.
   *
   * @returns {Promise<number>} The child's exit code.
   */
  start() {
    const stdin = this.opts.stdin ?? process.stdin;
    const stdout = this.opts.stdout ?? process.stdout;
    const stderr = this.opts.stderr ?? process.stderr;

    const spec = launchSpec(this.opts.command, this.opts.args);
    const child = spawn(spec.command, spec.args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, ...(this.opts.env ?? {}) },
      shell: spec.shell,
    });
    this.child = child;

    const fromClient = new LineFramer();
    const fromServer = new LineFramer();

    stdin.on('data', (chunk) => {
      for (const { message, raw, error } of fromClient.push(chunk)) {
        if (error) {
          // Not ours to repair: hand it upstream and let the server object.
          child.stdin.write(raw + '\n');
          continue;
        }
        this._handleClientMessage(message, child, stdout).catch((err) => {
          this.stats.errors++;
          this.emit('error', err);
          if (isRequest(message)) {
            stdout.write(
              encode(toolRefusal(/** @type {any} */ (message).id, `Deedwrit internal error: ${err.message}`)),
            );
          }
        });
      }
    });

    child.stdout.on('data', (chunk) => {
      for (const { message, raw, error } of fromServer.push(chunk)) {
        if (error) {
          stdout.write(raw + '\n');
          continue;
        }
        this._handleServerMessage(message, stdout);
      }
    });

    // The upstream server's logs are its own; pass them through untouched so
    // debugging the wrapped server still works.
    child.stderr.on('data', (chunk) => stderr.write(chunk));

    stdin.on('end', () => child.stdin.end());

    return new Promise((resolve) => {
      child.on('exit', (code) => {
        this.emit('exit', code ?? 0);
        resolve(code ?? 0);
      });
      child.on('error', (err) => {
        stderr.write(`deedwrit: could not start "${this.opts.command}": ${err.message}\n`);
        this.emit('error', err);
        resolve(127);
      });
    });
  }

  /**
   * @param {any} message
   * @param {import('node:child_process').ChildProcessWithoutNullStreams} child
   * @param {NodeJS.WritableStream} stdout
   */
  async _handleClientMessage(message, child, stdout) {
    if (!isRequest(message) || message.method !== 'tools/call') {
      child.stdin.write(encode(message));
      return;
    }

    const target = this._qualify(message.params?.name ?? 'unknown');
    const params = message.params?.arguments ?? {};
    const actor = { ...this.opts.actor, runtime: RUNTIME };
    const metrics = extractMetrics(this.opts.metrics ?? {}, target, params);

    let decision = this.policy.decide(
      { kind: 'tool_call', target, params, metrics, actor },
      this.history,
    );

    /** @type {import('@deedwrit/core').Decision['approval']} */
    let approval;

    if (this.monitor) {
      decision = this._monitor(decision, target);
    } else if (decision.outcome === 'escalate') {
      this.stats.escalated++;
      // The approver sees a redacted preview, never the raw arguments. A
      // human clicking "approve" in Slack should not thereby paste a customer's
      // card number into Slack's message history.
      const { value: preview } = redact(params);
      const verdict = await this.opts.approver({
        target,
        params: preview,
        reason: decision.reason,
        rules: decision.rules,
        actor,
      });
      if (verdict.approved) {
        this.stats.approved++;
        approval = { by: verdict.by, at: new Date().toISOString(), note: verdict.note };
        decision = { ...decision, outcome: 'allow', reason: `${decision.reason} — approved by ${verdict.by}` };
      } else {
        decision = {
          ...decision,
          outcome: 'deny',
          reason: verdict.note ? `${decision.reason} — ${verdict.note}` : decision.reason,
          // Who said no is evidence of oversight as much as who said yes. A
          // fallback (no approver, a timeout) is recorded as the policy
          // fallback it was, e.g. `policy:timeout`, never as a person.
          declined: { by: verdict.by, at: new Date().toISOString(), ...(verdict.note ? { note: verdict.note } : {}) },
        };
      }
    }

    if (decision.outcome !== 'allow') {
      this.stats.denied++;
      const receipt = this._record({ target, params, metrics, actor, decision: { ...decision, approval }, result: null });
      this.emit('denied', { target, decision, receipt });
      stdout.write(
        encode(
          toolRefusal(
            message.id,
            `Blocked by Deedwrit policy. ${decision.reason}\n` +
              `Rules: ${decision.rules.join(', ') || 'none'}\n` +
              `This refusal is recorded as receipt ${receipt.seq} in log ${receipt.log}.`,
          ),
        ),
      );
      return;
    }

    // Allowed. The receipt is written *before* the call goes out, not after
    // the result comes back. Two reasons, both learned the hard way:
    //
    //   1. Budgets. Spend recorded on completion means three pipelined refunds
    //      all evaluate against an empty ledger and every one of them passes a
    //      cap they collectively blow through. Committing at decision time is
    //      the only accounting that holds under concurrency.
    //   2. Crashes. A process killed between the call and its reply would
    //      otherwise leave an action that really happened with no record that
    //      it ever did — precisely the gap this product exists to close.
    //
    // The result is recorded as a second, linked receipt when it arrives.
    const intent = this._record({
      target,
      params,
      metrics,
      actor,
      decision: { ...decision, approval },
      result: null,
      phase: 'intent',
    });

    this._pending.set(message.id, {
      target,
      params,
      metrics,
      actor,
      decision: { ...decision, approval },
      intentHash: entryHash(intent),
      startedAt: Date.now(),
    });
    this.stats.forwarded++;
    child.stdin.write(encode(message));
  }

  /**
   * Monitor mode: the policy is evaluated exactly as it would be under
   * enforcement, and then ignored. Every call goes through.
   *
   * The receipt still has to tell the truth, and the truth is that the action
   * ran. So the outcome is always `allow` — a receipt saying `deny` for a call
   * that reached the upstream server would be a false record, and budgets,
   * which count allowed calls, would under-count real spend. What the policy
   * *would* have done is kept alongside, inside the signed body: `enforced:
   * false` on every receipt written in this mode, so an auditor can see the
   * policy was not a gate, and `wouldBe` on the calls it would have stopped.
   *
   * Escalations are not sent to the approver. Asking a human to approve
   * something that is going to run whatever they answer is theatre.
   *
   * @param {import('@deedwrit/core').PolicyDecision} decision
   * @param {string} target
   */
  _monitor(decision, target) {
    if (decision.outcome === 'allow') return { ...decision, enforced: false };

    const wouldBe = decision.outcome;
    if (wouldBe === 'escalate') this.stats.wouldEscalate++;
    else this.stats.wouldDeny++;
    const monitored = {
      ...decision,
      outcome: 'allow',
      enforced: false,
      wouldBe,
      reason: `not enforced (monitor mode): would ${wouldBe} — ${decision.reason}`,
    };
    this.emit('monitored', { target, wouldBe, reason: decision.reason, decision: monitored });
    return monitored;
  }

  /**
   * @param {any} message
   * @param {NodeJS.WritableStream} stdout
   */
  _handleServerMessage(message, stdout) {
    if (isResponse(message) && this._pending.has(message.id)) {
      const call = this._pending.get(message.id);
      this._pending.delete(message.id);

      const failed = Boolean(message.error) || message.result?.isError === true;
      const receipt = this._record({
        ...call,
        // Metrics are deliberately omitted here: they were already committed
        // by the intent receipt, and counting them twice would halve every
        // budget.
        metrics: undefined,
        phase: 'outcome',
        ref: call.intentHash,
        result: {
          status: failed ? 'error' : 'ok',
          code: message.error?.code !== undefined ? String(message.error.code) : undefined,
          latencyMs: Date.now() - call.startedAt,
          payload: message.error ?? message.result,
        },
      });
      this.emit('recorded', { target: call.target, receipt });
    }
    stdout.write(encode(message));
  }

  /**
   * @param {object} args
   * @returns {import('@deedwrit/core').Receipt}
   */
  _record(args) {
    const receipt = this.log.append({
      actor: args.actor,
      action: { kind: 'tool_call', target: args.target, params: args.params, metrics: args.metrics },
      decision: args.decision,
      result: args.result,
      phase: args.phase ?? 'atomic',
      ref: args.ref,
    });
    // Budgets and rate limits read from history, so it has to include the call
    // we just made — otherwise a burst of concurrent calls all see a stale
    // total and every one of them passes a cap they collectively blow through.
    this.history.push(receipt);
    return receipt;
  }

  /**
   * Flush anything still in flight when shutting down.
   *
   * A call we forwarded but never saw answered is not nothing: it is the most
   * interesting kind of gap, because it is exactly what an agent killed
   * mid-action looks like. It gets a receipt saying so.
   */
  finalize() {
    for (const [, call] of this._pending) {
      this._record({
        ...call,
        metrics: undefined,
        phase: 'outcome',
        ref: call.intentHash,
        result: { status: 'error', code: 'unfinished', latencyMs: Date.now() - call.startedAt, payload: null },
      });
    }
    this._pending.clear();
    if (this.log.size > 0) this.log.checkpoint();
  }
}
