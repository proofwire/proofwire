import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { History } from './policy.js';
import { redact } from './redact.js';
import { entryHash } from './receipt.js';

/**
 * Record the tool calls a JavaScript agent makes, the way `pw proxy` does for
 * MCP servers — for agents whose tools are plain functions: the Vercel AI SDK,
 * the OpenAI Agents SDK, LangChain.js, or your own function calling.
 *
 *     const log = ProofLog.open('.proofwire');
 *     const rec = new Recorder({ log, agent: 'support-bot', principal: 'ops@acme.com',
 *                                policy: Policy.parse(fs.readFileSync('proofwire.policy.json', 'utf8')) });
 *
 *     const refund = rec.wrap('stripe.refund', async ({ order, amount }) => stripe.refunds.create(...));
 *     await refund({ order: 'o_1', amount: 45 });     // checked, recorded, then run
 *
 * The rules are the proxy's, receipt for receipt:
 *
 *   - The policy decides first, with the same budgets and rate limits, judged
 *     against everything this log has recorded. A refused call gets one
 *     receipt, never runs, and throws `PolicyDenied`.
 *   - An escalation goes to `approver`, which sees a redacted preview of the
 *     arguments, never the raw ones. With no approver it is refused, and the
 *     receipt says it was a fallback (`policy:no-approver`), not a person.
 *   - An allowed call gets an `intent` receipt, durable *before* the call
 *     runs, so a crash mid-call still leaves evidence it was attempted
 *     (`findUnfinished` finds those), and an `outcome` receipt linked to it
 *     when it returns or throws. Metrics are committed on the intent, so
 *     concurrent calls cannot all slip under a budget together.
 *   - `monitor: true` evaluates the policy, records what it would have done,
 *     and runs every call anyway.
 */

const RUNTIME = `proofwire-js/${createRequire(import.meta.url)('../package.json').version}`;

/** Recorded when no policy is given: the call was recorded, and nothing decided it. */
export const NO_POLICY = Object.freeze({
  outcome: 'allow',
  policy: 'none',
  rules: [],
  reason: 'recorded without a policy',
});

/** The policy refused a call. It did not run. */
export class PolicyDenied extends Error {
  /**
   * @param {string} target
   * @param {object} decision
   * @param {import('./receipt.js').Receipt} receipt
   */
  constructor(target, decision, receipt) {
    super(`${target}: refused by policy: ${/** @type {any} */ (decision).reason || 'no reason given'}`);
    this.name = 'PolicyDenied';
    this.target = target;
    this.decision = decision;
    this.receipt = receipt;
  }
}

/**
 * @typedef {object} RecorderOptions
 * @property {import('./log.js').ProofLog} log
 * @property {string} agent       Which agent is acting.
 * @property {string} principal   On whose behalf.
 * @property {string} [session]   Defaults to a fresh id per recorder.
 * @property {string} [namespace] Prefix for tool names in receipts, e.g. `stripe`.
 * @property {{ decide: (ctx: object, history?: History) => any }} [policy]
 *   A `Policy`, or anything with the same `decide`. Omit to record only.
 * @property {(req: { target: string, params: unknown, reason: string, rules: string[], actor: object }) =>
 *   Promise<{ approved: boolean, by: string, note?: string }>} [approver]
 *   Who answers an escalation. Same contract as the proxy's approvers.
 * @property {(target: string, params: unknown) => Record<string, number>} [metrics]
 *   The clear-text numbers budgets aggregate over, e.g. `{ amount_usd: 45 }`.
 * @property {boolean} [monitor]  Decide and record, but never block.
 */

export class Recorder {
  /** @param {RecorderOptions} opts */
  constructor(opts) {
    if (!opts?.log) throw new TypeError('Recorder needs a log');
    for (const field of ['agent', 'principal']) {
      if (typeof opts[field] !== 'string' || opts[field] === '') {
        throw new TypeError(`Recorder needs ${field}, a non-empty string`);
      }
    }
    this.log = opts.log;
    this.policy = opts.policy ?? null;
    this.approver = opts.approver ?? null;
    this.metrics = opts.metrics ?? null;
    this.monitor = opts.monitor === true;
    this.namespace = opts.namespace ?? '';
    this.actor = {
      agent: opts.agent,
      runtime: RUNTIME,
      session: opts.session ?? `sess_${randomBytes(6).toString('hex')}`,
      principal: opts.principal,
    };
    // Budgets and rate limits read from what this log has already recorded,
    // and from every call made through this recorder since.
    this.history = new History([...opts.log.entries]);
    /** Calls sent and not yet answered, for `finalize`. @type {Map<number, { target: string, params: unknown, decision: object, intent: any, startedAt: number }>} */
    this.pending = new Map();
    this._next = 0;
  }

  /**
   * Check, record and run one call.
   *
   * @template T
   * @param {string} name     The tool, as receipts and policy rules name it.
   * @param {unknown} params  Its arguments.
   * @param {() => T | Promise<T>} fn  What actually runs, if it is allowed.
   * @param {{ metrics?: Record<string, number> }} [opts]
   * @returns {Promise<Awaited<T>>}
   */
  async run(name, params, fn, opts = {}) {
    const target = this.namespace ? `${this.namespace}.${name}` : name;
    const args = jsonable(params ?? {});
    const metrics = opts.metrics ?? this.metrics?.(target, args) ?? {};
    const actor = this.actor;

    let decision = /** @type {any} */ (
      this.policy ? this.policy.decide({ kind: 'tool_call', target, params: args, metrics, actor }, this.history) : { ...NO_POLICY }
    );
    if (!['allow', 'deny', 'escalate'].includes(decision?.outcome)) {
      throw new TypeError(`policy.decide() must return an outcome of allow, deny or escalate; got ${JSON.stringify(decision?.outcome)}`);
    }
    /** @type {any} */
    let approval;

    if (this.monitor) {
      decision = monitored(decision);
    } else if (decision.outcome === 'escalate') {
      const verdict = this.approver
        ? await this.approver({ target, params: redact(args).value, reason: decision.reason, rules: decision.rules, actor })
        : { approved: false, by: 'policy:no-approver', note: 'escalation needs an approver; none is configured' };
      const at = new Date().toISOString();
      if (verdict.approved) {
        approval = { by: verdict.by, at, note: verdict.note };
        decision = { ...decision, outcome: 'allow', reason: `${decision.reason} — approved by ${verdict.by}` };
      } else {
        decision = {
          ...decision,
          outcome: 'deny',
          reason: verdict.note ? `${decision.reason} — ${verdict.note}` : decision.reason,
          declined: { by: verdict.by, at, ...(verdict.note ? { note: verdict.note } : {}) },
        };
      }
    }
    if (approval) decision = { ...decision, approval };

    if (decision.outcome !== 'allow') {
      const receipt = this._append({ target, params: args, metrics, decision, result: null });
      throw new PolicyDenied(target, decision, receipt);
    }

    // Durable before the call runs.
    const intent = this._append({ target, params: args, metrics, decision, result: null, phase: 'intent' });
    const id = this._next++;
    const startedAt = Date.now();
    this.pending.set(id, { target, params: args, decision, intent, startedAt });

    try {
      const value = await fn();
      this._outcome(this.pending.get(id), { status: 'ok', latencyMs: Date.now() - startedAt, payload: jsonable(value) });
      return value;
    } catch (err) {
      const e = /** @type {any} */ (err);
      this._outcome(this.pending.get(id), {
        status: 'error',
        code: String(e?.code ?? e?.name ?? 'Error'),
        latencyMs: Date.now() - startedAt,
        payload: { error: String(e?.message ?? e).slice(0, 2000) },
      });
      throw err;
    } finally {
      this.pending.delete(id);
    }
  }

  /**
   * Wrap a tool function so every call to it goes through `run`. Its first
   * argument is recorded as the call's parameters: the shape every agent
   * framework passes tool arguments in.
   *
   * @template {(...args: any[]) => any} F
   * @param {string} name
   * @param {F} fn
   * @returns {(...args: Parameters<F>) => Promise<Awaited<ReturnType<F>>>}
   */
  wrap(name, fn) {
    if (typeof fn !== 'function') throw new TypeError(`wrap("${name}") needs a function`);
    return (...args) => this.run(name, args[0], () => fn(...args));
  }

  /**
   * Close every call still out, recording that it was given up on. Call it
   * when the agent shuts down; without it, those calls show as unfinished,
   * which is also true, just less specific.
   */
  finalize() {
    for (const call of this.pending.values()) {
      this._outcome(call, { status: 'error', code: 'unfinished', latencyMs: Date.now() - call.startedAt, payload: null });
    }
    this.pending.clear();
  }

  /** @param {any} call @param {object} result */
  _outcome(call, result) {
    if (!call) return;
    // Metrics are left off the outcome: the intent committed them, and
    // counting them twice would halve every budget.
    this._append({
      target: call.target,
      params: call.params,
      decision: call.decision,
      result,
      phase: 'outcome',
      ref: entryHash(call.intent),
    });
  }

  /**
   * @param {{ target: string, params: unknown, metrics?: Record<string, number>, decision: any,
   *   result: any, phase?: 'atomic'|'intent'|'outcome', ref?: string }} a
   */
  _append(a) {
    const receipt = this.log.append({
      actor: this.actor,
      action: {
        kind: 'tool_call',
        target: a.target,
        params: a.params,
        ...(a.metrics && Object.keys(a.metrics).length ? { metrics: a.metrics } : {}),
      },
      decision: a.decision,
      result: a.result,
      phase: a.phase ?? 'atomic',
      ref: a.ref,
    });
    this.history.push(receipt);
    return receipt;
  }
}

/**
 * Wrap every tool in a map of tools, for frameworks that describe a tool as an
 * object with an `execute` function: the Vercel AI SDK (`tool({ execute })`),
 * Mastra, and others of the same shape. Returns a new map; the originals are
 * untouched. Tools without `execute` (client-side tools) are passed through.
 *
 *     const tools = recordTools(rec, { weather: tool({ ... execute }), refund: tool({ ... }) });
 *     await generateText({ model, tools, prompt });
 *
 * @template {Record<string, any>} T
 * @param {Recorder} recorder
 * @param {T} tools
 * @returns {T}
 */
export function recordTools(recorder, tools) {
  /** @type {Record<string, any>} */
  const out = {};
  for (const [name, t] of Object.entries(tools ?? {})) {
    out[name] =
      t && typeof t.execute === 'function'
        ? { ...t, execute: (/** @type {any[]} */ ...args) => recorder.run(name, args[0], () => t.execute(...args)) }
        : t;
  }
  return /** @type {T} */ (out);
}

/**
 * Monitor mode: the proxy's rule. The receipt tells the truth — the call ran,
 * so it is `allow` — and keeps what the policy would have done beside it.
 *
 * @param {any} decision
 */
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
 * What can go into a receipt: JSON values as themselves, anything else as a
 * string, so recording never fails because a tool returned a class instance.
 *
 * @param {unknown} value
 */
function jsonable(value) {
  try {
    const text = JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
    return text === undefined ? null : JSON.parse(text);
  } catch {
    return { repr: String(value).slice(0, 2000) };
  }
}
