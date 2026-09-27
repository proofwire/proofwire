import { hashObject, hex, RECEIPT_PREFIX } from './hash.js';
import { hasSecrets, redact } from './redact.js';
import { regexProblem, wildcardMatch } from './safe-regex.js';

/**
 * Declarative policy, evaluated before an action runs.
 *
 * A log that only records is a log of things you failed to stop. The rules
 * here run first and can refuse, so the interesting receipts are the ones that
 * say `deny` — proof that the guardrail existed and fired, which is the
 * question an insurer or a regulator actually asks.
 *
 * Three deliberate defaults:
 *
 *   - Unknown rule syntax is a load error, not a silently skipped rule. A typo
 *     in a deny rule must never read as "allow".
 *   - `escalate` with no approver wired up resolves to `deny`. Failing open on
 *     the high-risk path is the one failure mode worth designing out.
 *   - Rules are evaluated in order and the first terminal decision wins, so a
 *     policy reads top-to-bottom like the document a compliance team wrote.
 */

/** @typedef {'allow'|'deny'|'escalate'} Outcome */

const OUTCOMES = new Set(['allow', 'deny', 'escalate']);

const OPERATORS = {
  eq: (a, b) => a === b,
  ne: (a, b) => a !== b,
  gt: (a, b) => typeof a === 'number' && a > b,
  gte: (a, b) => typeof a === 'number' && a >= b,
  lt: (a, b) => typeof a === 'number' && a < b,
  lte: (a, b) => typeof a === 'number' && a <= b,
  in: (a, b) => Array.isArray(b) && b.includes(a),
  nin: (a, b) => Array.isArray(b) && !b.includes(a),
  contains: (a, b) => typeof a === 'string' && a.includes(String(b)),
  matches: (a, b) => typeof a === 'string' && toRegExp(b).test(a),
  exists: (a, b) => (a !== undefined && a !== null) === Boolean(b),
};

/** Compiled patterns, keyed by their source text. */
const regexCache = new Map();

/**
 * Build a RegExp from the forms a policy author will actually write.
 *
 * JavaScript has no inline `(?i)` flag syntax, but every other regex dialect
 * does, so people write it and get a SyntaxError — or, worse in an earlier
 * draft of this file, a rule that silently never matched. Both `(?i)pattern`
 * and `/pattern/i` are accepted and translated.
 *
 * @param {string} source
 * @returns {RegExp}
 */
export function toRegExp(source) {
  const cached = regexCache.get(source);
  if (cached) return cached;

  let body = String(source);
  let flags = '';

  const inline = /^\(\?([imsux]+)\)/.exec(body);
  if (inline) {
    // `x` and `u` have no JS equivalent worth emulating; drop them quietly
    // rather than failing a rule that would otherwise work.
    flags = inline[1].replace(/[xu]/g, '');
    body = body.slice(inline[0].length);
  } else {
    const delimited = /^\/(.*)\/([gimsuy]*)$/s.exec(body);
    if (delimited) {
      body = delimited[1];
      flags = delimited[2].replace(/g/g, '');
    }
  }

  // Refused before it can ever run: see safe-regex.js.
  const problem = regexProblem(body);
  if (problem) throw new Error(`pattern ${JSON.stringify(String(source))} ${problem}`);
  const rx = new RegExp(body, flags);
  regexCache.set(source, rx);
  return rx;
}

/**
 * Parse a duration like `30s`, `15m`, `24h`, `7d` into milliseconds.
 *
 * @param {string|number} w
 * @returns {number}
 */
export function parseWindow(w) {
  if (typeof w === 'number') return w;
  const m = /^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)$/.exec(String(w).trim());
  if (!m) throw new Error(`invalid window "${w}" (use 30s, 15m, 24h, 7d)`);
  const scale = { ms: 1, s: 1e3, m: 6e4, h: 36e5, d: 864e5 };
  return Number(m[1]) * scale[m[2]];
}

/**
 * Glob match supporting `*` (any run of characters) — enough for the
 * `namespace.tool` naming that MCP servers use, without pulling in a matcher.
 * Not a regex underneath: see `wildcardMatch`.
 *
 * @param {string} pattern
 * @param {string} value
 * @returns {boolean}
 */
export function globMatch(pattern, value) {
  if (pattern === '*' || pattern === value) return true;
  return wildcardMatch(pattern, value);
}

/**
 * Read a dotted path out of a context object.
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
 * Evaluate one `when` clause.
 *
 * A clause is an object of field → condition. Fields are dotted paths into the
 * evaluation context (`target`, `kind`, `actor.principal`, `params.amount`,
 * `metrics.amount_usd`). A condition is either a literal (exact match, or a
 * glob when both sides are strings) or an operator object like `{ gt: 100 }`.
 *
 * @param {Record<string, unknown>} clause
 * @param {object} ctx
 * @returns {boolean}
 */
function matchClause(clause, ctx) {
  for (const [field, cond] of Object.entries(clause)) {
    const actual = pluck(ctx, field);

    if (cond !== null && typeof cond === 'object' && !Array.isArray(cond)) {
      for (const [op, operand] of Object.entries(cond)) {
        const fn = OPERATORS[op];
        if (!fn) throw new Error(`unknown operator "${op}" on field "${field}"`);
        if (!fn(actual, operand)) return false;
      }
      continue;
    }

    if (typeof cond === 'string' && typeof actual === 'string') {
      if (!globMatch(cond, actual)) return false;
      continue;
    }
    if (Array.isArray(cond)) {
      if (!cond.includes(actual)) return false;
      continue;
    }
    if (actual !== cond) return false;
  }
  return true;
}

/**
 * @param {object} rule
 * @param {string} where
 */
function validateRule(rule, where) {
  if (!rule.id) throw new Error(`${where}: every rule needs an id`);
  if (rule.then !== undefined && !OUTCOMES.has(rule.then)) {
    throw new Error(`${where} (${rule.id}): "then" must be allow, deny, or escalate`);
  }
  const clause = rule.when ?? rule.match ?? {};
  for (const [field, cond] of Object.entries(clause)) {
    if (cond !== null && typeof cond === 'object' && !Array.isArray(cond)) {
      for (const [op, operand] of Object.entries(cond)) {
        if (!OPERATORS[op]) {
          throw new Error(`${where} (${rule.id}): unknown operator "${op}" on "${field}"`);
        }
        // Compile now so a broken pattern fails at load, not at the moment a
        // deny rule was supposed to fire.
        if (op === 'matches') {
          try {
            toRegExp(String(operand));
          } catch (err) {
            throw new Error(
              `${where} (${rule.id}): invalid regex on "${field}": ${err.message}`,
            );
          }
        }
      }
    }
  }
}

/**
 * @typedef {object} PolicyDecision
 * @property {Outcome} outcome
 * @property {string[]} rules     Ids of every rule that fired.
 * @property {string} reason
 * @property {string} policy      Policy hash, recorded in the receipt.
 * @property {object} [meta]      Budget/limit detail, for the operator's UI.
 */

export class Policy {
  /**
   * @param {object} doc
   */
  constructor(doc) {
    if (doc?.version !== 1) {
      throw new Error('policy: expected { "version": 1 }');
    }
    this.doc = doc;
    this.name = doc.name ?? 'unnamed';

    const fallback = doc.defaults?.outcome ?? 'allow';
    if (!OUTCOMES.has(fallback)) {
      throw new Error(`policy: defaults.outcome must be allow, deny, or escalate`);
    }
    this.fallback = /** @type {Outcome} */ (fallback);

    this.rules = doc.rules ?? [];
    this.budgets = doc.budgets ?? [];
    this.rateLimits = doc.rateLimits ?? [];
    this.egress = doc.egress ?? {};

    this.rules.forEach((r) => validateRule(r, 'rules'));
    this.budgets.forEach((b) => {
      validateRule(b, 'budgets');
      if (typeof b.limit !== 'number') throw new Error(`budgets (${b.id}): numeric limit required`);
      if (!b.field) throw new Error(`budgets (${b.id}): "field" is required`);
      parseWindow(b.window ?? '24h');
    });
    this.rateLimits.forEach((r) => {
      validateRule(r, 'rateLimits');
      if (typeof r.limit !== 'number') throw new Error(`rateLimits (${r.id}): numeric limit required`);
      parseWindow(r.window ?? '1h');
    });

    /** Identity of this exact policy text, recorded in every receipt it decides. */
    this.hash = hex(hashObject(RECEIPT_PREFIX, doc));
  }

  /**
   * @param {string} json
   * @returns {Policy}
   */
  static parse(json) {
    // Tolerate `//` comments so a policy file can explain itself.
    const stripped = json.replace(/^\s*\/\/.*$/gm, '');
    return new Policy(JSON.parse(stripped));
  }

  /**
   * Decide on a proposed action.
   *
   * @param {object} ctx
   * @param {string} ctx.kind
   * @param {string} ctx.target
   * @param {unknown} ctx.params
   * @param {Record<string, number>} [ctx.metrics]  Clear-text numbers budgets aggregate over.
   * @param {import('./receipt.js').Actor} ctx.actor
   * @param {History} [history]  Prior activity, for budgets and rate limits.
   * @returns {PolicyDecision}
   */
  decide(ctx, history) {
    /** @type {string[]} */
    const fired = [];
    const evalCtx = {
      kind: ctx.kind,
      target: ctx.target,
      params: ctx.params,
      metrics: ctx.metrics ?? {},
      actor: ctx.actor,
    };

    // 1. Egress guard. Runs first because a secret in the arguments is a
    //    problem regardless of what the rest of the policy thinks.
    if (this.egress.denySecrets || this.egress.denyPii) {
      const { findings } = redact(ctx.params);
      const bad = this.egress.denySecrets
        ? hasSecrets(findings)
        : findings.length > 0;
      if (bad && findings.length > 0) {
        const types = [...new Set(findings.map((f) => f.type))].join(', ');
        return {
          outcome: 'deny',
          rules: ['egress.guard'],
          reason: `arguments contain ${types}; policy forbids sending these to a tool`,
          policy: this.hash,
          meta: { findings },
        };
      }
    }

    // 2. Explicit rules, in written order. The first rule that states a `then`
    //    decides; a rule with no `then` just records that it matched, which is
    //    how you tag traffic without changing the verdict.
    //
    //    An explicit `allow` is terminal for *rules* — otherwise an allowlist
    //    (`defaults.outcome: "deny"` plus a handful of allow rules) would fall
    //    through every allow rule and deny everything. It is not terminal for
    //    budgets and rate limits below: permission to use a tool is not
    //    permission to exceed your spending cap.
    let verdict = /** @type {Outcome|null} */ (null);
    let reason = '';

    for (const rule of this.rules) {
      const clause = rule.when ?? rule.match ?? {};
      if (!matchClause(clause, evalCtx)) continue;
      fired.push(rule.id);
      if (rule.then === undefined) continue;

      verdict = /** @type {Outcome} */ (rule.then);
      reason = rule.reason ?? `matched rule ${rule.id}`;
      break;
    }

    if (verdict === 'deny' || verdict === 'escalate') {
      return { outcome: verdict, rules: fired, reason, policy: this.hash };
    }

    if (verdict === null && this.fallback !== 'allow') {
      return {
        outcome: this.fallback,
        rules: fired,
        reason: fired.length
          ? `matched ${fired.join(', ')}, but no rule permitted this; default is ${this.fallback}`
          : `no rule permitted this action; policy default is ${this.fallback}`,
        policy: this.hash,
      };
    }

    // 3. Rate limits.
    for (const limit of this.rateLimits) {
      if (!matchClause(limit.match ?? limit.when ?? {}, evalCtx)) continue;
      const windowMs = parseWindow(limit.window ?? '1h');
      const used = history ? history.countSince(limit, windowMs, evalCtx) : 0;
      if (used >= limit.limit) {
        fired.push(limit.id);
        return {
          outcome: /** @type {Outcome} */ (limit.then ?? 'deny'),
          rules: fired,
          reason:
            `rate limit ${limit.id} exhausted: ${used} of ${limit.limit} ` +
            `calls in the last ${limit.window ?? '1h'}`,
          policy: this.hash,
          meta: { used, limit: limit.limit, window: limit.window ?? '1h' },
        };
      }
    }

    // 4. Budgets. Checked against the proposed spend, not just prior spend —
    //    the point is to stop the action that would breach the cap.
    for (const budget of this.budgets) {
      if (!matchClause(budget.match ?? budget.when ?? {}, evalCtx)) continue;
      const windowMs = parseWindow(budget.window ?? '24h');
      const proposed = Number(pluck(evalCtx, budget.field) ?? 0);
      if (!Number.isFinite(proposed)) continue;
      const spent = history ? history.sumSince(budget, windowMs, evalCtx) : 0;
      if (spent + proposed > budget.limit) {
        fired.push(budget.id);
        return {
          outcome: /** @type {Outcome} */ (budget.then ?? 'escalate'),
          rules: fired,
          reason:
            `budget ${budget.id} would be exceeded: ${spent} already committed ` +
            `plus ${proposed} proposed, against a cap of ${budget.limit} per ` +
            `${budget.window ?? '24h'}`,
          policy: this.hash,
          meta: { spent, proposed, limit: budget.limit, window: budget.window ?? '24h' },
        };
      }
    }

    return {
      outcome: 'allow',
      rules: fired,
      reason: reason || (fired.length
        ? `matched ${fired.join(', ')}; no rule objected`
        : 'no rule matched; policy default is allow'),
      policy: this.hash,
    };
  }
}

/**
 * Prior activity, read back out of the log.
 *
 * Deriving budget state from the receipt chain rather than a side database is
 * the whole trick: the spend ledger inherits the log's tamper-evidence, so
 * "the agent stayed under its cap" is provable rather than asserted.
 */
export class History {
  /**
   * @param {import('./receipt.js').Receipt[]} entries
   */
  constructor(entries = []) {
    this.entries = entries;
    /**
     * The moment windows are measured back from, in ms. Unset means "now".
     * Replaying a recorded log sets it to each receipt's own time, so a rate
     * limit is judged as it would have been then, not as of today.
     *
     * @type {number | undefined}
     */
    this.now = undefined;
  }

  /**
   * @param {import('./receipt.js').Receipt} receipt
   */
  push(receipt) {
    this.entries.push(receipt);
  }

  /**
   * Entries inside the window that the rule's own match clause selects.
   *
   * Only `allow` decisions count. A denied action spent nothing and used no
   * quota, and counting it would let an attacker exhaust a budget with calls
   * the policy already refused.
   *
   * @param {object} rule
   * @param {number} windowMs
   * @param {object} evalCtx
   * @returns {import('./receipt.js').Receipt[]}
   */
  _relevant(rule, windowMs, evalCtx) {
    const cutoff = (this.now ?? Date.now()) - windowMs;
    const clause = rule.match ?? rule.when ?? {};
    const scope = rule.per ? pluck(evalCtx, rule.per) : undefined;

    return this.entries.filter((e) => {
      // An outcome receipt restates an intent that was already counted.
      // Including both would silently halve every budget.
      if (e.phase === 'outcome') return false;
      if (e.decision?.outcome !== 'allow') return false;
      if (Date.parse(e.ts) < cutoff) return false;
      if (rule.per && pluck({ actor: e.actor, ...e.action }, rule.per) !== scope) return false;
      return matchClause(clause, {
        kind: e.action.kind,
        target: e.action.target,
        params: e.action.params?.preview ?? {},
        metrics: e.action.metrics ?? {},
        actor: e.actor,
      });
    });
  }

  /**
   * @param {object} rule
   * @param {number} windowMs
   * @param {object} evalCtx
   * @returns {number}
   */
  countSince(rule, windowMs, evalCtx) {
    return this._relevant(rule, windowMs, evalCtx).length;
  }

  /**
   * @param {object} rule
   * @param {number} windowMs
   * @param {object} evalCtx
   * @returns {number}
   */
  sumSince(rule, windowMs, evalCtx) {
    let total = 0;
    for (const e of this._relevant(rule, windowMs, evalCtx)) {
      const v = Number(
        pluck({ metrics: e.action.metrics ?? {}, params: e.action.params?.preview ?? {} }, rule.field),
      );
      if (Number.isFinite(v)) total += v;
    }
    return total;
  }
}
