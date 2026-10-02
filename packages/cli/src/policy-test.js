import fs from 'node:fs';
import path from 'node:path';
import { ProofLog, Policy, History } from '@deedwrit/core';
import { c, out, bad, warn, heading, kv, table } from './ui.js';
import { POLICY_FILE } from './legacy-paths.js';

/**
 * Replay a recorded log against a policy.
 *
 * The question this answers is "if this policy had been in force, what would
 * it have done to the traffic we actually saw?", which is the question to
 * ask before switching a policy from monitor mode to enforcement, or before
 * pushing a change to one that is already enforcing.
 *
 * Replay is as faithful as the log allows, and says where it is not:
 *
 *   - Each call is judged at its recorded time, against the calls before it
 *     that the *new* policy would have let through. A tighter policy that
 *     blocks an early refund therefore leaves more budget for a later one,
 *     exactly as it would have live.
 *   - Arguments are the redacted preview the receipt carries; the raw values
 *     were never stored. A call whose preview had anything masked is marked
 *     approximate, since a rule (or the egress guard) that looked at the
 *     masked value cannot be reproduced.
 *   - Approvals are not asked again. The recorded verdict is what the policy
 *     said at the time (escalate), not what the human then decided.
 */

/** @typedef {'allow'|'deny'|'escalate'} Verdict */

/**
 * What the policy in force at the time decided, as opposed to what happened.
 *
 * @param {any} r
 * @returns {Verdict}
 */
export function recordedVerdict(r) {
  if (r.decision.wouldBe) return r.decision.wouldBe;
  if (r.decision.approval || r.decision.declined) return 'escalate';
  return r.decision.outcome;
}

/**
 * Whether a recorded call actually reached the tool.
 *
 * @param {any} r
 */
function ran(r) {
  return r.decision.outcome === 'allow';
}

/**
 * @param {any[]} entries  Receipts in log order.
 * @param {Policy} policy
 * @returns {{
 *   results: Array<{ seq: number, ts: string, target: string, before: Verdict, after: Verdict,
 *                    rules: string[], reason: string, approximate: boolean }>,
 *   changed: number,
 *   transitions: Record<string, number>,
 * }}
 */
export function replay(entries, policy) {
  const history = new History();
  /** @type {ReturnType<typeof replay>['results']} */
  const results = [];
  /** @type {Record<string, number>} */
  const transitions = {};

  for (const r of entries) {
    // An outcome receipt restates its intent; judging both would count every
    // call twice.
    if (r.phase === 'outcome') continue;

    history.now = Date.parse(r.ts);
    const params = r.action.params?.preview;
    const decision = policy.decide(
      { kind: r.action.kind, target: r.action.target, params: params ?? {}, metrics: r.action.metrics ?? {}, actor: r.actor },
      history,
    );
    const before = recordedVerdict(r);
    const after = /** @type {Verdict} */ (decision.outcome);

    results.push({
      seq: r.seq,
      ts: r.ts,
      target: r.action.target,
      before,
      after,
      rules: decision.rules,
      reason: decision.reason,
      approximate: params === undefined || (r.action.params?.redacted?.length ?? 0) > 0,
    });
    if (before !== after) {
      const key = `${before} → ${after}`;
      transitions[key] = (transitions[key] ?? 0) + 1;
    }

    // What the new policy's budgets and rate limits would have seen: the
    // calls it lets through, plus escalations that really ran (a human said
    // yes then, and we assume they would again).
    if (after === 'allow' || (after === 'escalate' && ran(r))) {
      history.push({
        phase: r.phase,
        ts: r.ts,
        actor: r.actor,
        action: r.action,
        decision: { outcome: 'allow' },
      });
    }
  }

  return { results, changed: results.filter((x) => x.before !== x.after).length, transitions };
}

/** @param {Verdict} v */
function paint(v) {
  return v === 'allow' ? c.green(v) : v === 'deny' ? c.red(v) : c.yellow(v);
}

/**
 * `dw policy test [policy-file]`
 *
 * @param {any} args
 * @param {{ dir: string, config: any }} where
 */
export function cmdPolicyTest(args, where) {
  const file = path.resolve(args._[2] ?? args.policy ?? where.config.policy ?? POLICY_FILE());
  let policy;
  try {
    policy = Policy.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    bad(`${path.relative(process.cwd(), file) || file} will not load: ${/** @type {Error} */ (err).message}`);
    return 2;
  }

  let log;
  try {
    log = ProofLog.open(where.dir, { readOnly: true });
  } catch (err) {
    bad(`no log to replay at ${path.relative(process.cwd(), where.dir) || '.'}: ${/** @type {Error} */ (err).message}`);
    return 2;
  }

  let entries = log.entries;
  if (args.since) {
    const since = Date.parse(String(args.since));
    if (Number.isNaN(since)) {
      bad(`--since must be a date, e.g. 2026-09-01 or 2026-09-01T12:00:00Z`);
      return 2;
    }
    entries = entries.filter((r) => Date.parse(r.ts) >= since);
  }
  if (args.session) entries = entries.filter((r) => r.actor.session === args.session);
  if (args.target) entries = entries.filter((r) => r.action.target.includes(String(args.target)));

  const { results, changed, transitions } = replay(entries, policy);
  const approximate = results.filter((x) => x.approximate).length;
  const failOnChange = Boolean(args['fail-on-change']);

  if (args.json) {
    out(
      JSON.stringify(
        {
          policy: { name: policy.name, hash: policy.hash, file },
          log: log.logId,
          replayed: results.length,
          changed,
          approximate,
          transitions,
          results: results.filter((x) => x.before !== x.after || args.all),
        },
        null,
        2,
      ),
    );
    return failOnChange && changed ? 1 : 0;
  }

  heading(`policy ${policy.name} (${policy.hash.slice(0, 8)}) against ${log.logId}`);
  kv([
    ['replayed', `${results.length} calls`],
    ['unchanged', String(results.length - changed)],
    ['changed', changed ? c.yellow(String(changed)) : c.green('0')],
    ...Object.entries(transitions)
      .sort((a, b) => b[1] - a[1])
      .map(([k, n]) => /** @type {[string, string]} */ ([`  ${k}`, String(n)])),
  ]);

  const shown = results.filter((x) => x.before !== x.after || args.all);
  if (shown.length) {
    out('');
    table(
      ['#', 'when', 'tool', 'recorded', 'this policy', 'rule', 'reason'],
      shown.map((x) => [
        c.grey(String(x.seq)),
        x.ts.slice(0, 19).replace('T', ' '),
        x.target + (x.approximate ? c.grey(' ≈') : ''),
        paint(x.before),
        paint(x.after),
        x.rules.join(', ') || c.grey('—'),
        (x.reason ?? '').slice(0, 60),
      ]),
    );
  }

  if (approximate) {
    out('');
    warn(
      `${approximate} call(s) marked ≈ had values masked in the log, so a rule or egress guard ` +
        `that looked at those values could not be replayed exactly.`,
    );
  }
  out('');
  return failOnChange && changed ? 1 : 0;
}
