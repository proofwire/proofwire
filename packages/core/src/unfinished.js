import { entryHash } from './receipt.js';

/**
 * Actions that started and never finished.
 *
 * Every allowed tool call is recorded twice: an `intent` receipt, written and
 * made durable *before* the call is forwarded, and an `outcome` receipt, linked
 * to it by `ref`, when the reply arrives. An intent with no outcome is what a
 * process killed mid-action leaves behind: the log proves the action was
 * authorised and attempted, and says nothing about whether it happened. That
 * is exactly the case someone will ask about after an incident, so it is
 * surfaced rather than left for them to notice.
 *
 * Four kinds of finding:
 *
 *   unfinished  an intent with no outcome, older than `graceMs`. The recorder
 *               died, or was killed, while the call was out.
 *   abandoned   an outcome recorded as `unfinished`: the recorder shut down
 *               cleanly while the call was still out, and said so.
 *   inFlight    an intent with no outcome, younger than `graceMs`. Most likely
 *               a call still running; reported so a caller can show it, never
 *               as a problem.
 *   orphans     an outcome whose `ref` names no intent in the receipts given.
 *               In a complete log that cannot happen honestly. In a filtered
 *               export it is expected, which is why this function wants the
 *               whole log.
 *
 * Pure: the same receipts and `now` give the same answer.
 *
 * @param {import('./receipt.js').Receipt[]} receipts  The whole log, in order.
 * @param {object} [opts]
 * @param {number} [opts.now]      Epoch ms to judge age against. Defaults to now.
 * @param {number} [opts.graceMs]  How long a call may be out before it counts
 *   as unfinished. Defaults to five minutes.
 * @returns {{ unfinished: UnfinishedAction[], abandoned: UnfinishedAction[],
 *   inFlight: UnfinishedAction[], orphans: { seq: number, ref: string }[] }}
 */
export function findUnfinished(receipts, opts = {}) {
  const now = opts.now ?? Date.now();
  const graceMs = opts.graceMs ?? DEFAULT_GRACE_MS;

  /** @type {Map<string, import('./receipt.js').Receipt>} */
  const intents = new Map();
  /** @type {Set<string>} */
  const answered = new Set();
  const abandoned = [];
  const orphans = [];

  for (const r of receipts) {
    if (r?.phase === 'intent') intents.set(entryHash(r), r);
  }
  for (const r of receipts) {
    if (r?.phase !== 'outcome') continue;
    const ref = typeof r.ref === 'string' ? r.ref : '';
    const intent = intents.get(ref);
    if (!intent) {
      orphans.push({ seq: r.seq, ref });
      continue;
    }
    answered.add(ref);
    if (r.result?.code === 'unfinished') {
      abandoned.push({ ...describe(intent, ref), closedAt: r.ts, outcomeSeq: r.seq });
    }
  }

  const unfinished = [];
  const inFlight = [];
  for (const [hash, intent] of intents) {
    if (answered.has(hash)) continue;
    const at = Date.parse(intent.ts);
    // An unparseable timestamp cannot be young, so it is not given the benefit
    // of the doubt.
    const young = Number.isFinite(at) && now - at < graceMs;
    (young ? inFlight : unfinished).push(describe(intent, hash));
  }

  return { unfinished, abandoned, inFlight, orphans };
}

/** Five minutes: longer than any tool call a person would wait on. */
export const DEFAULT_GRACE_MS = 5 * 60_000;

/**
 * @typedef {object} UnfinishedAction
 * @property {number} seq          The intent receipt.
 * @property {string} ts           When the call was authorised.
 * @property {string} target       The tool.
 * @property {string} principal
 * @property {string} agent
 * @property {string} session
 * @property {string} intent       The intent's entry hash, which its outcome
 *   would have named as `ref`.
 * @property {string} [closedAt]   abandoned only: when the recorder gave up.
 * @property {number} [outcomeSeq] abandoned only: the closing receipt.
 */

/**
 * @param {import('./receipt.js').Receipt} r
 * @param {string} hash
 * @returns {UnfinishedAction}
 */
function describe(r, hash) {
  return {
    seq: r.seq,
    ts: r.ts,
    target: r.action?.target,
    principal: r.actor?.principal,
    agent: r.actor?.agent,
    session: r.actor?.session,
    intent: hash,
  };
}
