import { Policy } from './policy.js';

/**
 * Ready-made policies for the risks nearly every agent deployment has.
 *
 * A first policy is the hardest one to write: an empty file blocks nothing,
 * and a hand-written one tends to miss the obvious. These are starting points
 * written in the ordinary policy language, so each one can be read, tested
 * against recorded traffic (`vw policy test`) and edited like any policy.
 *
 * Two things they cannot know are your tool names and your argument names.
 * They match the conventions MCP servers and agent frameworks mostly use
 * (`send_email`, `params.sql`, `params.command`); `vw policy test` against a
 * week of monitor-mode traffic shows whether they fit yours before anything
 * is blocked.
 */

/** Argument names SQL tools commonly use. */
const SQL_FIELDS = ['params.sql', 'params.query', 'params.statement'];
/** Argument names shell and code-running tools commonly use. */
const SHELL_FIELDS = ['params.command', 'params.cmd', 'params.script'];

/**
 * A tool name whose verb is one of `verbs`: `gmail.send_email`,
 * `slack.postMessage`, `send`. The verb must start the name or follow a `.`
 * or `_`, and end it or be followed by `_` or a capital, so `posthog.get`
 * is not a "post" and `resend.status` is not a "send".
 *
 * @param {string[]} verbs
 */
const verb = (verbs) => `(^|[._])(${verbs.join('|')})(_|[A-Z]|$)`;

const PAYMENT_TOOLS = '(?i)(refund|payout|transfer|charge|payment|invoice)';
const SENDING = verb(['send', 'post', 'reply', 'forward', 'publish']);

/**
 * @typedef {object} PolicyTemplate
 * @property {string} id
 * @property {string} title
 * @property {string} summary   One line: what it stops.
 * @property {string[]} notes   What it assumes, and what to watch.
 * @property {{ rules?: any[], budgets?: any[], rateLimits?: any[], egress?: any, defaults?: any }} policy
 */

/** @type {readonly PolicyTemplate[]} */
export const POLICY_TEMPLATES = deepFreeze([
  {
    id: 'secrets',
    title: 'Keep credentials and card numbers away from tools',
    summary: 'Refuse any call whose arguments contain an API key, token, private key, card number or IBAN.',
    notes: [
      'Covers every tool. Detection is by format (the same detectors that redact receipts), so a secret shaped like prose is not caught.',
    ],
    policy: { egress: { denySecrets: true } },
  },
  {
    id: 'no-personal-data',
    title: 'Send no personal data to any tool',
    summary: 'Refuse any call whose arguments contain an email address, phone number, SSN, card number or credential.',
    notes: [
      'Covers every tool, so it also stops an email tool from receiving a recipient address.',
      'Use it for agents whose tools should never see personal data (analytics, search, third-party models); otherwise use "secrets".',
    ],
    policy: { egress: { denyPii: true } },
  },
  {
    id: 'destructive-sql',
    title: 'No destructive SQL',
    summary: 'Refuse DROP, TRUNCATE, ALTER TABLE, GRANT and REVOKE, and DELETE or UPDATE with no WHERE clause.',
    notes: [`Looks at ${SQL_FIELDS.join(', ')}. A tool that takes SQL under another name needs a rule for that field.`],
    policy: {
      rules: SQL_FIELDS.flatMap((field) => {
        const name = field.slice('params.'.length);
        return [
          {
            id: `destructive-sql.schema.${name}`,
            when: { [field]: { matches: '(?i)\\b(drop\\s+(table|database|schema|index|view)|truncate\\b|alter\\s+table|grant\\s|revoke\\s)' } },
            then: 'deny',
            reason: 'schema changes and permission grants from an agent are not permitted',
          },
          {
            id: `destructive-sql.unbounded.${name}`,
            when: { [field]: { matches: '(?i)^(?![\\s\\S]*\\bwhere\\b)[\\s\\S]*\\b(delete\\s+from|update\\s+\\S+\\s+set)\\b' } },
            then: 'deny',
            reason: 'DELETE or UPDATE with no WHERE clause would touch every row',
          },
        ];
      }),
    },
  },
  {
    id: 'sql-writes-need-approval',
    title: 'A person approves every SQL write',
    summary: 'Escalate INSERT, UPDATE, DELETE and MERGE to a person; reads run.',
    notes: [
      `Looks at ${SQL_FIELDS.join(', ')}.`,
      'Needs an approver (vw proxy --approve, Slack, or the hub). Without one, an escalation is refused.',
    ],
    policy: {
      rules: SQL_FIELDS.map((field) => ({
        id: `sql-writes.${field.slice('params.'.length)}`,
        when: { [field]: { matches: '(?i)\\b(insert\\s+into|update\\s+\\S+\\s+set|delete\\s+from|merge\\s+into)\\b' } },
        then: 'escalate',
        reason: 'writes to the database need a person',
      })),
    },
  },
  {
    id: 'payments',
    title: 'Cap what an agent can spend',
    summary: 'Escalate any single payment or refund over $500, and anything past $2,000 a day per person the agent acts for.',
    notes: [
      'Budgets add up metrics.amount_usd, which your config (vw proxy) or metrics function (Recorder) must extract, e.g. Stripe amounts in cents with scale 0.01. Without it these never fire, and vw proxy warns at startup.',
      'Tools are recognised by name: refund, payout, transfer, charge, payment, invoice.',
    ],
    policy: {
      rules: [
        {
          id: 'payments.large',
          when: { target: { matches: PAYMENT_TOOLS }, 'metrics.amount_usd': { gt: 500 } },
          then: 'escalate',
          reason: 'a single payment over $500 needs a person',
        },
      ],
      budgets: [
        {
          id: 'payments.daily',
          match: { target: { matches: PAYMENT_TOOLS } },
          field: 'metrics.amount_usd',
          limit: 2000,
          window: '24h',
          per: 'actor.principal',
          then: 'escalate',
        },
      ],
    },
  },
  {
    id: 'outbound-messages',
    title: 'A person approves what leaves the building',
    summary: 'Escalate every send, post, reply, forward and publish to a person.',
    notes: [
      'Recognises tools by verb: send_email, slack.postMessage, reply, forward, publish.',
      'Needs an approver. Without one, every message is refused. To let messages go without approval but cap them, use "outbound-rate-limit" instead.',
    ],
    policy: {
      rules: [
        {
          id: 'outbound-messages.approve',
          when: { target: { matches: SENDING } },
          then: 'escalate',
          reason: 'anything that leaves the building gets a person',
        },
      ],
    },
  },
  {
    id: 'outbound-rate-limit',
    title: 'Cap how much an agent can send',
    summary: 'Let sends, posts, replies, forwards and publishes through, at most 30 a session per hour.',
    notes: [
      'Recognises tools the same way as "outbound-messages".',
      'Combined with "outbound-messages" the cap never applies: every message already waits for a person, and a policy stops at the first decision.',
    ],
    policy: {
      rateLimits: [
        {
          id: 'outbound-rate-limit.session',
          match: { target: { matches: SENDING } },
          limit: 30,
          window: '1h',
          per: 'actor.session',
          then: 'deny',
        },
      ],
    },
  },
  {
    id: 'shell-safety',
    title: 'No destructive shell commands',
    summary: 'Refuse rm -rf, disk formatting, force-pushes, world-writable chmod and piping a download into a shell; escalate file deletes and moves.',
    notes: [
      `Commands are read from ${SHELL_FIELDS.join(', ')}.`,
      'A pattern list, not a sandbox: an agent that can run arbitrary code can find another way. Pair it with an allowlist ("read-only") where you can.',
    ],
    policy: {
      rules: [
        ...SHELL_FIELDS.map((field) => ({
          id: `shell-safety.dangerous.${field.slice('params.'.length)}`,
          when: {
            [field]: {
              matches:
                // rm with a recursive and a force flag, in any order or
                // grouping. Two independent lookaheads, each linear: an
                // earlier form that matched flag groups with a repeated
                // ambiguous group took exponential time on "rm -rrrr -rrrr …".
                '(\\brm\\b(?=[^;&|\\n]*\\s(-[a-zA-Z]*[rR]|--recursive\\b))(?=[^;&|\\n]*\\s(-[a-zA-Z]*f|--force\\b))|\\bmkfs\\b|\\bdd\\s+if=|' +
                ':\\(\\)\\s*\\{|\\bgit\\s+push\\b[^;&|]*(\\s--force\\b|\\s-f\\b)|\\bchmod\\s+(-R\\s+)?0?777\\b|' +
                '\\b(curl|wget)\\b[^|;&]*\\|\\s*(sudo\\s+)?(ba|z)?sh\\b|\\b(shutdown|reboot|halt)\\b)',
            },
          },
          then: 'deny',
          reason: 'a destructive or irreversible shell command',
        })),
        {
          id: 'shell-safety.file-changes',
          when: { target: { matches: verb(['delete', 'remove', 'move', 'rename']) } },
          then: 'escalate',
          reason: 'deleting or moving files needs a person',
        },
      ],
    },
  },
  {
    id: 'production-guard',
    title: 'A person approves anything aimed at production',
    summary: 'Escalate any call whose environment, env or stage argument names production.',
    notes: ['Reads params.environment, params.env and params.stage; values prod, production and live, in any case.'],
    policy: {
      rules: ['environment', 'env', 'stage'].map((name) => ({
        id: `production-guard.${name}`,
        when: { [`params.${name}`]: { matches: '(?i)^(prod|production|live)$' } },
        then: 'escalate',
        reason: 'changes aimed at production need a person',
      })),
    },
  },
  {
    id: 'loop-guard',
    title: 'Stop an agent stuck in a loop',
    summary: 'Refuse the same tool after 60 calls in 5 minutes, and escalate a session past 300 calls an hour.',
    notes: ['Counts only calls that were allowed; refusals cost nothing.'],
    policy: {
      rateLimits: [
        { id: 'loop-guard.same-tool', match: { target: '*' }, limit: 60, window: '5m', per: 'target', then: 'deny' },
        { id: 'loop-guard.session', match: { target: '*' }, limit: 300, window: '1h', per: 'actor.session', then: 'escalate' },
      ],
    },
  },
  {
    id: 'read-only',
    title: 'Read-only: allow lookups, refuse everything else',
    summary: 'Allow tools named get, list, read, search, query, fetch, find, describe, lookup, show, view or count; refuse the rest.',
    notes: [
      'An allowlist: a new tool is refused until a rule allows it. Composed with other templates, their refusals still apply first.',
      '"query" tools are allowed, so combine with "destructive-sql" if a query tool takes raw SQL.',
    ],
    policy: {
      defaults: { outcome: 'deny' },
      rules: [
        {
          id: 'read-only.lookups',
          when: {
            target: { matches: verb(['get', 'list', 'read', 'search', 'query', 'fetch', 'find', 'describe', 'lookup', 'show', 'view', 'count']) },
          },
          then: 'allow',
        },
      ],
    },
  },
]);

/**
 * @param {string} id
 * @returns {PolicyTemplate}
 */
export function policyTemplate(id) {
  const found = POLICY_TEMPLATES.find((t) => t.id === id);
  if (!found) {
    throw new Error(`no policy template "${id}"; available: ${POLICY_TEMPLATES.map((t) => t.id).join(', ')}`);
  }
  return found;
}

const SEVERITY = { deny: 0, escalate: 1, allow: 2 };

/**
 * One policy document from several templates.
 *
 * Rules are ordered refusals first, then escalations, then allows, then rules
 * that only tag. The engine stops at the first rule that decides, so this
 * order is what makes composition safe: an allowlist from one template can
 * never let through a call another template refuses. Budgets, rate limits
 * and guards are all kept; a single `defaults.outcome: "deny"` makes the whole
 * policy an allowlist.
 *
 * @param {string[]} ids
 * @param {{ name?: string }} [opts]
 * @returns {{ version: 1, name: string, templates: string[], rules: any[], budgets: any[], rateLimits: any[], egress?: any, defaults?: any }}
 */
export function composePolicy(ids, opts = {}) {
  const chosen = [...new Set(ids)].map(policyTemplate);
  if (chosen.length === 0) throw new Error('choose at least one policy template');

  const rules = chosen
    .flatMap((t) => t.policy.rules ?? [])
    .map((r, i) => ({ r, i }))
    .sort((a, b) => (SEVERITY[a.r.then] ?? 3) - (SEVERITY[b.r.then] ?? 3) || a.i - b.i)
    .map(({ r }) => clone(r));
  const egress = {};
  for (const t of chosen) {
    for (const [k, v] of Object.entries(t.policy.egress ?? {})) if (v) egress[k] = true;
  }
  const allowlist = chosen.some((t) => t.policy.defaults?.outcome === 'deny');

  const doc = {
    version: /** @type {const} */ (1),
    name: opts.name ?? chosen.map((t) => t.id).join('+'),
    templates: chosen.map((t) => t.id),
    ...(allowlist ? { defaults: { outcome: 'deny' } } : {}),
    rules,
    budgets: chosen.flatMap((t) => t.policy.budgets ?? []).map(clone),
    rateLimits: chosen.flatMap((t) => t.policy.rateLimits ?? []).map(clone),
    ...(Object.keys(egress).length ? { egress } : {}),
  };
  // Compile it: a template that did not load would be a broken guardrail.
  new Policy(doc);
  return doc;
}

/** @param {any} v */
function clone(v) {
  return JSON.parse(JSON.stringify(v));
}

/**
 * @template T
 * @param {T} v
 * @returns {T}
 */
function deepFreeze(v) {
  if (v && typeof v === 'object') {
    for (const x of Object.values(v)) deepFreeze(x);
    Object.freeze(v);
  }
  return v;
}
