import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Policy, History, parseWindow, globMatch } from '../src/policy.js';
import { redact, hasSecrets } from '../src/redact.js';

const ACTOR = {
  agent: 'claude-opus-5',
  runtime: 'vouchwell-proxy/0.1.0',
  session: 'sess_a',
  principal: 'ops@acme.test',
};

/** @param {object} doc */
function pol(doc) {
  return new Policy({ version: 1, name: 'test', ...doc });
}

/**
 * @param {string} target
 * @param {object} [params]
 * @param {object} [metrics]
 */
function ctx(target, params = {}, metrics = {}) {
  return { kind: 'tool_call', target, params, metrics, actor: ACTOR };
}

test('an empty policy allows by default, and says so', () => {
  const d = pol({ rules: [] }).decide(ctx('anything.at_all'));
  assert.equal(d.outcome, 'allow');
  assert.match(d.reason, /no rule matched/);
});

test('defaults.outcome: deny turns the policy into an allowlist', () => {
  const p = pol({
    defaults: { outcome: 'deny' },
    rules: [{ id: 'allow.reads', when: { target: 'db.read*' }, then: 'allow' }],
  });
  assert.equal(p.decide(ctx('db.read_rows')).outcome, 'allow');
  assert.equal(p.decide(ctx('db.drop_table')).outcome, 'deny');
});

test('a rule with no "then" annotates without deciding; the next one decides', () => {
  const p = pol({
    rules: [
      { id: 'a.note', when: { target: 'stripe.*' } },
      { id: 'b.block', when: { target: 'stripe.payout' }, then: 'deny', reason: 'no payouts' },
      { id: 'c.never', when: { target: '*' }, then: 'escalate' },
    ],
  });
  const d = p.decide(ctx('stripe.payout'));
  assert.equal(d.outcome, 'deny');
  assert.equal(d.reason, 'no payouts');
  assert.deepEqual(d.rules, ['a.note', 'b.block'], 'later rules must not be consulted');
});

test('an explicit allow is terminal, so a later deny cannot override it', () => {
  const p = pol({
    rules: [
      { id: 'a.permit-refunds', when: { target: 'stripe.refund' }, then: 'allow' },
      { id: 'b.block-stripe', when: { target: 'stripe.*' }, then: 'deny' },
    ],
  });
  assert.equal(p.decide(ctx('stripe.refund')).outcome, 'allow');
  assert.equal(p.decide(ctx('stripe.payout')).outcome, 'deny');
});

test('an explicit allow does not exempt an action from its budget', () => {
  // Permission to use a tool is not permission to exceed a spending cap.
  const p = pol({
    rules: [{ id: 'permit', when: { target: 'stripe.*' }, then: 'allow' }],
    budgets: [
      {
        id: 'spend.daily',
        match: { target: 'stripe.*' },
        field: 'metrics.amount_usd',
        limit: 100,
        window: '24h',
        then: 'escalate',
      },
    ],
  });
  assert.equal(p.decide(ctx('stripe.refund', {}, { amount_usd: 50 })).outcome, 'allow');
  assert.equal(p.decide(ctx('stripe.refund', {}, { amount_usd: 150 })).outcome, 'escalate');
});

test('numeric operators gate on argument values', () => {
  const p = pol({
    rules: [
      {
        id: 'escalate.big-refund',
        when: { target: 'stripe.refund', 'params.amount': { gt: 10000 } },
        then: 'escalate',
      },
    ],
  });
  assert.equal(p.decide(ctx('stripe.refund', { amount: 9999 })).outcome, 'allow');
  assert.equal(p.decide(ctx('stripe.refund', { amount: 10001 })).outcome, 'escalate');
});

test('regex operators catch destructive SQL', () => {
  const p = pol({
    rules: [
      {
        id: 'deny.destructive-sql',
        when: { target: 'postgres.query', 'params.sql': { matches: '(?i)\\b(drop|truncate|delete)\\b' } },
        then: 'deny',
        reason: 'destructive SQL is not permitted from an agent',
      },
    ],
  });
  assert.equal(p.decide(ctx('postgres.query', { sql: 'SELECT 1' })).outcome, 'allow');
  assert.equal(
    p.decide(ctx('postgres.query', { sql: 'delete from users where 1=1' })).outcome,
    'deny',
  );
  assert.equal(
    p.decide(ctx('postgres.query', { sql: 'DROP TABLE customers' })).outcome,
    'deny',
  );
});

test('rules can scope to the human the agent is acting for', () => {
  const p = pol({
    rules: [
      {
        id: 'deny.contractor-payouts',
        when: { target: 'stripe.*', 'actor.principal': { matches: '@contractor\\.' } },
        then: 'deny',
      },
    ],
  });
  assert.equal(p.decide(ctx('stripe.refund')).outcome, 'allow');
  assert.equal(
    p.decide({ ...ctx('stripe.refund'), actor: { ...ACTOR, principal: 'sam@contractor.test' } })
      .outcome,
    'deny',
  );
});

test('a typo in an operator is a load error, never a silently skipped rule', () => {
  assert.throws(
    () => pol({ rules: [{ id: 'oops', when: { 'params.amount': { greaterThan: 10 } }, then: 'deny' }] }),
    /unknown operator "greaterThan"/,
  );
});

test('an invalid outcome is a load error', () => {
  assert.throws(
    () => pol({ rules: [{ id: 'x', when: {}, then: 'block' }] }),
    /must be allow, deny, or escalate/,
  );
});

test('a rule without an id is refused', () => {
  assert.throws(() => pol({ rules: [{ when: {}, then: 'deny' }] }), /needs an id/);
});

test('rate limits count only allowed calls in the window', () => {
  const p = pol({
    rateLimits: [{ id: 'email.burst', match: { target: 'gmail.send' }, limit: 3, window: '1h' }],
  });
  const history = new History();
  const now = () => new Date().toISOString();

  for (let i = 0; i < 3; i++) {
    const d = p.decide(ctx('gmail.send'), history);
    assert.equal(d.outcome, 'allow', `call ${i} should be allowed`);
    history.push({
      ts: now(),
      actor: ACTOR,
      action: { kind: 'tool_call', target: 'gmail.send', params: { preview: {} }, metrics: {} },
      decision: { outcome: 'allow' },
    });
  }

  const blocked = p.decide(ctx('gmail.send'), history);
  assert.equal(blocked.outcome, 'deny');
  assert.match(blocked.reason, /rate limit email.burst exhausted: 3 of 3/);
});

test('a history can be judged as of a past moment, for replaying a recorded log', () => {
  const p = pol({
    rateLimits: [{ id: 'email.burst', match: { target: 'gmail.send' }, limit: 1, window: '1h' }],
  });
  const sent = (/** @type {string} */ ts) => ({
    ts,
    actor: ACTOR,
    action: { kind: 'tool_call', target: 'gmail.send', params: { preview: {} }, metrics: {} },
    decision: { outcome: 'allow' },
  });
  const history = new History([sent('2026-01-01T10:00:00Z')]);

  // Measured from today, a call in January is long outside the window.
  assert.equal(p.decide(ctx('gmail.send'), history).outcome, 'allow');

  // Measured from half an hour after it, the same call still counts.
  history.now = Date.parse('2026-01-01T10:30:00Z');
  assert.equal(p.decide(ctx('gmail.send'), history).outcome, 'deny');

  // And from two hours after, it has aged out.
  history.now = Date.parse('2026-01-01T12:00:00Z');
  assert.equal(p.decide(ctx('gmail.send'), history).outcome, 'allow');
});

test('denied calls do not consume quota', () => {
  const p = pol({
    rateLimits: [{ id: 'email.burst', match: { target: 'gmail.send' }, limit: 2, window: '1h' }],
  });
  const history = new History();
  for (let i = 0; i < 9; i++) {
    history.push({
      ts: new Date().toISOString(),
      actor: ACTOR,
      action: { kind: 'tool_call', target: 'gmail.send', params: { preview: {} }, metrics: {} },
      decision: { outcome: 'deny' },
    });
  }
  assert.equal(p.decide(ctx('gmail.send'), history).outcome, 'allow');
});

test('activity outside the window is forgotten', () => {
  const p = pol({
    rateLimits: [{ id: 'email.burst', match: { target: 'gmail.send' }, limit: 1, window: '1h' }],
  });
  const history = new History([
    {
      ts: new Date(Date.now() - 3 * 3600_000).toISOString(),
      actor: ACTOR,
      action: { kind: 'tool_call', target: 'gmail.send', params: { preview: {} }, metrics: {} },
      decision: { outcome: 'allow' },
    },
  ]);
  assert.equal(p.decide(ctx('gmail.send'), history).outcome, 'allow');
});

test('a budget stops the action that would breach the cap, not the one after', () => {
  const p = pol({
    budgets: [
      {
        id: 'spend.daily',
        match: { kind: 'tool_call', target: 'stripe.*' },
        field: 'metrics.amount_usd',
        limit: 1000,
        window: '24h',
        then: 'escalate',
      },
    ],
  });
  const history = new History([
    {
      ts: new Date().toISOString(),
      actor: ACTOR,
      action: {
        kind: 'tool_call',
        target: 'stripe.refund',
        params: { preview: {} },
        metrics: { amount_usd: 900 },
      },
      decision: { outcome: 'allow' },
    },
  ]);

  // 900 + 99 stays under; 900 + 101 does not, and is caught *before* it runs.
  assert.equal(p.decide(ctx('stripe.refund', {}, { amount_usd: 99 }), history).outcome, 'allow');
  const over = p.decide(ctx('stripe.refund', {}, { amount_usd: 101 }), history);
  assert.equal(over.outcome, 'escalate');
  assert.match(over.reason, /900 already committed plus 101 proposed, against a cap of 1000/);
  assert.equal(over.meta.spent, 900);
});

test('budgets can be scoped per principal', () => {
  const p = pol({
    budgets: [
      {
        id: 'spend.per-user',
        match: { target: 'stripe.*' },
        per: 'actor.principal',
        field: 'metrics.amount_usd',
        limit: 500,
        window: '24h',
        then: 'deny',
      },
    ],
  });
  const history = new History([
    {
      ts: new Date().toISOString(),
      actor: { ...ACTOR, principal: 'alex@acme.test' },
      action: {
        kind: 'tool_call',
        target: 'stripe.refund',
        params: { preview: {} },
        metrics: { amount_usd: 480 },
      },
      decision: { outcome: 'allow' },
    },
  ]);

  // Alex is nearly out of budget; Jordan's is untouched.
  assert.equal(
    p.decide({ ...ctx('stripe.refund', {}, { amount_usd: 50 }), actor: { ...ACTOR, principal: 'alex@acme.test' } }, history)
      .outcome,
    'deny',
  );
  assert.equal(
    p.decide({ ...ctx('stripe.refund', {}, { amount_usd: 50 }), actor: { ...ACTOR, principal: 'jordan@acme.test' } }, history)
      .outcome,
    'allow',
  );
});

test('the egress guard refuses to hand a secret to a tool', () => {
  const p = pol({ egress: { denySecrets: true } });
  const clean = p.decide(ctx('http.post', { body: 'hello world' }));
  assert.equal(clean.outcome, 'allow');

  const leaky = p.decide(
    ctx('http.post', { headers: { 'x-api-key': 'sk-ant-api03-abcdefghijklmnop12345' } }),
  );
  assert.equal(leaky.outcome, 'deny');
  assert.deepEqual(leaky.rules, ['egress.guard']);
  assert.match(leaky.reason, /anthropic_key/);
});

test('the egress guard runs before any allow rule can wave it through', () => {
  const p = pol({
    egress: { denySecrets: true },
    rules: [{ id: 'allow.everything', when: { target: '*' }, then: 'allow' }],
  });
  const d = p.decide(ctx('http.post', { card: '4111 1111 1111 1111' }));
  assert.equal(d.outcome, 'deny');
});

test('policy hash changes when any rule changes', () => {
  const a = pol({ rules: [{ id: 'r', when: { target: 'x' }, then: 'deny' }] });
  const b = pol({ rules: [{ id: 'r', when: { target: 'y' }, then: 'deny' }] });
  const aAgain = pol({ rules: [{ id: 'r', when: { target: 'x' }, then: 'deny' }] });
  assert.notEqual(a.hash, b.hash);
  assert.equal(a.hash, aAgain.hash, 'the same policy text must hash the same way');
  assert.match(a.hash, /^[0-9a-f]{64}$/);
});

test('windows parse the units a human would write', () => {
  assert.equal(parseWindow('30s'), 30_000);
  assert.equal(parseWindow('15m'), 900_000);
  assert.equal(parseWindow('24h'), 86_400_000);
  assert.equal(parseWindow('7d'), 604_800_000);
  assert.throws(() => parseWindow('soon'), /invalid window/);
});

test('glob matching handles the namespace.tool shape', () => {
  assert.ok(globMatch('stripe.*', 'stripe.refund'));
  assert.ok(globMatch('*', 'anything'));
  assert.ok(globMatch('*.delete', 'db.delete'));
  assert.equal(globMatch('stripe.*', 'adyen.refund'), false);
  // A dot is literal, not a wildcard.
  assert.equal(globMatch('stripe.refund', 'stripeXrefund'), false);
});

test('redaction finds the secrets that matter and leaves prose alone', () => {
  const { value, findings } = redact({
    note: 'Ship it to jordan@example.test by Friday',
    authorization: 'Bearer abcdefghijklmnopqrstuvwxyz012345',
    aws: 'AKIAIOSFODNN7EXAMPLE',
    card: '4111 1111 1111 1111',
    orderId: '1234567890123456',
    prose: 'The quarterly figures look strong.',
  });

  const types = new Set(findings.map((f) => f.type));
  assert.ok(types.has('email'));
  assert.ok(types.has('aws_access_key'));
  assert.ok(types.has('credit_card'));
  assert.ok(types.has('key:authorization'));
  assert.equal(value.prose, 'The quarterly figures look strong.');
  assert.ok(hasSecrets(findings));

  // 1234567890123456 fails the Luhn check, so it is not flagged as a card.
  assert.equal(value.orderId, '1234567890123456');
  assert.ok(!JSON.stringify(value).includes('AKIAIOSFODNN7EXAMPLE'));
});

test('redaction keeps the last four characters so incidents stay traceable', () => {
  const { value } = redact({ key: 'AKIAIOSFODNN7EXAMPLE' });
  assert.equal(value.key, '[redacted:aws_access_key:…MPLE]');
});

test('a policy document round-trips through JSON with comments', () => {
  const p = Policy.parse(`{
    // Block payouts outright.
    "version": 1,
    "name": "finance",
    "rules": [{ "id": "no.payouts", "when": { "target": "stripe.payout" }, "then": "deny" }]
  }`);
  assert.equal(p.name, 'finance');
  assert.equal(p.decide(ctx('stripe.payout')).outcome, 'deny');
});
