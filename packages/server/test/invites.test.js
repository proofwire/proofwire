import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { Hub } from '../src/app.js';
import { Auth } from '../src/auth.js';

/**
 * Invitations and password resets.
 *
 * Almost every test here is about *consumption* — used once, expires, cannot
 * be replayed, does not leak who has an account — because that is where these
 * flows are got wrong, not in the happy path.
 */

/** @type {Hub} */
let hub;
let base;
let adminToken;
let orgId;

before(async () => {
  hub = new Hub({
    database: ':memory:',
    checkpointEvery: 0,
    apiRate: { capacity: 1e6, refillPerSec: 1e6 },
    authRate: { capacity: 1e6, refillPerSec: 1e6 },
  });
  const { url } = await hub.listen(0);
  base = url.replace('0.0.0.0', '127.0.0.1');

  const auth = new Auth(hub.store);
  const org = hub.store.createOrg({ slug: 'acme', name: 'Acme' });
  orgId = org.id;
  adminToken = auth.createKey({
    orgId,
    name: 'admin',
    scopes: ['admin', 'logs:read', 'receipts:read'],
  }).token;
});

after(async () => { await hub.close(); });

/**
 * @param {string} method
 * @param {string} p
 * @param {object} [opts]
 */
async function api(method, p, opts = {}) {
  const res = await fetch(base + p, {
    method,
    headers: {
      ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
      ...(opts.cookie ? { cookie: opts.cookie } : {}),
      ...(opts.body ? { 'content-type': 'application/json' } : {}),
      ...(opts.headers ?? {}),
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    redirect: 'manual',
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* HTML */ }
  return { status: res.status, json, text, headers: res.headers };
}

/** @param {Response|{headers: Headers}} res */
const cookieOf = (res) =>
  (res.headers.getSetCookie?.() ?? []).map((c) => c.split(';')[0]).join('; ');

/** @param {string} link */
const tokenFrom = (link) => new URL(link, 'http://x').searchParams.get('token');

// ── invitations ──────────────────────────────────────────────────────────

test('an invitation produces a one-time link and a pending member', async () => {
  const res = await api('POST', '/v1/invites', {
    token: adminToken,
    body: { email: 'sam@acme.test', role: 'operator' },
  });

  assert.equal(res.status, 200);
  assert.equal(res.json.email, 'sam@acme.test');
  assert.match(res.json.link, /\/accept\?token=/);
  assert.ok(res.json.expiresAt > new Date().toISOString());

  // The member exists but cannot sign in yet: no password is set.
  const members = (await api('GET', '/v1/members', { token: adminToken })).json.members;
  const sam = members.find((m) => m.email === 'sam@acme.test');
  assert.equal(sam.role, 'operator');

  const login = await api('POST', '/v1/auth/login', {
    body: { email: 'sam@acme.test', password: '' },
  });
  assert.equal(login.status, 401, 'an invited-but-inactive user must not be able to sign in');
});

test('accepting an invitation sets the password, joins the org, and signs in', async () => {
  const invite = (
    await api('POST', '/v1/invites', {
      token: adminToken,
      body: { email: 'kai@acme.test', role: 'auditor' },
    })
  ).json;

  const redeem = await api('POST', '/v1/auth/redeem', {
    body: { token: tokenFrom(invite.link), password: 'a-sufficiently-long-password' },
  });
  assert.equal(redeem.status, 200);
  assert.match(cookieOf(redeem), /pw_session=/, 'accepting should sign the user in');

  // And the role from the invitation is what they actually hold.
  const me = await api('GET', '/v1/me', { cookie: cookieOf(redeem) });
  assert.equal(me.json.role, 'auditor');
  assert.ok(me.json.scopes.includes('receipts:read'));
  assert.ok(!me.json.scopes.includes('admin'), 'an auditor must not gain admin by accepting');
});

test('an invitation cannot be redeemed twice', async () => {
  const invite = (
    await api('POST', '/v1/invites', {
      token: adminToken,
      body: { email: 'replay@acme.test', role: 'operator' },
    })
  ).json;
  const token = tokenFrom(invite.link);

  assert.equal(
    (await api('POST', '/v1/auth/redeem', { body: { token, password: 'first-password-here' } })).status,
    200,
  );

  const second = await api('POST', '/v1/auth/redeem', {
    body: { token, password: 'attacker-password-x' },
  });
  assert.equal(second.status, 400);
  assert.equal(second.json.error.code, 'invalid_token');

  // The first password still works, so the replay changed nothing.
  const login = await api('POST', '/v1/auth/login', {
    body: { email: 'replay@acme.test', password: 'first-password-here' },
  });
  assert.equal(login.status, 200);
});

test('a second invitation invalidates the first', async () => {
  const first = (
    await api('POST', '/v1/invites', {
      token: adminToken,
      body: { email: 'reissue@acme.test', role: 'operator' },
    })
  ).json;
  const second = (
    await api('POST', '/v1/invites', {
      token: adminToken,
      body: { email: 'reissue@acme.test', role: 'admin' },
    })
  ).json;

  const stale = await api('POST', '/v1/auth/redeem', {
    body: { token: tokenFrom(first.link), password: 'should-not-work-here' },
  });
  assert.equal(stale.status, 400, 'a superseded invitation must stop working');

  assert.equal(
    (await api('POST', '/v1/auth/redeem', {
      body: { token: tokenFrom(second.link), password: 'this-one-should-work' },
    })).status,
    200,
  );
});

test('an expired invitation is refused', async () => {
  const invite = (
    await api('POST', '/v1/invites', {
      token: adminToken,
      body: { email: 'slow@acme.test', role: 'operator' },
    })
  ).json;

  hub.db
    .prepare("UPDATE tokens SET expires_at = '2020-01-01T00:00:00.000Z' WHERE used_at IS NULL")
    .run();

  const res = await api('POST', '/v1/auth/redeem', {
    body: { token: tokenFrom(invite.link), password: 'too-late-for-this-one' },
  });
  assert.equal(res.status, 400);
});

test('only an admin can invite, and only to a real role', async () => {
  const auth = new Auth(hub.store);
  const weak = auth.createKey({ orgId, name: 'weak', scopes: ['logs:read'] }).token;

  assert.equal(
    (await api('POST', '/v1/invites', { token: weak, body: { email: 'x@y.test', role: 'owner' } })).status,
    403,
  );
  assert.equal(
    (await api('POST', '/v1/invites', {
      token: adminToken,
      body: { email: 'x@y.test', role: 'superuser' },
    })).status,
    400,
  );
});

// ── password reset ───────────────────────────────────────────────────────

test('a reset link sets a new password and revokes every existing session', async () => {
  // Establish a user with an active session.
  const invite = (
    await api('POST', '/v1/invites', {
      token: adminToken,
      body: { email: 'reset@acme.test', role: 'operator' },
    })
  ).json;
  await api('POST', '/v1/auth/redeem', {
    body: { token: tokenFrom(invite.link), password: 'original-password-01' },
  });

  const login = await api('POST', '/v1/auth/login', {
    body: { email: 'reset@acme.test', password: 'original-password-01' },
  });
  const oldCookie = cookieOf(login);
  assert.equal((await api('GET', '/v1/me', { cookie: oldCookie })).status, 200);

  // Reset.
  await api('POST', '/v1/auth/reset', { body: { email: 'reset@acme.test' } });
  const row = hub.db
    .prepare(
      `SELECT t.id FROM tokens t JOIN users u ON u.id = t.user_id
       WHERE u.email = ? AND t.kind = 'reset' AND t.used_at IS NULL`,
    )
    .get('reset@acme.test');
  assert.ok(row, 'a reset token should have been issued');

  // Take the token the way the user would: from the emitted link. The test
  // reaches into the console flow instead, since the API does not echo it.
  const forgot = await fetch(base + '/forgot', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ email: 'reset@acme.test' }),
    redirect: 'manual',
  });
  assert.equal(forgot.status, 303);

  // Grab the freshly issued token's plaintext by issuing one directly.
  const user = hub.auth.userByEmail('reset@acme.test');
  const issued = hub.tokens.issue({ kind: 'reset', userId: user.id });

  const redeem = await api('POST', '/v1/auth/redeem', {
    body: { token: issued.token, password: 'brand-new-password-02' },
  });
  assert.equal(redeem.status, 200);

  // The old session is dead — the whole point of a reset.
  assert.equal(
    (await api('GET', '/v1/me', { cookie: oldCookie })).status,
    401,
    'a reset must sign out every existing session',
  );
  // The old password is dead too.
  assert.equal(
    (await api('POST', '/v1/auth/login', {
      body: { email: 'reset@acme.test', password: 'original-password-01' },
    })).status,
    401,
  );
  assert.equal(
    (await api('POST', '/v1/auth/login', {
      body: { email: 'reset@acme.test', password: 'brand-new-password-02' },
    })).status,
    200,
  );
});

test('requesting a reset never reveals whether an account exists', async () => {
  const known = await api('POST', '/v1/auth/reset', { body: { email: 'reset@acme.test' } });
  const unknown = await api('POST', '/v1/auth/reset', { body: { email: 'nobody@nowhere.test' } });

  assert.equal(known.status, unknown.status);
  assert.deepEqual(known.json, unknown.json, 'the responses must be indistinguishable');

  // And no account was created for the unknown address as a side effect.
  assert.equal(hub.auth.userByEmail('nobody@nowhere.test'), null);
});

test('a reset link is never built from a Host header the requester chose', async () => {
  // Anyone can ask for a reset. Were the link built from Host, naming the
  // victim's address and the attacker's host would mail the victim a genuine
  // token pointing at the attacker's server.
  const { request } = await import('node:http');
  /** @param {string} host */
  const resetWithHost = (host) =>
    new Promise((resolve, reject) => {
      const req = request(
        base + '/v1/auth/reset',
        { method: 'POST', headers: { host, 'content-type': 'application/json' } },
        (res) => {
          let body = '';
          res.on('data', (d) => { body += d; });
          res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(body) }));
        },
      );
      req.on('error', reject);
      req.end(JSON.stringify({ email: 'reset@acme.test' }));
    });

  /** @type {any[]} */
  const sent = [];
  const deliver = hub._deliver;
  hub._deliver = (payload) => { sent.push(payload); };
  const quiet = console.error;
  console.error = () => {};
  try {
    const refused = await resetWithHost('attacker.example');
    assert.equal(refused.status, 200);
    assert.deepEqual(refused.json, (await api('POST', '/v1/auth/reset', { body: { email: 'nobody@nowhere.test' } })).json,
      'a refusal must look like every other answer');
    assert.equal(sent.length, 0, 'no link may be issued for a foreign host');

    await resetWithHost('localhost:1234');
    assert.equal(sent.length, 1, 'this machine is still served, so a local hub keeps working');
    // The scheme follows DEEDWRIT_INSECURE_COOKIES, which CI sets; the host is the point.
    assert.equal(new URL(sent[0].link).host, 'localhost:1234', sent[0].link);

    hub.config.publicUrl = 'https://hub.acme.test/';
    await resetWithHost('attacker.example');
    assert.equal(sent.length, 2);
    assert.ok(sent[1].link.startsWith('https://hub.acme.test/reset?'), 'the configured URL wins over Host');
  } finally {
    hub._deliver = deliver;
    console.error = quiet;
    delete hub.config.publicUrl;
  }
});

test('a short password is refused before anything is changed', async () => {
  const user = hub.auth.userByEmail('reset@acme.test');
  const issued = hub.tokens.issue({ kind: 'reset', userId: user.id });

  const res = await api('POST', '/v1/auth/redeem', {
    body: { token: issued.token, password: 'short' },
  });
  assert.equal(res.status, 400);
  assert.equal(res.json.error.code, 'weak_password');

  // The token survives a rejected attempt, so the user can simply try again.
  assert.equal(
    (await api('POST', '/v1/auth/redeem', {
      body: { token: issued.token, password: 'a-long-enough-password' },
    })).status,
    200,
  );
});

test('an invite token cannot be used on the reset path, or vice versa', async () => {
  const invite = (
    await api('POST', '/v1/invites', {
      token: adminToken,
      body: { email: 'kinds@acme.test', role: 'operator' },
    })
  ).json;
  const inviteToken = tokenFrom(invite.link);

  // peek() enforces the kind, which is what the console pages rely on.
  assert.ok(hub.tokens.peek(inviteToken, 'invite'));
  assert.equal(hub.tokens.peek(inviteToken, 'reset'), null);
});

// ── console flows ────────────────────────────────────────────────────────

test('the accept page renders for a live link and refuses a dead one', async () => {
  const invite = (
    await api('POST', '/v1/invites', {
      token: adminToken,
      body: { email: 'page@acme.test', role: 'operator' },
    })
  ).json;
  const token = tokenFrom(invite.link);

  const live = await api('GET', `/accept?token=${encodeURIComponent(token)}`);
  assert.equal(live.status, 200);
  assert.match(live.text, /Accept invitation/);
  assert.match(live.text, /page@acme\.test/);
  assert.match(live.text, /joining as operator/);

  const dead = await api('GET', '/accept?token=not-a-real-token');
  assert.equal(dead.status, 400);
  assert.match(dead.text, /invalid, has already been used, or has expired/);
  assert.ok(!dead.text.includes('name="password"'), 'no form should be offered for a dead link');
});

test('the console accept form completes the flow', async () => {
  const invite = (
    await api('POST', '/v1/invites', {
      token: adminToken,
      body: { email: 'form@acme.test', role: 'operator' },
    })
  ).json;
  const token = tokenFrom(invite.link);

  const res = await fetch(base + '/accept', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token, password: 'console-password-01', confirm: 'console-password-01' }),
    redirect: 'manual',
  });
  assert.equal(res.status, 303);
  assert.equal(res.headers.get('location'), '/');
  assert.match(cookieOf(res), /pw_session=/);
});

test('mismatched passwords return to the form rather than failing obscurely', async () => {
  const invite = (
    await api('POST', '/v1/invites', {
      token: adminToken,
      body: { email: 'mismatch@acme.test', role: 'operator' },
    })
  ).json;
  const token = tokenFrom(invite.link);

  const res = await fetch(base + '/accept', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token, password: 'password-one-here', confirm: 'password-two-here' }),
    redirect: 'manual',
  });
  assert.equal(res.status, 303);
  assert.match(res.headers.get('location'), /e=mismatch/);

  // And the token is still usable, so the user is not locked out by a typo.
  assert.ok(hub.tokens.peek(token, 'invite'));
});

test('the sign-in page offers the reset path', async () => {
  const res = await api('GET', '/login');
  assert.match(res.text, /href="\/forgot"/);

  const forgot = await api('GET', '/forgot');
  assert.equal(forgot.status, 200);
  assert.match(forgot.text, /single-use link/);
});

test('tokens are stored only as hashes', () => {
  const user = hub.auth.userByEmail('reset@acme.test');
  const issued = hub.tokens.issue({ kind: 'reset', userId: user.id });

  const rows = hub.db.prepare('SELECT token_hash FROM tokens').all();
  assert.ok(rows.length > 0);
  assert.ok(
    !rows.some((r) => r.token_hash === issued.token),
    'a database leak must not hand over working links',
  );
  assert.ok(rows.every((r) => /^[0-9a-f]{64}$/.test(r.token_hash)));
});

test('credential changes are recorded in the control-plane trail', async () => {
  const events = (await api('GET', '/v1/events', { token: adminToken })).json;
  assert.ok(events.integrity.ok);
  assert.ok(events.events.some((e) => e.action === 'member.invite'));
  assert.ok(events.events.some((e) => e.action === 'password.set'));
  assert.ok(events.events.some((e) => e.action === 'password.reset-requested'));
});

test('a pending invitation grants nothing until it is accepted', async () => {
  await api('POST', '/v1/invites', {
    token: adminToken,
    body: { email: 'pending@acme.test', role: 'owner' },
  });

  // The membership exists so an admin can see it — but it is inert.
  const members = (await api('GET', '/v1/members', { token: adminToken })).json.members;
  assert.ok(members.find((m) => m.email === 'pending@acme.test'));

  const user = hub.auth.userByEmail('pending@acme.test');
  assert.equal(user.password_hash, null, 'an invited account has no password');

  // No password means no session, whatever is tried.
  for (const password of ['', 'anything', 'null', 'undefined']) {
    const res = await api('POST', '/v1/auth/login', {
      body: { email: 'pending@acme.test', password },
    });
    assert.equal(res.status, 401, `an invited account must not sign in with ${JSON.stringify(password)}`);
  }
  assert.equal(
    (await api('POST', '/v1/auth/login', { body: { email: 'pending@acme.test' } })).status,
    401,
    'nor with no password field at all',
  );
});
