import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash, generateKeyPairSync, randomBytes, sign as cryptoSign } from 'node:crypto';
import { Hub } from '../src/app.js';
import { Auth } from '../src/auth.js';
import { verifyIdToken, isPrivateAddress, fetchJson } from '../src/oidc.js';

/**
 * Single sign-on against a fake OpenID Connect provider that behaves like a
 * real one: discovery, published keys, a token endpoint that checks the PKCE
 * verifier and the client's credentials, and signed ID tokens. The "user
 * logging in at the provider" step is simulated by issuing a code directly.
 */

// ── the fake provider ─────────────────────────────────────────────────────

const idp = {
  issuer: '',
  clientId: 'vouchwell-hub',
  clientSecret: 'idp-client-secret',
  /** @type {any} */ key: null,
  kid: 'k1',
  /** @type {Map<string, any>} */ codes: new Map(),
  /** @type {http.Server | null} */ server: null,
  /** @type {any} */ lastGrant: null,
  /** What the next token will say, and how it will be signed. */
  /** @type {(claims: any) => any} */ tamper: (c) => c,
  signWith: /** @type {any} */ (null),
};

function rotateKey(kid) {
  idp.key = generateKeyPairSync('rsa', { modulusLength: 2048 });
  idp.kid = kid;
}

/** @param {any} header @param {any} claims @param {any} privateKey */
function jwt(header, claims, privateKey) {
  const enc = (/** @type {any} */ o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const data = `${enc(header)}.${enc(claims)}`;
  const sig = privateKey ? cryptoSign('sha256', Buffer.from(data), privateKey).toString('base64url') : '';
  return `${data}.${sig}`;
}

async function startIdp() {
  rotateKey('k1');
  idp.server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', idp.issuer);
    const send = (/** @type {number} */ status, /** @type {any} */ body) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (url.pathname === '/.well-known/openid-configuration') {
      return send(200, {
        issuer: idp.issuer,
        authorization_endpoint: `${idp.issuer}/authorize`,
        token_endpoint: `${idp.issuer}/token`,
        jwks_uri: `${idp.issuer}/jwks`,
        token_endpoint_auth_methods_supported: ['client_secret_basic'],
      });
    }
    if (url.pathname === '/jwks') {
      return send(200, { keys: [{ ...idp.key.publicKey.export({ format: 'jwk' }), kid: idp.kid, alg: 'RS256', use: 'sig' }] });
    }
    if (url.pathname === '/token' && req.method === 'POST') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const f = Object.fromEntries(new URLSearchParams(body));
        const basic = Buffer.from(String(req.headers.authorization ?? '').replace(/^Basic /, ''), 'base64').toString();
        if (basic !== `${idp.clientId}:${idp.clientSecret}`) return send(401, { error: 'invalid_client' });
        const grant = idp.codes.get(f.code);
        idp.codes.delete(f.code);
        if (!grant || f.grant_type !== 'authorization_code' || f.redirect_uri !== grant.redirectUri) {
          return send(400, { error: 'invalid_grant' });
        }
        // PKCE: the verifier must hash to the challenge the hub sent at the start.
        if (createHash('sha256').update(f.code_verifier ?? '').digest('base64url') !== grant.challenge) {
          return send(400, { error: 'invalid_grant', error_description: 'PKCE verifier mismatch' });
        }
        const now = Math.floor(Date.now() / 1000);
        const claims = idp.tamper({
          iss: idp.issuer, aud: idp.clientId, sub: grant.sub, email: grant.email, email_verified: true,
          name: 'Test Person', nonce: grant.nonce, iat: now, exp: now + 300,
        });
        const header = { alg: 'RS256', kid: idp.kid, typ: 'JWT' };
        send(200, { id_token: jwt(header, claims, idp.signWith ?? idp.key.privateKey), access_token: 'x', token_type: 'Bearer' });
      });
      return;
    }
    send(404, { error: 'not_found' });
  });
  await new Promise((r) => idp.server?.listen(0, '127.0.0.1', r));
  idp.issuer = `http://127.0.0.1:${/** @type {any} */ (idp.server.address()).port}`;
}

// ── the hub ───────────────────────────────────────────────────────────────

/** @type {Hub} */
let hub;
let base = '';
const acme = { org: '', slug: 'acme', admin: '' };

before(async () => {
  await startIdp();
  hub = new Hub({
    database: ':memory:',
    checkpointEvery: 0,
    oidcAllowPrivate: true,
    apiRate: { capacity: 100000, refillPerSec: 100000 },
    authRate: { capacity: 100000, refillPerSec: 100000 },
  });
  base = (await hub.listen(0)).url.replace('0.0.0.0', '127.0.0.1');
  const auth = new Auth(hub.store);
  const org = hub.store.createOrg({ slug: 'acme', name: 'Acme' });
  acme.org = org.id;
  acme.admin = auth.createKey({ orgId: org.id, name: 'admin', scopes: ['admin', 'logs:read'] }).token;
  const dana = auth.createUser({ email: 'dana@acme.test', password: 'dana-password-long-enough' });
  auth.addMember(org.id, dana.id, 'admin');
});

after(async () => {
  await hub.close();
  idp.server?.close();
});

/**
 * @param {string} method
 * @param {string} p
 * @param {{ token?: string, cookie?: string, body?: any }} [o]
 */
async function api(method, p, o = {}) {
  const res = await fetch(base + p, {
    method,
    redirect: 'manual',
    headers: {
      ...(o.token ? { authorization: `Bearer ${o.token}` } : {}),
      ...(o.cookie ? { cookie: o.cookie } : {}),
      ...(o.body !== undefined ? { 'content-type': 'application/json' } : {}),
    },
    body: o.body !== undefined ? JSON.stringify(o.body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* html */ }
  return { status: res.status, json, text, headers: res.headers };
}

const jar = (/** @type {Headers} */ h) => (h.getSetCookie?.() ?? []).map((c) => c.split(';')[0]).filter((c) => !c.endsWith('=')).join('; ');

/**
 * Walk a sign-in: start at the hub, "authenticate" at the provider, come back.
 *
 * @param {{ email: string, sub?: string, cookie?: (bound: string) => string }} who
 */
async function signIn(who) {
  const start = await api('GET', `/sso/${acme.slug}`);
  assert.equal(start.status, 200, start.text);
  const authUrl = new URL(start.text.match(/content="0;url=([^"]+)"/)[1].replace(/&amp;/g, '&'));
  const bound = jar(start.headers);
  const q = Object.fromEntries(authUrl.searchParams);
  assert.equal(q.code_challenge_method, 'S256');
  assert.equal(q.client_id, idp.clientId);

  const code = randomBytes(12).toString('hex');
  idp.lastGrant = { nonce: q.nonce, challenge: q.code_challenge, redirectUri: q.redirect_uri, email: who.email, sub: who.sub ?? `sub-${who.email}` };
  idp.codes.set(code, idp.lastGrant);
  const back = await api('GET', `/sso/callback?code=${code}&state=${encodeURIComponent(q.state)}`, {
    cookie: who.cookie ? who.cookie(bound) : bound,
  });
  return { status: back.status, location: back.headers.get('location'), cookie: jar(back.headers), state: q.state, code, bound, grant: idp.lastGrant };
}

// ── configuration ─────────────────────────────────────────────────────────

test('configuring SSO checks the issuer, the roles and the domains before saving', async () => {
  const good = { issuer: idp.issuer, clientId: idp.clientId, clientSecret: idp.clientSecret, domains: ['acme.test'] };
  assert.equal((await api('PUT', '/v1/integrations/oidc', { token: acme.admin, body: { ...good, issuer: `${idp.issuer}/nope` } })).json.error.code, 'bad_issuer');
  assert.equal((await api('PUT', '/v1/integrations/oidc', { token: acme.admin, body: { ...good, autoProvision: 'owner' } })).json.error.code, 'bad_role');
  assert.equal((await api('PUT', '/v1/integrations/oidc', { token: acme.admin, body: { ...good, domains: [], autoProvision: 'auditor' } })).json.error.code, 'domains_required');
  assert.equal((await api('PUT', '/v1/integrations/oidc', { token: acme.admin, body: { ...good, domains: ['not a domain'] } })).json.error.code, 'bad_domain');

  const set = await api('PUT', '/v1/integrations/oidc', { token: acme.admin, body: good });
  assert.equal(set.status, 200, JSON.stringify(set.json));
  assert.match(set.json.redirectUri, /\/sso\/callback$/);
  const shown = await api('GET', '/v1/integrations/oidc', { token: acme.admin });
  assert.equal(shown.json.clientSecret, 'set');
  assert.ok(!JSON.stringify(shown.json).includes(idp.clientSecret), 'the client secret was returned');
});

// ── signing in ────────────────────────────────────────────────────────────

test('a member signs in through the provider and gets a session', async () => {
  const r = await signIn({ email: 'dana@acme.test', sub: 'dana-sub' });
  assert.equal(r.status, 303);
  assert.equal(r.location, '/');
  const me = await api('GET', '/v1/me', { cookie: r.cookie });
  assert.equal(me.status, 200, me.text);
  assert.equal(me.json.label, 'dana@acme.test');
  assert.ok(hub.store.events(acme.org, 50).some((e) => e.action === 'auth.sso.login'));
});

test('someone the provider knows but the organization does not is turned away', async () => {
  const r = await signIn({ email: 'eve@acme.test' });
  assert.equal(r.location, '/login?e=sso_denied');
  assert.ok(hub.store.events(acme.org, 50).some((e) => e.action === 'auth.sso.refused' && e.actor === 'eve@acme.test'));
  const page = (await api('GET', '/login?e=sso_denied')).text;
  assert.match(page, /Ask an administrator to invite you/);
});

test('an email from another domain is refused even for a member', async () => {
  const auth = new Auth(hub.store);
  const outsider = auth.createUser({ email: 'sam@gmail.test' });
  auth.addMember(acme.org, outsider.id, 'operator');
  assert.equal((await signIn({ email: 'sam@gmail.test' })).location, '/login?e=sso_denied');
});

test('with provisioning on, a new person from an allowed domain joins with that role, never owner', async () => {
  await api('PUT', '/v1/integrations/oidc', {
    token: acme.admin,
    body: { issuer: idp.issuer, clientId: idp.clientId, clientSecret: idp.clientSecret, domains: ['acme.test'], autoProvision: 'auditor' },
  });
  const r = await signIn({ email: 'newhire@acme.test' });
  assert.equal(r.location, '/');
  const me = await api('GET', '/v1/me', { cookie: r.cookie });
  assert.deepEqual(me.json.scopes.sort(), ['approvals:read', 'logs:read', 'policies:read', 'receipts:read']);
});

// ── attacks ───────────────────────────────────────────────────────────────

test('a tampered or wrong ID token signs nobody in', async () => {
  const cases = {
    'another key signed it': () => { idp.signWith = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey; },
    'issued for another app': () => { idp.tamper = (c) => ({ ...c, aud: 'someone-else' }); },
    'expired': () => { idp.tamper = (c) => ({ ...c, exp: c.iat - 3600 }); },
    'nonce from another sign-in': () => { idp.tamper = (c) => ({ ...c, nonce: 'replayed' }); },
    'another issuer': () => { idp.tamper = (c) => ({ ...c, iss: 'https://evil.example' }); },
    'unverified email': () => { idp.tamper = (c) => ({ ...c, email_verified: false }); },
  };
  for (const [name, arrange] of Object.entries(cases)) {
    arrange();
    try {
      const r = await signIn({ email: 'dana@acme.test', sub: 'dana-sub' });
      assert.match(r.location ?? '', /^\/login\?e=sso/, name);
      assert.ok(!r.cookie.includes('pw_session'), `${name}: a session was issued`);
    } finally {
      idp.tamper = (c) => c;
      idp.signWith = null;
    }
  }
});

test("an unsigned token (alg: none) or an HMAC one is refused outright", () => {
  const claims = { iss: 'i', aud: 'a', sub: 's', nonce: 'n', iat: Date.now() / 1000, exp: Date.now() / 1000 + 60 };
  const jwks = { keys: [{ kty: 'oct', k: 'c2VjcmV0', kid: 'h' }] };
  for (const alg of ['none', 'HS256']) {
    assert.throws(() => verifyIdToken(jwt({ alg, kid: 'h' }, claims, null), { jwks, issuer: 'i', clientId: 'a', nonce: 'n' }), /not accepted/, alg);
  }
});

test('ES256 and EdDSA tokens verify as well as RS256', () => {
  const now = Date.now() / 1000;
  const claims = { iss: 'i', aud: 'a', sub: 's', nonce: 'n', iat: now, exp: now + 60 };
  const enc = (/** @type {any} */ o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  for (const [alg, type, opts, hash, sigOpts] of [
    ['ES256', 'ec', { namedCurve: 'P-256' }, 'sha256', { dsaEncoding: 'ieee-p1363' }],
    ['EdDSA', 'ed25519', {}, null, {}],
  ]) {
    const kp = generateKeyPairSync(/** @type {any} */ (type), /** @type {any} */ (opts));
    const data = `${enc({ alg, kid: 'x' })}.${enc(claims)}`;
    const sig = cryptoSign(/** @type {any} */ (hash), Buffer.from(data), { key: kp.privateKey, ...sigOpts }).toString('base64url');
    const jwks = { keys: [{ ...kp.publicKey.export({ format: 'jwk' }), kid: 'x' }] };
    assert.equal(verifyIdToken(`${data}.${sig}`, { jwks, issuer: 'i', clientId: 'a', nonce: 'n' }).sub, 's', alg);
  }
});

test('a callback is single use, and only completes in the browser that started it', async () => {
  // Someone else's sign-in, finished in your browser (login CSRF): refused.
  const foreign = await signIn({ email: 'dana@acme.test', sub: 'dana-sub', cookie: () => 'pw_sso=someone-elses-state' });
  assert.equal(foreign.location, '/login?e=sso');
  const none = await signIn({ email: 'dana@acme.test', sub: 'dana-sub', cookie: () => '' });
  assert.equal(none.location, '/login?e=sso');

  // A completed one, replayed. The provider is made to honour the same code
  // again, exactly as the first time, so only the hub's single-use state can
  // stop the second sign-in.
  const ok = await signIn({ email: 'dana@acme.test', sub: 'dana-sub' });
  assert.equal(ok.location, '/');
  idp.codes.set(ok.code, ok.grant);
  const again = await api('GET', `/sso/callback?code=${ok.code}&state=${encodeURIComponent(ok.state)}`, { cookie: ok.bound });
  assert.equal(again.headers.get('location'), '/login?e=sso');
});

test('an email address the provider has moved to a different account cannot take over the old one', async () => {
  // Dana is bound to subject "dana-sub". A different subject with her email is refused.
  const r = await signIn({ email: 'dana@acme.test', sub: 'someone-new' });
  assert.equal(r.location, '/login?e=sso_denied');
});

test('the provider rotating its signing key is followed without reconfiguring', async () => {
  rotateKey('k2');
  const r = await signIn({ email: 'dana@acme.test', sub: 'dana-sub' });
  assert.equal(r.location, '/');
});

test('when SSO is required, a password session loses the organization and an SSO one keeps it', async () => {
  const password = await fetch(base + '/login', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ email: 'dana@acme.test', password: 'dana-password-long-enough' }),
    redirect: 'manual',
  });
  const pwCookie = jar(password.headers);
  assert.equal((await api('GET', '/v1/me', { cookie: pwCookie })).status, 200);

  await api('PUT', '/v1/integrations/oidc', {
    token: acme.admin,
    body: { issuer: idp.issuer, clientId: idp.clientId, clientSecret: idp.clientSecret, domains: ['acme.test'], requireSso: true },
  });
  assert.equal((await api('GET', '/v1/me', { cookie: pwCookie })).status, 401, 'a password session still reached the org');

  const sso = await signIn({ email: 'dana@acme.test', sub: 'dana-sub' });
  assert.equal((await api('GET', '/v1/me', { cookie: sso.cookie })).status, 200);
  // Machines are unaffected.
  assert.equal((await api('GET', '/v1/me', { token: acme.admin })).status, 200);

  const html = (await api('GET', '/settings/integrations', { cookie: sso.cookie })).text;
  assert.match(html, /Single sign-on/);
  assert.match(html, /required/);
});

// ── the provider's address ────────────────────────────────────────────────

test('on a normal hub, an issuer on a private address or over plain HTTP is refused', async () => {
  const strict = new Hub({ database: ':memory:' });
  const at = (await strict.listen(0)).url.replace('0.0.0.0', '127.0.0.1');
  try {
    const org = strict.store.createOrg({ slug: 'x', name: 'x' });
    const token = new Auth(strict.store).createKey({ orgId: org.id, name: 'a', scopes: ['admin'] }).token;
    for (const issuer of [idp.issuer, 'https://127.0.0.1:1', 'https://169.254.169.254', 'https://[::1]:8443']) {
      const res = await fetch(`${at}/v1/integrations/oidc`, {
        method: 'PUT',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ issuer, clientId: 'c' }),
      });
      const json = await res.json();
      assert.equal(json.error.code, 'bad_issuer', issuer);
      assert.match(json.error.message, /not https|private address/, issuer);
    }
  } finally {
    await strict.close();
  }
  await assert.rejects(fetchJson('https://localhost:1/x'), /private address/);
  assert.equal(isPrivateAddress('8.8.8.8'), false);
  assert.equal(isPrivateAddress('169.254.169.254'), true);
  assert.equal(isPrivateAddress('::ffff:127.0.0.1'), true);
});
