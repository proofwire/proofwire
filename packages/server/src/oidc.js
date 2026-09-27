import { guardedRequest } from './egress.js';
import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify, constants } from 'node:crypto';

/**
 * Single sign-on with OpenID Connect: the authorization code flow with PKCE.
 *
 * The hub talks to the identity provider an organisation's admin named, which
 * on a hosted hub means a URL chosen by a tenant. So every request here goes
 * through `fetchJson`, which refuses private, loopback and link-local
 * addresses at connect time (after DNS, so a rebinding name can't slip past a
 * check done earlier), follows no redirects, and caps what it reads.
 *
 * ID tokens are verified in full: signature against the provider's published
 * keys (asymmetric algorithms only; `none` and HMAC are refused), issuer,
 * audience, authorized party, expiry, issued-at and nonce.
 */

export { isPrivateAddress } from './egress.js';

/**
 * GET or POST, and parse the JSON reply, under the egress rules in egress.js:
 * https only, no private addresses (checked after DNS), no redirects, capped.
 *
 * @param {string} url
 * @param {object} [opts]
 * @param {boolean} [opts.allowPrivate]  Tests and self-hosted setups whose IdP is on the LAN.
 * @param {Record<string, string>} [opts.form]  Sent as application/x-www-form-urlencoded.
 * @param {Record<string, string>} [opts.headers]
 * @param {number} [opts.timeoutMs]
 * @returns {Promise<{ status: number, json: any }>}
 */
export async function fetchJson(url, opts = {}) {
  /** @type {URL} */
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`not a URL: ${url}`);
  }
  const origin = parsed.origin;
  const body = opts.form ? new URLSearchParams(opts.form).toString() : undefined;
  let res;
  try {
    res = await guardedRequest(url, {
      method: body ? 'POST' : 'GET',
      body,
      allowPrivate: opts.allowPrivate,
      timeoutMs: opts.timeoutMs,
      headers: {
        accept: 'application/json',
        ...(body ? { 'content-type': 'application/x-www-form-urlencoded' } : {}),
        ...(opts.headers ?? {}),
      },
    });
  } catch (err) {
    // Keep the wording callers and their tests already rely on.
    const m = /** @type {Error} */ (err).message;
    if (m.endsWith(' must be https')) throw new Error(`${origin} is not https`);
    if (m.endsWith(' is a private address')) throw new Error(`${parsed.hostname.replace(/^\[|\]$/g, '')} is a private address`);
    throw err;
  }
  if (res.text && res.json === null) {
    throw new Error(`${origin} did not answer with JSON (HTTP ${res.status})`);
  }
  return { status: res.status, json: res.json };
}

/**
 * The provider's configuration, from its discovery document.
 *
 * @param {string} issuer
 * @param {{ allowPrivate?: boolean }} [opts]
 * @returns {Promise<{ issuer: string, authorization_endpoint: string, token_endpoint: string, jwks_uri: string, token_endpoint_auth_methods_supported?: string[] }>}
 */
export async function discover(issuer, opts = {}) {
  const base = issuer.replace(/\/+$/, '');
  const { status, json } = await fetchJson(`${base}/.well-known/openid-configuration`, opts);
  if (status !== 200 || !json) throw new Error(`discovery returned HTTP ${status}`);
  // OpenID Connect Discovery 1.0, section 4.3: the issuer in the document must
  // be exactly the one asked about. Otherwise one provider can impersonate
  // another's tokens.
  if (json.issuer !== issuer) {
    throw new Error(`the provider says its issuer is "${json.issuer}", not "${issuer}"`);
  }
  for (const k of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
    if (typeof json[k] !== 'string') throw new Error(`discovery document has no ${k}`);
    const p = new URL(json[k]).protocol;
    if (p !== 'https:' && !(opts.allowPrivate && p === 'http:')) throw new Error(`${k} is not https`);
  }
  return json;
}

/** @param {string} s */
function b64urlJson(s) {
  return JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
}

/** Asymmetric algorithms only: with HMAC, anyone holding the client secret could mint tokens. */
const ALGS = {
  RS256: (/** @type {any} */ key) => ({ hash: 'sha256', key }),
  RS384: (/** @type {any} */ key) => ({ hash: 'sha384', key }),
  RS512: (/** @type {any} */ key) => ({ hash: 'sha512', key }),
  PS256: (/** @type {any} */ key) => ({ hash: 'sha256', key: { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 } }),
  ES256: (/** @type {any} */ key) => ({ hash: 'sha256', key: { key, dsaEncoding: 'ieee-p1363' } }),
  ES384: (/** @type {any} */ key) => ({ hash: 'sha384', key: { key, dsaEncoding: 'ieee-p1363' } }),
  EdDSA: (/** @type {any} */ key) => ({ hash: null, key }),
};

/**
 * Verify an ID token and return its claims, or throw saying why not.
 *
 * @param {string} token
 * @param {object} expect
 * @param {{ keys: any[] }} expect.jwks
 * @param {string} expect.issuer
 * @param {string} expect.clientId
 * @param {string} expect.nonce
 * @param {number} [expect.nowMs]
 * @param {number} [expect.skewSeconds]
 */
export function verifyIdToken(token, expect) {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new Error('not a signed JWT');
  let header;
  let claims;
  try {
    header = b64urlJson(parts[0]);
    claims = b64urlJson(parts[1]);
  } catch {
    throw new Error('malformed token');
  }

  const alg = ALGS[/** @type {keyof typeof ALGS} */ (header.alg)];
  if (!alg) throw new Error(`algorithm "${header.alg}" is not accepted`);

  const candidates = (expect.jwks.keys ?? []).filter(
    (k) => (!header.kid || k.kid === header.kid) && (!k.use || k.use === 'sig') && (!k.alg || k.alg === header.alg),
  );
  if (candidates.length !== 1) {
    throw new Error(header.kid ? `no signing key "${header.kid}" published by the provider` : 'cannot tell which key signed this');
  }
  let key;
  try {
    key = createPublicKey({ key: candidates[0], format: 'jwk' });
  } catch {
    throw new Error('the provider published a key that is not usable');
  }
  if (key.type !== 'public') throw new Error('the provider published a key that is not a public key');

  const { hash, key: verifyKey } = alg(key);
  const ok = verify(hash, Buffer.from(`${parts[0]}.${parts[1]}`), verifyKey, Buffer.from(parts[2], 'base64url'));
  if (!ok) throw new Error('signature does not verify');

  const now = (expect.nowMs ?? Date.now()) / 1000;
  const skew = expect.skewSeconds ?? 120;
  if (claims.iss !== expect.issuer) throw new Error(`issued by "${claims.iss}", not "${expect.issuer}"`);
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(expect.clientId)) throw new Error('not issued for this application');
  if (aud.length > 1 && claims.azp !== expect.clientId) throw new Error('issued to several parties, and not authorised for this one');
  if (typeof claims.exp !== 'number' || claims.exp < now - skew) throw new Error('expired');
  if (typeof claims.iat !== 'number' || claims.iat > now + skew) throw new Error('issued in the future');
  if (typeof claims.nbf === 'number' && claims.nbf > now + skew) throw new Error('not valid yet');
  if (typeof claims.sub !== 'string' || !claims.sub) throw new Error('no subject');
  const a = Buffer.from(String(claims.nonce ?? ''));
  const b = Buffer.from(expect.nonce);
  if (a.length !== b.length || !timingSafeEqual(a, b)) throw new Error('nonce does not match this sign-in');
  return claims;
}

/** A PKCE pair: the verifier stays here, the S256 challenge goes to the provider. */
export function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}
