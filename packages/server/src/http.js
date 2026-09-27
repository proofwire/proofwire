import { randomBytes } from 'node:crypto';
import { StoreError } from './store.js';

/**
 * A small HTTP layer: routing, body limits, rate limiting, and the one place
 * errors become responses.
 *
 * Hand-written rather than pulled from npm because this process holds other
 * companies' audit trails, and every dependency on this path is someone else's
 * code with the same access. The router is ~200 lines; a framework is tens of
 * thousands plus its tree.
 */

/** @typedef {import('node:http').IncomingMessage} Req */
/** @typedef {import('node:http').ServerResponse} Res */

/**
 * @typedef {object} Ctx
 * @property {Req} req
 * @property {Res} res
 * @property {URL} url
 * @property {Record<string,string>} params
 * @property {URLSearchParams} query
 * @property {any} body
 * @property {string|null} rawBody  A form body exactly as received; null otherwise.
 * @property {import('./auth.js').Principal|null} principal
 * @property {string} requestId
 * @property {import('./store.js').Store} store
 * @property {import('./auth.js').Auth} auth
 * @property {object} config
 */

export class Router {
  constructor() {
    /** @type {{ method: string, parts: string[], handler: Function, raw: string }[]} */
    this.routes = [];
  }

  /**
   * @param {string} method
   * @param {string} pattern  e.g. `/v1/logs/:log/receipts`
   * @param {(ctx: Ctx) => any} handler
   */
  add(method, pattern, handler) {
    this.routes.push({
      method,
      parts: pattern.split('/').filter(Boolean),
      handler,
      raw: pattern,
    });
    return this;
  }

  get(p, h) { return this.add('GET', p, h); }
  post(p, h) { return this.add('POST', p, h); }
  put(p, h) { return this.add('PUT', p, h); }
  patch(p, h) { return this.add('PATCH', p, h); }
  delete(p, h) { return this.add('DELETE', p, h); }

  /**
   * @param {string} method
   * @param {string} pathname
   * @returns {{ handler: Function, params: Record<string,string> }|null}
   */
  match(method, pathname) {
    const parts = pathname.split('/').filter(Boolean);
    /** @type {string[]} */
    const allowed = [];

    for (const route of this.routes) {
      if (route.parts.length !== parts.length) continue;

      /** @type {Record<string,string>} */
      const params = {};
      let ok = true;
      for (let i = 0; i < parts.length; i++) {
        const seg = route.parts[i];
        if (seg.startsWith(':')) {
          params[seg.slice(1)] = decodeURIComponent(parts[i]);
        } else if (seg !== parts[i]) {
          ok = false;
          break;
        }
      }
      if (!ok) continue;

      if (route.method === method) return { handler: route.handler, params };
      allowed.push(route.method);
    }

    // The path exists but not for this verb — a 405 with an Allow header is
    // far more useful to a client than a 404 that suggests a typo.
    if (allowed.length) {
      throw new StoreError(405, 'method_not_allowed', `try ${allowed.join(', ')}`, { allowed });
    }
    return null;
  }
}

/**
 * Token bucket, keyed by credential or address.
 *
 * Ingest is the hot path and the one an agent in a retry loop will hammer, so
 * the limiter has to be cheap: no timers, no sweeps on the request path, just
 * arithmetic against a stored timestamp.
 */
export class RateLimiter {
  /**
   * @param {object} opts
   * @param {number} opts.capacity   Burst size.
   * @param {number} opts.refillPerSec
   */
  constructor(opts) {
    this.capacity = opts.capacity;
    this.refill = opts.refillPerSec;
    /** @type {Map<string, { tokens: number, at: number }>} */
    this.buckets = new Map();
    this._lastSweep = Date.now();
  }

  /**
   * @param {string} key
   * @param {number} [cost]
   * @returns {{ ok: boolean, remaining: number, retryAfter: number }}
   */
  take(key, cost = 1) {
    const nowMs = Date.now();

    // Amortised cleanup: a full bucket is indistinguishable from an absent
    // one, so idle entries can be dropped without affecting any decision.
    if (nowMs - this._lastSweep > 60_000) {
      for (const [k, b] of this.buckets) {
        if (b.tokens + ((nowMs - b.at) / 1000) * this.refill >= this.capacity) {
          this.buckets.delete(k);
        }
      }
      this._lastSweep = nowMs;
    }

    const bucket = this.buckets.get(key) ?? { tokens: this.capacity, at: nowMs };
    const elapsed = (nowMs - bucket.at) / 1000;
    const tokens = Math.min(this.capacity, bucket.tokens + elapsed * this.refill);

    if (tokens < cost) {
      this.buckets.set(key, { tokens, at: nowMs });
      return {
        ok: false,
        remaining: 0,
        retryAfter: Math.ceil((cost - tokens) / this.refill),
      };
    }

    this.buckets.set(key, { tokens: tokens - cost, at: nowMs });
    return { ok: true, remaining: Math.floor(tokens - cost), retryAfter: 0 };
  }

  /**
   * Whether `take` would succeed, without spending anything.
   *
   * @param {string} key
   * @param {number} [cost]
   * @returns {{ ok: boolean, retryAfter: number }}
   */
  peek(key, cost = 1) {
    const bucket = this.buckets.get(key);
    if (!bucket) return { ok: true, retryAfter: 0 };
    const tokens = Math.min(this.capacity, bucket.tokens + ((Date.now() - bucket.at) / 1000) * this.refill);
    return tokens >= cost
      ? { ok: true, retryAfter: 0 }
      : { ok: false, retryAfter: Math.ceil((cost - tokens) / this.refill) };
  }
}

/**
 * Read and parse a JSON body with a hard ceiling.
 *
 * The limit is enforced as bytes arrive rather than after buffering, so an
 * oversized upload is cut off instead of being absorbed and then rejected.
 *
 * @param {Req} req
 * @param {number} maxBytes
 * @returns {Promise<any>}
 */
export function readJson(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length'] ?? 0);
    if (declared > maxBytes) {
      reject(new StoreError(413, 'payload_too_large', `body exceeds ${maxBytes} bytes`));
      return;
    }

    /** @type {Buffer[]} */
    const chunks = [];
    let total = 0;

    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new StoreError(413, 'payload_too_large', `body exceeds ${maxBytes} bytes`));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('error', reject);
    req.on('end', () => {
      if (total === 0) return resolve(null);
      const text = Buffer.concat(chunks).toString('utf8');
      try {
        resolve(JSON.parse(text));
      } catch (err) {
        reject(new StoreError(400, 'malformed_json', `body is not valid JSON: ${err.message}`));
      }
    });
  });
}

/**
 * Read a body in whichever of the two encodings the client used.
 *
 * The console posts real HTML forms, which send `application/x-www-form-
 * urlencoded`; the API sends JSON. Handling both here keeps every route
 * handler reading from one `ctx.body` regardless of who called it.
 *
 * A form body also comes back as the exact text received, for the one kind of
 * caller that needs it: a signature (Slack's) computed over the raw bytes.
 * Re-serialising the parsed fields would not reproduce them.
 *
 * @param {Req} req
 * @param {number} maxBytes
 * @returns {Promise<{ body: any, raw: string | null }>}
 */
export async function readBody(req, maxBytes) {
  const type = String(req.headers['content-type'] ?? '');
  if (type.includes('application/x-www-form-urlencoded')) {
    const text = await readText(req, maxBytes);
    return { body: Object.fromEntries(new URLSearchParams(text)), raw: text };
  }
  return { body: await readJson(req, maxBytes), raw: null };
}

/**
 * @param {Req} req
 * @param {number} maxBytes
 * @returns {Promise<string>}
 */
function readText(req, maxBytes) {
  return new Promise((resolve, reject) => {
    /** @type {Buffer[]} */
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new StoreError(413, 'payload_too_large', `body exceeds ${maxBytes} bytes`));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('error', reject);
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

/**
 * @param {Res} res
 * @param {string} location
 * @param {string[]} [cookies]
 */
export function redirect(res, location, cookies) {
  const headers = { location };
  if (cookies?.length) headers['set-cookie'] = cookies;
  res.writeHead(303, headers);
  res.end();
}

/**
 * @param {Res} res
 * @param {number} status
 * @param {unknown} body
 * @param {Record<string,string>} [headers]
 */
export function sendJson(res, status, body, headers = {}) {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    ...headers,
  });
  res.end(text);
}

/**
 * @param {Res} res
 * @param {number} status
 * @param {string} html
 * @param {Record<string,string>} [headers]
 */
export function sendHtml(res, status, html, headers = {}) {
  const body = Buffer.from(html, 'utf8');
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'content-length': body.length,
    // The console renders customer-supplied strings (tool names, principals,
    // policy reasons). Everything is escaped at the template, and this is the
    // second line of defence if one ever is not.
    'content-security-policy':
      "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'",
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'same-origin',
    ...headers,
  });
  res.end(body);
}

/**
 * Parse a cookie header into a map.
 *
 * @param {string|undefined} header
 * @returns {Record<string,string>}
 */
export function parseCookies(header) {
  // A Map, not an object: a cookie named `__proto__` or `constructor` is
  // just a cookie, never a property of anything.
  /** @type {Map<string, string>} */
  const out = new Map();
  if (!header) return out;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 1) continue;
    let value;
    try {
      value = decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      continue; // A malformed %-escape is a broken cookie, not a 500.
    }
    out.set(part.slice(0, eq).trim(), value);
  }
  return out;
}

/**
 * The client's address, honouring a proxy header only when configured to.
 *
 * Trusting `x-forwarded-for` unconditionally would let any caller spoof their
 * way past a per-address rate limit by inventing a header.
 *
 * @param {Req} req
 * @param {boolean} trustProxy
 * @returns {string}
 */
export function clientAddress(req, trustProxy) {
  if (trustProxy) {
    const fwd = req.headers['x-forwarded-for'];
    if (typeof fwd === 'string' && fwd.length) return fwd.split(',')[0].trim();
  }
  return req.socket.remoteAddress ?? 'unknown';
}

/** @returns {string} */
export function newRequestId() {
  return 'req_' + randomBytes(8).toString('hex');
}

/**
 * Turn any thrown value into a response.
 *
 * Only `StoreError` messages reach the client. Anything else becomes a generic
 * 500 with a request id — an unexpected exception's message is as likely to
 * contain a file path or a fragment of someone's data as anything useful.
 *
 * @param {unknown} err
 * @param {string} requestId
 * @returns {{ status: number, body: object, internal: Error|null }}
 */
export function errorResponse(err, requestId) {
  if (err instanceof StoreError) {
    return {
      status: err.status,
      body: {
        error: { code: err.code, message: err.message, ...(err.detail ? { detail: err.detail } : {}) },
        requestId,
      },
      internal: null,
    };
  }
  return {
    status: 500,
    body: {
      error: {
        code: 'internal_error',
        message: 'the request could not be completed; quote the request id if you report this',
      },
      requestId,
    },
    internal: /** @type {Error} */ (err),
  };
}
