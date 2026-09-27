import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import net from 'node:net';

/**
 * Outbound requests to addresses a tenant chose.
 *
 * Several features make the hub call a URL an organisation's admin typed in:
 * its identity provider, its witnesses, the places it streams events to. On a
 * hosted hub that is a server-side request forgery surface: a tenant naming
 * `http://169.254.169.254/` would be asking the hub to read its own cloud
 * credentials. So every such request goes through `guardedRequest`, which:
 *
 *   - requires https (plain http only when private addresses are allowed);
 *   - refuses private, loopback, link-local and reserved addresses at connect
 *     time, after DNS, so a name that rebinds between a check and the
 *     connection cannot slip past;
 *   - follows no redirects, times out, and caps what it reads.
 *
 * `allowPrivate` exists for tests and for a self-hosted hub whose services
 * are on its own network. A hosted hub never sets it.
 */

const MAX_BYTES = 1024 * 1024;

/**
 * Whether an IP address is somewhere a hub must not be made to reach on a
 * tenant's say-so.
 *
 * @param {string} ip
 */
export function isPrivateAddress(ip) {
  let a = ip.toLowerCase();
  if (a.startsWith('::ffff:')) a = a.slice(7); // IPv4-mapped IPv6
  if (net.isIPv4(a)) {
    const [b0, b1] = a.split('.').map(Number);
    return (
      b0 === 0 || b0 === 10 || b0 === 127 ||
      (b0 === 100 && b1 >= 64 && b1 <= 127) || // carrier-grade NAT
      (b0 === 169 && b1 === 254) ||            // link-local, cloud metadata
      (b0 === 172 && b1 >= 16 && b1 <= 31) ||
      (b0 === 192 && b1 === 168) ||
      (b0 === 192 && b1 === 0) ||
      (b0 === 198 && (b1 === 18 || b1 === 19)) ||
      b0 >= 224                                // multicast and reserved
    );
  }
  if (net.isIPv6(a)) {
    return (
      a === '::' || a === '::1' ||
      a.startsWith('fe8') || a.startsWith('fe9') || a.startsWith('fea') || a.startsWith('feb') || // fe80::/10
      a.startsWith('fc') || a.startsWith('fd') || // unique local
      a.startsWith('ff')                          // multicast
    );
  }
  return true;
}

/**
 * Why a URL may not be used as a destination, or null when it may. Checked
 * when an admin saves one, so a bad URL is refused at once rather than
 * failing quietly on every later send.
 *
 * @param {string} raw
 * @param {{ allowPrivate?: boolean }} [opts]
 * @returns {string | null}
 */
export function destinationProblem(raw, opts = {}) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    return 'is not a URL';
  }
  if (u.username || u.password) return 'must not carry credentials in the URL';
  if (u.protocol !== 'https:' && !(opts.allowPrivate && u.protocol === 'http:')) return 'must be https';
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host) && !opts.allowPrivate && isPrivateAddress(host)) return 'is a private address';
  if (!opts.allowPrivate && /^(localhost|.*\.localhost|.*\.internal|.*\.local)$/i.test(host)) return 'is a private address';
  return null;
}

/**
 * Make one request under the rules above.
 *
 * @param {string} url
 * @param {object} [opts]
 * @param {string} [opts.method]
 * @param {Record<string, string>} [opts.headers]
 * @param {string | Buffer} [opts.body]
 * @param {boolean} [opts.allowPrivate]
 * @param {number} [opts.timeoutMs]
 * @returns {Promise<{ status: number, text: string, json: any }>}  `json` is null when the body is not JSON.
 */
export function guardedRequest(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const problem = destinationProblem(url, opts);
    if (problem) return reject(new Error(`${url} ${problem}`));
    const u = new URL(url);
    const body = opts.body === undefined ? undefined : Buffer.from(opts.body);
    const client = u.protocol === 'https:' ? https : http;
    const req = client.request(
      u,
      {
        method: opts.method ?? (body ? 'POST' : 'GET'),
        headers: {
          ...(body ? { 'content-length': String(body.length) } : {}),
          ...(opts.headers ?? {}),
        },
        timeout: opts.timeoutMs ?? 10_000,
        lookup: (hostname, options, cb) => {
          dns.lookup(hostname, { ...options, all: false }, (err, address, family) => {
            if (err) return cb(err, address, family);
            if (!opts.allowPrivate && isPrivateAddress(String(address))) {
              return cb(new Error(`${hostname} resolves to a private address`), address, family);
            }
            cb(null, address, family);
          });
        },
      },
      (res) => {
        let size = 0;
        /** @type {Buffer[]} */
        const chunks = [];
        res.on('data', (c) => {
          size += c.length;
          if (size > MAX_BYTES) {
            req.destroy(new Error('response too large'));
            return;
          }
          chunks.push(c);
        });
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try {
            json = text ? JSON.parse(text) : null;
          } catch {
            // Not JSON; the caller decides whether that matters.
          }
          resolve({ status: res.statusCode ?? 0, text, json });
        });
        res.on('error', reject);
      },
    );
    req.on('timeout', () => req.destroy(new Error(`${u.origin} did not answer in time`)));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}
