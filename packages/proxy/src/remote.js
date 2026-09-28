/**
 * Ships locally-signed receipts to a Vouchwell hub.
 *
 * The local log stays the source of truth and the hub is a replica. That
 * ordering is the whole design: receipts are signed and durable on disk before
 * anything is sent, so a hub that is down, slow, or compromised can delay the
 * evidence but never prevent it or alter it. An agent runtime that could not
 * act while the audit service was unreachable would be removed from production
 * the first time the audit service had an outage.
 *
 * Failure handling, in order of how often each actually happens:
 *
 *   network error / 5xx   retry with backoff, keep the queue, keep running
 *   sequence_gap          the hub is behind or ahead; resync and replay
 *   429                   honour Retry-After
 *   422 receipt_rejected  a receipt the hub will never accept — stop and shout,
 *                         because silently dropping it defeats the point
 */

/**
 * Drop trailing slashes from a URL. A loop rather than a `/+$` regex, which
 * backtracks quadratically on a long run of slashes followed by anything else.
 *
 * @param {string} s
 * @returns {string}
 */
export function trimSlashes(s) {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 47) end--;
  return s.slice(0, end);
}

const DEFAULT_FLUSH_MS = 2000;
const DEFAULT_BATCH = 200;

export class RemoteSink {
  /**
   * @param {object} opts
   * @param {string} opts.url       Hub base URL.
   * @param {string} opts.token     API key with `receipts:write`.
   * @param {string} opts.log       Log slug.
   * @param {import('@vouchwell/core').ProofLog} opts.localLog
   * @param {number} [opts.flushMs]
   * @param {number} [opts.batchSize]
   * @param {(level: string, msg: string) => void} [opts.onLog]
   */
  constructor(opts) {
    this.url = trimSlashes(opts.url);
    this.token = opts.token;
    this.log = opts.log;
    this.localLog = opts.localLog;
    this.flushMs = opts.flushMs ?? DEFAULT_FLUSH_MS;
    this.batchSize = opts.batchSize ?? DEFAULT_BATCH;
    this.onLog = opts.onLog ?? (() => {});

    /** Next local sequence number the hub has not confirmed. */
    this.cursor = 0;
    this.started = false;
    this.stopped = false;
    this.failures = 0;
    this.shipped = 0;
    /** @type {Error|null} */
    this.lastError = null;
    /** Set when the hub has rejected a receipt it will never take. */
    this.fatal = false;
  }

  /**
   * @param {string} path
   * @param {object} [init]
   */
  async _fetch(path, init = {}) {
    const res = await fetch(this.url + path, {
      ...init,
      headers: {
        authorization: `Bearer ${this.token}`,
        ...(init.body ? { 'content-type': 'application/json' } : {}),
        ...(init.headers ?? {}),
      },
      signal: AbortSignal.timeout(20_000),
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* non-JSON error page */ }
    return { status: res.status, json, text, headers: res.headers };
  }

  /**
   * Register this log with the hub, then find out how much of it the hub
   * already holds.
   *
   * @returns {Promise<boolean>} Whether the hub is usable.
   */
  async connect() {
    try {
      const reg = await this._fetch('/v1/logs', {
        method: 'POST',
        body: JSON.stringify({
          slug: this.log,
          // The agent's receipts are signed with *this* identifier in their
          // `log` field, so the hub has to bind to it. The slug above is only
          // the name humans will see in the console.
          canonical: this.localLog.logId,
          kid: this.localLog.identity.kid,
          publicKey: this.localLog.identity.publicKey,
        }),
      });

      if (reg.status === 409 && reg.json?.error?.code === 'log_key_mismatch') {
        this.fatal = true;
        this.lastError = new Error(reg.json.error.message);
        this.onLog(
          'error',
          `the hub has a log named "${this.log}" bound to a different key. ` +
            `Use a different --log name, or rotate on the hub.`,
        );
        return false;
      }
      if (reg.status !== 200) {
        throw new Error(`register failed: ${reg.status} ${reg.json?.error?.message ?? reg.text}`);
      }

      const head = await this._fetch(`/v1/logs/${encodeURIComponent(this.log)}/head`);
      if (head.status !== 200) throw new Error(`head failed: ${head.status}`);

      this.cursor = head.json.size;
      this.started = true;
      this.onLog(
        'info',
        `hub ${this.url} holds ${head.json.size} of ${this.localLog.size} entries`,
      );
      return true;
    } catch (err) {
      this.lastError = /** @type {Error} */ (err);
      this.onLog('warn', `hub unreachable (${err.message}); recording locally and retrying`);
      return false;
    }
  }

  /**
   * Push everything the hub has not confirmed. Safe to call concurrently: a
   * second call while one is in flight returns immediately.
   *
   * @returns {Promise<number>} Receipts accepted in this call.
   */
  async flush() {
    if (this._inFlight || this.fatal || this.stopped) return 0;
    this._inFlight = true;
    let sent = 0;

    try {
      while (this.cursor < this.localLog.size) {
        const slice = this.localLog.entries.slice(this.cursor, this.cursor + this.batchSize);
        if (slice.length === 0) break;

        // A stable batch id derived from what is in it, so a retry after a
        // timeout is recognised as the same submission rather than replayed.
        const batchId = `b_${this.log}_${slice[0].seq}_${slice.length}_${this._salt(slice)}`;

        const res = await this._fetch(`/v1/logs/${encodeURIComponent(this.log)}/receipts`, {
          method: 'POST',
          body: JSON.stringify({ receipts: slice, batchId }),
        });

        if (res.status === 200) {
          this.cursor = res.json.size;
          this.shipped += res.json.accepted;
          sent += res.json.accepted;
          this.failures = 0;
          this.lastError = null;
          continue;
        }

        if (res.status === 409 && res.json?.error?.code === 'sequence_gap') {
          // The hub and we disagree about where the log is. The hub is
          // authoritative about what it has accepted, so trust its number and
          // replay from there.
          const expected = res.json.error.detail?.expected;
          if (Number.isInteger(expected) && expected !== this.cursor) {
            this.onLog('warn', `resyncing to hub sequence ${expected} (was at ${this.cursor})`);
            this.cursor = expected;
            continue;
          }
          throw new Error(res.json.error.message);
        }

        if (res.status === 429) {
          const wait = Number(res.headers.get('retry-after') ?? 2) * 1000;
          this.onLog('warn', `hub rate limited; pausing ${wait}ms`);
          await sleep(wait);
          continue;
        }

        if (res.status === 422 || res.status === 403 || res.status === 401) {
          // Not retryable. Keep the receipts locally, stop shipping, and make
          // sure a human hears about it — a silently detached replica is the
          // one failure that would leave someone believing they had an audit
          // trail on the hub when they did not.
          this.fatal = true;
          this.lastError = new Error(res.json?.error?.message ?? res.text);
          this.onLog(
            'error',
            `hub refused receipts permanently: ${this.lastError.message}. ` +
              `Local log is intact; run \`vw push\` after fixing this.`,
          );
          return sent;
        }

        throw new Error(`hub returned ${res.status}: ${res.json?.error?.message ?? res.text}`);
      }
    } catch (err) {
      this.failures++;
      this.lastError = /** @type {Error} */ (err);
      this.onLog('warn', `flush failed (attempt ${this.failures}): ${err.message}`);
    } finally {
      this._inFlight = false;
    }

    return sent;
  }

  /**
   * A short digest of a batch, so the same receipts always produce the same
   * batch id and a different set never does.
   *
   * @param {import('@vouchwell/core').Receipt[]} slice
   */
  _salt(slice) {
    return slice[slice.length - 1].attest.sig.slice(0, 16).replace(/[^A-Za-z0-9]/g, '');
  }

  /** Begin periodic flushing with exponential backoff on failure. */
  start() {
    const tick = async () => {
      if (this.stopped) return;
      await this.flush();
      // Back off to at most a minute, so a long hub outage does not turn into
      // a retry storm the moment it comes back.
      const delay = this.failures === 0
        ? this.flushMs
        : Math.min(this.flushMs * 2 ** Math.min(this.failures, 5), 60_000);
      this._timer = setTimeout(tick, delay);
      this._timer.unref?.();
    };
    this._timer = setTimeout(tick, this.flushMs);
    this._timer.unref?.();
  }

  /**
   * Flush what remains and stop. Called on shutdown, where getting the last
   * few receipts off the box matters more than anywhere else.
   *
   * @param {number} [graceMs]
   */
  async stop(graceMs = 10_000) {
    clearTimeout(this._timer);
    const deadline = Date.now() + graceMs;
    while (this.cursor < this.localLog.size && Date.now() < deadline && !this.fatal) {
      const before = this.cursor;
      await this.flush();
      if (this.cursor === before) break;
    }
    this.stopped = true;

    const behind = this.localLog.size - this.cursor;
    if (behind > 0) {
      this.onLog(
        'warn',
        `${behind} receipt(s) never reached the hub. They are safe in the local log; ` +
          `run \`vw push\` to ship them.`,
      );
    }
    return behind;
  }

  /** @returns {object} */
  status() {
    return {
      url: this.url,
      log: this.log,
      shipped: this.shipped,
      behind: Math.max(0, this.localLog.size - this.cursor),
      failures: this.failures,
      fatal: this.fatal,
      lastError: this.lastError?.message ?? null,
    };
  }
}

/**
 * Resolve an escalation through the hub's approvals inbox.
 *
 * Returns the same shape as the local approvers, and keeps their contract: an
 * escalation that cannot be resolved — hub unreachable, nobody answered before
 * the deadline — is a denial, never a default approval.
 *
 * @param {object} opts
 * @param {string} opts.url
 * @param {string} opts.token
 * @param {string} opts.log
 * @param {number} [opts.timeoutMs]
 * @returns {(req: any) => Promise<{approved: boolean, by: string, note?: string}>}
 */
export function hubApprover(opts) {
  const base = trimSlashes(opts.url);
  const timeoutMs = opts.timeoutMs ?? 300_000;

  return async (req) => {
    const headers = { authorization: `Bearer ${opts.token}`, 'content-type': 'application/json' };
    try {
      const created = await fetch(`${base}/v1/approvals`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          log: opts.log,
          target: req.target,
          params: req.params,
          reason: req.reason,
          rules: req.rules,
          principal: req.actor.principal,
          agent: req.actor.agent,
          session: req.actor.session,
        }),
        signal: AbortSignal.timeout(15_000),
      });
      if (!created.ok) {
        return {
          approved: false,
          by: 'policy:approver-error',
          note: `the approvals service returned HTTP ${created.status}`,
        };
      }
      const { id } = await created.json();
      const deadline = Date.now() + timeoutMs;

      // Long-poll in hops rather than a tight poll, so the hub can wake us the
      // instant someone clicks. Each hop is capped by the time actually left:
      // a caller who asked to wait two seconds must not be held for thirty
      // because that happens to be the server's maximum.
      while (Date.now() < deadline) {
        const remaining = Math.max(1, Math.ceil((deadline - Date.now()) / 1000));
        const hop = Math.min(30, remaining);
        const res = await fetch(`${base}/v1/approvals/${id}?wait=${hop}`, {
          headers,
          signal: AbortSignal.timeout((hop + 10) * 1000),
        });
        if (!res.ok) break;
        const state = await res.json();
        if (state.status === 'approved') {
          return { approved: true, by: state.decidedBy ?? 'hub', note: state.note || 'approved in the console' };
        }
        if (state.status === 'denied') {
          return { approved: false, by: state.decidedBy ?? 'hub', note: state.note || 'declined in the console' };
        }
        if (state.status === 'expired') {
          return { approved: false, by: 'policy:timeout', note: 'nobody answered before the request expired' };
        }
      }
      return { approved: false, by: 'policy:timeout', note: 'no decision before the deadline' };
    } catch (err) {
      return {
        approved: false,
        by: 'policy:approver-unreachable',
        note: `could not reach the approvals service: ${/** @type {Error} */ (err).message}`,
      };
    }
  };
}

/**
 * Fetch the active policy from the hub.
 *
 * @param {object} opts
 * @param {string} opts.url
 * @param {string} opts.token
 * @param {string} opts.slug
 * @returns {Promise<{ policy: object, version: number, hash: string }|null>}
 */
export async function fetchPolicy(opts) {
  const base = trimSlashes(opts.url);
  const res = await fetch(`${base}/v1/policies/${encodeURIComponent(opts.slug)}`, {
    headers: { authorization: `Bearer ${opts.token}` },
    signal: AbortSignal.timeout(15_000),
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`could not fetch policy "${opts.slug}": HTTP ${res.status}`);
  return res.json();
}

/** @param {number} ms */
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
