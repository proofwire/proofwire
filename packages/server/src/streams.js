import { createHmac, randomBytes } from 'node:crypto';
import { guardedRequest, destinationProblem } from './egress.js';
import { StoreError } from './store.js';

/**
 * Streaming an organisation's events to the tools its security team already
 * watches: a signed webhook, Splunk (HTTP Event Collector), Datadog Logs, or
 * anything that takes OpenTelemetry logs over HTTP.
 *
 * Two kinds of event go out:
 *
 *   - `receipt`: what an agent did, or tried to, and what policy decided. The
 *     action's parameters and result are never streamed, only the facts a
 *     detection rule needs (who, what tool, which outcome, which rule).
 *   - `audit`: the hub's own control-plane trail (keys issued, policies
 *     pushed, approvals decided, a witness refusing a checkpoint).
 *
 * Delivery is at least once and survives restarts and outages. Receipts and
 * audit events are already durable in the database, so each destination is
 * only a cursor into them: a batch is sent, and only once the destination
 * accepts it does the cursor move. A destination that is down builds up a
 * backlog in place, not in memory, and catches up when it comes back.
 * Sending never happens on the ingest path, so a slow SIEM can't slow agents.
 */

export const STREAM_TYPES = ['webhook', 'splunk', 'datadog', 'otlp'];
const MAX_DESTINATIONS = 5;
const BATCH = 200;
const MAX_BACKOFF_MS = 5 * 60_000;
const NAME = /^[a-z0-9][a-z0-9-]{0,31}$/;
/** Headers an OTLP collector commonly wants (auth, tenancy); never ones that frame the request. */
const HEADER_NAME = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;
const RESERVED_HEADERS = new Set(['host', 'content-length', 'content-type', 'transfer-encoding', 'connection']);

/**
 * @typedef {object} Destination
 * @property {string} name
 * @property {'webhook'|'splunk'|'datadog'|'otlp'} type
 * @property {string} url
 * @property {string} [token]     Splunk HEC token, or Datadog API key.
 * @property {string} [secret]    Webhook signing secret.
 * @property {Record<string, string>} [headers]  OTLP only.
 * @property {'all'|'blocked'|'none'} receipts  `blocked`: denied and escalated only.
 * @property {boolean} audit
 */

/**
 * Check and normalise the destinations an admin sent. A destination that
 * keeps its name, type and URL may leave out its credentials to keep the old
 * ones, so changing a filter doesn't mean pasting a token again.
 *
 * @param {unknown} input
 * @param {Destination[]} previous
 * @param {{ allowPrivate: boolean }} opts
 * @returns {{ destinations: Destination[], generated: Record<string, string> }}
 *   `generated`: webhook secrets made here, to be shown once.
 */
export function parseDestinations(input, previous, opts) {
  if (!Array.isArray(input)) throw new StoreError(400, 'bad_destinations', 'body must be { destinations: [...] }');
  if (input.length > MAX_DESTINATIONS) {
    throw new StoreError(400, 'too_many_destinations', `at most ${MAX_DESTINATIONS} destinations`);
  }
  /** @type {Destination[]} */
  const out = [];
  /** @type {Record<string, string>} */
  const generated = {};
  const seen = new Set();
  for (const raw of input) {
    const d = /** @type {any} */ (raw ?? {});
    const name = String(d.name ?? '');
    if (!NAME.test(name) || seen.has(name)) {
      throw new StoreError(400, 'bad_destination_name', `"${name}": names are unique, lowercase letters, digits and dashes`);
    }
    seen.add(name);
    const type = String(d.type ?? '');
    if (!STREAM_TYPES.includes(type)) {
      throw new StoreError(400, 'bad_destination_type', `${name}: type must be one of ${STREAM_TYPES.join(', ')}`);
    }
    const url = String(d.url ?? (type === 'datadog' ? 'https://http-intake.logs.datadoghq.com' : ''));
    const problem = destinationProblem(url, opts);
    if (problem) throw new StoreError(400, 'bad_destination_url', `${name}: url ${problem}`);

    const receipts = d.receipts ?? 'all';
    if (!['all', 'blocked', 'none'].includes(receipts)) {
      throw new StoreError(400, 'bad_destination_filter', `${name}: receipts must be all, blocked or none`);
    }
    // Credentials are write-only. Left out, they are kept, but only for the
    // same destination at the same URL, so they can't be redirected elsewhere
    // by anyone who can edit this list.
    const prior = previous.find((p) => p.name === name && p.type === type && p.url === url);

    /** @type {Destination} */
    const dest = { name, type: /** @type {any} */ (type), url, receipts, audit: d.audit !== false };
    if (type === 'splunk' || type === 'datadog') {
      const token = d.token === undefined ? prior?.token : String(d.token);
      if (!token || /[\r\n]/.test(token)) {
        throw new StoreError(400, 'missing_token', `${name}: token is required (${type === 'splunk' ? 'the HEC token' : 'a Datadog API key'})`);
      }
      dest.token = token;
    }
    if (type === 'webhook') {
      let secret = d.secret === undefined ? prior?.secret : String(d.secret);
      if (secret === undefined) {
        secret = `whsec_${randomBytes(24).toString('base64url')}`;
        generated[name] = secret;
      }
      if (secret.length < 16) throw new StoreError(400, 'weak_secret', `${name}: secret must be at least 16 characters`);
      dest.secret = secret;
    }
    if (type === 'otlp') {
      const headers = d.headers === undefined ? prior?.headers ?? {} : d.headers;
      if (typeof headers !== 'object' || headers === null || Array.isArray(headers) || Object.keys(headers).length > 10) {
        throw new StoreError(400, 'bad_headers', `${name}: headers must be an object of at most 10 entries`);
      }
      /** @type {Record<string, string>} */
      const clean = {};
      for (const [k, v] of Object.entries(headers)) {
        if (!HEADER_NAME.test(k) || RESERVED_HEADERS.has(k.toLowerCase()) || typeof v !== 'string' || /[\r\n]/.test(v) || v.length > 4096) {
          throw new StoreError(400, 'bad_headers', `${name}: header "${k}" is not allowed`);
        }
        clean[k] = v;
      }
      dest.headers = clean;
    }
    out.push(dest);
  }
  return { destinations: out, generated };
}

/**
 * What an admin may see of a destination: where it points and what it
 * sends, never its credentials.
 *
 * @param {Destination} d
 */
export function describeDestination(d) {
  return {
    name: d.name,
    type: d.type,
    host: new URL(d.url).host,
    receipts: d.receipts,
    audit: d.audit,
    ...(d.token ? { token: 'set' } : {}),
    ...(d.secret ? { secret: 'set' } : {}),
    ...(d.headers ? { headers: Object.keys(d.headers) } : {}),
  };
}

// ── event shapes ────────────────────────────────────────────────────────

/**
 * @typedef {{ type: 'receipt'|'audit'|'test', id: string, time: string, org: string, [k: string]: unknown }} StreamEvent
 */

/** @param {any} row @param {string} org @returns {StreamEvent} */
function receiptEvent(row, org) {
  let decision = {};
  try {
    decision = JSON.parse(row.body)?.decision ?? {};
  } catch {
    // A pruned receipt has no body; its columns still say what happened.
  }
  const d = /** @type {any} */ (decision);
  return {
    type: 'receipt',
    id: `${row.log_slug}:${row.seq}`,
    time: row.ts,
    org,
    log: row.log_slug,
    seq: row.seq,
    hash: row.hash,
    ...(row.ref ? { ref: row.ref } : {}),
    phase: row.phase,
    kind: row.kind,
    target: row.target,
    outcome: row.outcome,
    agent: row.agent,
    principal: row.principal,
    session: row.session,
    ...(row.status ? { status: row.status } : {}),
    ...(row.latency_ms !== null && row.latency_ms !== undefined ? { latencyMs: row.latency_ms } : {}),
    ...(Array.isArray(d.rules) && d.rules.length ? { rules: d.rules.map(String) } : {}),
    ...(typeof d.reason === 'string' ? { reason: d.reason } : {}),
    ...(typeof d.policy === 'string' ? { policy: d.policy } : {}),
  };
}

/** @param {any} row @param {string} org @returns {StreamEvent} */
function auditEvent(row, org) {
  let meta = {};
  try {
    meta = JSON.parse(row.meta);
  } catch {
    // Stored by this hub, so always JSON; an empty object if not.
  }
  return {
    type: 'audit',
    id: `audit:${row.seq}`,
    time: row.at,
    org,
    seq: row.seq,
    hash: row.hash,
    actor: row.actor,
    actorKind: row.actor_kind,
    action: row.action,
    subject: row.subject,
    meta,
  };
}

/** A one-line summary, for the tools that show a message first. @param {StreamEvent} e */
export function summarize(e) {
  if (e.type === 'receipt') return `${e.outcome} ${e.kind} ${e.target} by ${e.agent} (${e.log}#${e.seq})`;
  if (e.type === 'audit') return `${e.action}${e.subject ? ` ${e.subject}` : ''} by ${e.actor}`;
  return String(e.message ?? 'Proofwire test event');
}

/** @param {StreamEvent} e */
function severity(e) {
  if (e.type === 'audit' && e.action === 'witness.refused') return { text: 'ERROR', number: 17 };
  if (e.type === 'receipt' && e.outcome !== 'allow') return { text: 'WARN', number: 13 };
  return { text: 'INFO', number: 9 };
}

// ── wire formats ────────────────────────────────────────────────────────

/** @param {string} url @param {string} path  Appended when the URL names only a host. */
function withPath(url, path) {
  const u = new URL(url);
  if (u.pathname === '' || u.pathname === '/') u.pathname = path;
  return u.toString();
}

/**
 * The request that delivers `events` to `d`.
 *
 * @param {Destination} d
 * @param {StreamEvent[]} events
 * @returns {{ url: string, headers: Record<string, string>, body: string }}
 */
export function formatBatch(d, events) {
  if (d.type === 'webhook') {
    const body = JSON.stringify({ events });
    const t = Math.floor(Date.now() / 1000);
    const sig = createHmac('sha256', /** @type {string} */ (d.secret)).update(`${t}.${body}`).digest('hex');
    return {
      url: d.url,
      headers: { 'content-type': 'application/json', 'proofwire-signature': `t=${t},v1=${sig}` },
      body,
    };
  }
  if (d.type === 'splunk') {
    // HEC takes events back to back, not as an array.
    const body = events
      .map((e) => JSON.stringify({
        time: Date.parse(e.time) / 1000,
        source: 'proofwire',
        sourcetype: `proofwire:${e.type}`,
        event: e,
      }))
      .join('\n');
    return {
      url: withPath(d.url, '/services/collector/event'),
      headers: { 'content-type': 'application/json', authorization: `Splunk ${d.token}` },
      body,
    };
  }
  if (d.type === 'datadog') {
    const body = JSON.stringify(events.map((e) => ({
      ...e,
      ddsource: 'proofwire',
      service: 'proofwire',
      ddtags: [`event:${e.type}`, e.outcome ? `outcome:${e.outcome}` : '', e.log ? `log:${e.log}` : ''].filter(Boolean).join(','),
      status: severity(e).text.toLowerCase(),
      message: summarize(e),
      timestamp: Date.parse(e.time),
    })));
    return {
      url: withPath(d.url, '/api/v2/logs'),
      headers: { 'content-type': 'application/json', 'dd-api-key': /** @type {string} */ (d.token) },
      body,
    };
  }
  // OpenTelemetry: OTLP/HTTP with the JSON encoding.
  const body = JSON.stringify({
    resourceLogs: [{
      resource: { attributes: [kv('service.name', 'proofwire')] },
      scopeLogs: [{
        scope: { name: 'proofwire' },
        logRecords: events.map((e) => {
          const s = severity(e);
          return {
            timeUnixNano: String(BigInt(Date.parse(e.time)) * 1_000_000n),
            severityNumber: s.number,
            severityText: s.text,
            body: { stringValue: summarize(e) },
            attributes: Object.entries(e).map(([k, v]) => kv(`proofwire.${k}`, v)),
          };
        }),
      }],
    }],
  });
  return {
    url: withPath(d.url, '/v1/logs'),
    headers: { 'content-type': 'application/json', ...(d.headers ?? {}) },
    body,
  };
}

/** @param {string} key @param {unknown} v */
function kv(key, v) {
  if (typeof v === 'number' && Number.isInteger(v)) return { key, value: { intValue: String(v) } };
  if (typeof v === 'string') return { key, value: { stringValue: v } };
  return { key, value: { stringValue: JSON.stringify(v) } };
}

// ── delivery ────────────────────────────────────────────────────────────

/**
 * @typedef {{ running: Promise<void> | null, again: boolean, timer: NodeJS.Timeout | null,
 *   failures: number, lastOkAt: string | null, lastError: string | null, lastErrorAt: string | null,
 *   delivered: number }} DestState
 */

export class Streams {
  /**
   * @param {object} a
   * @param {import('./store.js').Store} a.store
   * @param {() => boolean} a.allowPrivate
   * @param {(p: Promise<unknown>) => void} a.track  Registers work the hub waits for on close.
   * @param {number} [a.delayMs]  How long to gather events before sending.
   */
  constructor(a) {
    this.store = a.store;
    this.db = a.store.db;
    this.allowPrivate = a.allowPrivate;
    this.track = a.track;
    this.delayMs = a.delayMs ?? 250;
    /** @type {Map<string, DestState>} */
    this.state = new Map();
    this.closed = false;
  }

  /** @param {string} orgId @returns {Destination[]} */
  destinations(orgId) {
    return this.store.integration(orgId, 'streams')?.config.destinations ?? [];
  }

  /**
   * Save an organisation's destinations. A new destination starts at the
   * present, or at the beginning with `backfill`; one that keeps its name
   * keeps its place.
   *
   * @param {string} orgId
   * @param {Destination[]} destinations
   * @param {Set<string>} backfill  Names to deliver history to.
   */
  save(orgId, destinations, backfill) {
    /** @type {Record<string, number>} */
    const logHeads = {};
    for (const l of this.db.prepare('SELECT id, size FROM logs WHERE org_id = ?').all(orgId)) {
      logHeads[String(l.id)] = Number(l.size) - 1;
    }
    const heads = {
      receipts: JSON.stringify(logHeads),
      audit: Number(this.db.prepare('SELECT COALESCE(MAX(seq), -1) AS n FROM audit_events WHERE org_id = ?').get(orgId)?.n ?? -1),
    };
    const keep = new Set(destinations.map((d) => d.name));
    for (const row of this.db.prepare('SELECT name FROM stream_cursors WHERE org_id = ?').all(orgId)) {
      if (!keep.has(String(row.name))) {
        this.db.prepare('DELETE FROM stream_cursors WHERE org_id = ? AND name = ?').run(orgId, row.name);
        this._forget(orgId, String(row.name));
      }
    }
    for (const d of destinations) {
      const from = backfill.has(d.name) ? { receipts: '{}', audit: -1 } : heads;
      this.db
        .prepare(
          `INSERT INTO stream_cursors(org_id, name, receipts, audit_after) VALUES(?, ?, ?, ?)
           ON CONFLICT(org_id, name) DO ${backfill.has(d.name) ? 'UPDATE SET receipts = excluded.receipts, audit_after = excluded.audit_after' : 'NOTHING'}`,
        )
        .run(orgId, d.name, from.receipts, from.audit);
    }
    this.store.setIntegration(orgId, 'streams', { destinations });
  }

  /** @param {string} orgId */
  remove(orgId) {
    for (const d of this.destinations(orgId)) this._forget(orgId, d.name);
    this.db.prepare('DELETE FROM stream_cursors WHERE org_id = ?').run(orgId);
    return this.store.deleteIntegration(orgId, 'streams');
  }

  /** Something new happened in this organisation: send it soon. @param {string} orgId */
  poke(orgId) {
    if (this.closed) return;
    for (const d of this.destinations(orgId)) this._schedule(orgId, d.name, this.delayMs);
  }

  /** After a restart: pick up where each destination left off. */
  resume() {
    for (const row of this.db.prepare("SELECT org_id FROM integrations WHERE kind = 'streams'").all()) {
      this.poke(String(row.org_id));
    }
  }

  /**
   * Send everything pending now, and report how it went. For tests, and for
   * an admin's "send now" after fixing a destination.
   *
   * @param {string} orgId
   */
  async flush(orgId) {
    for (const d of this.destinations(orgId)) {
      const st = this._state(orgId, d.name);
      if (st.timer) clearTimeout(st.timer);
      st.timer = null;
      st.failures = 0;
      while (st.running) await st.running;
      await this._run(orgId, d.name);
    }
    return this.status(orgId);
  }

  /** @param {string} orgId */
  status(orgId) {
    return this.destinations(orgId).map((d) => {
      const st = this.state.get(`${orgId}:${d.name}`);
      const cur = this._cursor(orgId, d.name);
      return {
        ...describeDestination(d),
        pending: cur ? this._pending(orgId, d, cur) : 0,
        delivered: st?.delivered ?? 0,
        lastOkAt: st?.lastOkAt ?? null,
        lastError: st?.lastError ?? null,
        lastErrorAt: st?.lastErrorAt ?? null,
        retrying: Boolean(st?.failures),
      };
    });
  }

  /**
   * Send one test event to every destination, bypassing the cursors.
   * @param {string} orgId
   */
  async test(orgId) {
    const org = this.store.org(orgId);
    /** @type {StreamEvent} */
    const e = {
      type: 'test', id: `test:${Date.now()}`, time: new Date().toISOString(), org: org?.slug ?? orgId,
      message: 'Proofwire is connected. Receipts and audit events for this organization will arrive here.',
    };
    const results = [];
    for (const d of this.destinations(orgId)) {
      try {
        await this._send(d, [e]);
        results.push({ name: d.name, ok: true });
      } catch (err) {
        results.push({ name: d.name, ok: false, error: /** @type {Error} */ (err).message });
      }
    }
    return results;
  }

  async close() {
    this.closed = true;
    for (const st of this.state.values()) {
      if (st.timer) clearTimeout(st.timer);
      st.timer = null;
    }
    await Promise.allSettled([...this.state.values()].map((st) => st.running));
  }

  // ── internals ──

  /** @param {string} orgId @param {string} name @returns {DestState} */
  _state(orgId, name) {
    const key = `${orgId}:${name}`;
    let st = this.state.get(key);
    if (!st) {
      st = { running: null, again: false, timer: null, failures: 0, lastOkAt: null, lastError: null, lastErrorAt: null, delivered: 0 };
      this.state.set(key, st);
    }
    return st;
  }

  /** @param {string} orgId @param {string} name */
  _forget(orgId, name) {
    const st = this.state.get(`${orgId}:${name}`);
    if (st?.timer) clearTimeout(st.timer);
    this.state.delete(`${orgId}:${name}`);
  }

  /** @param {string} orgId @param {string} name @param {number} ms */
  _schedule(orgId, name, ms) {
    const st = this._state(orgId, name);
    if (st.running) {
      st.again = true;
      return;
    }
    // Waiting out a failure: new events join the backlog it will send.
    if (st.timer) return;
    st.timer = setTimeout(() => {
      st.timer = null;
      this._run(orgId, name);
    }, ms);
    st.timer.unref?.();
  }

  /** @param {string} orgId @param {string} name */
  _run(orgId, name) {
    const st = this._state(orgId, name);
    if (st.running) return st.running;
    st.running = this._pump(orgId, name).catch((err) => {
      // Not the destination refusing (that is handled inside), but this
      // side failing, e.g. the database closing under it. Retry like one.
      st.failures++;
      st.lastError = /** @type {Error} */ (err).message;
      st.lastErrorAt = new Date().toISOString();
    }).finally(() => {
      st.running = null;
      if (this.closed) return;
      if (st.failures > 0) {
        this._schedule(orgId, name, Math.min(1000 * 2 ** (st.failures - 1), MAX_BACKOFF_MS));
      } else if (st.again) {
        st.again = false;
        this._schedule(orgId, name, this.delayMs);
      }
    });
    this.track(st.running);
    return st.running;
  }

  /** Deliver until caught up, or until the destination refuses. @param {string} orgId @param {string} name */
  async _pump(orgId, name) {
    const st = this._state(orgId, name);
    const org = this.store.org(orgId)?.slug ?? orgId;
    for (;;) {
      if (this.closed) return;
      const d = this.destinations(orgId).find((x) => x.name === name);
      const cur = this._cursor(orgId, name);
      if (!d || !cur) return;
      const receipts = this._receipts(orgId, d, cur.receipts);
      const audits = d.audit
        ? this.db
          .prepare('SELECT * FROM audit_events WHERE org_id = ? AND seq > ? ORDER BY seq LIMIT ?')
          .all(orgId, cur.audit_after, BATCH)
        : [];
      if (receipts.length === 0 && audits.length === 0) return;

      const events = [
        ...receipts.map((r) => receiptEvent(r, org)),
        ...audits.map((r) => auditEvent(r, org)),
      ];
      try {
        await this._send(d, events);
      } catch (err) {
        st.failures++;
        st.lastError = /** @type {Error} */ (err).message;
        st.lastErrorAt = new Date().toISOString();
        console.error(JSON.stringify({ level: 'warn', event: 'stream.failed', destination: name, failures: st.failures, message: st.lastError }));
        return;
      }
      // The destination has them: only now does the cursor move.
      const moved = { ...cur.receipts };
      for (const r of receipts) moved[r.log_id] = Math.max(moved[r.log_id] ?? -1, Number(r.seq));
      this.db
        .prepare('UPDATE stream_cursors SET receipts = ?, audit_after = ? WHERE org_id = ? AND name = ?')
        .run(
          JSON.stringify(moved),
          audits.length ? Number(audits[audits.length - 1].seq) : cur.audit_after,
          orgId, name,
        );
      st.failures = 0;
      st.delivered += events.length;
      st.lastOkAt = new Date().toISOString();
    }
  }

  /**
   * @param {string} orgId @param {string} name
   * @returns {{ receipts: Record<string, number>, audit_after: number } | undefined}
   */
  _cursor(orgId, name) {
    const row = this.db
      .prepare('SELECT receipts, audit_after FROM stream_cursors WHERE org_id = ? AND name = ?')
      .get(orgId, name);
    if (!row) return undefined;
    return { receipts: JSON.parse(String(row.receipts)), audit_after: Number(row.audit_after) };
  }

  /** Each of the organisation's logs, and the last seq of it a destination has. @param {string} orgId @param {Record<string, number>} after */
  _logs(orgId, after) {
    return this.db
      .prepare('SELECT id, slug FROM logs WHERE org_id = ? ORDER BY created_at, id')
      .all(orgId)
      .map((l) => ({ id: String(l.id), slug: String(l.slug), after: after[String(l.id)] ?? -1 }));
  }

  /** @param {Destination} d */
  _outcomeFilter(d) {
    return d.receipts === 'blocked' ? " AND r.outcome <> 'allow'" : '';
  }

  /**
   * The next receipts to send, in each log's order, from as many logs as fit.
   * @param {string} orgId @param {Destination} d @param {Record<string, number>} after
   */
  _receipts(orgId, d, after) {
    if (d.receipts === 'none') return [];
    /** @type {any[]} */
    const out = [];
    const q = this.db.prepare(
      `SELECT r.* FROM receipts r WHERE r.log_id = ? AND r.seq > ?${this._outcomeFilter(d)} ORDER BY r.seq LIMIT ?`,
    );
    const logs = this._logs(orgId, after);
    // A share each, so one busy log can't keep the others waiting.
    const share = Math.max(20, Math.ceil(BATCH / Math.max(1, logs.length)));
    for (const l of logs) {
      if (out.length >= BATCH) break;
      for (const r of q.all(l.id, l.after, Math.min(share, BATCH - out.length))) out.push({ ...r, log_slug: l.slug });
    }
    return out;
  }

  /** @param {string} orgId @param {Destination} d @param {{ receipts: Record<string, number>, audit_after: number }} cur */
  _pending(orgId, d, cur) {
    let r = 0;
    if (d.receipts !== 'none') {
      const q = this.db.prepare(`SELECT COUNT(*) AS n FROM receipts r WHERE r.log_id = ? AND r.seq > ?${this._outcomeFilter(d)}`);
      for (const l of this._logs(orgId, cur.receipts)) r += Number(q.get(l.id, l.after)?.n ?? 0);
    }
    const a = d.audit ? Number(this.db
      .prepare('SELECT COUNT(*) AS n FROM audit_events WHERE org_id = ? AND seq > ?')
      .get(orgId, cur.audit_after)?.n ?? 0) : 0;
    return r + a;
  }

  /** @param {Destination} d @param {StreamEvent[]} events */
  async _send(d, events) {
    const req = formatBatch(d, events);
    const res = await guardedRequest(req.url, {
      method: 'POST', headers: req.headers, body: req.body, allowPrivate: this.allowPrivate(), timeoutMs: 15_000,
    });
    if (res.status < 200 || res.status >= 300) {
      throw new Error(`${d.type} answered HTTP ${res.status}${res.text ? `: ${res.text.slice(0, 200)}` : ''}`);
    }
  }
}
