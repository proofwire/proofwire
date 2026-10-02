import { hex } from './hash.js';

/**
 * Ask a witness to counter-sign a checkpoint: the client half of
 * `POST /v1/witness/cosign`, shared by `dw cosign`, `dw proxy` and the hub.
 *
 * A witness only signs a root that provably extends the last one it signed
 * for this log, so the request has to carry a consistency proof from exactly
 * that size. The client asks the witness which size that is (`GET
 * /v1/witness/position/:log`) rather than guessing from its own checkpoints:
 * a guess is wrong whenever the witness missed one, and the witness then
 * reports a rewritten history that never happened.
 *
 * Asking first has a second use. The witness's answer is a root it signed,
 * and this log can check it against its own tree before sending anything: if
 * the log's history at that size is not what the witness saw, one of them has
 * been rewritten, and that is reported here, as the alarm it is.
 */

/** Refusals that mean a history disagrees, as opposed to "could not ask". */
const ALARMS = new Set(['split_view', 'not_an_extension', 'log_shrank', 'log_key_mismatch', 'diverged']);

export class WitnessRefusal extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {{ status?: number, detail?: unknown }} [extra]
   */
  constructor(code, message, extra = {}) {
    super(message);
    this.name = 'WitnessRefusal';
    this.code = code;
    this.status = extra.status ?? 0;
    this.detail = extra.detail;
    /** True when the refusal is evidence that one history was rewritten. */
    this.alarming = ALARMS.has(code);
  }
}

/**
 * @typedef {(method: 'GET'|'POST', url: string, headers: Record<string, string>, body?: string) =>
 *   Promise<{ status: number, json: any }>} WitnessRequest
 */

/** @type {WitnessRequest} */
async function fetchRequest(method, url, headers, body) {
  const res = await fetch(url, { method, headers, body, redirect: 'error', signal: AbortSignal.timeout(15_000) });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    // An answer that is not JSON is reported by status below.
  }
  return { status: res.status, json };
}

/**
 * @param {object} a
 * @param {string} a.url     The witness's base URL.
 * @param {string} a.token   A key with `witness:sign` on that witness.
 * @param {import('./checkpoint.js').Checkpoint} a.checkpoint  Signed by the log.
 * @param {{ size: number, rootAt: (n: number) => Buffer, consistencyProof: (from: number, to: number) => Buffer[] }} a.tree
 *   The log's tree, at least as large as the checkpoint.
 * @param {string} a.logPublicKey  The key the checkpoint is signed with; the witness binds the log to it.
 * @param {number} [a.guessPriorSize]  For witnesses too old to report their
 *   position: the size to prove growth from.
 * @param {WitnessRequest} [a.request]  How to reach the network. The hub
 *   passes one that refuses private addresses.
 * @returns {Promise<{ signature: { role: 'witness', kid: string, sig: string, ts?: string },
 *   witness: { kid: string, publicKey: string }, logKey?: any, from: number | null }>}
 */
export async function witnessCheckpoint(a) {
  const base = trimSlashes(a.url);
  const request = a.request ?? fetchRequest;
  const headers = { authorization: `Bearer ${a.token}`, accept: 'application/json' };
  const cp = a.checkpoint;
  const name = cp.body.log;

  const pos = await request('GET', `${base}/v1/witness/position/${encodeURIComponent(name)}`, headers);
  /** @type {number | null} */
  let from = null;
  if (pos.status === 200 && Number.isInteger(pos.json?.size)) {
    from = pos.json.size;
    if (from > cp.body.size) {
      throw new WitnessRefusal(
        'log_shrank',
        `this witness already signed ${name} at size ${from}; this checkpoint covers only ${cp.body.size}. ` +
          'Either entries were removed from this log, or another log is using its name.',
        { detail: { witnessSize: from, offered: cp.body.size } },
      );
    }
    if (from <= a.tree.size && hex(a.tree.rootAt(from)) !== pos.json.root) {
      throw new WitnessRefusal(
        'diverged',
        `this witness signed a different history of ${name} at size ${from} than this log holds. ` +
          'One of the two histories was rewritten. Investigate before anything else.',
        { detail: { size: from, witnessRoot: pos.json.root, localRoot: hex(a.tree.rootAt(from)) } },
      );
    }
  } else if (pos.status === 404 && pos.json?.error?.code === 'no_position') {
    from = null; // first time this witness sees the log
  } else if (pos.status === 404 || pos.status === 405) {
    // A witness from before the position endpoint: fall back to the guess.
    from = Number.isInteger(a.guessPriorSize) ? /** @type {number} */ (a.guessPriorSize) : null;
  } else {
    throw failure(pos, 'asking the witness what it last signed');
  }

  const consistencyProof = from !== null && from > 0 && from < cp.body.size
    ? a.tree.consistencyProof(from, cp.body.size).map(hex)
    : undefined;
  const res = await request(
    'POST',
    `${base}/v1/witness/cosign`,
    { ...headers, 'content-type': 'application/json' },
    JSON.stringify({ checkpoint: cp, consistencyProof, logPublicKey: a.logPublicKey }),
  );
  if (res.status !== 200 || !res.json?.signature || !res.json?.witness) {
    throw failure(res, 'asking the witness to co-sign');
  }
  return { ...res.json, from };
}

/**
 * @param {{ status: number, json: any }} res
 * @param {string} doing
 */
function failure(res, doing) {
  const e = res.json?.error;
  return new WitnessRefusal(
    e?.code ?? `http_${res.status}`,
    e?.message ?? `HTTP ${res.status} while ${doing}`,
    { status: res.status, detail: e?.detail },
  );
}

/** @param {string} s */
function trimSlashes(s) {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 47) end--;
  return s.slice(0, end);
}
