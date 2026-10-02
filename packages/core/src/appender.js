import fs from 'node:fs';
import path from 'node:path';
import { canonicalize, canonicalBytes } from './canonical.js';
import { hex, unhex } from './hash.js';
import { leafHash, nodeHash, merkleRoot } from './merkle.js';
import { identityFromPem } from './keys.js';
import { buildReceipt, signReceipt, entryHash, GENESIS_PREV } from './receipt.js';
import { buildCheckpoint, signCheckpoint } from './checkpoint.js';

/**
 * Append to a log without reading all of it.
 *
 * `ProofLog.open` parses and hashes every receipt to rebuild the Merkle tree:
 * right for verifying, exporting and proving, and linear in the size of the
 * log. A writer that starts once per action, as `vw hook` does twice per tool
 * call, cannot afford that: at 5,000 receipts it was 0.4 s each time, growing
 * without bound.
 *
 * Appending needs much less than the whole tree: the size, the hash of the
 * last receipt, and the RFC 6962 "frontier", the roots of the perfect
 * subtrees the tree decomposes into, which is at most log₂(n) hashes. That is
 * kept in `append-state.json`, with how many bytes of `entries.jsonl` it
 * accounts for. Opening reads only what was appended after that.
 *
 * The cache is trusted only as far as the file agrees with it. The receipt
 * just before its byte offset must hash to its head, and every later receipt
 * must continue the chain. Anything else (a cache from another log, a file
 * that was truncated or rewritten, a writer that appended without updating
 * it) and the state is rebuilt from the whole file, exactly as `ProofLog.open`
 * would. The cache never decides what is true. `vw verify` does that, from
 * the entries alone.
 */

const ENTRIES = 'entries.jsonl';
const SALTS = 'salts.jsonl';
const CHECKPOINTS = 'checkpoints.jsonl';
const CACHE = 'append-state.json';

/**
 * @typedef {{ size: number, hash: Buffer }} Peak
 * @typedef {{ size: number, head: string, bytes: number, peaks: Peak[] }} State
 */

export class LogAppender {
  /** Bytes read at a time. Tests shrink it to cross every boundary. */
  static chunkSize = 64 * 1024;

  /**
   * @param {string} dir
   * @param {{ log: string, kid: string }} config
   * @param {import('./keys.js').Identity} identity
   * @param {State} state
   * @private
   */
  constructor(dir, config, identity, state) {
    this.dir = dir;
    this.config = config;
    this.identity = identity;
    this._state = state;
  }

  /**
   * @param {string} dir  A log made by `ProofLog.create`.
   * @returns {LogAppender}
   */
  static open(dir) {
    const config = JSON.parse(fs.readFileSync(path.join(dir, 'config.json'), 'utf8'));
    const identity = identityFromPem(fs.readFileSync(path.join(dir, 'key.pem'), 'utf8'));
    if (identity.kid !== config.kid) {
      throw new Error(`key.pem does not match config: key is ${identity.kid}, config says ${config.kid}`);
    }
    const fd = fs.openSync(path.join(dir, ENTRIES), 'r');
    try {
      const length = fs.fstatSync(fd).size;
      const cached = readCache(dir, config.log);
      const cachedBytes = cached?.bytes;
      const state = (cached && cached.bytes <= length && endsWith(fd, cached) && consume(fd, cached, length, true))
        || consume(fd, emptyState(), length, false);
      const appender = new LogAppender(dir, config, identity, /** @type {State} */ (state));
      if (cachedBytes !== appender._state.bytes) appender._saveCache();
      return appender;
    } finally {
      fs.closeSync(fd);
    }
  }

  /** @returns {string} */
  get logId() {
    return this.config.log;
  }

  /** @returns {number} */
  get size() {
    return this._state.size;
  }

  /** @returns {string} */
  get head() {
    return this._state.head;
  }

  /** @returns {string} The Merkle root, hex. Equal to `ProofLog#root` for the same entries. */
  get root() {
    return hex(rootOf(this._state.peaks));
  }

  /**
   * The receipts timestamped within the last `windowMs`, oldest first: what a
   * policy's budgets and rate limits look at. Read from the end of the file
   * back, stopping at the first older receipt.
   *
   * @param {number} windowMs
   * @returns {import('./receipt.js').Receipt[]}
   */
  recent(windowMs) {
    if (!(windowMs > 0) || this._state.size === 0) return [];
    const cutoff = Date.now() - windowMs;
    /** @type {import('./receipt.js').Receipt[]} */
    const found = [];
    for (const line of linesBackward(path.join(this.dir, ENTRIES), this._state.bytes)) {
      const receipt = JSON.parse(line);
      if (Date.parse(receipt.ts) < cutoff) break;
      found.push(receipt);
    }
    return found.reverse();
  }

  /**
   * Record an action, exactly as `ProofLog#append` does.
   *
   * @param {Parameters<import('./log.js').ProofLog['append']>[0]} args
   * @returns {import('./receipt.js').Receipt}
   */
  append(args) {
    const { body, salts } = buildReceipt({ log: this.config.log, seq: this._state.size, prev: this._state.head, ...args });
    const receipt = signReceipt(this.identity, body);
    const line = canonicalize(receipt) + '\n';
    // Durable before the in-memory state moves, and in ProofLog's order.
    fs.appendFileSync(path.join(this.dir, ENTRIES), line);
    fs.appendFileSync(path.join(this.dir, SALTS), canonicalize({ seq: receipt.seq, ...salts }) + '\n', { mode: 0o600 });
    advance(this._state, receipt, Buffer.byteLength(line));
    this._saveCache();
    return receipt;
  }

  /**
   * Sign and store the current tree head, as `ProofLog#checkpoint` does.
   *
   * @returns {import('./checkpoint.js').Checkpoint}
   */
  checkpoint() {
    const body = buildCheckpoint({ log: this.config.log, size: this.size, root: this.root, head: this.head });
    const cp = signCheckpoint(this.identity, body, 'log');
    fs.appendFileSync(path.join(this.dir, CHECKPOINTS), canonicalize(cp) + '\n');
    return cp;
  }

  _saveCache() {
    const s = this._state;
    const file = path.join(this.dir, CACHE);
    const tmp = `${file}.${process.pid}`;
    fs.writeFileSync(tmp, JSON.stringify({
      v: 1, log: this.config.log, size: s.size, head: s.head, bytes: s.bytes,
      peaks: s.peaks.map((p) => ({ size: p.size, hash: hex(p.hash) })),
    }) + '\n');
    fs.renameSync(tmp, file);
  }
}

/** @returns {State} */
function emptyState() {
  return { size: 0, head: GENESIS_PREV, bytes: 0, peaks: [] };
}

/**
 * The cached state, or null if there is none or it is not for this log.
 *
 * @param {string} dir
 * @param {string} logId
 * @returns {State | null}
 */
function readCache(dir, logId) {
  try {
    const c = JSON.parse(fs.readFileSync(path.join(dir, CACHE), 'utf8'));
    if (c?.v !== 1 || c.log !== logId || !Number.isInteger(c.size) || !Number.isInteger(c.bytes) || !Array.isArray(c.peaks)) return null;
    return { size: c.size, head: String(c.head), bytes: c.bytes, peaks: c.peaks.map((/** @type {any} */ p) => ({ size: p.size, hash: unhex(p.hash) })) };
  } catch {
    return null;
  }
}

/**
 * Whether the receipt ending exactly at `state.bytes` is the one the state
 * says is the head.
 *
 * @param {number} fd
 * @param {State} state
 */
function endsWith(fd, state) {
  if (state.bytes === 0) return state.size === 0;
  let start = state.bytes;
  /** @type {Buffer} */
  let tail = Buffer.alloc(0);
  do {
    const from = Math.max(0, start - LogAppender.chunkSize);
    const buf = Buffer.alloc(start - from);
    fs.readSync(fd, buf, 0, buf.length, from);
    tail = Buffer.concat([buf, tail]);
    start = from;
  } while (start > 0 && newlineBefore(tail, tail.length - 1) === -1);
  if (tail[tail.length - 1] !== 0x0a) return false;
  const line = tail.subarray(newlineBefore(tail, tail.length - 1) + 1, tail.length - 1).toString('utf8');
  try {
    return entryHash(JSON.parse(line)) === state.head;
  } catch {
    return false;
  }
}

/**
 * Fold the receipts after `state.bytes` into the state. With `continuing`,
 * any receipt that does not extend the chain makes it give up (return null),
 * so the caller rebuilds from the start. A partial last line, a write still
 * in progress or cut short, is left for the next reader.
 *
 * @param {number} fd
 * @param {State} state
 * @param {number} length
 * @param {boolean} continuing
 * @returns {State | null}
 */
function consume(fd, state, length, continuing) {
  let pos = state.bytes;
  let carry = Buffer.alloc(0);
  while (pos < length) {
    const buf = Buffer.alloc(Math.min(LogAppender.chunkSize * 16, length - pos));
    const n = fs.readSync(fd, buf, 0, buf.length, pos);
    if (n === 0) break;
    pos += n;
    let data = Buffer.concat([carry, buf.subarray(0, n)]);
    let nl;
    while ((nl = data.indexOf(0x0a)) !== -1) {
      const raw = data.subarray(0, nl);
      data = data.subarray(nl + 1);
      const text = raw.toString('utf8');
      if (text.trim() === '') {
        state.bytes += nl + 1;
        continue;
      }
      let receipt;
      try {
        receipt = JSON.parse(text);
      } catch (err) {
        if (continuing) return null;
        throw new Error(`entries.jsonl line ${state.size + 1} is not valid JSON: ${/** @type {Error} */ (err).message}`);
      }
      if (continuing && (receipt.seq !== state.size || receipt.prev !== state.head)) return null;
      advance(state, receipt, nl + 1);
    }
    carry = data;
  }
  return state;
}

/**
 * @param {State} state
 * @param {import('./receipt.js').Receipt} receipt
 * @param {number} lineBytes
 */
function advance(state, receipt, lineBytes) {
  /** @type {Peak[]} */
  const peaks = state.peaks;
  peaks.push({ size: 1, hash: leafHash(canonicalBytes(receipt)) });
  // MerkleTree#append's merge, on the peaks alone.
  while (peaks.length > 1 && peaks[peaks.length - 2].size === peaks[peaks.length - 1].size) {
    const right = /** @type {Peak} */ (peaks.pop());
    const left = /** @type {Peak} */ (peaks.pop());
    peaks.push({ size: left.size + right.size, hash: nodeHash(left.hash, right.hash) });
  }
  state.size += 1;
  state.head = entryHash(receipt);
  state.bytes += lineBytes;
}

/** MerkleTree#root, on the peaks alone. @param {Peak[]} peaks */
function rootOf(peaks) {
  if (peaks.length === 0) return merkleRoot([]);
  let acc = peaks[peaks.length - 1].hash;
  for (let i = peaks.length - 2; i >= 0; i--) acc = nodeHash(peaks[i].hash, acc);
  return acc;
}

/**
 * The last newline strictly before index `end`, or -1. Not `lastIndexOf` with
 * `end - 1` directly: a negative offset counts from the end of the buffer,
 * so a buffer holding just "\n" would find that same newline forever.
 *
 * @param {Buffer} buf
 * @param {number} end
 */
function newlineBefore(buf, end) {
  return end <= 0 ? -1 : buf.lastIndexOf(0x0a, end - 1);
}

/**
 * Non-empty lines of a file, last first, reading only as far back as the
 * caller consumes.
 *
 * @param {string} file
 * @param {number} end  Byte offset to read back from.
 */
function* linesBackward(file, end) {
  const fd = fs.openSync(file, 'r');
  try {
    let pos = end;
    let carry = Buffer.alloc(0);
    while (pos > 0) {
      const from = Math.max(0, pos - LogAppender.chunkSize);
      const buf = Buffer.alloc(pos - from);
      fs.readSync(fd, buf, 0, buf.length, from);
      pos = from;
      let data = Buffer.concat([buf, carry]);
      let nl;
      while ((nl = newlineBefore(data, data.length - 1)) !== -1) {
        const line = data.subarray(nl + 1).toString('utf8').trim();
        data = data.subarray(0, nl + 1);
        if (line) yield line;
      }
      carry = data;
    }
    const first = carry.toString('utf8').trim();
    if (first) yield first;
  } finally {
    fs.closeSync(fd);
  }
}
