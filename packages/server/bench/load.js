#!/usr/bin/env node
/**
 * Not a test — a measurement.
 *
 * Throughput, concurrency and memory numbers for the ingest path, so capacity
 * planning is arithmetic rather than optimism. Run it before claiming the hub
 * is ready for anyone's production traffic:
 *
 *     node --no-warnings=ExperimentalWarning packages/server/bench/load.js
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateIdentity, buildReceipt, signReceipt, entryHash, GENESIS_PREV } from '@deedwrit/core';
import { Hub } from '../src/app.js';
import { Auth } from '../src/auth.js';

const B = (s) => `[1m${s}[0m`;
const DIM = (s) => `[90m${s}[0m`;
const G = (s) => `[32m${s}[0m`;
const Y = (s) => `[33m${s}[0m`;

/** A local agent producing a valid, chained, signed stream. */
class Agent {
  /** @param {string} slug */
  constructor(slug) {
    const { identity } = generateIdentity();
    this.identity = identity;
    this.slug = slug;
    this.seq = 0;
    this.prev = GENESIS_PREV;
  }

  make() {
    const { body } = buildReceipt({
      log: this.slug,
      seq: this.seq,
      prev: this.prev,
      actor: { agent: 'claude-opus-5', runtime: 'load/0.2.0', session: 'sess_load', principal: 'ops@acme.test' },
      action: {
        kind: 'tool_call',
        target: 'ops.refund',
        params: { order: `ord_${this.seq}`, note: 'x'.repeat(200) },
        metrics: { amount_usd: 1 },
      },
      decision: { outcome: 'allow', policy: 'p_load', rules: [] },
      result: { status: 'ok', payload: { id: `re_${this.seq}` }, latencyMs: 12 },
    });
    const r = signReceipt(this.identity, body);
    this.seq++;
    this.prev = entryHash(r);
    return r;
  }

  /** @param {number} n */
  batch(n) {
    return Array.from({ length: n }, () => this.make());
  }
}

/** @param {number} ms */
const rate = (n, ms) => Math.round(n / (ms / 1000)).toLocaleString();
const mb = () => Math.round(process.memoryUsage().heapUsed / 1024 / 1024);

async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deedwrit-load-'));
  const dbFile = path.join(dir, 'hub.db');

  // A real file, not :memory:, so the numbers include fsync.
  const hub = new Hub({
    database: dbFile,
    checkpointEvery: 1000,
    ingestRate: { capacity: 1e9, refillPerSec: 1e9 },
    apiRate: { capacity: 1e9, refillPerSec: 1e9 },
  });
  const { url } = await hub.listen(0);
  const base = url.replace('0.0.0.0', '127.0.0.1');

  const auth = new Auth(hub.store);
  const org = hub.store.createOrg({ slug: 'load', name: 'Load' });
  const token = auth.createKey({
    orgId: org.id,
    name: 'load',
    scopes: ['receipts:write', 'receipts:read', 'logs:write', 'logs:read'],
  }).token;

  const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
  const post = (p, body) => fetch(base + p, { method: 'POST', headers, body: JSON.stringify(body) });

  console.log('');
  console.log(B('  Deedwrit hub — load profile'));
  console.log(DIM(`  ${process.version} · ${os.cpus()[0].model.trim()} · ${os.cpus().length} cores`));
  console.log(DIM('  ─────────────────────────────────────────────────────────────'));

  // ── 1. Signing cost on the agent side ─────────────────────────────────
  {
    const agent = new Agent('bench-sign');
    const t = Date.now();
    agent.batch(2000);
    const ms = Date.now() - t;
    console.log(`  ${B('sign')}          ${rate(2000, ms)}/s  ${DIM(`(${(ms / 2000).toFixed(3)} ms/receipt, agent side)`)}`);
  }

  // ── 2. Ingest throughput by batch size ────────────────────────────────
  for (const size of [1, 50, 200, 1000]) {
    const agent = new Agent(`bench-b${size}`);
    await post('/v1/logs', {
      slug: agent.slug, canonical: agent.slug,
      kid: agent.identity.kid, publicKey: agent.identity.publicKey,
    });

    const total = size === 1 ? 300 : 4000;
    const batches = [];
    for (let i = 0; i < total / size; i++) batches.push(agent.batch(size));

    const t = Date.now();
    for (const b of batches) {
      const res = await post(`/v1/logs/${agent.slug}/receipts`, { receipts: b });
      if (res.status !== 200) throw new Error(`ingest failed: ${res.status} ${await res.text()}`);
    }
    const ms = Date.now() - t;
    console.log(
      `  ${B('ingest')} ${String(size).padStart(4)}/batch  ${String(rate(total, ms)).padStart(7)}/s` +
        DIM(`  ${(ms / (total / size)).toFixed(1)} ms/request, ${total} receipts`),
    );
  }

  // ── 3. Concurrent agents, separate logs ───────────────────────────────
  for (const agents of [4, 16]) {
    const pool = [];
    for (let i = 0; i < agents; i++) {
      const a = new Agent(`bench-c${agents}-${i}`);
      await post('/v1/logs', {
        slug: a.slug, canonical: a.slug, kid: a.identity.kid, publicKey: a.identity.publicKey,
      });
      pool.push(a);
    }

    const perAgent = 500;
    const t = Date.now();
    const results = await Promise.all(
      pool.map(async (a) => {
        for (let i = 0; i < perAgent / 100; i++) {
          const res = await post(`/v1/logs/${a.slug}/receipts`, { receipts: a.batch(100) });
          if (res.status !== 200) return { ok: false, status: res.status, body: await res.text() };
        }
        return { ok: true };
      }),
    );
    const ms = Date.now() - t;
    const failed = results.filter((r) => !r.ok);
    const label = `${agents} agents`.padEnd(13);
    console.log(
      `  ${B('concurrent')} ${label} ${String(rate(agents * perAgent, ms)).padStart(7)}/s` +
        (failed.length
          ? `  ${Y(`${failed.length} failed: ${failed[0].status} ${String(failed[0].body).slice(0, 60)}`)}`
          : DIM(`  ${agents * perAgent} receipts, no contention errors`)),
    );
  }

  // ── 4. Read path against a large log ──────────────────────────────────
  {
    const big = hub.store.logBySlug(org.id, 'bench-b1000');
    const size = big.size;

    let t = Date.now();
    for (let i = 0; i < 200; i++) hub.store.proof(org.id, big.id, i % size);
    console.log(
      `  ${B('proof')}         ${rate(200, Date.now() - t)}/s  ${DIM(`(inclusion proof, tree of ${size})`)}`,
    );

    // The tree is cached; the cold path is what a restart or an evicted
    // tenant actually pays.
    hub.store.forgetTree(big.id);
    t = Date.now();
    hub.store.tree(big.id);
    console.log(`  ${B('tree rebuild')}  ${Date.now() - t} ms  ${DIM(`(cold, ${size} leaves — cost of a restart)`)}`);

    t = Date.now();
    const audit = hub.store.audit(org.id, big.id);
    console.log(
      `  ${B('self-audit')}    ${Date.now() - t} ms  ${DIM(`(${size} receipts re-verified)`)} ` +
        (audit.ok ? G('ok') : Y('FAILED')),
    );

    t = Date.now();
    const bundle = hub.store.bundle(org.id, big.id);
    const bytes = Buffer.byteLength(JSON.stringify(bundle));
    console.log(
      `  ${B('bundle')}        ${Date.now() - t} ms  ${DIM(`${(bytes / 1024 / 1024).toFixed(1)} MB for ${size} receipts`)}`,
    );
  }

  // ── 5. Footprint ──────────────────────────────────────────────────────
  {
    const total = hub.db.prepare('SELECT count(*) AS n FROM receipts').get().n;
    const bytes = fs.statSync(dbFile).size;
    console.log(DIM('  ─────────────────────────────────────────────────────────────'));
    console.log(
      `  ${B('stored')}        ${total.toLocaleString()} receipts · ${(bytes / 1024 / 1024).toFixed(1)} MB` +
        DIM(`  (${Math.round(bytes / total)} bytes each)`),
    );
    console.log(`  ${B('heap')}          ${mb()} MB`);
    console.log(
      DIM(`  projection: 1M receipts ≈ ${((bytes / total) * 1e6 / 1024 / 1024 / 1024).toFixed(1)} GB on disk`),
    );
    console.log('');
  }

  await hub.close();
  fs.rmSync(dir, { recursive: true, force: true });
}

await main();
