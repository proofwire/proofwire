import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ProofLog, verifyBundle, adoptLegacyEnv } from '../src/index.js';

/** Until 0.5.0 the project was called Proofwire, then briefly Vouchwell. What either wrote stays valid. */

test('a bundle written before the rename still verifies; an unknown kind does not', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dw-legacy-'));
  try {
    const log = ProofLog.create(dir);
    for (let i = 0; i < 3; i++) {
      log.append({
        actor: { agent: 'bot', runtime: 'test', session: 's', principal: 'p' },
        action: { kind: 'tool_call', target: 'crm.lookup', params: { i } },
        decision: { outcome: 'allow', policy: 'p', rules: [] },
      });
    }
    log.checkpoint();
    const bundle = JSON.parse(JSON.stringify(log.bundle()));
    assert.equal(bundle.kind, 'deedwrit.bundle');
    // The kind sits outside every signature: relabelling it changes no proof.
    assert.ok(verifyBundle({ ...bundle, kind: 'proofwire.bundle' }).ok);
    assert.ok(verifyBundle({ ...bundle, kind: 'vouchwell.bundle' }).ok);
    const other = verifyBundle({ ...bundle, kind: 'something.bundle' });
    assert.equal(other.ok, false);
    assert.match(other.issues[0], /not a Deedwrit v1 bundle/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('PROOFWIRE_* settings are read as DEEDWRIT_* unless the new one is set, and it says so', () => {
  /** @type {Record<string, string>} */
  const env = { PROOFWIRE_DB: '/data/old.db', PROOFWIRE_PORT: '9000', DEEDWRIT_PORT: '8787', OTHER: 'x' };
  /** @type {string[]} */
  const said = [];
  const adopted = adoptLegacyEnv(env, (m) => said.push(m));
  assert.deepEqual(adopted, ['PROOFWIRE_DB']);
  assert.equal(env.DEEDWRIT_DB, '/data/old.db');
  assert.equal(env.DEEDWRIT_PORT, '8787', 'the new name wins when both are set');
  assert.match(said.join(''), /PROOFWIRE_DB.*rename to DEEDWRIT_/);
  assert.deepEqual(adoptLegacyEnv({ DEEDWRIT_DB: 'x' }, (m) => said.push(m)), []);
});

test('VOUCHWELL_* settings are read too, and win over PROOFWIRE_* ones as the more recent name', () => {
  /** @type {Record<string, string>} */
  const env = { VOUCHWELL_DB: '/data/v.db', PROOFWIRE_DB: '/data/p.db', PROOFWIRE_TLS: 'internal' };
  /** @type {string[]} */
  const said = [];
  const adopted = adoptLegacyEnv(env, (m) => said.push(m));
  assert.equal(env.DEEDWRIT_DB, '/data/v.db');
  assert.equal(env.DEEDWRIT_TLS, 'internal');
  assert.deepEqual(adopted.sort(), ['PROOFWIRE_TLS', 'VOUCHWELL_DB']);
  assert.match(said.join(''), /VOUCHWELL_DB/);
});
