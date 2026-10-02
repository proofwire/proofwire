import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ProofLog, verifyBundle, adoptLegacyEnv } from '../src/index.js';

/** Until 0.5.0 the project was called Proofwire. What it wrote stays valid. */

test('a bundle written before the rename still verifies; an unknown kind does not', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vw-legacy-'));
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
    assert.equal(bundle.kind, 'vouchwell.bundle');
    // The kind sits outside every signature: relabelling it changes no proof.
    assert.ok(verifyBundle({ ...bundle, kind: 'proofwire.bundle' }).ok);
    const other = verifyBundle({ ...bundle, kind: 'something.bundle' });
    assert.equal(other.ok, false);
    assert.match(other.issues[0], /not a Vouchwell v1 bundle/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('PROOFWIRE_* settings are read as VOUCHWELL_* unless the new one is set, and it says so', () => {
  /** @type {Record<string, string>} */
  const env = { PROOFWIRE_DB: '/data/old.db', PROOFWIRE_PORT: '9000', VOUCHWELL_PORT: '8787', OTHER: 'x' };
  /** @type {string[]} */
  const said = [];
  const adopted = adoptLegacyEnv(env, (m) => said.push(m));
  assert.deepEqual(adopted, ['PROOFWIRE_DB']);
  assert.equal(env.VOUCHWELL_DB, '/data/old.db');
  assert.equal(env.VOUCHWELL_PORT, '8787', 'the new name wins when both are set');
  assert.match(said.join(''), /PROOFWIRE_DB.*rename to VOUCHWELL_/);
  assert.deepEqual(adoptLegacyEnv({ VOUCHWELL_DB: 'x' }, (m) => said.push(m)), []);
});
