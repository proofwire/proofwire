import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Hub } from '../src/app.js';
import { resolveDatabase } from '../src/legacy.js';

/**
 * A hub set up before the project was renamed from Proofwire keeps its data,
 * its settings and the address verifiers already use.
 */

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/bin.js');

/** @param {Record<string, string>} env */
function identity(env) {
  const clean = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(VOUCHWELL|PROOFWIRE)_/.test(k)));
  const res = spawnSync(process.execPath, [BIN, 'identity', '--json'], {
    encoding: 'utf8',
    env: { ...clean, NODE_OPTIONS: '--no-warnings=ExperimentalWarning', ...env },
  });
  assert.equal(res.status, 0, res.stderr);
  return { json: JSON.parse(res.stdout), stderr: res.stderr };
}

test('an upgraded hub keeps using its proofwire.db, keys and all', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vw-legacy-hub-'));
  try {
    const old = new Hub({ database: path.join(dir, 'proofwire.db') });
    const kid = old.witnessSigner.kid;
    await old.close();

    assert.deepEqual(resolveDatabase(path.join(dir, 'vouchwell.db')), { file: path.join(dir, 'proofwire.db'), legacy: true });
    // A name the operator chose is never second-guessed.
    assert.equal(resolveDatabase(path.join(dir, 'mine.db')).legacy, false);

    // The Docker image's new default, pointing at a volume from before.
    const viaNew = identity({ VOUCHWELL_DB: path.join(dir, 'vouchwell.db') });
    assert.equal(viaNew.json.witness.kid, kid, 'it opened the old database, not a new empty one');
    assert.match(viaNew.stderr, /database from before the rename/);
    assert.ok(!fs.existsSync(path.join(dir, 'vouchwell.db')), 'no second database was created');

    // Settings written for the old name.
    const viaOldEnv = identity({ PROOFWIRE_DB: path.join(dir, 'proofwire.db') });
    assert.equal(viaOldEnv.json.witness.kid, kid);
    assert.match(viaOldEnv.stderr, /PROOFWIRE_DB/);

    // Once a vouchwell.db exists, it is the one used.
    const fresh = new Hub({ database: path.join(dir, 'vouchwell.db') });
    await fresh.close();
    assert.equal(resolveDatabase(path.join(dir, 'vouchwell.db')).legacy, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the discovery document answers at the old address too, on a hub and on a witness', async () => {
  for (const witnessOnly of [false, true]) {
    const hub = new Hub({ database: ':memory:', witnessOnly });
    const base = (await hub.listen(0)).url.replace('0.0.0.0', '127.0.0.1');
    try {
      const now = await (await fetch(`${base}/.well-known/vouchwell`)).json();
      const before = await fetch(`${base}/.well-known/proofwire`);
      assert.equal(before.status, 200);
      assert.deepEqual(await before.json(), now);
      assert.equal(now.service, witnessOnly ? 'vouchwell-witness' : 'vouchwell-hub');
    } finally {
      await hub.close();
    }
  }
});
