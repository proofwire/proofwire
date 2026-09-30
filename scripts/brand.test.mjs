import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { trackedFiles } from './repo-hygiene.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// The wordmark is written in two coloured halves, `vouch<em>well</em>`, so a
// plain search for the old name misses it: that is how every logo kept saying
// proofwire after the rename. Old names elsewhere are deliberate (reading
// pre-rename logs, settings and evidence) and are spelled out in full.
const SPLIT_OLD_MARK = /proof\s*<[^>]*>\s*wire/i;

test('no logo still reads proofwire', () => {
  const found = trackedFiles(ROOT)
    .filter((f) => /\.(html|js|mjs|css|md)$/.test(f) && f !== 'scripts/brand.test.mjs')
    .filter((f) => SPLIT_OLD_MARK.test(fs.readFileSync(path.join(ROOT, f), 'utf8')));
  assert.deepEqual(found, []);
});
