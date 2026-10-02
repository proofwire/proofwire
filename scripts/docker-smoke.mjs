// Drives a hub container the way a real client does: register a log, sign
// and push receipts with @deedwrit/core directly (no CLI/proxy layer,
// which is unit-tested elsewhere), fetch the bundle back, and verify it. This
// is what building the image is *for* — a `docker build` that succeeds proves
// nothing about any of this on its own, as one earlier receipt shape found
// out the hard way (a crash this repository's tests now cover directly).
//
// With WITNESS_URL and WITNESS_TOKEN set it also drives a second container,
// run witness-only: the hub's checkpoint is co-signed there, the witness's
// key is taken from the witness itself, and the result is verified with that
// key pinned — the whole point of running a witness as a separate process.
import { generateIdentity, buildReceipt, signReceipt, entryHash, GENESIS_PREV, verifyBundle, verifyCheckpoint } from '@deedwrit/core';

const HUB = process.env.HUB_URL ?? 'http://localhost:8787';
const token = process.env.AGENT_TOKEN;
const auditToken = process.env.AUDIT_TOKEN ?? token;
if (!token) throw new Error('AGENT_TOKEN not set');

async function call(method, path, body, { as = token } = {}) {
  const res = await fetch(HUB + path, {
    method,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${as}` },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = text; }
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status}: ${JSON.stringify(json).slice(0, 300)}`);
  return json;
}

const { identity } = generateIdentity();
const slug = 'ci-smoke-' + Date.now().toString(36);

console.log('register log', slug);
const log = await call('POST', '/v1/logs', { slug, kid: identity.kid, publicKey: identity.publicKey });

console.log('write 3 receipts');
let prev = GENESIS_PREV;
const receipts = [];
for (let seq = 0; seq < 3; seq++) {
  const { body } = buildReceipt({
    log: log.slug, seq, prev,
    actor: { agent: 'ci-smoke', runtime: 'ci-smoke/1', session: 'sess_ci', principal: 'ci@deedwrit.test' },
    action: { kind: 'ops.query', target: `smoke.${seq}`, params: { n: seq } },
    decision: { outcome: 'allow', policy: 'p_ci', rules: [] },
    result: { status: 'ok', payload: { ok: true } },
  });
  const receipt = signReceipt(identity, body);
  prev = entryHash(receipt);
  receipts.push(receipt);
}
const write = await call('POST', `/v1/logs/${log.slug}/receipts`, { receipts });
if (write.accepted !== 3) throw new Error(`expected 3 accepted, got ${JSON.stringify(write)}`);

console.log('checkpoint');
const checkpoint = await call('POST', `/v1/logs/${log.slug}/checkpoint`, {});

console.log('fetch and verify the bundle');
const bundle = await call('GET', `/v1/logs/${log.slug}/bundle`, undefined, { as: auditToken });
const result = verifyBundle(bundle);
if (!result.ok) throw new Error(`bundle did not verify: ${JSON.stringify(result.issues)}`);

console.log('confirm a bogus token is rejected');
const bad = await fetch(HUB + '/v1/logs', { headers: { authorization: 'Bearer pwk_bogus.notreal' } });
if (bad.status !== 401) throw new Error(`expected 401 for a bogus token, got ${bad.status}`);

console.log(`OK: ${bundle.entries.length} entries, ${result.checked} checked, root ${bundle.root.slice(0, 16)}…`);

const WITNESS = process.env.WITNESS_URL;
const witnessToken = process.env.WITNESS_TOKEN;
if (WITNESS) {
  if (!witnessToken) throw new Error('WITNESS_URL is set but WITNESS_TOKEN is not');
  const getJson = async (url, headers = {}) => {
    const res = await fetch(url, { headers });
    return { status: res.status, json: await res.json().catch(() => null) };
  };

  console.log('witness: identify itself as witness-only, and publish only its own key');
  const wk = await getJson(`${WITNESS}/.well-known/deedwrit`);
  if (wk.json?.service !== 'deedwrit-witness') throw new Error(`witness is not in witness-only mode: ${JSON.stringify(wk.json)}`);
  if ('hub' in wk.json) throw new Error('witness-only node advertised a hub key');

  console.log('witness: refuse everything a hub would answer');
  for (const p of ['/v1/logs', '/v1/keys', '/v1/policies', '/']) {
    const res = await getJson(WITNESS + p, { authorization: `Bearer ${witnessToken}` });
    if (res.status !== 404) throw new Error(`witness answered GET ${p} with ${res.status}, expected 404`);
  }

  // A hub's checkpoints are signed with the hub's key, so that is the key the
  // witness binds this log to.
  const hubKeys = (await getJson(`${HUB}/.well-known/deedwrit`)).json;
  const cosign = (cp, logPublicKey) => fetch(`${WITNESS}/v1/witness/cosign`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${witnessToken}` },
    body: JSON.stringify({ checkpoint: cp, ...(logPublicKey ? { logPublicKey } : {}) }),
  });

  console.log('witness: refuse a first checkpoint that names no key');
  const unnamed = await cosign(checkpoint);
  if (unnamed.status !== 400) throw new Error(`expected 400 missing_log_key, got ${unnamed.status}`);

  console.log('witness: co-sign the hub\'s checkpoint, binding the log to the hub key');
  const res = await cosign(checkpoint, hubKeys.hub.publicKey);
  const cosigned = await res.json();
  if (!res.ok) throw new Error(`witness refused: ${res.status} ${JSON.stringify(cosigned)}`);
  if (cosigned.logKey?.kid !== hubKeys.hub.kid || !cosigned.logKey.newlyBound) {
    throw new Error(`expected the log to be bound to ${hubKeys.hub.kid}: ${JSON.stringify(cosigned.logKey)}`);
  }

  console.log('witness: refuse the same log offered under a different key');
  const imposter = generateIdentity().identity;
  const other = await cosign(checkpoint, imposter.publicKey);
  if (other.status !== 409) throw new Error(`expected 409 log_key_mismatch, got ${other.status}`);

  console.log('verify it, with the witness key pinned from the witness and the log key from the hub');
  const witnessed = { body: checkpoint.body, sigs: [...checkpoint.sigs, cosigned.signature] };
  const check = verifyCheckpoint(witnessed, { [hubKeys.hub.kid]: hubKeys.hub.publicKey }, {
    minWitnesses: 1,
    trustedWitnesses: { [wk.json.witness.kid]: wk.json.witness.publicKey },
  });
  if (!check.ok) throw new Error(`witnessed checkpoint did not verify: ${check.issues.join('; ')}`);

  console.log(`OK: checkpoint at size ${checkpoint.body.size} co-signed by ${wk.json.witness.kid}, verified with it pinned`);
}
