import { verifyBundle, ed25519Supported, canonicalize } from './verify.js';

/**
 * The interactive verifier on the site.
 *
 * Everything shown here comes from an evidence bundle, which is untrusted input:
 * tool names, principals and reasons are whatever an agent or an attacker put
 * there. So nothing is ever written with innerHTML — every node is built with
 * createElement and text is always set as text.
 */

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();

/**
 * @param {string} tag
 * @param {Record<string, any>} [props]
 * @param {...any} kids  Strings become text nodes; nothing is parsed as markup.
 */
function el(tag, props = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const kid of kids.flat()) if (kid != null) node.append(kid);
  return node;
}

/** `replaceChildren(null)` inserts the text "null", so empty slots are dropped first. */
const fill = (node, kids) => node.replaceChildren(...kids.flat().filter((k) => k != null));

const short = (h, n = 14) => (typeof h === 'string' && h.length > n ? h.slice(0, n) + '…' : String(h ?? '—'));
const money = (n) => `$${Number(n).toLocaleString(undefined, { maximumFractionDigits: 2 })}`;

// ── the bundle in the box ───────────────────────────────────────────────

/** The text as first loaded, so a cheat can be undone. */
let original = '';

function setBundleText(text, { remember = false } = {}) {
  $('bundle').value = text;
  if (remember) original = text;
  $('undo').disabled = $('bundle').value === original;
}

async function loadSample() {
  try {
    const res = await fetch('sample.bundle.json');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    setBundleText(await res.text(), { remember: true });
    $('cheat-note').hidden = true;
    await run();
  } catch (err) {
    showProblem(
      `Could not load the sample (${err.message}). Serve this folder over HTTP — browsers block ` +
        `module scripts on file:// — or paste a bundle instead.`,
    );
  }
}

// ── options ─────────────────────────────────────────────────────────────

/**
 * Witness keys are one per line: `kid publicKey` or `kid=publicKey`.
 *
 * @returns {Record<string, string>|undefined}  undefined when the box is empty,
 *   which is different from an empty set: it means "I have not pinned anyone".
 */
function readTrusted() {
  /** @type {Record<string, string>} */
  const out = {};
  for (const raw of $('trusted').value.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = line.match(/^(\S+?)\s*[=\s]\s*(\S+)$/);
    if (m) out[m[1]] = m[2];
  }
  return Object.keys(out).length ? out : undefined;
}

function readOptions() {
  return {
    expectRoot: $('expect-root').value.trim() || undefined,
    minWitnesses: Math.max(0, Math.floor(Number($('min-witnesses').value) || 0)),
    trustedWitnesses: readTrusted(),
  };
}

// ── verifying ───────────────────────────────────────────────────────────

let runId = 0;

async function run() {
  const mine = ++runId;
  const text = $('bundle').value.trim();

  if (!text) {
    $('result').hidden = true;
    return;
  }

  let bundle;
  try {
    bundle = JSON.parse(text);
  } catch (err) {
    showProblem(`That is not valid JSON: ${err.message}`);
    return;
  }

  const opts = readOptions();
  const res = await verifyBundle(bundle, opts);
  if (mine !== runId) return; // a newer run superseded this one
  render(res, bundle, opts);
}

function showProblem(message) {
  $('result').hidden = false;
  $('verdict').className = 'verdict bad';
  $('verdict').replaceChildren(el('b', { text: '✗ Nothing to verify' }), el('span', { text: message }));
  for (const id of ['facts', 'issues', 'notes', 'receipts']) $(id).replaceChildren();
}

/** @param {any} res @param {any} bundle @param {ReturnType<typeof readOptions>} opts */
function render(res, bundle, opts) {
  $('result').hidden = false;
  const s = res.summary;

  // ── verdict ──
  const verdict = $('verdict');
  verdict.className = 'verdict ' + (res.ok ? 'ok' : 'bad');
  if (res.ok) {
    verdict.replaceChildren(
      el('b', { text: '✓ Verified' }),
      el('span', {
        text: s.partial
          ? `A partial bundle: each of its ${s.entries} entries is proven genuine, but nothing here can show that other entries were not left out.`
          : `Every receipt is signed, provably in the tree, and the chain is unbroken from entry 0 to ${s.entries - 1}.`,
      }),
    );
  } else {
    verdict.replaceChildren(
      el('b', { text: `✗ ${res.issues.length} problem${res.issues.length === 1 ? '' : 's'} found` }),
      el('span', { text: 'This bundle has been altered, is incomplete, or is not what it claims to be. Do not rely on it.' }),
    );
  }

  // ── facts ──
  const facts = [];
  if (s) {
    facts.push(['Receipts', String(s.entries), s.partial ? `of ${s.treeSize} in the log` : 'in this bundle']);
    facts.push(['Signatures valid', `${s.signed} / ${s.entries}`, 'Ed25519']);
    facts.push([
      'Decisions',
      `${s.outcomes.allow} allowed · ${s.outcomes.deny} blocked`,
      s.outcomes.escalate ? `${s.outcomes.escalate} escalated` : 'each one recorded',
    ]);
    const last = s.checkpoints[s.checkpoints.length - 1];
    facts.push([
      'Checkpoints',
      String(s.checkpoints.length),
      last ? `latest covers ${last.size}` : 'none — nothing to compare against',
    ]);
    facts.push(['Merkle root', short(s.root, 12), `${s.treeSize} entries`]);
  }
  $('facts').replaceChildren(
    ...facts.map(([label, value, hint]) =>
      el('div', { class: 'fact' }, el('span', { class: 'fact-label', text: label }), el('b', { text: value }), el('span', { class: 'fact-hint', text: hint })),
    ),
  );

  // ── problems ──
  fill($('issues'), [
    ...res.issues.slice(0, 40).map((m) => el('li', {}, el('span', { class: 'x', text: '✗' }), el('span', { text: m }))),
    res.issues.length > 40 ? el('li', { class: 'dim' }, `…and ${res.issues.length - 40} more`) : null,
  ]);

  // ── notes: what "verified" does and does not establish ──
  const notes = [];
  const claimed = (bundle?.checkpoints ?? [])
    .map((cp) => (cp?.sigs ?? []).filter((x) => x?.role === 'witness').length)
    .reduce((a, b) => Math.max(a, b), 0);

  if (claimed > 0 && !opts.trustedWitnesses) {
    notes.push({
      title: 'Witnesses are claimed, not counted',
      body:
        `This bundle carries up to ${claimed} witness signature${claimed === 1 ? '' : 's'} on a checkpoint, but you have not said ` +
        `which witnesses you trust, so none are counted. A bundle's own keyring cannot vouch for its witnesses — an operator ` +
        `could invent as many as they liked.`,
      action: ['Trust the witnesses this bundle names (demo)', pinNamedWitnesses],
    });
  } else if (opts.trustedWitnesses && s) {
    const last = s.checkpoints[s.checkpoints.length - 1];
    if (last) {
      notes.push({
        title: 'Witnesses you pinned',
        body:
          `${last.witnesses} of the witnesses on the latest checkpoint are ones you trust` +
          (opts.minWitnesses ? `, and you require at least ${opts.minWitnesses} on every checkpoint.` : '. Set a minimum below to make that a requirement.'),
      });
    }
    if (res.ok && Number.isInteger(s.witnessedSize) && s.witnessedSize < s.treeSize) {
      notes.push({
        title: 'Not every entry is witnessed yet',
        body:
          `Your witnesses vouch for ${s.witnessedSize === 0 ? 'none' : `entries 0–${s.witnessedSize - 1}`} of ${s.treeSize}. ` +
          `Entries from ${s.witnessedSize} on are signed by the log alone, until a newer checkpoint is witnessed.`,
      });
    }
  }
  if (!opts.expectRoot && res.ok) {
    notes.push({
      title: 'Verified against the keys inside the bundle',
      body:
        'That shows the bundle has not been altered since it was signed. It does not show the keys belong to who you think, or that ' +
        'you were shown the same history as everyone else. To pin that, paste a root you obtained from somewhere else into “Expected root”.',
    });
  }
  $('notes').replaceChildren(
    ...notes.map((n) =>
      el('div', { class: 'note' }, el('b', { text: n.title }), el('p', { text: n.body }), n.action ? el('button', { type: 'button', class: 'btn-sm', text: n.action[0], 'data-act': 'pin' }) : null),
    ),
  );

  // ── receipts ──
  const rows = (s?.receipts ?? []).slice(0, 200);
  fill($('receipts'), [
    ...rows.map((r) => {
      const seq = r?.seq;
      const outcome = r?.decision?.outcome;
      const detail =
        outcome === 'allow'
          ? [r?.result?.status ?? (r?.phase === 'intent' ? 'committed' : ''), r?.result?.latencyMs != null ? `${r.result.latencyMs}ms` : '']
              .filter(Boolean)
              .join(' · ')
          : (r?.decision?.reason ?? '') + (r?.decision?.approval ? ` — approved by ${r.decision.approval.by}` : '');
      const amount = r?.action?.metrics?.amount_usd;
      return el(
        'tr',
        { class: res.badSeqs.has(seq) ? 'bad' : '' },
        el('td', { class: 'mono dim', text: String(seq ?? '?') }),
        el('td', {}, el('span', { class: `pill ${['allow', 'deny', 'escalate'].includes(outcome) ? outcome : ''}`, text: String(outcome ?? '?') })),
        el('td', { class: 'mono', text: String(r?.action?.target ?? '?') }),
        el('td', { class: 'mono dim', text: String(r?.phase ?? '') }),
        el('td', { class: 'dim', text: amount != null ? money(amount) : '' }),
        el('td', { text: detail }),
      );
    }),
    (s?.receipts?.length ?? 0) > 200 ? el('tr', {}, el('td', { colspan: 6, class: 'dim', text: `…and ${s.receipts.length - 200} more` })) : null,
  ]);
}

// ── the cheats ──────────────────────────────────────────────────────────

const b64u = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const hex = (bytes) => Array.from(bytes, (x) => x.toString(16).padStart(2, '0')).join('');
const sha256 = async (...parts) => {
  const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) (all.set(p, at), (at += p.length));
  return new Uint8Array(await crypto.subtle.digest('SHA-256', all));
};

/** A witness that has never existed, signing the latest checkpoint. */
async function inventWitness(b) {
  const cp = b.checkpoints?.[b.checkpoints.length - 1];
  if (!cp) throw new Error('this bundle has no checkpoint to witness');
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const kid = 'pw1' + hex((await sha256(raw)).slice(0, 16));
  const digest = await sha256(Uint8Array.of(0x03), enc.encode(canonicalize(cp.body)));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, digest));
  b.keyring[kid] = b64u(raw);
  cp.sigs.push({ role: 'witness', kid, sig: b64u(sig), ts: new Date().toISOString() });
}

const CHEATS = {
  edit(b) {
    const e = b.entries.find((x) => x.receipt?.action?.metrics?.amount_usd > 0);
    if (!e) throw new Error('there is no refund in this bundle to edit');
    const was = e.receipt.action.metrics.amount_usd;
    e.receipt.action.metrics.amount_usd = 1;
    return `Entry ${e.receipt.seq}: a ${money(was)} refund now says $1. Nothing else was touched.`;
  },
  delete(b) {
    if (b.entries.length < 3) throw new Error('too few entries to remove one');
    const [gone] = b.entries.splice(Math.floor(b.entries.length / 2), 1);
    return `Removed entry ${gone.receipt.seq}. Every other receipt, signature and proof is untouched.`;
  },
  tail(b) {
    const n = Math.min(3, b.entries.length - 1);
    if (n < 1) throw new Error('too few entries to cut');
    b.entries.splice(-n, n);
    return `Cut off the last ${n} entries and left everything else — including the claim that this is the whole log — as it was. Every remaining proof is genuine.`;
  },
  head(b) {
    b.head = 'ab'.repeat(32);
    return 'Replaced the head, which names the last entry, with something else.';
  },
  async witnesses(b) {
    const cp = b.checkpoints?.[b.checkpoints.length - 1];
    if (!cp) throw new Error('this bundle has no checkpoint to witness');
    cp.sigs = cp.sigs.filter((x) => x.role !== 'witness');
    for (let i = 0; i < 3; i++) await inventWitness(b);
    return 'Replaced the real witnesses on the latest checkpoint with three invented ones, each with a fresh key added to the bundle. Unpinned, that still verifies — which is exactly why witnesses must be pinned.';
  },
};

async function cheat(name) {
  let bundle;
  try {
    bundle = JSON.parse($('bundle').value);
  } catch {
    showProblem('Load a bundle first.');
    return;
  }
  try {
    const message = await CHEATS[name](bundle);
    setBundleText(JSON.stringify(bundle, null, 2));
    $('cheat-note').hidden = false;
    $('cheat-note').replaceChildren(el('b', { text: 'You did: ' }), message);
    await run();
  } catch (err) {
    $('cheat-note').hidden = false;
    $('cheat-note').replaceChildren(el('b', { text: 'Could not: ' }), err.message);
  }
}

/** Demo only: copy the witness keys the bundle itself names into the trust box. */
function pinNamedWitnesses() {
  try {
    const b = JSON.parse($('bundle').value);
    const seen = new Map();
    for (const cp of b.checkpoints ?? []) {
      for (const s of cp.sigs ?? []) {
        if (s.role === 'witness' && b.keyring?.[s.kid]) seen.set(s.kid, b.keyring[s.kid]);
      }
    }
    $('trusted').value = [...seen].map(([kid, key]) => `${kid} ${key}`).join('\n');
    if (!Number($('min-witnesses').value)) $('min-witnesses').value = '1';
    $('trust-details').open = true;
    run();
  } catch {
    /* nothing to pin */
  }
}

// ── wiring ──────────────────────────────────────────────────────────────

function readFile(file) {
  if (!file) return;
  file.text().then((t) => {
    setBundleText(t, { remember: true });
    $('cheat-note').hidden = true;
    run();
  });
}

let timer;
const later = () => {
  clearTimeout(timer);
  timer = setTimeout(run, 350);
};

$('load-sample').addEventListener('click', loadSample);
$('verify-btn').addEventListener('click', run);
$('clear').addEventListener('click', () => {
  setBundleText('', { remember: true });
  $('cheat-note').hidden = true;
  run();
});
$('undo').addEventListener('click', () => {
  setBundleText(original);
  $('cheat-note').hidden = true;
  run();
});
$('file').addEventListener('change', (e) => readFile(e.target.files?.[0]));
$('bundle').addEventListener('input', () => {
  $('undo').disabled = $('bundle').value === original;
  later();
});
for (const id of ['expect-root', 'min-witnesses', 'trusted']) $(id).addEventListener('input', later);

for (const btn of document.querySelectorAll('[data-cheat]')) {
  btn.addEventListener('click', () => cheat(btn.dataset.cheat));
}
$('notes').addEventListener('click', (e) => {
  if (e.target instanceof HTMLElement && e.target.dataset.act === 'pin') pinNamedWitnesses();
});

const drop = $('bundle');
for (const type of ['dragenter', 'dragover']) {
  drop.addEventListener(type, (e) => (e.preventDefault(), drop.classList.add('over')));
}
for (const type of ['dragleave', 'drop']) {
  drop.addEventListener(type, () => drop.classList.remove('over'));
}
drop.addEventListener('drop', (e) => {
  e.preventDefault();
  readFile(e.dataTransfer?.files?.[0]);
});

// ── start ───────────────────────────────────────────────────────────────

(async function start() {
  if (!(await ed25519Supported())) {
    $('unsupported').hidden = false;
    $('verify-btn').disabled = true;
    for (const b of document.querySelectorAll('[data-cheat], #load-sample')) b.disabled = true;
    return;
  }
  loadSample();
})();

// Whether the npm packages exist yet. `release.json` is written at deploy time
// from the registry, and it is our own file, so this asks no third party
// anything about the visitor.
fetch('release.json')
  .then((r) => (r.ok ? r.json() : null))
  .then((j) => {
    if (!j?.npm) return;
    $('install-npm').hidden = false;
    $('npm-version').textContent = j.npm;
    $('install-source-title').textContent = 'Or from source';
  })
  .catch(() => {});

// Deedwrit's own witness keys. `witness-keys.json` is witnesses/keys.json,
// copied in at deploy time and served from this origin — but read like any
// other input here: shown as text, never parsed as markup.
fetch('witness-keys.json')
  .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
  .then(showWitnessKeys)
  .catch(() => {
    // The page already links the record itself, just below.
    $('witness-keys-status').textContent =
      'The record could not be loaded here — it is in the repository, linked below.';
  });

/** @param {unknown} record */
function showWitnessKeys(record) {
  const entries = Array.isArray(record)
    ? record.filter((e) => e && typeof e.kid === 'string' && typeof e.publicKey === 'string')
    : [];
  if (!entries.length) {
    // The honest empty state. A key for a witness that isn't running would be
    // worse than none: an auditor would pin something nobody operates.
    $('witness-keys-status').textContent =
      'None yet. Deedwrit does not run a witness yet, so there is no key of ours to pin — and this page will not show one until there is.';
    return;
  }

  // Revoked keys stay listed — the record is append-only — but are never pinned.
  const pinnable = entries.filter((e) => !e.revokedAt);
  $('witness-keys-status').textContent =
    `${entries.length} key${entries.length === 1 ? '' : 's'} published; ${pinnable.length} to pin. ` +
    'A retired key stopped signing but what it signed stays good, so it is still pinned; a revoked one never is.';

  fill($('witness-key-list'), entries.map((e) => {
    const state = e.revokedAt ? 'revoked' : e.retiredAt ? 'retired' : 'active';
    const label = e.revokedAt
      ? `revoked ${String(e.revokedAt)} — do not pin`
      : e.retiredAt ? `retired ${String(e.retiredAt)} — still pinned` : 'active';
    const meta = [e.operator, e.node, e.addedAt ? `added ${e.addedAt}` : null]
      .filter((x) => typeof x === 'string' && x).join(' · ');
    return el('li', { class: `wkey ${state}` },
      el('div', { class: 'wkey-head' },
        el('span', { class: 'wkey-kid', text: e.kid }),
        el('span', { class: 'wkey-state', text: label })),
      meta ? el('p', { class: 'wkey-meta', text: meta }) : null,
      el('code', { class: 'wkey-pub', text: e.publicKey }),
      typeof e.note === 'string' && e.note ? el('p', { class: 'wkey-meta', text: e.note }) : null,
    );
  }));
  $('witness-key-list').hidden = false;

  if (!pinnable.length) return;
  const button = $('pin-deedwrit');
  button.hidden = false;
  button.addEventListener('click', () => {
    // Added to whatever is already there, never replacing it: someone pinning
    // their own auditor's witness should not lose it by clicking this.
    const have = readTrusted() ?? {};
    const add = pinnable.filter((e) => have[e.kid] !== e.publicKey);
    if (add.length) {
      $('trusted').value = [
        $('trusted').value.trim(),
        '# Deedwrit, from witnesses/keys.json',
        ...add.map((e) => `${e.kid} ${e.publicKey}`),
      ].filter(Boolean).join('\n');
    }
    $('trust-details').open = true;
    run();
  });
}

// The hero transcript resolves once on load, starting from a fully visible
// resting state: without this script, or with reduced motion, it is all there.
(function stage() {
  const term = $('verify-term');
  if (!term || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  term.classList.add('staged');
  term.querySelectorAll('.reveal').forEach((node, i) => setTimeout(() => node.classList.add('in'), 300 + i * 420));
})();
