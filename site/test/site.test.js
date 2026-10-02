// Static checks on the website. The verifier is tested against the core
// implementation in verify.test.js; this file is about the page around it —
// the properties that quietly rot: a link that stops resolving, a third-party
// request slipping in, a root-absolute path that works locally and 404s once the
// site is served from /vouchwell/.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SITE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ROOT = path.resolve(SITE, '..');
const read = (f) => readFileSync(path.join(SITE, f), 'utf8');

const REPO = 'https://github.com/vouchwell/vouchwell';
const INDEX = read('index.html');
const NOT_FOUND = read('404.html');
const APP = read('app.js');
const VERIFY = read('verify.js');
const FONTS_CSS = read('fonts/fonts.css');

const attrs = (html, name) => [...html.matchAll(new RegExp(`\\s${name}="([^"]*)"`, 'g'))].map((m) => m[1]);
const isExternal = (u) => /^(https?:)?\/\//i.test(u);
const isRelative = (u) => !isExternal(u) && !u.startsWith('/') && !u.startsWith('#') && !/^[a-z][a-z0-9+.-]*:/i.test(u);

/**
 * Files the page fetches that are not in site/ but copied in when Pages
 * deploys, published path → source in the repository. Kept to a list someone
 * has to edit on purpose: anything else the page references must be in site/.
 */
const DEPLOYED = {
  'witness-keys.json': 'witnesses/keys.json',
};

/** Where a referenced file comes from, relative to the repository root. */
const sourceOf = (file) => DEPLOYED[file] ?? `site/${file}`;

/** Every file the page pulls in, as paths under site/. */
function referencedFiles() {
  const refs = [
    ...attrs(INDEX, 'href'), ...attrs(INDEX, 'src'),
    ...[...FONTS_CSS.matchAll(/url\("([^"]+)"\)/g)].map((m) => `fonts/${m[1]}`),
    ...[...APP.matchAll(/fetch\('([^']+)'\)/g)].map((m) => m[1]),
    ...[...APP.matchAll(/from '(\.[^']+)'/g)].map((m) => m[1]),
  ].filter(isRelative);
  return refs.map((ref) => (ref === './' ? 'index.html' : path.posix.normalize(ref.split(/[?#]/)[0])));
}

test('every relative reference resolves to a file that is published', () => {
  const files = referencedFiles();
  assert.ok(files.length >= 6, `expected to find the page's own assets, found ${files.length}`);
  for (const file of files) {
    assert.ok(existsSync(path.join(ROOT, sourceOf(file))), `${file} does not exist (looked for ${sourceOf(file)})`);
  }
});

test('files copied in at deploy time are copied in, and redeploy when they change', () => {
  const pages = readFileSync(path.join(ROOT, '.github/workflows/pages.yml'), 'utf8');
  for (const [published, source] of Object.entries(DEPLOYED)) {
    assert.ok(referencedFiles().includes(published), `${published} is listed as deployed but the page never fetches it`);
    assert.ok(
      pages.includes(`cp ${source} _site/${published}`),
      `pages.yml does not copy ${source} to ${published}, so the deployed page would 404 on it`,
    );
    assert.ok(pages.includes(`'${source}'`), `pages.yml does not redeploy when ${source} changes`);
  }
});

test('everything the page references is tracked by git, not merely present on this machine', (t) => {
  // .gitignore has `*.bundle.json`, so the sample bundle sat on disk, every test
  // passed here, and the first place anyone found out was a red CI run — with a
  // deployed page whose sample would have 404ed. This is where it should show.
  const git = spawnSync('git', ['ls-files', '--', 'site', ...Object.values(DEPLOYED)], { cwd: ROOT, encoding: 'utf8' });
  if (git.error || git.status !== 0 || !git.stdout.trim()) return t.skip('not a git checkout');
  const tracked = new Set(git.stdout.split('\n').map((f) => f.trim()));
  for (const file of new Set(referencedFiles())) {
    const source = sourceOf(file);
    assert.ok(tracked.has(source), `${source} exists but git does not track it — check .gitignore (git check-ignore -v ${source})`);
  }
});

test('no root-absolute paths: they break the moment the site is served from /vouchwell/', () => {
  for (const [name, html] of [['index.html', INDEX], ['app.js', APP]]) {
    const rooted = [...attrs(html, 'href'), ...attrs(html, 'src')].filter((u) => u.startsWith('/') && !u.startsWith('//'));
    assert.deepEqual(rooted, [], `${name} has root-absolute references`);
  }
  assert.doesNotMatch(APP, /fetch\('\//, 'app.js fetches a root-absolute path');
  // The 404 is served at whatever path was mistyped, so its one root-relative
  // link is rewritten by a script that knows whether this is a project site.
  assert.deepEqual(attrs(NOT_FOUND, 'href').filter((u) => u.startsWith('/')), ['/']);
  assert.match(NOT_FOUND, /location\.pathname\.indexOf\('\/vouchwell\/'\)/);
});

test('in-page anchors point at ids that exist', () => {
  const ids = new Set(attrs(INDEX, 'id'));
  const anchors = attrs(INDEX, 'href').filter((u) => u.startsWith('#'));
  assert.ok(anchors.length >= 4);
  for (const a of anchors) assert.ok(ids.has(a.slice(1)), `${a} has no matching id`);
  // Ids that app.js looks up by name must be in the markup, or it fails at runtime.
  for (const id of new Set([...APP.matchAll(/\$\('([\w-]+)'\)/g)].map((m) => m[1]))) {
    assert.ok(ids.has(id), `app.js reads #${id}, which index.html does not define`);
  }
});

test('repository links go to this repository, and documents they name exist', () => {
  const links = attrs(INDEX, 'href').filter((u) => u.startsWith('https://github.com/'));
  assert.ok(links.length >= 6);
  for (const link of links) {
    assert.ok(link === REPO || link.startsWith(`${REPO}/`), `${link} is not under ${REPO}`);
    const doc = link.match(/\/blob\/main\/(.+)$/)?.[1];
    if (doc) assert.ok(existsSync(path.join(ROOT, doc)), `${link} points at ${doc}, which is not in the repository`);
  }
});

test('the site makes no third-party requests', () => {
  // Resources: nothing loaded, embedded, or fetched from another origin.
  const loaded = [
    ...[...INDEX.matchAll(/<link\b[^>]*\shref="([^"]*)"/g)].map((m) => m[1]),
    ...attrs(INDEX, 'src'),
    ...[...INDEX.matchAll(/url\(\s*['"]?([^)'"]+)/g)].map((m) => m[1]),
    ...[...INDEX.matchAll(/@import\s+['"]?([^'";)]+)/g)].map((m) => m[1]),
    ...[...FONTS_CSS.matchAll(/url\(\s*['"]?([^)'"]+)/g)].map((m) => m[1]),
  ];
  for (const u of loaded) assert.ok(!isExternal(u), `loads ${u} from another origin`);

  // The scripts never name a host at all: no URLs, no sockets, no beacons.
  for (const [name, src] of [['app.js', APP], ['verify.js', VERIFY]]) {
    const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    assert.doesNotMatch(code, /https?:\/\//, `${name} contains a URL`);
    assert.doesNotMatch(code, /XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts/, `${name} opens a channel`);
    for (const m of code.matchAll(/fetch\(\s*([^)]*)\)/g)) assert.match(m[1], /^'[^'/][^']*'$/, `${name}: fetch(${m[1]}) is not a same-origin literal`);
  }
});

test('a Content-Security-Policy enforces it', () => {
  const policy = INDEX.match(/http-equiv="Content-Security-Policy"\s+content="([^"]+)"/)?.[1];
  assert.ok(policy, 'index.html has no Content-Security-Policy');
  const dirs = Object.fromEntries(policy.split(';').map((d) => d.trim().split(/\s+/)).filter((d) => d[0]).map(([k, ...v]) => [k, v]));

  assert.deepEqual(dirs['default-src'], ["'none'"]);
  assert.deepEqual(dirs['script-src'], ["'self'"], 'scripts must come from this origin only, with no unsafe-inline or unsafe-eval');
  assert.deepEqual(dirs['connect-src'], ["'self'"], 'the page may talk to nothing but itself');
  assert.deepEqual(dirs['base-uri'], ["'none'"]);
  assert.deepEqual(dirs['form-action'], ["'none'"]);
  for (const [dir, sources] of Object.entries(dirs)) {
    for (const s of sources) assert.doesNotMatch(s, /^(\*|https?:)/, `${dir} allows ${s}`);
  }
  // Inline styles are used; inline scripts must not be — the policy has no
  // hash or nonce that would let one run.
  assert.doesNotMatch(INDEX.replace(/<script[^>]*\ssrc="[^"]*"[^>]*><\/script>/g, ''), /<script/i, 'index.html has an inline script');
  assert.equal(attrs(INDEX, 'src').filter((s) => s.endsWith('.js')).join(), 'app.js');
  assert.doesNotMatch(INDEX, /\son[a-z]+="/i, 'index.html has an inline event handler, which the policy blocks');
});

test('untrusted text never reaches an HTML parser', () => {
  // A pasted bundle is attacker-controlled. Every node is built with
  // createElement and textContent; these are the ways that would stop being true.
  for (const [name, src] of [['app.js', APP], ['verify.js', VERIFY]]) {
    const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    assert.doesNotMatch(code, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|createContextualFragment|DOMParser|eval\(|new Function|setTimeout\(\s*['"`]/, `${name} parses a string as code or markup`);
  }
});

test('no reference to a domain that does not exist', () => {
  for (const [name, text] of [['index.html', INDEX], ['404.html', NOT_FOUND], ['app.js', APP], ['verify.js', VERIFY]]) {
    assert.doesNotMatch(text, /vouchwell\.(dev|io|com|ai)\b/i, `${name} names a domain nobody owns`);
  }
});

test('fonts are self-hosted, present, and licensed', () => {
  const files = [...FONTS_CSS.matchAll(/url\("([^"]+)"\)/g)].map((m) => m[1]);
  assert.equal(files.length, 4);
  for (const f of files) {
    assert.ok(existsSync(path.join(SITE, 'fonts', f)), `fonts/${f} missing`);
    // WOFF2 magic: a truncated download or an HTML error page saved as .woff2 fails here.
    assert.equal(readFileSync(path.join(SITE, 'fonts', f)).subarray(0, 4).toString('latin1'), 'wOF2', `${f} is not a WOFF2 file`);
  }
  const licences = readdirSync(path.join(SITE, 'fonts')).filter((f) => f.startsWith('OFL-'));
  assert.ok(licences.length >= 3, 'the SIL OFL requires the licence to travel with the fonts');
  for (const l of licences) assert.match(read(`fonts/${l}`), /SIL OPEN FONT LICENSE/i, `${l} is not the licence text`);
});

test('release.json says whether the packages exist, and says it plainly', () => {
  const rel = JSON.parse(read('release.json'));
  assert.deepEqual(Object.keys(rel), ['npm']);
  assert.ok(rel.npm === null || /^\d+\.\d+\.\d+(-[\w.]+)?$/.test(rel.npm), `npm must be null or a version, got ${JSON.stringify(rel.npm)}`);
});

test('the page is well-formed enough to be found and shared', () => {
  assert.match(INDEX, /<html lang="en">/);
  assert.match(INDEX, /<meta name="viewport" content="width=device-width, initial-scale=1">/);
  assert.match(INDEX, /<title>[^<]{10,}<\/title>/);
  assert.match(INDEX, /<meta name="description" content="[^"]{60,}">/);
  assert.equal((INDEX.match(/<h1[\s>]/g) ?? []).length, 1, 'exactly one <h1>');
  assert.match(NOT_FOUND, /<meta name="robots" content="noindex">/);
  const ids = attrs(INDEX, 'id');
  assert.equal(new Set(ids).size, ids.length, `duplicate ids: ${ids.filter((x, i) => ids.indexOf(x) !== i)}`);
});

test('paid tiers never look purchasable, since nothing is', () => {
  // The one thing worse than no pricing page is one that quietly starts
  // implying a checkout exists. Every non-"Open" tier's call to action must
  // go to the waitlist issue form, not somewhere that looks transactional,
  // and must carry its own "not live yet" disclaimer right next to it.
  //
  // Plain indexOf/slice rather than one clever regex: the block nests a
  // variable amount of markup per card, and a regex built to match its exact
  // shape breaks the moment that shape changes — indexOf on markers that are
  // true by construction (every card opens with the same class, the whole
  // block ends at the next 2-space-indented </div>) does not.
  const open = INDEX.indexOf('<div class="tiers">');
  assert.ok(open !== -1, 'could not find the .tiers block');
  const close = INDEX.indexOf('\n  </div>', open);
  assert.ok(close !== -1, 'could not find the end of the .tiers block');
  const tiersBlock = INDEX.slice(open, close);

  const starts = [...tiersBlock.matchAll(/<div class="tier( now)?">/g)];
  assert.ok(starts.length >= 4, `expected at least 4 tier cards, found ${starts.length}`);
  const cards = starts.map((m, i) => ({
    isNow: m[1] === ' now',
    body: tiersBlock.slice(m.index, starts[i + 1]?.index ?? tiersBlock.length),
  }));

  for (const { isNow, body } of cards) {
    const cta = body.match(/<a class="btn[^"]*" href="([^"]+)"[^>]*>([^<]+)<\/a>/);
    assert.ok(cta, `a tier card has no call-to-action button:\n${body.slice(0, 200)}`);
    // href is raw HTML source text — "&amp;" between query params, correctly,
    // is what a browser decodes to "&" before ever handing it to JavaScript.
    const [, rawHref, label] = cta;
    const href = rawHref.replace(/&amp;/g, '&');

    if (isNow) {
      // The one tier that exists today may link into the page itself.
      assert.match(href, /^#/, `the available tier's CTA should be an in-page link, got ${href}`);
      continue;
    }

    assert.ok(
      href.startsWith('https://github.com/vouchwell/vouchwell/issues/new?') && /[?&]labels=waitlist(?:&|$)/.test(href),
      `"${label}" (href="${href}") does not open a labelled waitlist issue`,
    );
    assert.doesNotMatch(label, /buy|purchase|subscribe|checkout|start (trial|now)/i, `"${label}" reads as purchasable`);
    assert.match(body, /not yet live/i, `a paid tier's card has no "not yet live" disclaimer`);
  }
});

test('the logo reads vouchwell in the header, the footer and the 404 page', () => {
  const marks = (html) => [...html.matchAll(/class="mark"[^>]*>(.*?)<\/(?:a|span)>/g)].map((m) => m[1].replace(/<[^>]+>/g, ''));
  assert.deepEqual(marks(INDEX), ['vouchwell', 'vouchwell']);
  assert.deepEqual(marks(NOT_FOUND), ['vouchwell']);
});
