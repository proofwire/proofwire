import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { regexProblem, wildcardMatch } from '../src/safe-regex.js';
import { Policy, globMatch } from '../src/policy.js';

test('patterns that can take exponential time are refused, with a way to rewrite them', () => {
  for (const [pattern, says] of /** @type {[string, RegExp][]} */ ([
    ['(a+)+$', /repeats inside itself.*"a\+"/],
    ['^(\\w*\\s?)*x', /repeats inside itself/],
    ['(x{1,3})+', /repeats inside itself/],
    ['(a|ab)*c', /alternatives.*character class/],
    ['(\\w|\\d)+', /alternatives/],
    ['(a?a?)+', /optional parts/],
    ['((a|aa)b)+', /alternatives/],
    ['(?:(?:a+)b)*', /repeats inside itself/],
    ['(?<w>a+){2,}', /repeats inside itself/],
    ['(a)\\1', /backreference/],
    ['(?<n>a)\\k<n>', /backreference/],
    ['a'.repeat(1001), /longer than 1000/],
  ])) {
    const problem = regexProblem(pattern);
    assert.ok(problem, `${pattern} should be refused`);
    assert.match(problem, says, pattern);
  }
});

test('ordinary policy patterns pass', () => {
  for (const pattern of [
    '^.*\\brm\\b', '[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}', '(?:foo){3}', '(?:\\d{3}-)+\\d{4}',
    'colou?r', '(a|b)c', '^(?=.*\\brm\\b)(?=.*\\s-\\w*r)', '\\bDROP\\s+(TABLE|DATABASE)\\b',
    'sk_(live|test)_[A-Za-z0-9]{24,}', '[(+*|]+', '\\u{1F600}+', 'a{2,5}', '\\(a+\\)+', '[\\]]+',
  ]) {
    assert.equal(regexProblem(pattern), null, pattern);
  }
});

test('a policy with a refused pattern does not load, and says which rule', () => {
  assert.throws(
    () => new Policy({ version: 1, rules: [{ id: 'bad-email', when: { 'params.to': { matches: '^([a-z]+\\.?)+@x$' } }, then: 'deny' }] }),
    /bad-email.*"params\.to".*exponential/,
  );
  // Both authoring forms are checked.
  assert.throws(() => new Policy({ version: 1, rules: [{ id: 'r', when: { target: { matches: '/(a+)+$/i' } }, then: 'deny' }] }), /exponential/);
  assert.throws(() => new Policy({ version: 1, rules: [{ id: 'r', when: { target: { matches: '(?i)(a|b)*' } }, then: 'deny' }] }), /exponential/);
});

test('globs match as before, without a regex', () => {
  for (const [p, v, want] of /** @type {[string, string, boolean][]} */ ([
    ['*', '', true], ['stripe.*', 'stripe.refund', true], ['stripe.*', 'stripe', false], ['*.refund', 'stripe.refund', true],
    ['a*b*c', 'axxbyyc', true], ['a*b*c', 'axxbyy', false], ['a.b', 'axb', false], ['a+b', 'a+b', true], ['**', 'x', true],
    ['*x*', 'abc', false], ['', '', true], ['', 'a', false], ['(x)', '(x)', true],
  ])) {
    assert.equal(wildcardMatch(p, v), want, `${p} ~ ${v}`);
    assert.equal(globMatch(p, v), want, `${p} ~ ${v}`);
  }
  // A glob built into a regex backtracks polynomially in its stars.
  const t = performance.now();
  assert.equal(globMatch('*a'.repeat(40) + 'b', 'a'.repeat(5000)), false);
  assert.ok(performance.now() - t < 1000);
});

test('no pattern the check accepts is slow on inputs built to make regexes backtrack', () => {
  // Random small patterns from the constructs that cause trouble, kept only
  // when accepted, then run against the classic hostile inputs. A hang blocks
  // the event loop, so this runs in a child that is killed after 20 seconds.
  const script = `
    import { regexProblem } from ${JSON.stringify(new URL('../src/safe-regex.js', import.meta.url).href)};
    let seed = 7;
    const rnd = (n) => { seed = (Math.imul(seed, 1103515245) + 12345) >>> 0; return (seed >>> 16) % n; };
    const atoms = ['a', 'b', 'ab', '[ab]', '\\\\w', '.', '\\\\s'];
    const quant = ['', '', '*', '+', '?', '{1,3}', '{2}', '{2,}'];
    function gen(depth) {
      const parts = [];
      const n = 1 + rnd(3);
      for (let i = 0; i < n; i++) {
        let p = depth > 0 && rnd(3) === 0 ? '(?:' + gen(depth - 1) + (rnd(3) === 0 ? '|' + gen(depth - 1) : '') + ')' : atoms[rnd(atoms.length)];
        parts.push(p + quant[rnd(quant.length)]);
      }
      return parts.join('');
    }
    const inputs = ['a'.repeat(30) + '!', 'ab'.repeat(20) + '!', 'b'.repeat(30) + '!', ' '.repeat(30) + '!', 'aab'.repeat(12) + '!'];
    let accepted = 0, refused = 0, worst = 0, worstPattern = '';
    for (let i = 0; i < 3000; i++) {
      const body = '^' + gen(3) + '$';
      if (regexProblem(body)) { refused++; continue; }
      let rx;
      try { rx = new RegExp(body); } catch { continue; }
      accepted++;
      for (const s of inputs) {
        const t = performance.now();
        rx.test(s);
        const ms = performance.now() - t;
        if (ms > worst) { worst = ms; worstPattern = body; }
      }
    }
    console.log(JSON.stringify({ accepted, refused, worst, worstPattern }));
    if (worst > 200) process.exit(1);
  `;
  const res = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 20_000 });
  assert.equal(res.signal, null, 'an accepted pattern hung');
  assert.equal(res.status, 0, `${res.stdout}${res.stderr}`);
  const r = JSON.parse(res.stdout);
  assert.ok(r.accepted > 500 && r.refused > 500, res.stdout);
});
