/**
 * Refusing policy patterns that can take exponential time to match.
 *
 * JavaScript's regex engine backtracks, and a policy's `matches` patterns run
 * against tool arguments the agent chose. A pattern like `(a+)+$` takes
 * exponential time on `aaaa…!`: thirty characters stall the check for
 * seconds, forty for hours, and an agent (or whatever prompt steered it) can
 * write those characters. A synchronous match can't be interrupted, so the
 * defence is to refuse such patterns when a policy is loaded or published,
 * before they can ever run.
 *
 * What is refused, and why each is the exponential case:
 *
 *   - a repeated group that repeats inside itself: `(a+)+`, `(\w*\s?)*`,
 *     `(x{1,3})+`. Every way of dividing the input between the inner and outer
 *     repetition is tried before a failing match gives up;
 *   - a repeated group with alternatives or optional parts, at any depth:
 *     `(a|ab)*`, `(\w|\d)+`, `(a?a?)+`, `((a|aa)b)+`. When they can match the
 *     same text more than one way, every way is tried. Whether they can isn't
 *     cheap to decide, so all are refused; a character class (`[\w\d]+`)
 *     usually says the same thing safely;
 *   - backreferences (`\1`, `\k<name>`), which no linear strategy can match.
 *
 * Outside a repeated group, `?`, alternatives and an exact count (`{3}`) are
 * always fine. This is deliberately a little stricter than necessary: a rejected pattern gets a
 * message saying how to rewrite it, while a missed one hangs a production agent.
 */

/** Longest pattern accepted; policy patterns are short, and a huge one is a mistake or an attack. */
export const MAX_PATTERN_LENGTH = 1000;

/**
 * Why a regex body may take exponential time to match, or null if it can't.
 *
 * @param {string} body  The pattern without delimiters or flags.
 * @returns {string | null}
 */
export function regexProblem(body) {
  if (body.length > MAX_PATTERN_LENGTH) return `is longer than ${MAX_PATTERN_LENGTH} characters`;

  /**
   * `repeats`: something inside repeats. `choice`: something inside can match
   * more than one way without repeating (alternatives, `?`, `{n,m}`).
   * @typedef {{ start: number, repeats: boolean, choice: boolean }} Group
   */
  /** @type {Group[]} */
  const stack = [{ start: 0, repeats: false, choice: false }];
  /** The group or atom just closed, which a following quantifier applies to. */
  /** @type {{ group: Group | null, start: number } | null} */
  let last = null;

  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    const top = stack[stack.length - 1];

    if (ch === '\\') {
      const next = body[i + 1] ?? '';
      if (/[1-9]/.test(next) || (next === 'k' && body[i + 2] === '<')) {
        return 'uses a backreference, which can take exponential time to match';
      }
      last = { group: null, start: i };
      i++; // the escaped character
      // \u{…}, \x.., \p{…}: skip a braced part so its braces aren't read as a quantifier.
      if (/[up]/i.test(next) && body[i + 1] === '{') {
        const close = body.indexOf('}', i + 1);
        if (close !== -1) i = close;
      }
      continue;
    }

    if (ch === '[') {
      const start = i;
      i++;
      if (body[i] === '^') i++;
      if (body[i] === ']') i++; // a literal ] first in a class
      while (i < body.length && body[i] !== ']') {
        if (body[i] === '\\') i++;
        i++;
      }
      last = { group: null, start };
      continue;
    }

    if (ch === '(') {
      stack.push({ start: i, repeats: false, choice: false });
      last = null;
      // Skip the group's prefix (?: (?= (?! (?<= (?<! (?<name>) so its
      // characters aren't read as a quantifier or atom.
      if (body[i + 1] === '?') {
        if (body[i + 2] === '<' && body[i + 3] !== '=' && body[i + 3] !== '!') {
          const close = body.indexOf('>', i);
          i = close === -1 ? i + 2 : close;
        } else {
          i += body[i + 2] === '<' ? 3 : 2;
        }
      }
      continue;
    }

    if (ch === ')') {
      if (stack.length === 1) return null; // unbalanced; `new RegExp` reports it
      const closed = /** @type {Group} */ (stack.pop());
      const parent = stack[stack.length - 1];
      // What is inside a group is inside its parent too.
      if (closed.repeats) parent.repeats = true;
      if (closed.choice) parent.choice = true;
      last = { group: closed, start: closed.start };
      continue;
    }

    if (ch === '|') {
      top.choice = true;
      last = null;
      continue;
    }

    const q = quantifierAt(body, i);
    if (q) {
      if (q.repeats) {
        const g = last?.group;
        if (g && g.repeats) {
          return `repeats the group "${body.slice(g.start, i + q.length)}", which repeats inside itself, ` +
            'and can take exponential time to match. Remove the inner repetition or the outer one ' +
            '(for example "(a+)+" is just "a+")';
        }
        if (g && g.choice) {
          return `repeats the group "${body.slice(g.start, i + q.length)}", which has alternatives or ` +
            'optional parts, and can take exponential time to match. Use a character class instead ' +
            '(for example "(a|b)+" is "[ab]+"), or match the group once';
        }
        top.repeats = true;
      } else if (!q.exact) {
        top.choice = true; // `?`: present or not
      }
      i += q.length - 1;
      // A lazy or possessive suffix belongs to the quantifier.
      if (body[i + 1] === '?') i++;
      last = null;
      continue;
    }

    last = { group: null, start: i };
  }
  return null;
}

/**
 * The quantifier at `i`, if there is one: its length, whether it repeats
 * (anything but `?` and an exact `{n}`), and whether it is an exact count.
 *
 * @param {string} s
 * @param {number} i
 * @returns {{ length: number, repeats: boolean, exact: boolean } | null}
 */
function quantifierAt(s, i) {
  const ch = s[i];
  if (ch === '*' || ch === '+') return { length: 1, repeats: true, exact: false };
  if (ch === '?') return { length: 1, repeats: false, exact: false };
  if (ch === '{') {
    const m = /^\{(\d+)(,(\d*))?\}/.exec(s.slice(i, i + 24));
    if (!m) return null; // a literal brace
    const exact = m[2] === undefined || m[3] === m[1];
    return { length: m[0].length, repeats: !exact, exact };
  }
  return null;
}

/**
 * `*` wildcard matching in linear space and O(pattern × value) time, with no
 * regex: a glob built into a regex (`.*a.*a.*a…b`) backtracks polynomially
 * in the number of stars.
 *
 * @param {string} pattern
 * @param {string} value
 * @returns {boolean}
 */
export function wildcardMatch(pattern, value) {
  let p = 0;
  let v = 0;
  let star = -1;
  let resume = 0;
  while (v < value.length) {
    if (p < pattern.length && pattern[p] !== '*' && pattern[p] === value[v]) {
      p++;
      v++;
    } else if (p < pattern.length && pattern[p] === '*') {
      star = p++;
      resume = v;
    } else if (star !== -1) {
      p = star + 1;
      v = ++resume;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] === '*') p++;
  return p === pattern.length;
}
