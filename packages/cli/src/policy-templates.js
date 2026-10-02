import fs from 'node:fs';
import { POLICY_TEMPLATES, composePolicy } from '@deedwrit/core';
import { c, out, ok, bad, info, heading } from './ui.js';

/**
 * `dw policy templates` and `dw policy template <id...>`.
 *
 * Templates are ordinary policy, so the useful path is: pick some, write
 * them to a file, replay last week's traffic against it with `dw policy
 * test`, then enforce. Nothing here enforces anything by itself.
 */

/** @param {any} args */
export function cmdPolicyTemplates(args) {
  if (args.json) {
    out(JSON.stringify(POLICY_TEMPLATES.map(({ id, title, summary, notes }) => ({ id, title, summary, notes })), null, 2));
    return 0;
  }
  heading('Policy templates');
  for (const t of POLICY_TEMPLATES) {
    out(`  ${c.cyan(t.id.padEnd(26))} ${t.summary}`);
  }
  out('');
  info(`Details and caveats: ${c.cyan('dw policy template <id> --explain')}`);
  info(`Combine several:     ${c.cyan('dw policy template secrets destructive-sql payments --out deedwrit.policy.json')}`);
  out('');
  return 0;
}

/** @param {any} args */
export function cmdPolicyTemplate(args) {
  const ids = args._.slice(2).flatMap((/** @type {string} */ a) => String(a).split(',')).filter(Boolean);
  if (ids.length === 0) {
    bad('which templates? `dw policy template <id...>`; `dw policy templates` lists them');
    return 2;
  }
  const doc = composePolicy(ids, { name: args.name });

  if (args.explain) {
    for (const id of doc.templates) {
      const t = /** @type {any} */ (POLICY_TEMPLATES.find((x) => x.id === id));
      heading(`${t.id} · ${t.title}`);
      out(`  ${t.summary}`);
      for (const n of t.notes) out(`  ${c.grey('•')} ${n}`);
      out('');
    }
    return 0;
  }

  const text = JSON.stringify(doc, null, 2) + '\n';
  if (!args.out) {
    out(text.trimEnd());
    return 0;
  }
  try {
    fs.writeFileSync(args.out, text, { flag: args.force ? 'w' : 'wx' });
  } catch (err) {
    if (/** @type {NodeJS.ErrnoException} */ (err).code === 'EEXIST') {
      bad(`${args.out} already exists; pass --force to replace it`);
      return 1;
    }
    throw err;
  }
  ok(`Wrote ${args.out}: ${doc.templates.join(', ')}`);
  out('');
  info(`Before it can block anything, replay your recorded traffic against it:`);
  out(`    ${c.cyan(`dw policy test ${args.out}`)}`);
  out('');
  return 0;
}

/**
 * The policy file `dw init --template a,b` writes in place of the starter.
 *
 * @param {string|true} spec
 * @returns {string}
 */
export function templatePolicyText(spec) {
  const ids = String(spec === true ? '' : spec).split(',').map((s) => s.trim()).filter(Boolean);
  return JSON.stringify(composePolicy(ids), null, 2) + '\n';
}
