import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { ProofLog, verifyBundle, findUnfinished } from '@vouchwell/core';
import { c, out, bad, warn, info, heading, kv } from './ui.js';
import { witnessKeysFrom } from './witness-keys.js';

/**
 * `vw report` — an evidence pack for an auditor or an assessor.
 *
 * What goes in the pack is evidence, and the report around it is an index to
 * that evidence, not a verdict. Vouchwell can show what an agent did, what the
 * policy decided, who approved what, and that none of it was altered. Whether
 * that satisfies a regulation or a control is an assessor's call, so the report
 * says "supports", never "complies", and its mapping to frameworks is
 * a starting point for that conversation.
 *
 * The pack, in one directory:
 *
 *   evidence.bundle.json   the signed receipts and proofs; `vw check` verifies it
 *   report.html            for people: self-contained, no scripts, prints cleanly
 *   summary.json           the same facts, for tools
 *   SHA256SUMS             so a copy can be checked against the original
 */

/**
 * The facts a report is built from. Pure: the same receipts give the same
 * summary, whatever the date.
 *
 * @param {any[]} entries   Receipts in the period, in log order.
 * @param {object} [opts]
 * @param {any[]} [opts.unfinished]  Actions that started and never finished,
 *   from `findUnfinished` over the *whole* log: judged from the period alone,
 *   a call whose result landed just after it ends would look unfinished.
 *   Defaults to judging the entries given.
 * @returns {object}
 */
export function summarise(entries, opts = {}) {
  const calls = entries.filter((r) => r.phase !== 'outcome');
  const outcomes = entries.filter((r) => r.phase === 'outcome' || r.phase === 'atomic');

  /** @type {Record<string, number>} */
  const byTool = {};
  /** @type {Record<string, number>} */
  const byPrincipal = {};
  /** @type {Record<string, number>} */
  const byAgent = {};
  /** @type {Record<string, number>} */
  const wouldBlock = {};
  /** @type {Record<string, number>} */
  const spend = {};
  /** @type {Map<string, { hash: string, firstSeen: string, lastSeen: string, calls: number }>} */
  const policies = new Map();
  const denials = [];
  /** Escalations, and what became of them: approved or declined, by whom. */
  const decisions = [];
  let allowed = 0;
  let denied = 0;
  let unenforced = 0;

  for (const r of calls) {
    const d = r.decision;
    byTool[r.action.target] = (byTool[r.action.target] ?? 0) + 1;
    byPrincipal[r.actor.principal] = (byPrincipal[r.actor.principal] ?? 0) + 1;
    byAgent[r.actor.agent] = (byAgent[r.actor.agent] ?? 0) + 1;

    if (d.policy) {
      const p = policies.get(d.policy) ?? { hash: d.policy, firstSeen: r.ts, lastSeen: r.ts, calls: 0 };
      p.lastSeen = r.ts;
      p.calls++;
      policies.set(d.policy, p);
    }
    if (d.enforced === false) unenforced++;
    if (d.wouldBe) {
      for (const rule of d.rules?.length ? d.rules : ['(default)']) wouldBlock[rule] = (wouldBlock[rule] ?? 0) + 1;
    }
    const review = d.approval ?? d.declined;
    if (review) {
      decisions.push({
        seq: r.seq,
        ts: r.ts,
        target: r.action.target,
        principal: r.actor.principal,
        decision: d.approval ? 'approved' : 'declined',
        by: review.by,
        // A fallback (no approver, a timeout) is a decision the policy made
        // for want of a person, and is shown as that.
        human: !String(review.by).startsWith('policy:'),
        at: review.at,
        note: review.note ?? '',
      });
    }
    if (d.outcome === 'allow') {
      allowed++;
      for (const [k, v] of Object.entries(r.action.metrics ?? {})) spend[k] = (spend[k] ?? 0) + Number(v);
    } else {
      denied++;
      denials.push({ seq: r.seq, ts: r.ts, target: r.action.target, principal: r.actor.principal, rules: d.rules ?? [], reason: d.reason ?? '' });
    }
  }

  // Tool errors, not counting the calls that never returned at all: those are
  // listed on their own below.
  const errors = outcomes.filter((r) => r.result?.status === 'error' && r.result?.code !== 'unfinished');
  // With no clock given, every open intent counts: that keeps this pure.
  const found = opts.unfinished ?? unfinishedIn(entries, { now: Infinity });
  const first = entries[0]?.ts ?? null;
  const last = entries.at(-1)?.ts ?? null;
  const top = (/** @type {Record<string, number>} */ m) =>
    Object.entries(m).sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count }));

  return {
    period: {
      first,
      last,
      days: first && last ? Math.max(1, Math.ceil((Date.parse(last) - Date.parse(first)) / 86_400_000)) : 0,
    },
    receipts: entries.length,
    calls: calls.length,
    allowed,
    denied,
    decisions,
    approvedByPerson: decisions.filter((x) => x.decision === 'approved' && x.human).length,
    declinedByPerson: decisions.filter((x) => x.decision === 'declined' && x.human).length,
    unanswered: decisions.filter((x) => !x.human).length,
    denials,
    monitor: { unenforced, wouldBlock: top(wouldBlock) },
    errors: errors.length,
    unfinished: found.length,
    unfinishedActions: found,
    spend,
    tools: top(byTool),
    principals: top(byPrincipal),
    agents: top(byAgent),
    policies: [...policies.values()],
  };
}

/**
 * Intents without an outcome, and outcomes recorded as unfinished, as one list
 * in log order.
 *
 * @param {any[]} entries
 * @param {{ now?: number }} [clock]  Passed to `findUnfinished`.
 * @param {(u: any) => boolean} [keep]
 */
function unfinishedIn(entries, clock = {}, keep = () => true) {
  const found = findUnfinished(entries, clock);
  return [
    ...found.unfinished.map((u) => ({ ...u, why: 'no result recorded' })),
    ...found.abandoned.map((u) => ({ ...u, why: 'recorder stopped before the reply' })),
  ].filter(keep).sort((a, b) => a.seq - b.seq);
}

/**
 * What each framework asks for, what in this pack speaks to it, and where. The
 * wording is deliberately "supports": this is where an assessor starts, not
 * what they conclude.
 *
 * @param {any} s  A summary.
 */
export function frameworkMap(s) {
  const integrity = 'Integrity section; evidence.bundle.json (verify with `vw check`)';
  return {
    'ai-act': {
      title: 'EU AI Act (Regulation (EU) 2024/1689)',
      note:
        'Applies to high-risk AI systems. Which obligations fall on you depends on your role (provider or deployer) and the system\'s classification. Confirm with counsel; application dates for high-risk obligations have been subject to change.',
      rows: [
        ['Art. 12(1): automatic recording of events over the system\'s lifetime', `Every tool call is recorded as a signed receipt before it runs (${s.calls} calls in this period).`, 'Activity; evidence.bundle.json'],
        ['Art. 12(2)(a): events relevant to identifying situations that may present a risk', `${s.denied} refused, ${s.decisions.length} escalated to a person, ${s.monitor.wouldBlock.reduce((n, w) => n + w.count, 0)} that policy would have stopped in monitor mode, ${s.errors} tool errors.`, 'Refused actions; Human decisions; Monitor mode'],
        ['Art. 12(2)(b): facilitating post-market monitoring', 'Per-tool, per-principal and per-agent activity over the period, and the policy versions in force.', 'Activity; Policies in force'],
        ['Art. 12(2)(c): monitoring of operation by deployers', 'Each call names the agent, the principal it acted for, and the session.', 'Activity'],
        ['Art. 14: human oversight', `${s.approvedByPerson} escalations approved and ${s.declinedByPerson} declined by a named person, with when and why; ${s.unanswered} closed by a fallback because nobody answered.`, 'Human decisions'],
        ['Art. 19 / Art. 26(6): keep logs at least six months', `This pack covers ${s.period.days} day(s). Retention is how long you keep the log, which this report can state but not ensure.`, 'Period'],
        ['Integrity of the records', 'Hash-chained, signed and Merkle-committed; any alteration or deletion fails verification. Witness signatures, where present, bind the history to third parties.', integrity],
      ],
    },
    soc2: {
      title: 'SOC 2 (AICPA Trust Services Criteria)',
      note: 'Illustrative mapping of this evidence to commonly relevant criteria. Your auditor decides which controls this evidence supports.',
      rows: [
        ['CC6.1: logical access to protected resources is restricted', 'Agent tool calls pass a policy before reaching the tool; refusals are recorded with the rule that fired.', 'Refused actions; Policies in force'],
        ['CC7.2: system components are monitored for anomalies', `Refusals, escalations, tool errors (${s.errors}) and unfinished calls (${s.unfinished}) are recorded as they happen.`, 'Refused actions; Activity'],
        ['CC7.3: security events are evaluated', 'Escalated events carry the person who decided, their decision and note.', 'Human decisions'],
        ['CC8.1: changes are authorised and tracked', `Each receipt names the policy version (hash) in force; ${s.policies.length} version(s) were in force this period, with when each was first and last used.`, 'Policies in force'],
        ['CC4.1: ongoing evaluations of controls', 'The log re-verifies end to end, and third-party witnesses can countersign its state.', integrity],
      ],
    },
  };
}

/** HTML-escape everything that came from the log. */
function h(/** @type {unknown} */ s) {
  return String(s ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch] ?? ch);
}

/**
 * @param {string[]} head
 * @param {Array<Array<unknown>>} rows
 * @param {number[]} [ids]  Columns holding identifiers (hashes, sequence
 *   numbers, tool names), set in monospace and allowed to break anywhere.
 * @param {string} [cls]
 */
function table(head, rows, ids = [], cls = '') {
  if (!rows.length) return '<p class="empty">None in this period.</p>';
  return `<table${cls ? ` class="${cls}"` : ''}><thead><tr>${head.map((x) => `<th>${h(x)}</th>`).join('')}</tr></thead><tbody>${rows
    .map((r) => `<tr>${r.map((x, i) => `<td${ids.includes(i) ? ' class="id"' : ''}>${h(x)}</td>`).join('')}</tr>`)
    .join('')}</tbody></table>`;
}

/**
 * The report for people. Self-contained (no scripts, no fetches), so it opens
 * the same from an email attachment in five years as it does today.
 *
 * @param {any} r  The full report object (see `buildReport`).
 */
export function renderHtml(r) {
  const s = r.summary;
  const frameworks = frameworkMap(s);
  const selected = r.frameworks.map((f) => frameworks[f]).filter(Boolean);
  const cap = 200;
  const clipped = (/** @type {any[]} */ list) => (list.length > cap ? `First ${cap} of ${list.length}; all are in evidence.bundle.json.` : '');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Vouchwell evidence report · ${h(r.log.id)}</title>
<style>
  :root { --ink:#16181d; --ink2:#4a5060; --line:#dde1e8; --ok:#0f7b4f; --bad:#b42318; --hold:#9a6700; --bg:#fff; --panel:#f6f7f9; }
  * { box-sizing: border-box; }
  body { font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--ink); background: var(--bg); margin: 0; }
  main { max-width: 980px; margin: 0 auto; padding: 32px 20px 64px; }
  h1 { font-size: 24px; margin: 0 0 4px; }
  h2 { font-size: 17px; margin: 36px 0 10px; padding-top: 12px; border-top: 1px solid var(--line); }
  .sub, .empty, .note { color: var(--ink2); }
  .note { font-size: 13px; }
  .mono, code { font-family: ui-monospace, "SFMono-Regular", Consolas, monospace; font-size: 12.5px; }
  dl { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 4px 16px; margin: 0; }
  dt { color: var(--ink2); } dd { margin: 0; overflow-wrap: anywhere; }
  .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 14px 16px; }
  .verdict { font-weight: 700; font-size: 15px; }
  .ok { color: var(--ok); } .bad { color: var(--bad); } .hold { color: var(--hold); }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; }
  .stat { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 10px 12px; }
  .stat b { display: block; font-size: 20px; }
  table { width: 100%; border-collapse: collapse; margin: 6px 0; font-size: 13px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; overflow-wrap: break-word; }
  table.fw td:nth-child(3) { width: 26%; font-size: 12px; color: var(--ink2); overflow-wrap: anywhere; }
  td.id { font-family: ui-monospace, "SFMono-Regular", Consolas, monospace; font-size: 12.5px; overflow-wrap: anywhere; }
  th { color: var(--ink2); font-weight: 600; }
  .scroll { overflow-x: auto; }
  footer { margin-top: 48px; color: var(--ink2); font-size: 12px; }
  @media print { main { padding: 0; } h2 { break-after: avoid; } tr { break-inside: avoid; } }
</style></head>
<body><main>
<h1>Evidence report</h1>
<p class="sub">Log <span class="mono">${h(r.log.id)}</span> · generated ${h(r.generatedAt)} by ${h(r.generator)}</p>

<div class="panel">
  <p style="margin:0 0 8px" class="verdict ${r.integrity.ok ? 'ok' : 'bad'}">${r.integrity.ok
    ? `Verified: all ${h(s.receipts)} receipts in this pack are signed, unaltered and part of this log.`
    : `Verification FAILED: ${h(r.integrity.issues.length)} problem(s). Do not rely on this pack.`}</p>
  <p class="note" style="margin:0">Don't take this page's word for it. Anyone can re-check the pack independently:
  <code>vw check evidence.bundle.json${r.integrity.pinned ? ' --witnesses 1 --witness-keys &lt;keys&gt;' : ''}</code>,
  then compare the root below with the one they hold.</p>
</div>

<h2>Period</h2>
<dl>
  <dt>first receipt</dt><dd>${h(s.period.first ?? '—')}</dd>
  <dt>last receipt</dt><dd>${h(s.period.last ?? '—')}</dd>
  <dt>covers</dt><dd>${h(s.period.days)} day(s)${r.filter.since || r.filter.until ? ` (requested: ${h(r.filter.since ?? 'start')} to ${h(r.filter.until ?? 'now')})` : ''}</dd>
</dl>

<h2>Integrity</h2>
<dl>
  <dt>log</dt><dd class="mono">${h(r.log.id)}</dd>
  <dt>signing key</dt><dd class="mono">${h(r.log.kid)}</dd>
  <dt>receipts in log</dt><dd>${h(r.integrity.treeSize)}${r.integrity.partial ? ` (this pack holds ${h(s.receipts)}: a filtered export, each entry proven part of the full log)` : ''}</dd>
  <dt>root</dt><dd class="mono">${h(r.integrity.root)}</dd>
  <dt>checkpoints</dt><dd>${h(r.integrity.checkpoints)}</dd>
  <dt>witnessed</dt><dd>${r.integrity.witnessSignatures
    ? `${h(r.integrity.witnessSignatures)} witness signature(s) on the latest checkpoint${r.integrity.pinned
      ? `; <span class="ok">${h(r.integrity.pinnedWitnesses)} verified against keys the report's author pinned</span>`
      : '; <span class="hold">not checked against pinned keys</span>'}`
    : '<span class="hold">no witness signatures: the log vouches for itself only</span>'}</dd>
  ${r.integrity.ok ? '' : `<dt>problems</dt><dd class="bad">${r.integrity.issues.slice(0, 20).map(h).join('<br>')}</dd>`}
</dl>

<h2>Activity</h2>
<div class="stats">
  <div class="stat"><b>${h(s.calls)}</b>tool calls</div>
  <div class="stat"><b class="ok">${h(s.allowed)}</b>allowed</div>
  <div class="stat"><b class="bad">${h(s.denied)}</b>refused</div>
  <div class="stat"><b class="hold">${h(s.decisions.length)}</b>escalated to a person</div>
  <div class="stat"><b>${h(s.errors)}</b>tool errors</div>
  <div class="stat"><b>${h(s.unfinished)}</b>unfinished</div>
</div>
<div class="scroll">${table(['tool', 'calls'], s.tools.slice(0, 25).map((t) => [t.name, t.count]), [0])}</div>
<div class="scroll">${table(['on behalf of', 'calls'], s.principals.slice(0, 25).map((t) => [t.name, t.count]))}</div>
<div class="scroll">${table(['agent', 'calls'], s.agents.slice(0, 25).map((t) => [t.name, t.count]), [0])}</div>
${Object.keys(s.spend).length ? `<div class="scroll">${table(['metric', 'total allowed'], Object.entries(s.spend).map(([k, v]) => [k, Number(v).toFixed(2)]), [0])}</div>` : ''}

${s.unfinished ? `<h2>Actions that never finished</h2>
<p class="note"><span class="hold">These calls were authorised and sent, and no result was ever recorded.</span>
The recorder stopped, or was stopped, while they were out. Whether each one took effect is not in this log:
check it with the system it called.</p>
<div class="scroll">${table(['#', 'when', 'tool', 'on behalf of', 'session', 'why'], s.unfinishedActions.slice(0, cap).map((u) => [u.seq, u.ts, u.target, u.principal, u.session, u.why]), [0, 2, 4])}</div>
<p class="note">${h(clipped(s.unfinishedActions))}</p>
` : ''}<h2>Human decisions</h2>
<p class="note">Every escalation and what became of it, as recorded in the signed receipt:
${h(s.approvedByPerson)} approved and ${h(s.declinedByPerson)} declined by a person, ${h(s.unanswered)} closed by a fallback.</p>
<div class="scroll">${table(['#', 'when', 'tool', 'on behalf of', 'decision', 'by', 'note'], s.decisions.slice(0, cap).map((a) => [a.seq, a.ts, a.target, a.principal, a.decision, a.human ? a.by : `${a.by} (no person)`, a.note]), [0, 2, 5])}</div>
<p class="note">${h(clipped(s.decisions))}</p>

<h2>Refused actions</h2>
<p class="note">Calls the policy stopped, or a person declined. None of them reached the tool.</p>
<div class="scroll">${table(['#', 'when', 'tool', 'on behalf of', 'rules', 'reason'], s.denials.slice(0, cap).map((d) => [d.seq, d.ts, d.target, d.principal, d.rules.join(', '), d.reason]), [0, 2, 4])}</div>
<p class="note">${h(clipped(s.denials))}</p>

${s.monitor.unenforced ? `<h2>Monitor mode</h2>
<p class="note"><span class="hold">${h(s.monitor.unenforced)} call(s) ran with the policy observed but not enforced.</span> These would have been stopped:</p>
<div class="scroll">${table(['rule', 'calls'], s.monitor.wouldBlock.map((w) => [w.name, w.count]), [0])}</div>` : ''}

<h2>Policies in force</h2>
<p class="note">Each receipt names the exact policy version that decided it, by hash.</p>
<div class="scroll">${table(['policy hash', 'first used', 'last used', 'calls'], s.policies.map((p) => [p.hash, p.firstSeen, p.lastSeen, p.calls]), [0])}</div>

${selected.map((f) => `<h2>${h(f.title)}</h2>
<p class="note">${h(f.note)}</p>
<div class="scroll">${table(['requirement', 'what this pack shows', 'where'], f.rows, [], 'fw')}</div>`).join('\n')}

<h2>What this report does not show</h2>
<ul class="note">
  <li>Actions that did not pass through Vouchwell. It records what its proxy saw; a credential used around it leaves no receipt.</li>
  <li>The contents of arguments and results. Receipts commit to them by hash, and the pack carries no payloads.</li>
  <li>Whether a decision was right. It shows what was decided, by what rule or person, and that the record is intact.</li>
  <li>Compliance. This is evidence for an assessment, not its conclusion.</li>
</ul>

<footer>Files in this pack: ${r.files.map((f) => `<span class="mono">${h(f)}</span>`).join(', ')} and <span class="mono">SHA256SUMS</span>.</footer>
</main></body></html>
`;
}

/**
 * @param {object} opts
 * @param {ProofLog} opts.log
 * @param {string} [opts.since]
 * @param {string} [opts.until]
 * @param {string[]} opts.frameworks
 * @param {Record<string, string> | undefined} opts.trustedWitnesses
 * @param {string} opts.generator
 */
export function buildReport(opts) {
  const since = opts.since ? new Date(opts.since).toISOString() : undefined;
  const until = opts.until ? new Date(opts.until).toISOString() : undefined;
  const filter = since || until ? (/** @type {any} */ r) => (!since || r.ts >= since) && (!until || r.ts <= until) : undefined;

  const bundle = opts.log.bundle(filter ? { filter } : {});
  const verified = verifyBundle(bundle);
  const latest = bundle.checkpoints.at(-1);
  const witnessSignatures = latest ? latest.sigs.filter((/** @type {any} */ x) => x.role === 'witness').length : 0;

  // How many of the latest checkpoint's witnesses verify against the pinned
  // keys: the largest n for which verification with minWitnesses n passes.
  let pinnedWitnesses = 0;
  if (opts.trustedWitnesses) {
    for (let n = Object.keys(opts.trustedWitnesses).length; n >= 1; n--) {
      if (verifyBundle(bundle, { minWitnesses: n, trustedWitnesses: opts.trustedWitnesses }).ok) {
        pinnedWitnesses = n;
        break;
      }
    }
  }

  return {
    bundle,
    report: {
      kind: 'vouchwell.report',
      v: 1,
      generatedAt: new Date().toISOString(),
      generator: opts.generator,
      log: { id: opts.log.logId, kid: opts.log.identity.kid },
      filter: { since: since ?? null, until: until ?? null },
      frameworks: opts.frameworks,
      integrity: {
        ok: verified.ok,
        issues: verified.issues,
        treeSize: bundle.treeSize,
        partial: bundle.partial,
        root: bundle.root,
        checkpoints: bundle.checkpoints.length,
        witnessSignatures,
        pinned: Boolean(opts.trustedWitnesses),
        pinnedWitnesses,
      },
      summary: summarise(bundle.entries.map((/** @type {any} */ e) => e.receipt), {
        unfinished: unfinishedIn(opts.log.entries, {}, (u) => (!since || u.ts >= since) && (!until || u.ts <= until)),
      }),
      files: ['evidence.bundle.json', 'report.html', 'summary.json'],
    },
  };
}

/**
 * @param {any} args
 * @param {{ dir: string }} where
 * @param {string} version
 */
export function cmdReport(args, where, version) {
  const frameworks = String(args.framework ?? 'ai-act,soc2').split(',').map((f) => f.trim()).filter(Boolean);
  const unknown = frameworks.filter((f) => !['ai-act', 'soc2'].includes(f));
  if (unknown.length) {
    bad(`unknown framework "${unknown.join(', ')}": use ai-act, soc2, or both`);
    return 2;
  }
  for (const flag of ['since', 'until']) {
    if (args[flag] !== undefined && Number.isNaN(Date.parse(String(args[flag])))) {
      bad(`--${flag} must be a date, e.g. 2026-07-01`);
      return 2;
    }
  }

  let trustedWitnesses;
  try {
    trustedWitnesses = witnessKeysFrom(args);
  } catch (err) {
    bad(/** @type {Error} */ (err).message);
    return 2;
  }

  const log = ProofLog.open(where.dir, { readOnly: true });
  const { bundle, report } = buildReport({
    log,
    since: args.since,
    until: args.until,
    frameworks,
    trustedWitnesses,
    generator: `vouchwell ${version}`,
  });

  const outDir = path.resolve(String(args.out ?? `vouchwell-report-${log.logId}-${report.generatedAt.slice(0, 10)}`));
  fs.mkdirSync(outDir, { recursive: true });
  const write = (/** @type {string} */ name, /** @type {string} */ text) => fs.writeFileSync(path.join(outDir, name), text);
  write('evidence.bundle.json', JSON.stringify(bundle, null, 2) + '\n');
  write('summary.json', JSON.stringify(report, null, 2) + '\n');
  write('report.html', renderHtml(report));
  write(
    'SHA256SUMS',
    report.files
      .map((f) => `${createHash('sha256').update(fs.readFileSync(path.join(outDir, f))).digest('hex')}  ${f}`)
      .join('\n') + '\n',
  );

  const s = report.summary;
  heading('Evidence pack written');
  kv([
    ['directory', path.relative(process.cwd(), outDir) || '.'],
    ['period', s.period.first ? `${s.period.first.slice(0, 10)} → ${s.period.last.slice(0, 10)} (${s.period.days} day(s))` : c.grey('no receipts')],
    ['calls', `${s.calls} · ${s.allowed} allowed · ${s.denied} refused · ${s.decisions.length} escalated`],
    ['integrity', report.integrity.ok ? c.green('verified') : c.red(`FAILED: ${report.integrity.issues.length} problem(s)`)],
    ['witnesses', report.integrity.witnessSignatures ? `${report.integrity.witnessSignatures} on the latest checkpoint${report.integrity.pinned ? `, ${report.integrity.pinnedWitnesses} pinned` : ''}` : c.yellow('none')],
    ['frameworks', frameworks.join(', ')],
  ]);
  out('');
  info(`Open ${c.cyan(path.join(path.relative(process.cwd(), outDir) || '.', 'report.html'))}. Send the whole directory.`);
  if (!report.integrity.witnessSignatures) {
    warn('No witness has countersigned this log, so the pack proves consistency, not that history was never rewritten.');
    warn(`Get a checkpoint witnessed first: ${c.cyan('vw cosign --remote <witness>')}`);
  }
  out('');
  return report.integrity.ok ? 0 : 1;
}
