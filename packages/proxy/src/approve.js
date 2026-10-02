import fs from 'node:fs';
import { createInterface } from 'node:readline';

/**
 * Human-in-the-loop approval for actions the policy escalates.
 *
 * The contract every approver here honours: **an escalation that cannot be
 * resolved is a denial.** Timeouts, a missing terminal, an unreachable webhook,
 * a malformed reply — all resolve to `deny`. The alternative is a system that
 * quietly degrades into "allow everything" exactly when it is under stress,
 * which is when the guardrail was supposed to matter most.
 */

/**
 * @typedef {object} ApprovalRequest
 * @property {string} target
 * @property {unknown} params      Already redacted — an approver sees a preview, not secrets.
 * @property {string} reason
 * @property {string[]} rules
 * @property {import('@vouchwell/core').Actor} actor
 */

/**
 * @typedef {object} ApprovalOutcome
 * @property {boolean} approved
 * @property {string} by
 * @property {string} [note]
 */

/**
 * Never approves. The default, and the right default: a team that has not yet
 * wired up an approver should find escalated actions blocked, not waved
 * through.
 *
 * @returns {(req: ApprovalRequest) => Promise<ApprovalOutcome>}
 */
export function denyingApprover() {
  return async () => ({
    approved: false,
    by: 'policy:no-approver',
    note: 'the policy escalated this action and no approver is configured',
  });
}

/**
 * Ask a human at the terminal.
 *
 * Reads from the controlling TTY rather than stdin, because stdin is the MCP
 * channel and is already spoken for. Without a TTY — CI, a daemon — this
 * denies rather than hanging forever.
 *
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs=120000]
 * @param {string} [opts.by='tty']
 * @returns {(req: ApprovalRequest) => Promise<ApprovalOutcome>}
 */
export function ttyApprover(opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 120_000;
  const by = opts.by ?? 'tty';

  return async (req) => {
    /** @type {number|undefined} */
    let fd;
    try {
      fd = fs.openSync(process.platform === 'win32' ? '\\\\.\\CONIN$' : '/dev/tty', 'r');
    } catch {
      return {
        approved: false,
        by: 'policy:no-tty',
        note: 'escalation needed a human but no terminal is attached',
      };
    }

    const input = fs.createReadStream('', { fd });
    const out = fs.createWriteStream('', {
      fd: fs.openSync(process.platform === 'win32' ? '\\\\.\\CONOUT$' : '/dev/tty', 'w'),
    });

    out.write('\n');
    out.write('  ┌─ Vouchwell: approval required ' + '─'.repeat(28) + '\n');
    out.write(`  │ tool     ${req.target}\n`);
    out.write(`  │ for      ${req.actor.principal}\n`);
    out.write(`  │ reason   ${req.reason}\n`);
    out.write(`  │ rules    ${req.rules.join(', ') || '—'}\n`);
    const preview = JSON.stringify(req.params);
    out.write(`  │ args     ${preview.length > 160 ? preview.slice(0, 157) + '…' : preview}\n`);
    out.write('  └' + '─'.repeat(58) + '\n');

    const rl = createInterface({ input, terminal: false });

    const answer = await new Promise((resolve) => {
      const timer = setTimeout(() => resolve(null), timeoutMs);
      out.write(`  Approve? [y/N] (${Math.round(timeoutMs / 1000)}s) `);
      rl.once('line', (line) => {
        clearTimeout(timer);
        resolve(line.trim().toLowerCase());
      });
    });

    rl.close();
    out.write('\n');
    out.end();

    if (answer === null) {
      return { approved: false, by: 'policy:timeout', note: 'no answer before the deadline' };
    }
    const approved = answer === 'y' || answer === 'yes';
    return { approved, by, note: approved ? 'approved at the terminal' : 'declined at the terminal' };
  };
}

/**
 * Ask a service — Slack, PagerDuty, an internal approvals app.
 *
 * @param {object} opts
 * @param {string} opts.url
 * @param {Record<string,string>} [opts.headers]
 * @param {number} [opts.timeoutMs=60000]
 * @returns {(req: ApprovalRequest) => Promise<ApprovalOutcome>}
 */
export function webhookApprover(opts) {
  const timeoutMs = opts.timeoutMs ?? 60_000;

  return async (req) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(opts.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(opts.headers ?? {}) },
        body: JSON.stringify(req),
        signal: controller.signal,
      });
      if (!res.ok) {
        return {
          approved: false,
          by: 'policy:approver-error',
          note: `approver returned HTTP ${res.status}`,
        };
      }
      const body = await res.json();
      return {
        approved: body?.approved === true,
        by: typeof body?.by === 'string' ? body.by : 'webhook',
        note: typeof body?.note === 'string' ? body.note : undefined,
      };
    } catch (err) {
      return {
        approved: false,
        by: 'policy:approver-unreachable',
        note: `could not reach the approver: ${/** @type {Error} */ (err).message}`,
      };
    } finally {
      clearTimeout(timer);
    }
  };
}

/**
 * @param {object} [config]
 * @param {'deny'|'tty'|'webhook'} [config.mode]
 * @param {string} [config.url]
 * @param {Record<string,string>} [config.headers]
 * @param {number} [config.timeoutMs]
 * @returns {(req: ApprovalRequest) => Promise<ApprovalOutcome>}
 */
export function approverFrom(config = {}) {
  switch (config.mode) {
    case 'tty':
      return ttyApprover(config);
    case 'webhook':
      if (!config.url) throw new Error('approval.mode "webhook" requires a url');
      return webhookApprover({ url: config.url, headers: config.headers, timeoutMs: config.timeoutMs });
    case 'deny':
    case undefined:
      return denyingApprover();
    default:
      throw new Error(`unknown approval mode "${config.mode}"`);
  }
}
