import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Slack approvals.
 *
 * When a policy escalates a call, the hub posts it to the organisation's Slack
 * channel with Approve and Deny buttons. A click comes back to
 * `POST /v1/integrations/slack/interactions`, signed by Slack, and decides the
 * approval exactly as the console would. The agent's proxy, long-polling the
 * hub, sees the decision within a second either way.
 *
 * Deliberately built on an incoming webhook plus interactivity, with no bot
 * token: the hub can post to one channel and hear clicks on its own messages,
 * and nothing else. A leaked webhook URL lets someone post to that channel; it
 * does not let them read Slack or approve anything, because approval needs a
 * request signed with the app's signing secret.
 */

/** Slack's hosts for incoming webhooks and interaction response URLs. */
export const SLACK_HOSTS = Object.freeze(['hooks.slack.com']);

/** How far Slack's request timestamp may drift before a request is refused. */
const MAX_SKEW_SECONDS = 300;

/**
 * Verify a request came from Slack, following
 * https://api.slack.com/authentication/verifying-requests-from-slack: an
 * HMAC-SHA256 over `v0:<timestamp>:<raw body>` with the app's signing secret,
 * and a timestamp within five minutes, so a captured request can't be replayed
 * later.
 *
 * @param {object} args
 * @param {string} args.signingSecret
 * @param {string | undefined} args.timestamp  `X-Slack-Request-Timestamp`
 * @param {string | undefined} args.signature  `X-Slack-Signature`
 * @param {string} args.rawBody                The body exactly as received.
 * @param {number} [args.nowMs]
 * @returns {boolean}
 */
export function verifySlackSignature({ signingSecret, timestamp, signature, rawBody, nowMs = Date.now() }) {
  if (!signingSecret || !timestamp || !signature) return false;
  if (!/^\d{1,12}$/.test(timestamp)) return false;
  if (Math.abs(nowMs / 1000 - Number(timestamp)) > MAX_SKEW_SECONDS) return false;
  const expected = Buffer.from(
    'v0=' + createHmac('sha256', signingSecret).update(`v0:${timestamp}:${rawBody}`).digest('hex'),
  );
  const given = Buffer.from(signature);
  return expected.length === given.length && timingSafeEqual(expected, given);
}

/**
 * Whether a URL is one the hub may send to on an organisation's behalf.
 *
 * On a hosted hub, whoever configures an integration is a tenant, and a URL
 * they supply is a URL the hub will fetch. Restricting it to Slack's own hosts
 * keeps that from becoming a way to make the hub call internal addresses.
 *
 * @param {string} raw
 * @param {readonly string[]} hosts  Allowed `host` values (hostname[:port]).
 * @returns {string | null} A reason it is refused, or null.
 */
export function slackUrlProblem(raw, hosts = SLACK_HOSTS) {
  let url;
  try {
    url = new URL(String(raw));
  } catch {
    return 'not a URL';
  }
  if (!hosts.includes(url.host)) return `must be on ${hosts.join(' or ')}`;
  // Only a test configuration lists a non-Slack host, and only there is plain
  // HTTP tolerated; Slack's own hosts are always HTTPS.
  if (url.protocol !== 'https:' && SLACK_HOSTS.includes(url.host)) return 'must be https';
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return 'must be https';
  if (url.username || url.password) return 'must not contain credentials';
  return null;
}

/** Slack's mrkdwn treats only these three as markup. */
function escape(/** @type {unknown} */ s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * @param {unknown} value
 * @param {number} max
 */
function preview(value, max) {
  let text = JSON.stringify(value ?? {}, null, 2);
  if (text.length > max) text = text.slice(0, max) + '\n…';
  // A run of three backticks inside the block would end it early.
  return escape(text.replace(/`{3,}/g, (m) => 'ˋ'.repeat(m.length)));
}

/**
 * The message posted when a call is escalated.
 *
 * @param {object} a
 * @param {string} a.id
 * @param {string} a.target
 * @param {string} a.log
 * @param {unknown} a.params   The redacted preview the proxy sent; never raw.
 * @param {string} a.reason
 * @param {string[]} a.rules
 * @param {string} a.principal
 * @param {string} a.agent
 * @param {string} a.expiresAt
 * @param {string} consoleUrl
 */
export function approvalMessage(a, consoleUrl) {
  const expires = Math.floor(Date.parse(a.expiresAt) / 1000);
  return {
    text: `Approval needed: ${a.target}`,
    blocks: [
      { type: 'header', text: { type: 'plain_text', text: `Approval needed: ${a.target}`.slice(0, 150) } },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Tool*\n\`${escape(a.target)}\`` },
          { type: 'mrkdwn', text: `*On behalf of*\n${escape(a.principal) || '—'}` },
          { type: 'mrkdwn', text: `*Agent*\n${escape(a.agent) || '—'}` },
          { type: 'mrkdwn', text: `*Log*\n${escape(a.log)}` },
          { type: 'mrkdwn', text: `*Rules*\n${escape(a.rules.join(', ')) || '—'}` },
          { type: 'mrkdwn', text: `*Expires*\n<!date^${expires}^{time}|${escape(a.expiresAt)}>` },
        ],
      },
      { type: 'section', text: { type: 'mrkdwn', text: `*Why*\n${escape(a.reason) || '—'}` } },
      {
        type: 'section',
        text: { type: 'mrkdwn', text: `*Arguments* (secrets already masked)\n\`\`\`${preview(a.params, 2500)}\`\`\`` },
      },
      {
        type: 'actions',
        block_id: 'vouchwell_decision',
        elements: [
          {
            type: 'button',
            action_id: 'vouchwell_approve',
            style: 'primary',
            text: { type: 'plain_text', text: 'Approve' },
            value: a.id,
            confirm: {
              title: { type: 'plain_text', text: 'Approve this action?' },
              text: { type: 'mrkdwn', text: `The agent will run \`${escape(a.target)}\`, and your name goes on the receipt.` },
              confirm: { type: 'plain_text', text: 'Approve' },
              deny: { type: 'plain_text', text: 'Cancel' },
            },
          },
          {
            type: 'button',
            action_id: 'vouchwell_deny',
            style: 'danger',
            text: { type: 'plain_text', text: 'Deny' },
            value: a.id,
          },
        ],
      },
      {
        type: 'context',
        elements: [{ type: 'mrkdwn', text: `${escape(a.id)} · <${consoleUrl}|Open in the console>` }],
      },
    ],
  };
}

/**
 * What the message becomes once decided: the buttons go, the outcome stays.
 *
 * @param {object} a
 * @param {string} a.target
 * @param {string} a.id
 * @param {'approved' | 'denied' | 'expired'} status
 * @param {string} by    Who decided, as the receipt will record it.
 * @param {boolean} [already]  Someone else got there first.
 */
export function decidedMessage(a, status, by, already = false) {
  const icon = status === 'approved' ? ':white_check_mark:' : status === 'denied' ? ':no_entry:' : ':hourglass:';
  const verb = status === 'expired' ? 'Expired before anyone decided' : `${status === 'approved' ? 'Approved' : 'Denied'} by ${escape(by)}`;
  return {
    replace_original: true,
    text: `${a.target}: ${status}`,
    blocks: [
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `${icon} \`${escape(a.target)}\` — ${verb}${already ? ' (before this click)' : ''}`,
        },
      },
      { type: 'context', elements: [{ type: 'mrkdwn', text: escape(a.id) }] },
    ],
  };
}

/**
 * How the approval records a Slack user. Stable id first, since display names
 * change; the name is there for people reading the receipt.
 *
 * @param {{ id?: string, username?: string, name?: string }} user
 */
export function slackActor(user) {
  const id = String(user?.id ?? 'unknown').replace(/[^A-Za-z0-9]/g, '').slice(0, 32) || 'unknown';
  const name = String(user?.username ?? user?.name ?? '').replace(/[^\w.@-]/g, '').slice(0, 64);
  return name ? `slack:${id} (${name})` : `slack:${id}`;
}
