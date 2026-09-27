# Slack approvals

When a policy **escalates** a call, the hub posts it to a Slack channel with
**Approve** and **Deny** buttons. Whoever clicks decides it, exactly as if
they had used the console. The agent waiting on the decision continues within
a second, and the receipt records who approved, by Slack user ID and name,
for example `slack:U024BE7LH (dana)`.

It needs a hub (not a witness-only node) reachable from the internet over
HTTPS, because Slack delivers the button clicks to it. [`DEPLOY.md`](DEPLOY.md)
sets that up.

---

## Set it up (about 10 minutes)

### 1. Create the Slack app from a manifest

Go to <https://api.slack.com/apps>, choose **Create New App**, then **From a
manifest**, and pick your workspace. Paste this, replacing `HUB` with your
hub's address, e.g. `hub.yourdomain.com`:

```json
{
  "display_information": {
    "name": "Proofwire approvals",
    "description": "Approve or deny AI agent actions that your Proofwire policy escalates."
  },
  "features": {
    "bot_user": { "display_name": "Proofwire", "always_online": false }
  },
  "oauth_config": {
    "scopes": { "bot": ["incoming-webhook"] }
  },
  "settings": {
    "interactivity": {
      "is_enabled": true,
      "request_url": "https://HUB/v1/integrations/slack/interactions"
    },
    "org_deploy_enabled": false,
    "socket_mode_enabled": false,
    "token_rotation_enabled": false
  }
}
```

The app asks for one permission, `incoming-webhook`: post to the one channel
you choose. It can't read messages, list channels or see users.

### 2. Install it and pick the channel

In the app's settings, open **Incoming Webhooks**, choose **Add New Webhook
to Workspace**, and pick the channel approvals should go to. Use a **private
channel** with only the people who should decide. Copy the **Webhook URL**.

Then open **Basic Information** and copy the **Signing Secret**.

### 3. Connect the hub

With an admin API key configured (`pw remote add ...`), pass the two values
through the environment, not the command line, where they'd land in your shell
history:

```bash
export PROOFWIRE_SLACK_WEBHOOK_URL='https://hooks.slack.com/services/...'
export PROOFWIRE_SLACK_SIGNING_SECRET='...'
pw slack connect --approver U024BE7LH,U0G9QF9C6
pw slack test
```

`--approver` lists the Slack **user IDs** allowed to decide. Find one under a
person's profile → ⋯ → **Copy member ID**. Leave it out and anyone who can
see the channel can decide, which is only reasonable for a private channel.

`pw slack test` posts a plain message to confirm the webhook works. The
console's **Settings → Integrations** page shows the connection too, with a
button to send a test message.

```bash
pw slack status        # connected? who can approve?
pw slack disconnect    # approvals go back to the console only
```

---

## What a request looks like

The message shows the tool, who the agent acts for, the agent, the log, the
rules that fired, why, when the request expires, and the arguments. The
arguments are the **redacted preview** the proxy sends, so card numbers, API
keys and other secrets are already masked before anything reaches the hub,
let alone Slack.

**Approve** asks for confirmation first, because the person clicking puts
their name on the receipt. After a decision, the message is replaced with the
outcome and who made it. If two people click at once, exactly one decision
lands, and the other is told who got there first.

A request nobody answers expires after `PROOFWIRE_APPROVAL_TTL` seconds
(default 900). An expired request is a **denial**, and the agent is told so.

---

## Security

- **Every click is verified.** Slack signs each request with the app's signing
  secret, and the hub checks that signature over the exact bytes received,
  using [Slack's documented scheme](https://api.slack.com/authentication/verifying-requests-from-slack).
  A request with no signature, the wrong one, a timestamp over five minutes old
  (a replay), or a body altered after signing decides nothing and gets `401`.
  Slack's published worked example is one of the tests.
- **Organisations are isolated.** Each organisation's clicks are checked
  against its own signing secret, so one Slack app can't decide another
  organisation's approvals.
- **The hub only sends to Slack.** Webhook URLs, and the response URLs Slack
  supplies, must be on `hooks.slack.com` over HTTPS. So a URL entered on a
  hosted hub can't be used to make it call internal addresses. Redirects are
  not followed.
- **Nothing in a request can ping the channel.** Text taken from the agent's
  call is escaped, so `<!channel>` in an argument shows as text.
- **Credentials are never shown back.** The API, CLI and console report that
  Slack is connected and which host the webhook is on, never the URL or the
  secret. The audit trail records connecting and disconnecting, not the values.
- **Both credentials are stored in the hub's database**, like the default
  signing keys. Protect the database and its backups accordingly.
- **Every decision is in the audit trail** (`approval.approved` /
  `approval.denied`, marked `via: slack`), and so is every refused attempt by
  someone not on the approver list (`approval.refused`).

## Limits

- A request decided in the **console** still shows its buttons in Slack. A
  click there then replies with who already decided it, and changes nothing.
  Updating the Slack message after a console decision needs a bot token,
  which this integration deliberately doesn't ask for.
- One channel per organisation.
- Tested against Slack's documented request format and signature scheme, with
  a simulated Slack. It has not yet been run against a live workspace. If the
  first real click fails, `docker compose logs node` shows why.
