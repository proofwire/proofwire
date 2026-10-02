# Design partners: the first month

This is for a team trying Vouchwell on real agents with us. The whole plan
fits in four weeks, starts without blocking anything, and never sends us your
data. Everything runs on your machines.

**What you get:** tamper-evident receipts for every tool call your agents
make, a policy you can prove against your own traffic before it enforces
anything, and an evidence pack your auditors can check without trusting you
or us.

**What we ask:** 15 minutes a week to tell us what broke, what was
confusing, and what you'd need before relying on it. And, if you can, one
person outside the engineering team (security, compliance, an auditor) who
tries to verify a pack.

---

## Week 1: record, block nothing (15 minutes)

```bash
npm install -g vouchwell
cd your-agent-project
vw init
```

Then change the one line in your agent's MCP configuration that launches a
tool server:

```json
"command": "npx", "args": ["-y", "@acme/mcp-crm"]
```

becomes

```json
"command": "vw", "args": ["proxy", "--monitor", "--namespace", "crm", "--", "npx", "-y", "@acme/mcp-crm"]
```

`--monitor` means **nothing is blocked**: every call goes through exactly as
before, and each one gets a signed receipt. The starter policy is evaluated
too, and what it *would* have stopped is recorded without being enforced.

Check it's working:

```bash
vw log                  # recent receipts
vw stats                # totals, and what would have been stopped
vw verify               # the log checks out end to end
vw dash                 # a local, read-only dashboard
```

**Removing it** is the same one-line change in reverse. Nothing else in your
setup depends on it.

## Week 2: fit the policy to your traffic

Edit `vouchwell.policy.json`: deny what should never happen, escalate what
needs a person, and cap spend. Then test the new version against the week you
just recorded:

```bash
vw policy test vouchwell.policy.json
```

It lists every call whose outcome would change (`allow → deny`,
`allow → escalate`) and the rule responsible. Iterate until that list is only
things you want stopped. `--fail-on-change` exits non-zero, so you can put this
in CI and review policy changes like code.

## Week 3: enforce

Drop `--monitor`. Calls the policy denies now return a refusal to the agent
(which the model sees and can explain), and escalations wait for a person:

- **In a terminal:** `"approval": { "mode": "tty" }` in `vouchwell.config.json`.
- **In Slack**, with a hub: Approve and Deny buttons in a channel. See
  [SLACK.md](SLACK.md).
- **By webhook** to your own system: `"mode": "webhook", "url": "https://…"`.

An escalation nobody answers is denied, never allowed.

Optionally, run a **hub** for your team: one place for the shared policy, the
approvals inbox and a copy of every log. It's self-hosted, and your data stays
yours. [DEPLOY.md](DEPLOY.md) takes a server to HTTPS in about half an hour.

## Week 4: hand an auditor the evidence

```bash
vw report --since 2026-09-01 --out evidence-september
```

This writes a directory with a readable report, the verifiable bundle and
checksums; see [EVIDENCE.md](EVIDENCE.md). Give it to someone who wasn't
involved and ask them to verify it with `vw check`, without your help. Their
experience is the most useful feedback you can give us.

---

## What we hold

Nothing. The CLI, proxy and hub run on your machines, and nothing phones home.
The only network traffic is to a hub or witness **you** configure.

## The weekly check-in

Five questions, answered however suits you:

1. What did Vouchwell record or block this week that surprised you?
2. What did it get in the way of?
3. What did you have to read the source to figure out?
4. Did anyone besides the person who set it up look at a receipt, a report or
   the dashboard?
5. What would have to be true for you to rely on it in production?

## When something goes wrong

- **The agent can't reach a tool:** run `vw log --denied`. It shows whether
  the policy refused the call, and which rule.
- **Something looks off with the log:** `vw verify` says exactly which receipt
  and why.
- **Anything else:** open an issue, or for anything security-related use
  private vulnerability reporting ([SECURITY.md](../SECURITY.md)).
