# deedwrit

**Tamper-evident receipts for AI agent actions.**

[![CI](https://github.com/deedwrit/deedwrit/actions/workflows/ci.yml/badge.svg)](https://github.com/deedwrit/deedwrit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)

Your agents spend money, send mail, and touch customer data. When something
goes wrong, "our logs say it didn't" is not an answer — your logs are a text
file you can edit.

Deedwrit makes every agent action **policy-gated before it runs** and
**cryptographically provable afterwards**.

```bash
npm install -g deedwrit
dw init
```

Then wrap any MCP server — this is the whole integration:

```jsonc
// .mcp.json — before
{ "command": "npx", "args": ["-y", "@acme/mcp-crm"] }

// after
{ "command": "dw", "args": ["proxy", "--namespace", "crm", "--", "npx", "-y", "@acme/mcp-crm"] }
```

Every tool call now hits your policy first, and every decision — allowed,
blocked, or escalated to a human — lands in an append-only log an outside
party can verify without trusting you.

```
BLOCKED  ops.query    destructive SQL from an agent is never permitted
BLOCKED  ops.refund   budget refunds.daily would be exceeded: 45 already
                      committed plus 90 proposed, against a cap of 100 per 24h
BLOCKED  ops.query    arguments contain anthropic_key; policy forbids sending
                      these to a tool
```

## Why it is not just logging

Everyone is building agent *observability* — dashboards you have to take on
faith. Deedwrit builds agent **evidence**: a record whose integrity a third
party can check independently, using nothing but the file you hand them.

- **Signed** — Ed25519 over an RFC 8785 canonical form.
- **Chained** — each receipt commits to its predecessor's hash.
- **Tree-anchored** — RFC 6962 Merkle log, the construction Certificate
  Transparency uses. Verified against the published CT reference vectors.
- **Sealed** — arguments are salted commitments, not payloads. Destroy the
  salts and those payloads become permanently unopenable while every proof
  still verifies, so a GDPR erasure does not gut the audit trail.

## Commands

```
dw init                    create a log, a starter policy, and a config
dw proxy -- <cmd...>       wrap an MCP server; enforce policy, write receipts
dw log / dw stats / dw dash        inspect
dw verify                  audit the local log end to end
dw prove <seq>             inclusion proof for one receipt
dw export / dw check       evidence bundle for a third party, and verify one
dw remote add / dw push    connect to a hub and ship receipts
dw cosign                  have an independent witness counter-sign your root
dw shred --before <date>   destroy payload commitments, keep the audit trail
```

`dw verify` exits non-zero when a log has been altered — put it in CI.

## What it does not do

- **It cannot prove an action it never saw.** An agent with a second,
  unwrapped path to the same API leaves no receipt.
- **The cryptography has not been reviewed by anyone independent.** It is
  pinned to published RFC 6962 and RFC 8032 vectors rather than only to
  itself, but that is not the same thing.

Full threat model: https://github.com/deedwrit/deedwrit/blob/main/docs/THREAT-MODEL.md

## Part of Deedwrit

| Package | What it is |
| --- | --- |
| [`deedwrit`](https://npmjs.com/package/deedwrit) | The `dw` CLI — start here |
| [`@deedwrit/core`](https://npmjs.com/package/@deedwrit/core) | Receipts, Merkle log, policy engine. Zero dependencies. |
| [`@deedwrit/proxy`](https://npmjs.com/package/@deedwrit/proxy) | The MCP proxy and the hub client |
| [`@deedwrit/server`](https://npmjs.com/package/@deedwrit/server) | The multi-tenant hub |
| [`@deedwrit/dashboard`](https://npmjs.com/package/@deedwrit/dashboard) | Local read-only dashboard |

Full documentation: **https://github.com/deedwrit/deedwrit**

Apache-2.0. The format, the verifier and the CLI are open and stay open:
evidence you cannot verify without a vendor's permission is not evidence.
