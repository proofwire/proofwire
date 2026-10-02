# vouchwell

**Tamper-evident receipts for AI agent actions.**

[![CI](https://github.com/vouchwell/vouchwell/actions/workflows/ci.yml/badge.svg)](https://github.com/vouchwell/vouchwell/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)

Your agents spend money, send mail, and touch customer data. When something
goes wrong, "our logs say it didn't" is not an answer — your logs are a text
file you can edit.

Vouchwell makes every agent action **policy-gated before it runs** and
**cryptographically provable afterwards**.

```bash
npm install -g vouchwell
vw init
```

Then wrap any MCP server — this is the whole integration:

```jsonc
// .mcp.json — before
{ "command": "npx", "args": ["-y", "@acme/mcp-crm"] }

// after
{ "command": "vw", "args": ["proxy", "--namespace", "crm", "--", "npx", "-y", "@acme/mcp-crm"] }
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
faith. Vouchwell builds agent **evidence**: a record whose integrity a third
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
vw init                    create a log, a starter policy, and a config
vw proxy -- <cmd...>       wrap an MCP server; enforce policy, write receipts
vw log / vw stats / vw dash        inspect
vw verify                  audit the local log end to end
vw prove <seq>             inclusion proof for one receipt
vw export / vw check       evidence bundle for a third party, and verify one
vw remote add / vw push    connect to a hub and ship receipts
vw cosign                  have an independent witness counter-sign your root
vw shred --before <date>   destroy payload commitments, keep the audit trail
```

`vw verify` exits non-zero when a log has been altered — put it in CI.

## What it does not do

- **It cannot prove an action it never saw.** An agent with a second,
  unwrapped path to the same API leaves no receipt.
- **The cryptography has not been reviewed by anyone independent.** It is
  pinned to published RFC 6962 and RFC 8032 vectors rather than only to
  itself, but that is not the same thing.

Full threat model: https://github.com/vouchwell/vouchwell/blob/main/docs/THREAT-MODEL.md

## Part of Vouchwell

| Package | What it is |
| --- | --- |
| [`vouchwell`](https://npmjs.com/package/vouchwell) | The `vw` CLI — start here |
| [`@vouchwell/core`](https://npmjs.com/package/@vouchwell/core) | Receipts, Merkle log, policy engine. Zero dependencies. |
| [`@vouchwell/proxy`](https://npmjs.com/package/@vouchwell/proxy) | The MCP proxy and the hub client |
| [`@vouchwell/server`](https://npmjs.com/package/@vouchwell/server) | The multi-tenant hub |
| [`@vouchwell/dashboard`](https://npmjs.com/package/@vouchwell/dashboard) | Local read-only dashboard |

Full documentation: **https://github.com/vouchwell/vouchwell**

Apache-2.0. The format, the verifier and the CLI are open and stay open:
evidence you cannot verify without a vendor's permission is not evidence.
