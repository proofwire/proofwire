# @vouchwell/core

Signed, hash-chained, Merkle-anchored receipts for AI agent actions.
**Zero dependencies** — Node's standard library only.

[![CI](https://github.com/vouchwell/vouchwell/actions/workflows/ci.yml/badge.svg)](https://github.com/vouchwell/vouchwell/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)

```bash
npm install @vouchwell/core
```

```js
import fs from 'node:fs';
import { ProofLog, Policy, Recorder, PolicyDenied } from '@vouchwell/core';

const rec = new Recorder({
  log: ProofLog.open('.vouchwell'),
  agent: 'support-bot',
  principal: 'ops@acme.com',
  policy: Policy.parse(fs.readFileSync('vouchwell.policy.json', 'utf8')),
  metrics: (tool, args) => (tool === 'stripe.refund' ? { amount_usd: args.amount } : {}),
  approver: async (req) => askSomeone(req),   // optional: who answers an escalation
});

const refund = rec.wrap('stripe.refund', async ({ order, amount }) => stripe.refunds.create({ ... }));
await refund({ order: 'o_1', amount: 45 });   // checked, recorded, then run; throws PolicyDenied if refused
```

The same rules as `vw proxy`, receipt for receipt: the policy (budgets and
rate limits included) decides first; an allowed call gets an intent receipt
*before* it runs and a linked outcome after; a refused one never runs;
`monitor: true` records what would have been blocked without blocking it.
Call `rec.finalize()` on shutdown.

Tools described as objects with an `execute` function (the Vercel AI SDK's
`tool()`, Mastra) can be wrapped in one go:

```js
import { recordTools } from '@vouchwell/core';
const result = await generateText({ model, tools: recordTools(rec, { weather, refund }), prompt });
```

Python agents have the same in [`vouchwell`](https://github.com/vouchwell/vouchwell/tree/main/sdk/python), with
adapters for LangChain and the OpenAI Agents SDK.

## What is in here

| | |
| --- | --- |
| `canonical.js` | RFC 8785 deterministic JSON — two parties must produce identical bytes or every signature is arguable |
| `merkle.js` | RFC 6962 tree, inclusion and consistency proofs |
| `receipt.js` | The signed record, and salted payload commitments |
| `checkpoint.js` | Signed tree heads and witness co-signatures |
| `log.js` | Append-only file-backed log, audit, evidence bundles |
| `policy.js` | Declarative rules, budgets, rate limits |
| `redact.js` | Secret and PII detection |
| `recorder.js` | `Recorder` and `recordTools`: check and record an agent's own tool calls |
| `unfinished.js` | `findUnfinished`: calls that were sent and never answered |
| `templates.js` | `POLICY_TEMPLATES` and `composePolicy`: ready-made policies for secrets, SQL, payments, messages, shell, loops |

## Verified against published vectors

Not only against itself. The **RFC 6962 Certificate Transparency reference
tree** (all nine roots, with proofs checked against them) and **RFC 8032**
Ed25519 test vectors, pinning signature bytes rather than round-trips.

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
