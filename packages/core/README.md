# @proof_wire/core

Signed, hash-chained, Merkle-anchored receipts for AI agent actions.
**Zero dependencies** — Node's standard library only.

[![CI](https://github.com/proofwire/proofwire/actions/workflows/ci.yml/badge.svg)](https://github.com/proofwire/proofwire/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)

```bash
npm install @proof_wire/core
```

```js
import fs from 'node:fs';
import { ProofLog, Policy, Recorder, PolicyDenied } from '@proof_wire/core';

const rec = new Recorder({
  log: ProofLog.open('.proofwire'),
  agent: 'support-bot',
  principal: 'ops@acme.com',
  policy: Policy.parse(fs.readFileSync('proofwire.policy.json', 'utf8')),
  metrics: (tool, args) => (tool === 'stripe.refund' ? { amount_usd: args.amount } : {}),
  approver: async (req) => askSomeone(req),   // optional: who answers an escalation
});

const refund = rec.wrap('stripe.refund', async ({ order, amount }) => stripe.refunds.create({ ... }));
await refund({ order: 'o_1', amount: 45 });   // checked, recorded, then run; throws PolicyDenied if refused
```

The same rules as `pw proxy`, receipt for receipt: the policy (budgets and
rate limits included) decides first; an allowed call gets an intent receipt
*before* it runs and a linked outcome after; a refused one never runs;
`monitor: true` records what would have been blocked without blocking it.
Call `rec.finalize()` on shutdown.

Tools described as objects with an `execute` function (the Vercel AI SDK's
`tool()`, Mastra) can be wrapped in one go:

```js
import { recordTools } from '@proof_wire/core';
const result = await generateText({ model, tools: recordTools(rec, { weather, refund }), prompt });
```

Python agents have the same in [`proof-wire`](https://github.com/proofwire/proofwire/tree/main/sdk/python), with
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

## Part of Proofwire

| Package | What it is |
| --- | --- |
| [`proofwire`](https://npmjs.com/package/proofwire) | The `pw` CLI — start here |
| [`@proof_wire/core`](https://npmjs.com/package/@proof_wire/core) | Receipts, Merkle log, policy engine. Zero dependencies. |
| [`@proof_wire/proxy`](https://npmjs.com/package/@proof_wire/proxy) | The MCP proxy and the hub client |
| [`@proof_wire/server`](https://npmjs.com/package/@proof_wire/server) | The multi-tenant hub |
| [`@proof_wire/dashboard`](https://npmjs.com/package/@proof_wire/dashboard) | Local read-only dashboard |

Full documentation: **https://github.com/proofwire/proofwire**

Apache-2.0. The format, the verifier and the CLI are open and stay open:
evidence you cannot verify without a vendor's permission is not evidence.
