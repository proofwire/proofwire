# @vouchwell/proxy

A transparent MCP proxy that enforces policy and writes tamper-evident
receipts, plus the client that ships them to a Vouchwell hub.

[![CI](https://github.com/vouchwell/vouchwell/actions/workflows/ci.yml/badge.svg)](https://github.com/vouchwell/vouchwell/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)

Most people want the [`vouchwell`](https://npmjs.com/package/vouchwell) CLI
instead — this is the library underneath it.

```js
import { McpProxy } from '@vouchwell/proxy';
import { RemoteSink, hubApprover } from '@vouchwell/proxy/remote';
```

It speaks MCP to both sides, so adopting it changes one line of config.
Everything that is not a `tools/call` is forwarded untouched — MCP gains
methods faster than any proxy can track, and one that only forwards what it
recognises breaks on the next release.

**A denied call never reaches the upstream server**, and the denial itself
becomes a receipt — which is the record that matters most, because it is proof
the guardrail existed and fired.

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
