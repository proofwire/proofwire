# @vouchwell/dashboard

A local, read-only dashboard over a Vouchwell log.

[![CI](https://github.com/vouchwell/vouchwell/actions/workflows/ci.yml/badge.svg)](https://github.com/vouchwell/vouchwell/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)

```bash
vw dash --port 7788
```

Read-only and loopback-only, both deliberately: this process can see the log
directory, which on a live machine sits next to the signing key.

Shows the receipt timeline, decisions and reasons, redacted argument previews,
and the inclusion proof for any entry.

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
