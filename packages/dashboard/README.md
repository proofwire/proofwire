# @deedwrit/dashboard

A local, read-only dashboard over a Deedwrit log.

[![CI](https://github.com/deedwrit/deedwrit/actions/workflows/ci.yml/badge.svg)](https://github.com/deedwrit/deedwrit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)

```bash
dw dash --port 7788
```

Read-only and loopback-only, both deliberately: this process can see the log
directory, which on a live machine sits next to the signing key.

Shows the receipt timeline, decisions and reasons, redacted argument previews,
and the inclusion proof for any entry.

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
