# Changelog

All five packages — `proofwire` and `@proof_wire/{core,proxy,dashboard,server}` —
release together at the same version.

## Unreleased

### Security

- **Witness requirements could be met without the witnesses.** Three gaps,
  identical in `pw check`/`verifyBundle`, the website's verifier and the
  Python SDK:
  - one pinned witness's signature, repeated, counted as several witnesses;
    each public key now counts once;
  - a bundle with no checkpoints met any `--witnesses` minimum; now at least
    one checkpoint has to meet it;
  - in a filtered bundle a checkpoint's root was never tied to the bundle's,
    so a genuine witnessed checkpoint of one log vouched for forged entries
    of another. A checkpoint now counts only when its root is tied to the
    bundle's tree.
- **A password-reset link could point at another host.** Without
  `PROOFWIRE_PUBLIC_URL` the hub built reset links from the request's `Host`
  header, which whoever requests the reset chooses. It now issues resets
  only when that URL is set or the request is addressed to this machine, and
  answers identically either way.
- **`pw check --witnesses abc` silently required no witnesses.** A NaN minimum
  compared false against every count. The CLI now refuses anything but a whole
  number, and `verifyBundle` fails a minimum that is not a non-negative integer.

### Added

- **Calls that never finished are found and reported.** Every allowed call
  writes an intent receipt before it runs and an outcome after; an intent with
  no outcome is what an agent killed mid-call leaves behind, and nothing
  looked for it. `findUnfinished` (`find_unfinished` in Python) returns those,
  the ones a recorder gave up on at shutdown, calls still in flight (under
  five minutes old), and outcomes that name no intent. `pw verify` lists them
  (`--fail-on-unfinished` exits 3), `pw log --unfinished` filters to them, the
  evidence report gains an "Actions that never finished" section, `pw dash`
  and the hub console show a banner and a filter, and the hub serves
  `GET /v1/logs/:log/unfinished`, answered by the database (migration
  `011_receipt_links` adds an index) and working across pruned receipts.
- **`Recorder` for JavaScript agents that don't use MCP** (`@proof_wire/core`).
  `rec.run(tool, args, fn)` and `rec.wrap(tool, fn)` apply the proxy's rules
  receipt for receipt: the full policy language with budgets and rate limits
  judged against the log's history, escalations to an `approver` that sees
  only a redacted preview, intent before the call and a linked outcome after,
  `monitor` mode, `PolicyDenied` for a refusal, and `finalize()` on shutdown.
  `recordTools(rec, tools)` wraps every `execute`-style tool at once (the
  Vercel AI SDK's `tool()`, Mastra).
- **Python adapters for LangChain and the OpenAI Agents SDK**
  (`proof_wire.integrations.langchain` / `.openai_agents`, each with a
  `record_tools`). A refused call never runs, and the model is told why in
  the tool's reply, as the proxy does. Install with
  `pip install "proof-wire[langchain]"` or `"proof-wire[openai-agents]"`; the
  frameworks are imported only when the adapter is, and CI tests both against
  the real packages.
- **Bundles carry a consistency proof** (`consistency: { "<size>": [...] }`)
  from the latest witnessed checkpoint to their root, so a filtered bundle —
  which every hub bundle becomes once retention prunes anything — can still
  tie its witnesses to its entries. Older verifiers ignore the field.
- **`verifyBundle` reports `witnessedSize`** when witnesses are required: the
  entries a witnessed checkpoint covers. `pw check` and the website say when
  later entries are signed by the log alone.

### Changed

- The evidence report's "tool errors" no longer counts calls that never
  returned; those are listed on their own.

### Fixed

- `GET /v1/events?limit=` is clamped to 1–500; a negative limit meant "no
  limit" to SQLite.
- `verifyReceipt` looks up a signer only among the keyring's own properties,
  as `verifyCheckpoint` already did.

## 0.4.0 — 2026-09-25

### Security

- **`pw dash` refuses requests whose `Host` is not its own**, which closes DNS
  rebinding: a web page could previously point its own domain at `127.0.0.1`
  and read the local dashboard's receipts. The page's script moved to its own
  file, and the CSP allows only this server's scripts and forbids framing. Internal
  errors no longer echo their message, which could include file paths.
- **Hub sign-in no longer reveals which emails have accounts.** An unknown
  address now costs the same scrypt as a wrong password.
- **Failed sign-ins are limited per account**, as well as per address: ten, then
  one more every 90 seconds (`accountLoginRate`). A throttled account is
  refused before its password is checked (`429 too_many_attempts`, or a notice
  on the console sign-in page). `/forgot` now falls under the strict auth limit.
- **`pw remote add` refuses a plain `http://` hub URL** unless it is on this
  machine or `--insecure` is given, so an API key is not sent unencrypted by
  accident.
- **CI hardening:** every GitHub Action is pinned to a commit SHA, workflows
  default to a read-only token, and CodeQL and Dependabot are configured.
  `scripts/repo-hygiene.mjs` blocks keys, salts, environment and database files,
  and token-shaped strings in CI and in the release preflight.
- **Windows: an argument could break out of its quotes and run a second
  command.** The quoting escaped `"` for the program but not for cmd.exe, which
  ignores backslash escapes, so `x"&echo PWNED` ran `echo`. The arguments come
  from the operator's own config, so this was not reachable remotely, but an
  argument ending in `\` was also silently merged with the next one.
  `pw proxy` now resolves the command first: an `.exe` runs directly with no
  shell at all, and a `.cmd`/`.bat` shim gets every argument escaped for the C
  runtime and for cmd.exe (twice for a shim, which re-parses `%*`). `%VAR%` in
  an argument is no longer expanded. The release script uses the same code.
  Found by CodeQL.
- **Smaller hardening from the first CodeQL scan:** the hub's cookie parser
  ignores `__proto__` and skips malformed escapes instead of failing the
  request; URL trailing-slash trimming no longer uses a regex with quadratic
  backtracking; `pw init` creates its files exclusively (`wx`) instead of
  check-then-write; the dashboard checks and reads a file through one handle;
  unused imports removed.

### Fixed

- **A checkpoint of an empty log no longer fails bundle verification.**
  `verifyBundle`, in the CLI and in the website's verifier, compared a size-0
  checkpoint against no root at all and reported "history was rewritten", a
  false tampering alarm. Found while writing the Python SDK.
- **`pw proxy` no longer triggers Node's DEP0190 warning on Windows** when it
  wraps a bare command such as `npx`. A shim now gets one finished command line
  with no separate args, and an executable no longer goes through a shell.

### Changed

- **`pw check --witness-keys` skips list entries that carry `revokedAt`**, and
  says which. A revoked witness key could "witness" anything; a retired one
  (`retiredAt`) is still pinned, since what it signed before stays good.

### Added

- **A Python SDK, `proof-wire`** ([`sdk/python`](sdk/python/README.md)), imported as
  `proof_wire`. It writes and verifies exactly the format the CLI reads: a log
  written in Python passes `pw verify`, its bundles pass `pw check`, and logs
  and bundles from the JavaScript side verify in Python and can be continued
  there. `Recorder` wraps a Python agent's tools (decorator, async, or context
  manager) with the proxy's intent and outcome receipts, redaction and sealed
  arguments, plus an optional `decide` hook that refuses calls before they
  run. `verify_bundle`, `push` to a hub, checkpoints and witnesses are all
  there too. Tested against the RFC 6962 and RFC 8032 vectors, and in CI
  against the real CLI on Linux and Windows with Python 3.9 and 3.13, including
  byte-level canonicalization parity over hundreds of awkward values. One
  dependency: `cryptography`.
- **Single sign-on with OpenID Connect** ([`docs/SSO.md`](docs/SSO.md)), for Okta,
  Microsoft Entra ID, Google Workspace or any OIDC provider. Authorization code
  flow with PKCE and a browser-bound, single-use state; ID tokens verified in
  full (asymmetric algorithms only; `none` and HMAC refused; issuer, audience,
  authorised party, expiry, nonce), with key rotation followed. Accounts are
  bound to the provider's subject, not only the email. Optional email-domain
  allowlist, just-in-time provisioning (never as owner), and `requireSso`,
  which makes an organisation reachable only by its own SSO sessions (API keys
  unaffected). Requests to the provider refuse private addresses at connect
  time, after DNS, and follow no redirects. SSO sessions last a day. Configured
  with `/v1/integrations/oidc`; "Continue with SSO" on the sign-in page; shown
  on Settings; every sign-in, refusal and provisioning audited.
- **Retention for hub copies of receipts** (HUB.md, *Retention*). An
  organisation's admins set a period (`PUT /v1/settings/retention`), and an
  operator can cap it per plan (`proofwire-hub retention <org> --cap N`); the
  shorter applies. An hourly sweep clears the body of each older receipt and
  every column that could identify someone, and keeps seq, hash, prev and four
  non-identifying facts. The tree is built from the hashes, so roots,
  checkpoints, witness signatures, inclusion proofs, the self-audit and
  further ingest all keep working. Pruned receipts answer `410 pruned` with
  their hash, and are left out of listings and bundles. Agents' local logs are
  untouched. A period under six months returns a warning citing the EU AI Act's
  record-keeping minimum. Shown on the console's Settings page.
- **`pw report`: an evidence pack for auditors** ([`docs/EVIDENCE.md`](docs/EVIDENCE.md)).
  One directory holding `report.html` (self-contained, no scripts),
  `evidence.bundle.json` (verifiable with `pw check`), `summary.json` and
  `SHA256SUMS`. It covers integrity (with pinned witnesses via `--witness-key(s)`),
  activity, every escalation with who approved or declined it, refusals, monitor
  mode, and the policy versions in force. It maps the evidence to the EU AI Act
  (Arts. 12, 14, 19/26(6)) and SOC 2 (CC4.1, CC6.1, CC7.2, CC7.3, CC8.1),
  worded as what the evidence supports, never as compliance. `--since`,
  `--until`, `--framework`, `--out`.
- **Receipts record who declined an escalation**, as `decision.declined = { by,
  at, note }`, inside the signature, as approvals already did. A fallback (no
  approver, a timeout) is recorded as the `policy:*` fallback it was, never as
  a person. `pw policy test` reads these as escalations.
- **Slack approvals** ([`docs/SLACK.md`](docs/SLACK.md)). An escalation is
  posted to the organisation's Slack channel with Approve and Deny buttons; a
  click decides it as the console would, and the receipt records who, as
  `slack:<user id> (<name>)`. Every click is verified with Slack's request
  signature over the raw body, within a five-minute replay window, against the
  organisation's own signing secret. Webhook and response URLs are limited to
  `hooks.slack.com`. An optional approver list restricts who may decide;
  refusals are audited. Nothing in the agent's arguments can mention the
  channel, and the arguments shown are the already-redacted preview. Set up
  with `pw slack connect|status|test|disconnect` (admin key; credentials from
  the environment), and shown on the console's Settings page. The API is
  `/v1/integrations/slack`. Slack being down never delays an escalation.
- **Deciding an approval is atomic.** The API, the console and Slack share one
  path whose update applies only while the request is still pending and
  unexpired, so two simultaneous decisions can't both land.
- **A production deployment kit, `deploy/`, with a runbook,
  [`docs/DEPLOY.md`](docs/DEPLOY.md).** Takes one Linux server and a domain to
  a Proofwire node on HTTPS: Caddy in front (automatic Let's Encrypt
  certificates, HTTP to HTTPS, HSTS), the node's port never published, both
  containers read-only with capabilities dropped, Caddy pinned by digest,
  scheduled backups to their own volume, and log rotation. `setup.sh` checks
  the prerequisites, waits for HTTPS, and prints the node's keys. Witness-only
  by default; one setting makes it a hub. CI runs the kit on every push and
  drives a customer's co-signing through its TLS.
- **`proofwire-hub identity [--json]`** prints the node's public keys from the
  host, with the command that publishes the witness key.
- **`pw policy test [policy-file]`** replays the local log against a policy and
  lists every call whose verdict would change, such as `deny → allow`, with the
  rule responsible. Each call is judged at its recorded time, against only what
  the new policy would have let through, so budgets and rate limits behave as
  they would have live. Monitored calls are compared on what the policy would
  have done. Options: `--since`, `--session`, `--target`, `--json`, `--all`, and
  `--fail-on-change` (exit 1 if anything differs, for CI). Calls whose logged
  arguments were partly masked are marked approximate. No hub is needed.
- **Monitor mode: `pw proxy --monitor`**, or `"monitor": true` in
  `proofwire.config.json` (`--enforce` overrides it). The policy is evaluated
  as usual but every call is forwarded, and escalations never reach an
  approver. Each receipt written in this mode carries `decision.enforced:
  false`. A call the policy would have stopped is recorded as `allow` (it ran)
  with `decision.wouldBe: "deny" | "escalate"` and a reason that says it was
  not enforced. These fields are signed, and monitored calls count toward
  budgets. `pw log --would-block` lists them, `pw stats` tallies them by rule,
  and the dashboard and hub console label them "would deny". `McpProxy` takes
  `monitor: true`.
- **`witnesses/keys.json`**, the published record of Proofwire-operated
  witness keys — empty until there is a real node. Append-only, enforced by
  replaying its git history in CI; `pw check --witness-keys` reads it directly.

## 0.3.0 — 2026-09-22

### Breaking

- **A witness binds each log to its signing key.** The first request to
  co-sign a log must name the key its checkpoints are signed with
  (`logPublicKey`) and carry a valid `log` signature from it; every later
  checkpoint must be signed by that key. A first request naming no key is
  `400 missing_log_key`, another key `409 log_key_mismatch`, a missing or
  invalid signature `422 bad_log_signature`. **`pw` 0.2.0 does not send
  `logPublicKey`**, so it cannot start witnessing a new log against a 0.3.0
  witness — upgrade the CLI. Logs a witness recorded under 0.2.0 bind on their
  next successful co-signing.
- **`buildReceipt` throws on a missing `actor.principal`, `actor.agent`,
  `actor.session`, `action.kind`, `action.target` or `decision.outcome`**,
  and `verifyReceipt` reports them (plus `ts` and `phase`) as format issues.
  Such receipts used to verify and then crash a hub's ingest with a raw
  SQLite error; they are now refused cleanly, before they are signed.
- **Keys and signatures must be canonical base64url.** A string whose final
  character carries non-zero unused bits — `QB`, where `QA` is the canonical
  encoding of the same byte — is rejected, in both the CLI's verifier and the
  browser's. Every encoder in
  common use emits the canonical form, so this only rejects hand-made input.

### Added

- **Witness-only mode** (`PROOFWIRE_WITNESS_ONLY=1`): the hub answers six
  routes — health, readiness, `/.well-known/proofwire`, `/v1/me`, the witness
  key and co-signing — and 404s everything else. No console, no log ingest, no
  key management over HTTP, no hub key. `docker-compose.yml`'s witness uses it.
- **`proofwire-hub witness-key <customer>`** — gives a customer their own
  organization and a witness-scoped key, and prints the witness's public key
  for them to pin.
- **`proofwire-hub witness-rebind <customer> <log> <public key>`** — the only
  way to change a log's binding after a key rotation. Host-only, recorded in
  the audit trail, and it keeps the recorded position: a new key must extend
  what the witness already attested to.
- **`pw cosign`** sends the log's key, shows the binding, and explains a key
  mismatch.

### Fixed

- A hub fed a malformed-but-validly-signed receipt answered 500; it now
  answers `422 receipt_rejected` (see *Breaking*).
- Version strings reported by `pw --version`, the hub banner,
  `/.well-known/proofwire` and the proxy's receipts (`actor.runtime`) are read
  from the package, not typed into source. 0.2.0's all said `0.2.0` by hand.

### Infrastructure

- The Dockerfile is built on every push and driven end to end — as a hub and
  as a separate witness-only node that co-signs the hub's checkpoint, verified
  with the witness key pinned.

## 0.2.0 — 2026-09-22

First release on npm.
