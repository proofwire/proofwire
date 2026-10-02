# Vouchwell threat model

What Vouchwell defends against, what it does not, and why each line is drawn
where it is. A security tool that overstates its guarantees is worse than no
tool, because it buys confidence it has not earned.

---

## The asset

A **receipt** — a signed, chained assertion that at time T, agent A, acting for
principal P, proposed action X; policy Q decided D; and the result was R.

What we protect is not the receipt's confidentiality. It is the receipt's
**integrity over time** and the **completeness of the sequence**. Anyone should
be able to answer "is this the record that was written then, and is it all of
it?" without trusting the party who holds it.

---

## Adversaries

| # | Adversary | Capability | Defended? |
|---|-----------|-----------|-----------|
| A1 | Careless operator | Edits a log file to "fix" an entry | ✅ Fully |
| A2 | Motivated insider | Shell access, can edit any file | ✅ After checkpoint |
| A3 | Insider with the signing key | Can forge signatures | ⚠️ Past only |
| A4 | Compromised agent | Controls what actions get proposed | ✅ Policy + record |
| A5 | Malicious log operator | Runs the log, wants a split view | ⚠️ Needs witnesses |
| A6 | Adversary at rest | Steals the whole directory later | ✅ Commitments |
| A7 | Network attacker | Sits between agent and tool | ❌ Out of scope |

---

## A1 — Careless or casual tampering

**Attack.** Someone opens `entries.jsonl` and changes an amount, a decision, or
a timestamp.

**Defense.** Every receipt is signed over its canonical (RFC 8785) form. Any
byte change breaks the Ed25519 signature. Canonicalization is what makes this
airtight: without a deterministic serialization, two honest parties can
disagree about the bytes and every signature becomes arguable.

**Residual risk.** None. Detection is immediate and unambiguous.

---

## A2 — Insider with file access, no key

**Attack.** Delete an inconvenient entry; truncate the log; reorder entries.

**Defense.** Three independent mechanisms, and an attacker must defeat all of
them:

1. **Hash chain.** Each receipt commits to its predecessor's hash. Removing
   entry *k* breaks entry *k+1*'s `prev`.
2. **Sequence numbers.** A gap is visible without any cryptography.
3. **Checkpoint consistency.** Any previously signed root must still be a
   prefix of the current tree (RFC 6962 consistency proof). A truncation is
   caught even if the chain was rebuilt.

**Residual risk.** Entries appended *after* the last checkpoint can be removed
without contradicting any published root. Checkpoint frequently: the proxy
writes one at the end of every session, and a checkpoint costs one signature.

---

## A3 — Insider with the signing key

**Attack.** Steal `key.pem`, delete an entry, re-sign the entire chain with
correct sequence numbers and links. The result is internally perfect.

**Defense.** Consistency against a **witnessed** checkpoint. The rewritten log
cannot reproduce any root that was published before the rewrite, because the
removed entry is baked into it. This is the case the demo's third attack
exercises, and it is caught.

**Residual risk — and it is real.** An attacker holding the key can write
*new*, false receipts going forward, and nothing in the format prevents it.
The chain proves consistency, not truthfulness: it proves nobody edited history,
not that history was honestly recorded in the first place.

**Mitigations.**
- Keep the key in a KMS or HSM. The format only needs a sign operation;
  it never needs the key material in process memory.
- Rotate keys and keep old public keys in the keyring. A receipt signed by a
  retired key still verifies, and its validity window is auditable.
- Witness checkpoints continuously, so the window for an undetected rewrite is
  bounded by the witnessing interval rather than by when someone next looks.

---

## A4 — Compromised or misaligned agent

**Attack.** A prompt-injected agent tries to exfiltrate data, drain a budget,
or run a destructive command.

**Defense.** Policy evaluates **before** the call is forwarded. A denied call
never reaches the upstream server, and the denial itself becomes a receipt —
which is the record that matters most, because it is proof the guardrail
existed and fired.

Specific controls:
- **Egress guard** runs before any allow rule and refuses to pass credentials
  or card numbers to a tool, whatever the rest of the policy says.
- **Budgets** commit at decision time, so concurrent calls cannot race past a
  cap.
- **Rate limits** count allowed calls only, so a denied flood cannot exhaust
  someone else's quota.
- **Escalation** routes to a human, who sees a *redacted* preview — approving
  in Slack must not paste a customer's card number into Slack.

**Residual risk.** Vouchwell records and gates what passes through it. An agent
with a second, unwrapped path to the same API — a raw API key in its
environment, an HTTP tool that is not proxied — leaves no receipt. **This is
the most likely real-world failure**, and it is a deployment problem, not a
cryptographic one. Route every tool through the proxy and treat unwrapped
credentials as the hole they are.

---

## A5 — Malicious log operator (split view)

**Attack.** The operator maintains two histories and shows each auditor a
different one. Both verify perfectly in isolation. This is the attack a
self-hosted transparency log fundamentally cannot defend against alone.

**Defense.** Witness co-signatures. A witness counter-signs a root only if it
extends the last root it saw from that log, and refuses to sign two different
roots at the same size. An auditor who requires *k* witness signatures from
witnesses **they** chose forces the operator to show everyone the same history.

```bash
vw check evidence.json --witnesses 2 --witness-keys witnesses.json
```

`witnesses.json` holds the witnesses' public keys **as their operators
published them** — never taken from the bundle. A bundle's own keyring comes
from the party whose honesty is in question, so it cannot vouch for witnesses:
an operator could add any number of fresh keys and "witness" their own
checkpoints. Only signatures from keys you pinned are counted, and asking for
`--witnesses` without pinning any is refused rather than answered by counting
whatever the bundle contains.

**Residual risk.** Witnesses are only as independent as the deployment makes
them. Three witnesses running on infrastructure the operator controls provide
one witness's worth of assurance. Witnesses should be operated by the parties
who would be harmed by a split view — the auditor, the insurer, the
counterparty — not by the log's owner.

---

## A6 — Adversary at rest

**Attack.** Steal the log directory, today or in five years, and mine it for
customer data.

**Defense.** The log does not contain payloads. It contains
`sha256(salt ‖ canonical(payload))` plus a preview with known secret and PII
formats masked.

The salt is what makes this worth doing. An unsalted commitment to a
low-entropy value — `{"amount": 50}`, a customer's email — is trivially
brute-forced, and leaks exactly the data it pretends to protect. Salts are
stored in a separate file, are never signed, and are never included in an
export.

`vw shred` destroys salts for matching entries. Afterwards those commitments
cannot be opened by anyone — including the operator, including under legal
compulsion — while every signature, chain link and inclusion proof continues to
verify.

**Residual risk.** The redacted *preview* is stored in the clear and is
best-effort. The detectors catch known credential formats and common PII
patterns; they will not catch a secret shaped like ordinary prose. If previews
are unacceptable for a workload, seal without one — the commitment alone is
sufficient for proof.

---

## A7 — Network attacker

Out of scope. Vouchwell proxies a local stdio transport. Transport security
between the tool server and whatever it talks to is that server's problem, and
TLS's.

The hub is a different matter: it is a network service, and its API keys
travel over whatever URL the operator gives `vw remote add`. That command
refuses plain `http://` to anything but the local machine unless `--insecure`
is passed, so a typo cannot quietly send a token across a network in the clear.

## A8 — Attacks on the operator's own tools

Not attacks on the evidence, but on the people and machines that handle it.

| Attack | Mitigation |
| ------ | ---------- |
| **DNS rebinding against `vw dash`.** A web page points its own domain at `127.0.0.1` and reads the local dashboard's receipts as if same-origin. | The dashboard answers only to `Host: 127.0.0.1`, `localhost` or `[::1]` on its own port; any other name gets a 403 before anything is read. |
| **Script injection into the dashboard or console** via strings in receipts (tool names, reasons, principals). | Everything is escaped on output, and the dashboard's CSP allows only its own inline script, by SHA-256 hash, and no other script source. The hub console's CSP allows no script at all. Neither page can be framed. |
| **Account discovery at hub sign-in** by timing: an unknown email used to return before the password hash ran. | Every attempt pays for one scrypt, known account or not, and the response is identical either way. |
| **Credential stuffing** spread over many addresses, which a per-address limit never sees. | Failed sign-ins are also counted per account: ten, then one more every 90 seconds, from anywhere. A throttled account is refused before its password is checked, and an account that does not exist throttles identically. Password-reset requests share the strict sign-in limit. |
| **Argument injection when launching a tool server on Windows.** `.cmd` shims such as `npx` need cmd.exe, which has its own metacharacters and no notion of backslash escapes. | The command is resolved first; an `.exe` runs with no shell. A shim gets each argument escaped for the C runtime and then `^`-escaped for cmd.exe, twice, since the shim re-parses `%*`. Tested against a real shim with quotes, `&`, `%VAR%`, `!`, `^` and trailing backslashes. |
| **Attacks on single sign-on**: a forged or replayed ID token, a sign-in finished in the victim's browser (login CSRF), a reassigned email taking over an account, or an issuer URL pointed at internal addresses. | Full ID-token verification (asymmetric signatures only; issuer, audience, expiry, nonce); PKCE; a single-use state bound to the browser by a cookie; accounts bound to the provider's subject, not just the email; every request to the provider refused on private addresses at connect time, after DNS, with no redirects. See [`SSO.md`](SSO.md). |
| **A forged Slack approval**: a request to the hub's Slack endpoint claiming someone clicked Approve. | Every click must carry Slack's HMAC signature over the exact body, made with that organisation's signing secret and dated within five minutes; anything else changes nothing and gets the same `401`, whether or not the approval exists. An optional approver list limits who may decide even with a genuine click. The hub only ever sends to `hooks.slack.com`. See [`SLACK.md`](SLACK.md). |
| **A poisoned CI dependency** (a GitHub Action whose tag is moved to malicious code). | Every action is pinned to a full commit SHA; Dependabot proposes updates as reviewable PRs. Workflows get a read-only token unless a job declares otherwise. |
| **A secret committed to this public repository.** | `scripts/repo-hygiene.mjs` runs in CI and before every release, refusing key files, salts, environment and database files, and token-shaped strings. Removing a pushed secret does not un-publish it, so the check runs before a push can matter. |

---

## Cryptographic choices

| Choice | Why |
| ------ | --- |
| **Ed25519** | Deterministic signing: no per-signature nonce, so no way to leak the key by reusing one. That matters when the signer is an unattended runtime producing thousands of signatures an hour. |
| **SHA-256** | Ubiquitous, hardware-accelerated, and what RFC 6962 verifiers already implement. |
| **RFC 8785 (JCS)** | Two parties must produce identical bytes for the same logical object or every signature is arguable. `JSON.stringify` does not promise key order. |
| **RFC 6962 domain separation** | The `0x00`/`0x01` leaf/node tags block the second-preimage attack where an interior node's bytes are also a valid leaf, letting an attacker splice a forged subtree in. |
| **Salted commitments** | Unsalted hashes of low-entropy payloads are brute-forceable. |
| **Synchronous writes** | An audit log that returns before the record is durable will, on the one day it matters, be missing the record that matters. |

---

## Known gaps

Tracked honestly rather than quietly:

1. **Gap between action and receipt on crash.** Mitigated by two-phase
   receipts: the intent is durable *before* the call is forwarded, so a process
   killed mid-call leaves evidence that the action was authorised and attempted.
   An intent with no outcome is itself a signal worth alerting on.
2. **Clock trust.** Timestamps come from the signing host. A backdated entry is
   flagged when it contradicts its neighbours, but a uniformly wrong clock is
   not detectable from the log alone. RFC 3161 timestamping or witness
   countersignature times bound this externally.
3. **Policy is only as good as it is written.** Vouchwell validates syntax
   aggressively — a typo is a load error — but it cannot know that your deny
   rule has a gap in it. Policies deserve tests, like any other code.
4. **No distributed log yet.** `0.1.0` is a single-writer local log. Multiple
   concurrent proxies need either separate logs (each independently verifiable)
   or the hosted log service, which serialises appends.
