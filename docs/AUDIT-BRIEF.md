# Audit brief

**For a cryptographic reviewer.** This document exists to make a review cheap,
fast, and pointed — scope stated, ground truth identified, and the places I am
least sure about named rather than left to be found.

*Line counts, test counts and the findings list below are current as of
2026-09-22. If you're reading this later, `wc -l` the files in the table and
`npm test`'s summary line will tell you if it has drifted.*

It is written in the knowledge that **I wrote both the implementation and its
tests**, which is exactly why an outside review is needed: the tests check what
their author thought to check.

---

## What to review

**~1,600 lines.** Everything else is plumbing around it.

| File | Lines | Why it matters |
| --- | ---: | --- |
| `packages/core/src/merkle.js` | ~375 | RFC 6962 tree, inclusion and consistency proofs. **The highest-value target.** |
| `packages/core/src/canonical.js` | ~110 | RFC 8785. If two parties disagree on bytes, every signature is arguable. |
| `packages/core/src/receipt.js` | ~375 | What is signed, what is chained, the salted commitments, and the shape checks that keep a malformed-but-validly-signed receipt from reaching storage |
| `packages/core/src/hash.js` | ~76 | Domain separation |
| `packages/core/src/keys.js` | ~180 | Ed25519, a hand-assembled DER SPKI header, and strict base64url decoding |
| `packages/core/src/checkpoint.js` | ~225 | Signed tree heads, witness co-signatures, witness pinning |
| `packages/server/src/store.js` → `ingest()` | ~155 | The admission checks |
| `packages/server/src/app.js` → `/v1/witness/cosign` | ~170 | Split-view refusal, the log-to-key binding, and their shared transaction boundary |

Out of scope unless you want to: the console, the CLI, the policy engine
(security-relevant but not cryptographic), backups.

## Running it

```bash
npm install          # zero external dependencies; installs 5 workspace links
npm test             # 400+ tests
node --no-warnings=ExperimentalWarning packages/server/bench/load.js
npm run demo         # attacks a real log four ways
```

There is also a from-scratch second implementation of the verifier
(`site/verify.js`, for the browser) with no shared code, checked against the
first over honest, tampered and 650 randomly mutated bundles:

```bash
node --no-warnings=ExperimentalWarning --test 'site/test/*.test.js'   # 65 tests
```

Disagreement between the two on any bundle is itself a failing test. This is
the harness that found the gaps in item 7 below, and it is the cheapest way to
keep finding more of that class — a reviewer who wants to try a mutation the
suite doesn't cover can add it to `ATTACKS` in `site/test/verify.test.js` and
run it against both verifiers in one command.

No build step. Node ≥ 22.13 (where `node:sqlite` stopped needing a flag); the core needs
only ≥ 20.11 and has no dependencies at all.

---

## The claims, stated so they can be falsified

1. **A receipt cannot be altered undetectably.** Signed over its RFC 8785
   canonical form with Ed25519.
2. **An entry cannot be removed or reordered undetectably.** Hash chain plus
   sequence numbers.
3. **History cannot be rewritten undetectably once checkpointed** — even by an
   attacker holding the signing key, who can re-sign every receipt. The
   consistency proof against a published root is what closes this.
4. **A log operator cannot show two histories** to two auditors, given at least
   one honest witness **whose public key the auditor obtained independently**.
   (Until recently the verifier counted witnesses against the bundle's own
   keyring, which made this claim false — see item 7 below.)
5. **A receipt reveals nothing about its payload** beyond size and a redacted
   preview, and destroying salts makes payloads permanently unopenable while
   leaving every proof intact.
6. **The hub cannot forge a receipt**, because it never holds an agent's key.

Break any of these and the product is wrong. Claims 3 and 4 are the interesting
ones.

---

## External ground truth already checked

`packages/core/test/vectors.test.js` pins the implementation to published
values rather than to itself:

- **RFC 6962** — the Certificate Transparency reference tree (eight leaves of
  increasing length), all nine prefix roots, plus inclusion and consistency
  proofs verified against those roots.
- Two anchors derivable from the spec text with nothing to misremember:
  `MTH({}) = SHA-256("")` and `MTH({""}) = SHA-256(0x00)`.
- **RFC 8032** — Ed25519 TEST 1 and TEST 2, pinning the *signature bytes*, not
  merely that sign-then-verify round-trips. This also exercises the
  hand-assembled SPKI header in `publicKeyObject`, which is the one place raw
  DER is constructed by hand.
- **RFC 8785** — key ordering by UTF-16 code unit, `-0` normalisation,
  exponent forms, escape minimality.

Please check those constants against the source documents. A known-answer test
whose answers are wrong is worse than none.

---

## Where I would look first

Ordered by where I think a bug is most likely to be, not by severity.

### 1. `verifyConsistency` — the trailing-ones loop

```js
while ((fn & 1) === 1) { fn >>>= 1; sn >>>= 1; }
if (proof.length === 0) return false;
let i = 0;
if (fn !== 0) { fr = proof[i]; sr = proof[i]; i++; } else { fr = firstRoot; sr = firstRoot; }
```

This is the densest code in the project and the least self-evident. It is
exercised exhaustively for every `(m, n)` pair to n=48 and randomly beyond, but
exhaustive testing of a correct-looking implementation does not prove the
*rejection* side is tight. **Specifically: is there a proof shape that verifies
against a root it should not?** Length confusion and the `sn !== 0` terminal
check are where I would attack it.

### 2. The cached-level fast path in `inclusionProof`

Recently added to fix an O(n²) blow-up. It is asserted byte-identical to the
recursive reference for every tree size to 128 and randomly beyond — but the
equivalence of "pair adjacent, promote the odd one" to RFC 6962's
"split at the largest power of two" is an argument I made, not one I can cite.
**Is that equivalence actually total, or only for the sizes tested?**

### 3. Two-phase receipts and budget accounting

An allowed action writes an `intent` receipt before the call and an `outcome`
receipt after. Budgets aggregate over `intent` and skip `outcome`
(`History._relevant`). **Is there an interleaving where a budget is
double-counted or bypassed?** This fixed a real TOCTOU where pipelined calls
all evaluated against an empty ledger.

### 4. The witness transaction boundary

`/v1/witness/cosign` validates and *claims* the position inside one
transaction, then signs outside it, because signing may be a KMS round-trip.
The intended property: two concurrent requests offering different roots at the
same size cannot both be signed. **Is the claim actually atomic against SQLite's
isolation, and is failing-after-claim genuinely the safe direction?**

The same transaction now also binds a log to its signing key on first use
(`witness_log_keys`, migration `007`), and checks every later checkpoint's
`log` signature against that key *before* the position is read. Two things
worth attacking: **the first-use trust** — the first key to reach the witness
for a log name wins, contained only by each customer having their own
organization — and **the rebind path** (`vouchwell-hub witness-rebind`), which
is host-only by design and keeps the position. Is there a sequence of rebinds
and co-signings that lets a new key attest to a history the old one never
extended to? `packages/server/test/witness-binding.test.js` is where the
current answer is pinned down.

### 5. Salted commitments

`sha256(salt || canonical(value))`, salt 16 bytes, stored outside the signed
body. **Is 16 bytes enough, and is anything about the construction length-
extendable or otherwise weak given an attacker who knows the plaintext
distribution?** Note `preview` is stored in the clear and is best-effort
redaction — I treat that as a known, documented leak, not a defence.

### 6. `normalizeSignature`

Accepts hex, base64 and base64url from an external signer. **Can a crafted
string be coerced into 64 bytes that are not the signature the KMS produced?**
(This does not share item 7's base64 malleability — it always re-encodes with
`Buffer#toString('base64url')`, Node's own canonical encoder, so no matter how
the KMS spelled its input, the stored output is always the one canonical
spelling. The question here is narrower: whether the hex-vs-base64 sniffing
itself can be fooled.)

### 7. What a bundle is allowed to say about itself

Three gaps in bundle verification were found by me *after* the first version
of this brief, all while writing a second verifier for the website
(`site/verify.js`) — the first two by the two implementations disagreeing on
a concrete bundle, never by reasoning about the format in the abstract; the
third by a different method, described in its own entry below, because the
two implementations shared the mistake and would have agreed. All three are
fixed; please check that the fixes cover the class and not just the
instances — and, for the third, that "disagreement between two from-scratch
implementations" is not being over-trusted as a method now that it has a
demonstrated blind spot.

- **Completeness was taken on the sender's word.** A bundle with its last
  entries removed and `partial` left false verified clean, as did one whose
  `head` had been replaced — every remaining inclusion proof was genuine.
  `verifyBundle` now requires a complete bundle to hold `treeSize` entries, its
  root and head to match its own entries, and every checkpoint root to match the
  same-size prefix of them.
- **Witnesses were counted against the bundle's own keyring.** The keyring is
  supplied by the party under suspicion, so an operator could invent any number
  of witnesses by adding fresh keys. `--witnesses N` now requires
  `trustedWitnesses` (kid → public key, from the witness operators), counts only
  those, checks them against the pinned key rather than the bundle's, and refuses
  the request outright if none are supplied.
- **Base64url decoding was lenient in both implementations, identically, and
  the leniency was many-to-one — which is why differential testing did not
  catch it.** Gaps 1 and 2 above surfaced because the two verifiers
  *disagreed*. This one is different in kind: `Buffer.from(s, 'base64url')`
  and the browser's `atob` are *equally* forgiving about a base64 quantum's
  unused padding bits, so both sides would have agreed — wrongly — on the
  same wrong answer, and the differential harness has no way to notice two
  implementations being wrong the same way. It was found by checking both
  against a third thing: whether re-encoding the decoded bytes reproduces the
  original string. Concretely, a base64 quantum whose final symbol carries
  bits no byte value uses (2 symbols encoding 1 leftover byte have 4 such
  bits; 3 symbols encoding 2 leftover bytes have 2) is supposed to have those
  bits at zero, and nothing was checking that:
  `Buffer.from('QB', 'base64url')` and `atob('QB==')` both decode `'QB'` to
  the same byte as the canonical `'QA'`, and 15 other respellings do too — a
  64-byte Ed25519 signature's trailing 2-symbol quantum has exactly 16 ways
  to spell the same bytes, a 32-byte key's trailing 3-symbol quantum has 4.
  **Fixed** in both `decodeBase64url` (`packages/core/src/keys.js`) and
  `fromB64u` (`site/verify.js`) by decoding, re-encoding, and requiring the
  result to equal the input — exhaustive over all 64 possible final symbols
  for both tail shapes, cross-checked between the two implementations over
  20,000 random strings, zero disagreements. `vectors.test.js` covers it
  against real signed material, not synthetic strings.

  **What I want checked, because I could not rule it out by reasoning alone:**
  before the fix, could an in-scope adversary (the log operator, holding the
  signing key) use this to make one Merkle leaf's canonical bytes ambiguous
  in a way that helps forge a **root collision** — the same root from two
  different histories — without an actual SHA-256 collision? My own answer is
  no: `entryHash` is a domain-separated hash of the receipt's literal bytes,
  re-spelling `attest.sig` changes those bytes and therefore the leaf, and a
  Merkle root is sensitive to every leaf, so two different spellings still
  produce two different, honestly-computed roots — matching a previously
  witnessed root via encoding tricks alone would still require breaking
  SHA-256, which base64 says nothing about. I would like that argument
  checked rather than trusted from its author, since it's exactly the kind of
  reasoning that's easy to get subtly wrong. Separately: this is a transport-
  adjacent issue too (a party who can alter bytes in flight, without holding
  the key, could re-spell `attest.sig` and change what a receiving hub
  computes as that entry's hash — a real availability/integrity hazard for
  whoever's `prev` pointer no longer matches). `docs/THREAT-MODEL.md` A7
  already puts network attackers out of scope and pushes that to TLS; I have
  not re-examined whether that's still the right call in light of this
  specific mechanism, and it's a fair question for review too.

**The open question behind the second one:** a checkpoint signature's `role`
(`log` or `witness`) is a label the signature does not cover. Pinning makes that
harmless for witnesses, and a pinned key is refused as a log signature, but the
`log` role itself is still just a claim. Should the role be inside the signed
digest (a format v2), or is pinning the right and sufficient answer?

**Three more, in how witnesses were counted — all shared by all three
verifiers, so again invisible to differential testing.** Found by code review,
each confirmed with a concrete bundle, all fixed in core, the website and the
Python SDK:

- **One witness counted many times.** A pinned witness's signature repeated
  three times in `sigs` met `--witnesses 3`. Each public key now counts once.
- **No checkpoint, no requirement.** The witness minimum was applied per
  checkpoint, so a bundle with `checkpoints: []` met any minimum. A minimum
  now requires at least one checkpoint that meets it *and* is tied to this
  bundle's tree.
- **A witnessed checkpoint was not tied to the bundle it arrived in.** For a
  filtered bundle, checkpoint roots were never compared with anything, so a
  genuine witnessed checkpoint from one log vouched for forged entries from
  another. A checkpoint now counts only when its root equals the rebuilt
  prefix root (complete bundle), equals the bundle root at the same size, or
  is linked to it by a consistency proof in the bundle's new `consistency`
  field (`{ "<size>": [hex, …] }`, one proof from the latest witnessed
  checkpoint). The result reports `witnessedSize`: entries at or past it are
  signed by the log alone, and `vw check` says so.

Also worth knowing: `site/test/verify.test.js` runs the two independent
verifiers over honest, tampered and 650 randomly mutated bundles and requires
the same verdict every time. That is how all three gaps surfaced, and it is
the cheapest way to keep finding more of them — see "Running it" above.

---

## Known limitations — no need to rediscover these

Documented in `docs/THREAT-MODEL.md`; repeated here so review time is not spent
confirming them:

- An attacker with the signing key can write **new** false receipts going
  forward. The chain proves consistency, not truthfulness.
- Vouchwell records only what passes through it. An unwrapped path to the same
  API leaves no receipt.
- Timestamps come from the signing host. A uniformly wrong clock is not
  detectable from the log alone.
- Redaction is pattern-based and will not catch a secret shaped like prose.
- Witnesses are only as independent as the deployment makes them.
- A restored hub **cannot detect its own staleness** — the evidence was in the
  data the restore discarded. Only an outside party holding a later checkpoint
  can see it.

---

## Threat model in one paragraph

The adversary is **the operator of the log**, possibly holding the signing key,
with full write access to storage. They want to remove or alter a record of
something an AI agent did, after the fact, without an auditor detecting it. The
defender is a third party — an auditor, insurer, regulator, or opposing counsel
— who holds a bundle and at most one previously published root, and who
distrusts everyone involved.

## Publishing

The review will be **published unedited, findings and all**, including anything
you find that I got wrong. That is a condition of the engagement, not a
concession: a security product whose audit is summarised by its vendor has not
been audited in any sense a buyer should care about.

Findings can also be reported privately, under the policy in
[`SECURITY.md`](../SECURITY.md), through GitHub's private vulnerability
reporting.
