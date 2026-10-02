# Deedwrit's witness keys

[`keys.json`](keys.json) is the published record of every witness key
Deedwrit operates. **It is empty, because Deedwrit does not operate a
witness yet.** An empty list is the true state, and publishing a key for a
node that isn't running — or a test key whose private half sits on someone's
laptop — would invite auditors to pin something nobody is accountable for.
The first entry goes in when the first real node starts signing.

## Why it lives here

A witness's public key, served by the witness itself, is the witness vouching
for itself — exactly what `dw check` refuses to trust from a bundle's own
keyring. An auditor needs the key from somewhere that can't be changed
quietly. This file is that place: every change to it is a public commit, and
it is **append-only, enforced**:

- An entry is added once and never edited, reordered or removed.
- `retiredAt` may be set once: the key stopped signing. What it signed before
  stays valid, so it stays pinned.
- `revokedAt` may be set once: the key must not be trusted at all —
  compromised, or out of Deedwrit's control. `dw check` will not pin it.
- Every `kid` must be the id its `publicKey` actually derives to, and every key
  must be in the one canonical encoding the verifier accepts.

`scripts/witness-record.test.mjs` replays this file's whole git history on
every CI run and fails if any step broke those rules. It is not a promise; a
commit that breaks it goes red.

## Using it

The [website](https://deedwrit.github.io/deedwrit/#witness-keys) shows this
record too — copied in when the site deploys, never kept as a second file —
and its browser verifier can pin these keys in one click. Neither is the trust
anchor: the site is served by Deedwrit. This file's history is.

Pin every current Deedwrit witness in one go:

```bash
dw check evidence.json --witnesses 1 --witness-keys witnesses/keys.json
```

Take the file from a commit you have reason to trust — a tag, or one you
recorded when you started relying on it — not merely from whatever is newest.
The history is what makes a silent change detectable; reading only the tip
throws that away.

What this record does **not** tell you: that a witness is independent of the
log you're checking. Every key here is run by Deedwrit. For a log Deedwrit
also hosts, a Deedwrit witness adds redundancy, not independence — pin a
witness run by someone else for that.

## Changing it

```bash
node scripts/witness-record.mjs add --operator Deedwrit --public-key <key> --node https://witness1.example
node scripts/witness-record.mjs retire <kid>
node scripts/witness-record.mjs revoke <kid>
node scripts/witness-record.mjs check
```

Take the public key from the witness host itself (`deedwrit-hub witness-key`
prints it), not from the node's HTTP API. Commit each change on its own, so
the history says exactly when each key started and stopped being trusted.

Entry format:

```json
{
  "kid": "pw1…",
  "publicKey": "<raw Ed25519 key, canonical base64url>",
  "operator": "Deedwrit",
  "node": "https://witness1.example",
  "addedAt": "2026-09-23",
  "retiredAt": null,
  "revokedAt": null,
  "note": null
}
```
