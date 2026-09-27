# Running the Proofwire hub

The hub is the multi-tenant half of Proofwire: a transparency log your whole
organisation writes to, a policy registry your agents read from, an approvals
inbox your people work out of, and a witness service that makes any of it worth
believing.

---

## The trust model, first

Everything else follows from one property:

> **The hub cannot forge a receipt, because it never holds a signing key.**

Agents sign locally with keys that never leave the machine. The hub verifies
every receipt on arrival and stores what it can verify. That leaves it able to
do exactly three dishonest things, and each has a defence:

| What a malicious hub could try | What stops it |
| --- | --- |
| Alter a receipt | The signature fails. Ingest rejects it; so does any later audit. |
| Drop or reorder receipts | The chain breaks at the next entry, and consistency proofs against a published checkpoint expose the gap. |
| Show two customers two histories | Witness countersignatures. A witness signs only roots signed by the key it bound the log to, that extend the last one it saw, and refuses two roots at one size. |

The corollary matters as much: **the hub is optional.** An agent whose hub is
unreachable keeps running and keeps recording locally, and ships the backlog
when the hub returns. An audit service that could halt production would be
removed from production after its first outage.

---

## Quick start

```bash
docker compose up -d
docker compose exec hub node packages/server/src/bin.js bootstrap
```

That runs on your machine over plain HTTP, for trying it out. **For a real
server** with a domain, automatic HTTPS and a hardened setup, use `deploy/`:
[`docs/DEPLOY.md`](DEPLOY.md) walks through it end to end.

> **Built and driven for real:** CI's `docker` job builds this image, boots it,
> registers a log, signs and pushes receipts, checkpoints, fetches the bundle back
> and verifies it, confirms a bad token is refused, and checks the container
> actually runs read-only and non-root (`scripts/docker-smoke.mjs`). It also caught
> a real bug: a receipt missing an actor field crashed the hub with a raw SQLite
> error instead of a clean 4xx — fixed in `buildReceipt`/`verifyReceipt`. The two-
> container witnessing flow below (`docker compose up -d witness`, `pw remote add
> --name witness`, `pw cosign --remote witness`) was run by hand against both
> containers, through to `pw check --witnesses 1` on the resulting bundle.

`bootstrap` prints an admin password and two API keys, once:

```
  org        acme  org_c8139b3e88ae61b955f1d961
  admin      admin@example.com
  password   kR2mFqXt9

  API keys  (shown once — they are not stored in recoverable form)
  agent      pwk_5f28cece….tZXYRJZMDLgFPpHM…
             receipts:write logs:write logs:read policies:read
  auditor    pwk_72f15eec….2wARtiM9Uq3AwURZ…
             read-only: the credential to hand an outside firm
```

Point an agent at it:

```bash
pw remote add --url https://hub.acme.com --token <agent token>
pw proxy --namespace crm -- npx -y @acme/mcp-crm
```

From that moment the proxy fetches the org's active policy at startup, enforces
it, records every decision locally, and streams the receipts to the hub.

---

## Configuration

Environment only. A config file that anyone who can reach the filesystem can
edit is one more thing to get wrong in a container.

| Variable | Default | Notes |
| --- | --- | --- |
| `PROOFWIRE_PORT` | `8787` | |
| `PROOFWIRE_HOST` | `0.0.0.0` | |
| `PROOFWIRE_DB` | `./data/proofwire.db` | Put this on a durable volume. |
| `PROOFWIRE_TRUST_PROXY` | `0` | Set to `1` **only** behind a proxy you control. |
| `PROOFWIRE_CHECKPOINT_EVERY` | `500` | Receipts between automatic checkpoints. |
| `PROOFWIRE_WITNESS_ONLY` | `0` | Set to `1` to run a witness and nothing else — see [Witnessing](#witnessing). |
| `PROOFWIRE_SELFCHECK_MINUTES` | `60` | Re-verify every stored log on this interval. |
| `PROOFWIRE_APPROVAL_TTL` | `900` | Seconds before an undecided escalation expires. |
| `PROOFWIRE_ACCESS_LOG` | on | Set `off` to silence per-request JSON logs. |
| `PROOFWIRE_INSECURE_COOKIES` | unset | Drops `Secure` on session cookies and suppresses HSTS. Local development only. |
| `PROOFWIRE_SIGNER` | `local` | `local`, `command`, or `http`. See **Keys** below. |
| `PROOFWIRE_BACKUP_DIR` | unset | Enables scheduled backups. |
| `PROOFWIRE_BACKUP_HOURS` | `6` | |
| `PROOFWIRE_BACKUP_KEEP` | `14` | Snapshots retained before pruning. |
| `PROOFWIRE_NOTIFY_URL` | unset | Webhook for invitation and reset links. |
| `PROOFWIRE_PUBLIC_URL` | unset | Base URL for those links, and for SSO's redirect URI. Set it behind a proxy. Without it, password resets are only issued to requests addressed to this machine (`localhost`, `127.x`, `[::1]`): anyone can request a reset, so its link is never built from a `Host` header the requester chose. |
| `PROOFWIRE_OIDC_ALLOW_PRIVATE` | `0` | `1` lets an SSO provider live on a private address. Only for a self-hosted hub whose provider is on its own network. |
| `PROOFWIRE_RETENTION_SWEEP_MINUTES` | `60` | How often retention runs. `0` disables it. |

### On `PROOFWIRE_TRUST_PROXY`

`X-Forwarded-For` is a header any client can set. With no proxy in front,
honouring it lets anyone evade the per-address rate limit by inventing an
address. Turn it on only when something you operate is guaranteed to overwrite
it.

Sign-in has a second limit that no header can dodge: failed attempts are
counted per account, whatever address they come from. After ten, the account
accepts one more attempt every 90 seconds, and it refuses even the correct
password until then. The API answers `429 too_many_attempts`; the console says
so on its sign-in page. An address with no account behaves identically, so the
limit reveals nothing about which accounts exist.

---

## Retention

By default the hub keeps every receipt forever. An organisation can choose a
retention period, and the operator of a hosted hub can cap it at what the plan
includes:

```bash
# An admin of the organisation, over the API:
curl -X PUT https://hub.example/v1/settings/retention \
  -H "authorization: Bearer $ADMIN_KEY" -H 'content-type: application/json' \
  -d '{"days": 365}'

# The operator, on the host. The cap exists only here, not in the API:
proofwire-hub retention acme --cap 365
proofwire-hub retention acme                  # show
```

The hub applies the shorter of the two, sweeping hourly
(`PROOFWIRE_RETENTION_SWEEP_MINUTES`).

**What pruning does.** A receipt older than the period loses its signed body
and every column that could name a person or a customer: tool, principal,
agent, session, metrics and result. It keeps its sequence number, its hash, its
link to the previous receipt, and four facts that identify nobody: when, what
phase, what kind of action, and the outcome.

**What it doesn't break.** The log's Merkle tree is built from those hashes,
so after pruning:

- the root is unchanged;
- every checkpoint and every witness signature still verifies;
- an inclusion proof for a pruned receipt still works;
- the hub's self-audit still checks the whole chain, including across pruned
  rows, and still catches a tampered one;
- agents keep pushing, and the chain continues.

A pruned receipt answers `410 pruned` with its hash. Bundles leave pruned
receipts out and say so (`partial: true`), and every entry they do carry
still proves inclusion in the full tree.

**What it doesn't touch: your agents' local logs.** They are the
authoritative copy and keep everything. Setting a period under six months
returns a warning, because the EU AI Act asks for logs of high-risk systems to
be kept at least that long (Arts. 19 and 26(6)). If the hub keeps less, keep the
local logs, or `pw report` evidence packs, for the full period.

## Keys

By default the hub generates its own Ed25519 keys and stores them in its
database. That is fine for development and for a self-hosted hub whose operator
accepts the risk knowingly. **It is not what a hosted service should run**, and
the hub says so on every startup.

### Moving keys out

Signing goes through a three-member interface — `{ kid, publicKey, sign(digest) }`
— so every key store is an adapter rather than a rewrite.

```bash
# Anything that reads a digest on stdin and prints a signature.
PROOFWIRE_SIGNER=command
PROOFWIRE_SIGNER_COMMAND=/usr/local/bin/kms-sign
PROOFWIRE_SIGNER_ARGS="--key-id alias/proofwire-hub"
PROOFWIRE_PUBLIC_KEY=<raw Ed25519 public key, base64url>
```

```bash
# Or a signing sidecar over HTTP.
PROOFWIRE_SIGNER=http
PROOFWIRE_SIGNER_URL=https://signer.internal/sign
PROOFWIRE_SIGNER_TOKEN=<bearer>
PROOFWIRE_PUBLIC_KEY=<raw Ed25519 public key, base64url>
```

Each role can be configured separately with `PROOFWIRE_HUB_SIGNER` and
`PROOFWIRE_WITNESS_SIGNER`. **Put the witness key in different custody** — a
witness whose key sits beside the log's key is not independent of it.

Signatures are accepted as hex, base64 or base64url; an Ed25519 signature is
always 64 bytes, which makes the encodings unambiguous.

### What happens when it is wrong

- **A misconfigured signer disables signing.** It never falls back to a local
  key, because quietly minting one defeats the purpose of moving to a KMS.
- **Startup self-tests** by signing a random digest and verifying it against
  the configured public key. A missing command, a denied grant, the wrong key,
  or an unexpected encoding all surface at boot.
- **A dead signer stops checkpoints, never ingest.** Receipts keep being
  accepted and verified; only the tree-head signature pauses.

### Rotation

Recording a new key for a role retires the old one and keeps it forever, so a
checkpoint signed by a retired key still verifies — otherwise rotating would
silently invalidate the history it was meant to protect.
`/.well-known/proofwire` publishes every key, retired ones included.

---

## Backups

```bash
proofwire-hub backup ./backups/today.db
proofwire-hub verify-backup ./backups/today.db
proofwire-hub restore ./backups/today.db
proofwire-hub reconcile
```

Set `PROOFWIRE_BACKUP_DIR` and the hub takes them on a schedule with retention.

Backups use `VACUUM INTO`, which reads through SQLite's own MVCC: consistent
without stopping writes, and a single file with none of the WAL sidecars that
make a naive `cp` subtly wrong. Each backup gets a manifest with a SHA-256, and
`verify-backup` re-verifies **every log inside it** — find the bad backup on a
quiet afternoon, not during an incident.

### The thing to understand before you need it

**A restored hub cannot detect its own staleness.**

Restore a snapshot taken at 10 entries onto a hub that had reached 18, and the
result is perfectly self-consistent: 10 entries, a checkpoint covering 10,
everything verifying. The proof that 18 ever existed was in the data the
restore discarded. `reconcile` will report clean — and will tell you that a
clean result here proves internal consistency, not currency.

To an auditor holding the later checkpoint, that gap is **indistinguishable
from deletion**. It has to be: a system where the operator can say "that was a
restore, not a deletion" and be believed has no integrity guarantee at all.

Only a party holding later evidence can see it:

- **the agent**, whose local log is longer. This is the normal path and it
  self-heals — `pw push` notices the shortfall and re-sends the difference,
  idempotently.
- **a witness or auditor** with a later checkpoint:
  `proofwire-hub reconcile --against checkpoints.json`

So: **after any restore, re-push from every agent.** A restore runbook that
does not end there is incomplete. And this is why the agents' local logs are
never optional — they are the authoritative copy; the hub is a replica.

`reconcile` distinguishes a **recoverable** gap (re-push fixes it) from a
**divergent** one (the stored history contradicts a signed root — no re-push
fixes that, and it should be treated as an incident).

---

## Credentials

### API keys — machines

Scoped and, for agents, pinned to a single log. A key pinned to `payments`
cannot read or write `support`, which contains a leaked agent credential to the
blast radius of the one runtime that held it.

| Scope | For |
| --- | --- |
| `receipts:write` | An agent runtime pushing receipts |
| `receipts:read` | Auditors, dashboards, CI verification |
| `logs:write` / `logs:read` | Registering logs; reading their state |
| `policies:read` | Agents fetching the active policy at startup |
| `policies:write` | Whoever is allowed to change the rules |
| `approvals:read` / `approvals:write` | The escalation inbox |
| `witness:sign` | A client asking the witness to counter-sign |
| `admin` | Members, keys, org settings |

An agent needs `receipts:write logs:write logs:read policies:read`. Nothing more.
Giving it `receipts:read` lets a compromised agent read back the entire
organisation's history of what other agents did.

### Invitations and resets

```bash
curl -X POST $HUB/v1/invites -H "authorization: Bearer $ADMIN" \
  -d '{"email":"auditor@bigfour.test","role":"auditor"}'
```

The link is returned **once** and never stored — only its hash is. Set
`PROOFWIRE_NOTIFY_URL` and it is also POSTed to your own mail service;
delivery is a webhook rather than built-in SMTP so the hub never depends on an
SMTP configuration nobody notices is broken. The link is returned either way,
so an admin is never stuck.

Users reset their own passwords at `/forgot`. Four properties worth knowing:

- Tokens are stored **only as hashes**, so a database leak does not hand over
  working reset links.
- A new token **invalidates any outstanding one** of the same kind.
- Setting a password **revokes every existing session** — a reset exists
  because the account may already be in someone else's hands.
- Requesting a reset answers **identically** whether or not the address exists.

An invited account holds a membership an admin can see, shown as `invited`, but
cannot be signed in to until the invitation is accepted.

### Sessions — people

Console users get scopes from their role, not from a list, because a person's
authority changes when their job does:

| Role | Can |
| --- | --- |
| `owner` | Everything, including minting keys |
| `admin` | Everything except ownership transfer |
| `operator` | Read, and resolve escalations |
| `auditor` | **Read everything, change nothing** |

`auditor` is the role to hand an outside firm. It cannot alter what it is
auditing, which is the point.

---

## Witnessing

A hub signing its own roots proves very little — it can sign two. Independent
witnesses are what close that.

Everything below is for running your own.

```bash
# On the witness's own infrastructure. docker-compose.yml runs it witness-only.
docker compose up -d witness

# Give each customer a key — on the host, not over HTTP. It also prints this
# witness's public key, for the customer and their auditors to pin.
docker compose exec witness node packages/server/src/bin.js witness-key acme

# From the customer's agent machine:
pw remote add --name witness --url https://witness.example.org --token <key>
pw cosign --remote witness
```

**Run a witness witness-only** (`PROOFWIRE_WITNESS_ONLY=1`, which
`docker-compose.yml` already sets). It then answers exactly six routes —
health, readiness, `/.well-known/proofwire`, `/v1/me`, the witness key and
co-signing — and 404s everything else: no console, no log ingest, no key
management over HTTP, and no hub key created at all. A witness is the one
component whose compromise defeats the split-view defence, so it should not
be carrying a whole hub's surface for no reason. `bootstrap` refuses on a
witness-only node; `witness-key` replaces it.

**One customer, one organization.** `witness-key` creates an organization per
customer, and that is load-bearing: a witness binds each log name, per
organization, to the key that signs its first checkpoint (below). Customers
sharing an organization could each bind the other's log name to their own key
first and lock the other out. Running `witness-key` again for the same
customer adds a credential, which is how rotating *that* starts.

The witness enforces three rules and returns a signature only if all hold:

1. **Only the log signs for the log.** The first request for a log names the
   key its checkpoints are signed with (`logPublicKey` — `pw cosign` sends it);
   the witness checks the checkpoint is signed by that key and binds the log to
   it. Every later checkpoint must carry a valid `log` signature from the bound
   key. Naming a different key is `409 log_key_mismatch`; a missing or invalid
   signature is `422 bad_log_signature`; a first request naming no key is
   `400 missing_log_key`. This is checked before anything else, so a
   checkpoint the log never signed cannot move or probe what the witness
   remembers.
2. **Never sign two different roots at the same size.** This is the split-view
   refusal, returned as `409 split_view`.
3. **Never sign a larger root without a consistency proof** that it extends the
   last root this witness saw. Returned as `409 not_an_extension`.

A refusal on any of these grounds is not a transient error. It means the
history, or the signer, the witness was shown does not match what it saw
before.

**Rotating a log's key.** A binding changes only on the host, by the witness
operator, never over HTTP — whoever can rebind a log decides whose checkpoints
the witness accepts for it:

```bash
docker compose exec witness node packages/server/src/bin.js \
  witness-rebind <customer> <log> <new public key>
```

Get the new public key from the customer through a channel other than their
witness credential — a stolen credential is exactly what a rebind request
would otherwise be made with. The rebind is recorded in the control-plane
audit trail, and it keeps the recorded position: the new key has to extend the
history the witness already attested to, with a consistency proof, like any
other checkpoint. It cannot start the log over. Switching a hub to a KMS
signer changes its key, so plan the rebind alongside that change.

Positions a witness recorded before it bound keys (anything from 0.2.0) are
bound on their next successful co-signing, under the same first-use rule.

**Witnesses are only as independent as you make them.** Three witnesses on
infrastructure the log operator controls provide one witness's worth of
assurance. They should be run by whoever would be harmed by a split view — the
auditor, the insurer, the counterparty — not by the log's owner.

Auditors then demand the signatures:

```bash
pw check evidence.json --witnesses 2 --witness-keys witnesses.json
```

`witnesses.json` holds the witnesses' public keys **as their operators
published them** — never taken from the bundle. A bundle's own keyring comes
from the party whose honesty is in question, so it cannot vouch for witnesses:
an operator could add any number of fresh keys and "witness" their own
checkpoints. Only signatures from keys you pinned are counted, and asking for
`--witnesses` without pinning any is refused rather than answered by counting
whatever the bundle contains.

`witnesses.json` can be a `{ "kid": "publicKey" }` map or a list of
`{ kid, publicKey }` entries. Proofwire's own witness keys, once there are any,
are published in that list form at
[`witnesses/keys.json`](../witnesses/keys.json) — append-only, with every
change a commit — and a list entry carrying `revokedAt` is never pinned.

---

## Operating it

### Health

- `GET /health` — the process is up.
- `GET /ready` — the database answers. This is the one to put in a load
  balancer, so a hub with a wedged disk leaves rotation instead of serving
  errors.
- `GET /.well-known/proofwire` — the hub's and witness's public keys, served
  **without credentials**. A verifier that must authenticate to obtain the key
  it verifies with is not independent.

### Verifying the hub against itself

```bash
docker compose exec hub node packages/server/src/bin.js check
```

Re-derives every log from stored receipts — signatures, chain links, inclusion
proofs, and every checkpoint replayed — and exits non-zero on any failure. The
server also does this on `PROOFWIRE_SELFCHECK_MINUTES` and logs
`selfcheck.failed`. **Alert on that line.**

A hosted log that only ever checks its customers' data and never its own is
asking to be taken at its word.

### Backups

Back up `PROOFWIRE_DB`. SQLite in WAL mode needs the `-wal` and `-shm`
sidecars too, or use `sqlite3 proofwire.db ".backup out.db"` for a consistent
copy.

A restore from a backup that predates some receipts looks *exactly* like
malicious truncation to any auditor holding a later checkpoint — because from
the evidence alone it is indistinguishable. Agents still hold their local logs,
so re-run `pw push` from each to refill the gap.

### Scaling

The hub is single-writer per process. SQLite in WAL mode handles concurrent
readers comfortably, and ingest is a few hundred microseconds of verification
plus one transaction. For more than one hub process, shard by organisation —
each log has exactly one writer by design, so sharding is natural and needs no
coordination.

---

## The API

All endpoints are tenant-scoped by credential. There is deliberately no way to
address a log by id across an organisation boundary.

```
POST   /v1/logs                          register a log (slug, canonical, kid, publicKey)
GET    /v1/logs                          list
GET    /v1/logs/:log                     state: size, head, root
GET    /v1/logs/:log/head                resync point for a reconnecting agent
POST   /v1/logs/:log/receipts            append a verified batch  { receipts, batchId }
GET    /v1/logs/:log/receipts/:seq       one receipt
GET    /v1/receipts                      query across logs  [?denied&target&session&since]
GET    /v1/logs/:log/proof/:seq          inclusion proof
GET    /v1/logs/:log/consistency?from=   consistency proof
GET    /v1/logs/:log/audit               the hub re-verifies its own storage
GET    /v1/logs/:log/bundle              evidence bundle for a third party
POST   /v1/logs/:log/checkpoint          sign the current root
GET    /v1/logs/:log/checkpoints

POST   /v1/witness/cosign                counter-sign  { checkpoint, consistencyProof, logPublicKey }
GET    /v1/witness/key

GET    /v1/policies                      versions
GET    /v1/policies/:slug                the active one — what agents fetch
POST   /v1/policies/:slug                publish a new version
POST   /v1/policies/:slug/activate       roll back to a version

POST   /v1/approvals                     raise an escalation
GET    /v1/approvals                     the inbox  [?status]
GET    /v1/approvals/:id?wait=30         long-poll for a decision
POST   /v1/approvals/:id/decide          { approved, note }

GET    /v1/integrations/slack            connected? approvers?  (admin)
PUT    /v1/integrations/slack            { webhookUrl, signingSecret, approvers }  (admin)
DELETE /v1/integrations/slack            (admin)
POST   /v1/integrations/slack/test       post a test message  (admin)
POST   /v1/integrations/slack/interactions   Slack's button clicks, signed by Slack

GET    /v1/keys · POST /v1/keys · DELETE /v1/keys/:id
GET    /v1/members · POST /v1/members
GET    /v1/events                        the hub's own hash-chained audit trail
GET    /v1/usage
GET    /v1/settings/retention            period, plan cap, pruned so far  (admin)
GET    /v1/integrations/oidc             SSO settings, never the secret  (admin)
PUT    /v1/integrations/oidc             { issuer, clientId, clientSecret, domains, autoProvision, requireSso }  (admin)
DELETE /v1/integrations/oidc             (admin)
GET    /sso/:org · /sso/callback         the browser sign-in flow
PUT    /v1/settings/retention            { days | null }  (admin; not above the cap)
```

### Ingest semantics

A batch is accepted whole or rejected whole. Four checks, any failure rejecting
everything:

1. Signature verifies against the key bound to the log at registration.
2. The receipt names the log it is being sent to (the *signed* identifier).
3. Sequence numbers continue from the hub's current size.
4. `prev` equals the hub's current head.

Rejecting the batch rather than its valid prefix is deliberate: a partial accept
leaves the client's head and the hub's silently diverged, and the next batch
fails for a reason unrelated to what actually went wrong.

Pass a `batchId` and retries are idempotent — the hub recognises a resubmission
and returns the original result rather than replaying it.

On `409 sequence_gap` the error carries the sequence to resume from. The
`RemoteSink` handles this automatically.

---

## Hardening checklist

- [ ] TLS terminated in front; `PROOFWIRE_TRUST_PROXY=1` only then
- [ ] `PROOFWIRE_DB` on a durable, backed-up volume
- [ ] Container runs read-only except `/data`, as non-root (the shipped
      compose file does both)
- [ ] Agent keys pinned to one log each, with no `receipts:read`
- [ ] At least one witness run by someone other than you
- [ ] Alerting on `selfcheck.failed` and on `split_view` refusals
- [ ] The hub and witness public keys published somewhere auditors can reach
      independently of the hub
- [ ] Bootstrap admin password rotated

---

## Known limits

Stated plainly, because a security product that hides its edges is selling
confidence rather than evidence.

1. **Single-writer per log.** By design — a chain has one author. Multiple
   agents use multiple logs.
2. **Keys are bound to a log for its lifetime.** Rotation means registering a
   new log. A chain signed by two keys over its life is one whose validity
   depends on knowing exactly when the swap happened, which the log cannot
   itself establish.
3. **The default `local` signer still keeps keys in the database.** Set
   `PROOFWIRE_SIGNER` to move them out. Vendor wrapper scripts for AWS/GCP/Azure
   KMS are not written yet — the `command` backend takes any of them.
4. **Timestamps come from the signing host.** A backdated entry is flagged when
   it contradicts its neighbours; a uniformly wrong clock is not detectable
   from the log alone.
5. **SSO is OpenID Connect only** ([`SSO.md`](SSO.md)), one provider per
   organisation, with no SCIM. SAML is not supported.
6. **Slack approvals** ([`SLACK.md`](SLACK.md)) post to one channel per
   organisation, and a request decided in the console keeps its buttons in
   Slack (a click then says who already decided).
6. **`node:sqlite` is still marked experimental** upstream. It is stable in
   practice and the API surface used here is small, but it is worth knowing.
7. **A witness trusts the first key it sees for a log name.** It binds the log
   to that key and holds it to it afterwards, but the first binding itself is
   trust on first use. Each customer having their own organization on the
   witness is what keeps one customer from binding another's log names.
