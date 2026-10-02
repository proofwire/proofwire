# Streaming events to your SIEM

A hub can send every receipt and every control-plane event to the tools your
security team already watches: **Splunk** (HTTP Event Collector),
**Datadog Logs**, anything that takes **OpenTelemetry** logs over HTTP, or a
**signed webhook** of your own. Each organisation chooses its own
destinations, at most five.

```bash
# An admin key, from a machine connected with `vw remote add`.
VOUCHWELL_STREAM_TOKEN=<HEC token> \
  vw streams add splunk --type splunk --url https://splunk.example.com:8088

VOUCHWELL_STREAM_TOKEN=<API key> \
  vw streams add datadog --type datadog --url https://http-intake.logs.datadoghq.eu

vw streams add otel --type otlp --url https://otel-collector.example.com:4318 \
  --header "authorization=Bearer <token>"

vw streams add soc --type webhook --url https://soc.example.com/vouchwell --receipts blocked

vw streams test     # one test event to each, and whether it arrived
vw streams list     # what each sends, what's pending, the last error
```

Tokens and secrets can come from the environment
(`VOUCHWELL_STREAM_TOKEN`, `VOUCHWELL_STREAM_SECRET`,
`VOUCHWELL_STREAM_HEADERS` as a JSON object) to keep them out of shell
history. The hub never hands them back: `list` says only that one is set.

**Or from the console:** an admin can do all of this under
**Settings → Integrations**: add or remove a destination, send a test event,
send what's pending now, and see each one's backlog and last error. A webhook's
generated secret is shown once, on the page it was made on.

## What is sent

**Receipts**: what an agent did, or tried to, and what policy decided.

```json
{
  "type": "receipt", "id": "payments:41", "time": "2026-09-27T10:04:11.201Z",
  "org": "acme", "log": "payments", "seq": 41, "hash": "5f0c…",
  "phase": "intent", "kind": "tool_call", "target": "stripe.refund",
  "outcome": "deny", "rules": ["payments.big"], "reason": "over the limit",
  "policy": "b2e1…", "agent": "billing-bot", "principal": "ana@acme.com",
  "session": "s-19"
}
```

**The action's parameters and result are never streamed.** Only the facts a
detection rule needs leave the hub: who, which tool, which outcome, which rule.
The full receipt stays in the log, where it can be proven.

`--receipts blocked` sends only denials and escalations, and `--receipts none`
sends none.

**Audit events**: the hub's own hash-chained control-plane trail. It covers
keys issued and revoked, members invited, policies published, approvals
decided, integrations changed, and a witness refusing a checkpoint
(`witness.refused`, sent at error severity). `--no-audit` leaves these out.

```json
{
  "type": "audit", "id": "audit:17", "time": "…", "org": "acme", "seq": 17,
  "hash": "…", "actor": "ana@acme.com", "actorKind": "user",
  "action": "policy.publish", "subject": "default", "meta": { "hash": "…", "rules": 12 }
}
```

`id` is stable, so a destination can drop the duplicates that at-least-once
delivery can produce (below).

## The formats

| Type | Sent to | Auth | Body |
| --- | --- | --- | --- |
| `splunk` | `<url>/services/collector/event` | `Authorization: Splunk <token>` | HEC events back to back, `sourcetype` `vouchwell:receipt` or `vouchwell:audit` |
| `datadog` | `<url>/api/v2/logs` (default `https://http-intake.logs.datadoghq.com`) | `DD-API-KEY` | A JSON array, `ddsource: vouchwell`, tags `event:`, `outcome:`, `log:` |
| `otlp` | `<url>/v1/logs` | your `--header`s | OTLP/HTTP JSON; attributes are `vouchwell.<field>`; denials are `WARN` |
| `webhook` | `<url>` exactly | `vouchwell-signature` | `{ "events": [...] }` |

For the first three, a URL with a path is used as given, so you can point at a
proxy or a non-standard path.

### Verifying a webhook

Each delivery carries `vouchwell-signature: t=<unix seconds>,v1=<hex>`, where
`v1` is HMAC-SHA256 over `<t>.<raw body>` with the destination's secret. When
you don't pass `--secret`, the hub makes one (`whsec_…`) and shows it once.

```js
import { createHmac, timingSafeEqual } from 'node:crypto';

function verify(secret, header, rawBody, toleranceSec = 300) {
  const { t, v1 } = Object.fromEntries(header.split(',').map((p) => p.split('=')));
  if (Math.abs(Date.now() / 1000 - Number(t)) > toleranceSec) return false; // replayed
  const want = createHmac('sha256', secret).update(`${t}.${rawBody}`).digest();
  const got = Buffer.from(v1 ?? '', 'hex');
  return got.length === want.length && timingSafeEqual(got, want);
}
```

## Delivery

**At least once, in each log's order, and nothing is lost to an outage.**
Receipts and audit events are already durable in the hub's database, so a
destination is only a cursor into them: per log, the last receipt `seq` it
accepted, and the last audit `seq`. A batch of up to 200 events is sent, and the cursor
moves only after the destination accepts it with a 2xx. While a destination
is down, the backlog waits in the database rather than in memory. It is retried
with backoff (1 s doubling to 5 minutes) and resumes after a hub restart.
`vw streams flush` retries now, without waiting out the backoff.

**Sending never touches the ingest path.** A slow or failing SIEM can't slow
or fail an agent.

**A new destination starts at the present.** Pass `--backfill` to have it
receive the organisation's whole history first. Re-adding a destination under
the same name keeps its place and its credentials. Credentials are kept only
when the name, type and URL are all unchanged, so a stored token can't be
redirected to a new address.

## Security

On a hosted hub, destinations are addresses a tenant typed in, so every send
is guarded against server-side request forgery. Only https is allowed, with no
credentials in the URL. Private, loopback, link-local and metadata addresses
are refused, including names that resolve to them, checked at connect time.
Redirects are not followed, and timeouts and response sizes are capped.
`VOUCHWELL_EGRESS_ALLOW_PRIVATE=1` lifts the address rules for a self-hosted
hub whose collector is on its own network. It also applies to outside
witnesses and SSO discovery.

## API

```
GET    /v1/integrations/streams            destinations, pending counts, last error   (admin)
PUT    /v1/integrations/streams            { destinations: [...] }, the whole list    (admin)
PUT    /v1/integrations/streams/:name      add or replace one                         (admin)
DELETE /v1/integrations/streams/:name      remove one                                 (admin)
DELETE /v1/integrations/streams            remove all                                 (admin)
POST   /v1/integrations/streams/test       one test event to each                     (admin)
POST   /v1/integrations/streams/flush      send what's pending now                    (admin)
```

A destination is
`{ name, type, url, token?, secret?, headers?, receipts: "all"|"blocked"|"none", audit: true, backfill? }`.
