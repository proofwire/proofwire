# Security policy

## Reporting

Use GitHub's private vulnerability reporting:

**https://github.com/vouchwell/vouchwell/security/advisories/new**

It reaches the maintainers privately and keeps the fix and the disclosure in
one place. There is no security mailbox yet; this file will say so when
there is one.

Please include enough to reproduce: a failing test, a crafted bundle, or the
sequence of API calls. A proof-of-concept that makes `vw check` accept
something it should reject is worth more than any amount of prose.

**What to expect:** acknowledgement within 3 working days, an assessment within
10, and agreement with you on a disclosure date before anything is published.
If we disagree about severity, we will say so and publish your view alongside
ours.

Do not test against infrastructure you do not operate. Everything here runs
locally in one command, so there is no reason to.

## What we consider a vulnerability

The bar is the claims in [`docs/AUDIT-BRIEF.md`](docs/AUDIT-BRIEF.md). Anything
that breaks one of these is in scope, at any severity:

1. A receipt altered without detection.
2. An entry removed or reordered without detection.
3. History rewritten without detection **after a checkpoint was published** —
   including by an attacker holding the signing key.
4. Two different histories shown to two auditors, with at least one honest
   witness present.
5. A payload recovered from a receipt beyond its size and redacted preview, or
   a shredded payload recovered at all.
6. A forged receipt attributed to an agent whose key the attacker does not
   hold.

Also in scope: cross-tenant access by any route, privilege escalation across
roles or scopes, authentication bypass, and anything that makes a **verifier**
accept evidence it should reject. That last category is the most serious thing
that can go wrong here.

## What we do not consider a vulnerability

These are documented properties, not oversights. Reporting them is welcome but
will be closed as known — see [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md):

- **An attacker with an agent's signing key can write new false receipts.** The
  chain proves consistency, not truthfulness. It still cannot rewrite the past
  once a checkpoint is witnessed.
- **Actions that bypass the proxy leave no receipt.** Vouchwell records what
  passes through it. An unwrapped credential is a deployment gap.
- **Redaction misses secrets shaped like prose.** It is pattern-based and
  best-effort; commitments, not redaction, keep payloads out of the log.
- **A uniformly wrong clock is undetectable from the log alone.**
- **Witnesses run by the log's operator provide no independence.** That is a
  deployment choice the format cannot prevent.
- **A restored hub cannot detect its own staleness.** The evidence was in the
  data the restore discarded; only an outside party can see it.
- Self-inflicted denial of service against your own hub.

## Supported versions

| Version | Supported |
| ------- | --------- |
| Latest release | Yes |
| Anything older | No: upgrade |

Pre-1.0, only the latest release gets fixes. Security fixes ship as a patch
release and are noted in the changelog with the reporter credited, unless they
prefer otherwise.

## How the project protects itself

- **Static analysis:** CodeQL runs on every push, every pull request and weekly.
- **Dependencies:** there are no third-party runtime dependencies. Dependabot
  watches the CI actions, and any npm dependency that is ever added.
- **CI supply chain:** every GitHub Action is pinned to a full commit SHA, and
  workflows run with a read-only token unless a job needs more.
- **No secrets in the repo:** `scripts/repo-hygiene.mjs` blocks key files, salts,
  environment and database files, and token-shaped strings, in CI and before
  every release.
- **Releases** are built and published from CI, with npm provenance linking each
  tarball to the commit and workflow run that produced it.

The attacks these answer are listed in
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md), section A8.

## Our commitments

- **Any commissioned audit is published unedited**, findings and all. A
  security product whose audit is summarised by its vendor has not been audited
  in any sense a buyer should care about.
- **The verifier stays open source, permanently.** Evidence you cannot check
  without a vendor's permission is not evidence, and a licence change here
  would invalidate the entire proposition.
- **Known limitations stay documented in the repository**, not in a sales
  conversation.
