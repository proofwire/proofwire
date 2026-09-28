# Single sign-on (OpenID Connect)

People can sign in to a hub's console through your identity provider, such as
Okta, Microsoft Entra ID, Google Workspace, or anything that speaks OpenID
Connect, instead of with a hub password. You can also *require* it, so the
organisation is reachable only through SSO.

API keys are unaffected: they're machines, and keep working whatever the
sign-in rules are.

---

## 1. Register the hub with your provider

Create a **web application** (a confidential OIDC client) in your provider:

| Setting | Value |
| --- | --- |
| Sign-in redirect URI | `https://<your hub>/sso/callback` |
| Grant type | Authorization code (PKCE is used automatically) |
| Scopes | `openid email profile` |

Note the **client ID** and **client secret**, and the **issuer** URL:

| Provider | Issuer |
| --- | --- |
| Okta | `https://<your-org>.okta.com` (or an authorization server, e.g. `https://<your-org>.okta.com/oauth2/default`) |
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant id>/v2.0` |
| Google Workspace | `https://accounts.google.com` |
| Anything else | Whatever its `/.well-known/openid-configuration` names as `issuer` |

The hub reads the provider's discovery document at that issuer, and refuses
it unless the document names exactly that issuer.

> **Microsoft Entra ID** doesn't always include the `email` claim. Add it
> under *Token configuration → Add optional claim → ID → email*, or sign-in
> will be refused with "the provider sent no email address".

## 2. Connect it (admin key)

```bash
curl -X PUT https://<your hub>/v1/integrations/oidc \
  -H "authorization: Bearer $ADMIN_KEY" -H 'content-type: application/json' \
  -d '{
    "issuer": "https://acme.okta.com",
    "clientId": "0oa1b2c3d4",
    "clientSecret": "…",
    "domains": ["acme.com"],
    "autoProvision": null,
    "requireSso": false
  }'
```

| Field | Meaning |
| --- | --- |
| `domains` | Only emails at these domains may sign in through SSO. Recommended always, and required with `autoProvision`. |
| `autoProvision` | `null`: only people already invited can sign in. A role (`admin`, `operator`, `auditor`): anyone from an allowed domain who signs in joins with that role. `owner` is never allowed, because signing in must not be how someone gets full control. |
| `requireSso` | `true`: members can reach this organisation only through a session started by its SSO. Password sessions lose access immediately, **including the one you're using**. Keep an admin API key to undo it. |
| `clientSecret` | Optional. Leave it out for a public client, and PKCE alone protects the exchange. |

The response gives the exact redirect URI to register, and the sign-in link
for your people: `https://<your hub>/sso/<organisation>`. They can also use
**Continue with SSO** on the console's sign-in page.

`GET /v1/integrations/oidc` shows the settings, never the secret.
`DELETE` turns SSO off.

---

## What the hub checks

On every sign-in, before anyone gets a session:

- **The flow is bound to your browser.** The sign-in starts with a random
  `state` held in a cookie, single use and valid for ten minutes. A callback
  that doesn't carry the same state from the same browser is refused. That
  stops someone completing their own sign-in in your browser, which is a known
  attack called login CSRF.
- **PKCE (S256)** ties the code to the sign-in that asked for it, so an
  intercepted code is useless.
- **The ID token is verified in full:**
  - its signature, against the provider's published keys (RS256/384/512,
    PS256, ES256/384 or EdDSA);
  - issuer, audience, authorised party, expiry, issued-at, not-before;
  - the nonce, which ties the token to this sign-in.

  Unsigned (`alg: none`) and HMAC-signed tokens are refused outright. When the
  provider rotates its keys, the hub fetches the new ones.
- **Accounts are bound to the provider's subject**, not only to an email
  address. If the provider later gives a departed employee's address to
  someone else, that new account can't sign in as the old one.
- **Email checks.** An email the provider marks as unverified is refused, and
  so is one outside `domains`.
- **The provider's address.** The hub only talks to a provider over HTTPS, on
  a public address. The check happens at connection time, after DNS, so a name
  that resolves to an internal address (cloud metadata, a private network) is
  refused, even if the name re-points after it was configured. Redirects
  aren't followed. On a self-hosted hub whose provider is on your own network,
  set `VOUCHWELL_OIDC_ALLOW_PRIVATE=1`; never on a hub others use.

SSO sessions last a day, and password sessions fourteen. Re-authenticating
daily keeps the hub in step with your provider: someone disabled there can't
keep a hub session for two weeks.

Every sign-in, refusal and provisioning is written to the organisation's
hash-chained audit trail (`auth.sso.login`, `auth.sso.refused` with the
reason, `auth.sso.provisioned`). The person signing in sees one of two plain
messages; the specific reason is for admins, so it can't be used to probe.

## Limits

- One provider per organisation.
- No SCIM: people removed at the provider can't start new sessions, but keep
  their hub membership until an admin removes it. Their existing session ends
  within a day.
- Tested against a simulated provider that follows the OpenID Connect
  specification (discovery, key rotation, PKCE, signed tokens), not yet
  against a live Okta, Entra ID or Google tenant. Sign in once as an admin
  before setting `requireSso`.
