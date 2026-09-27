# Deploying a Proofwire node

This takes one Linux server from nothing to a Proofwire node serving HTTPS on
your own domain: a witness-only node by default. The same kit runs a full hub
by changing one setting.

Everything here runs in CI on every push: `deploy/setup.sh` from a fresh
checkout, then a customer co-signing through TLS and an auditor verifying the
result. So these steps are known to work as written.

**You need:**

- A domain, and the ability to add a DNS record for it.
- A small Linux server with a public IPv4 address: 1 vCPU, 1 GB RAM, 20 GB
  disk is plenty. Ubuntu 24.04 LTS or Debian 12. Any provider works.
- About 30 minutes.

---

## 1. Point the domain at the server

Create an **A record** for the hostname the node will use, for example
`witness1.yourdomain.com`, with the server's public IPv4 address as its value.
If the server has IPv6, add an **AAAA record** too.

Do this first: certificates can't be issued until the record resolves, and
DNS can take a few minutes to spread.

## 2. Harden the server

Log in as root (or a sudo user) over SSH, then:

```bash
# Updates, now and automatically from here on.
apt update && apt -y upgrade
apt -y install unattended-upgrades curl git
dpkg-reconfigure -f noninteractive unattended-upgrades

# A firewall that allows SSH and web traffic, and nothing else.
apt -y install ufw
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
ufw --force enable
```

Then make SSH key-only, if your provider didn't already. Confirm you can log in
with your key before you do this, or you will lock yourself out:

```bash
sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl reload ssh
```

> Docker publishes ports through its own firewall rules, and those bypass
> `ufw`. That's why `compose.yml` publishes only 80 and 443 (Caddy), and the
> node itself publishes nothing.

## 3. Install Docker

Follow Docker's official instructions for your distribution:
<https://docs.docker.com/engine/install/ubuntu/> (or `/debian/`). Use the
`apt` repository method. When you're done, this should print a version:

```bash
docker compose version
```

## 4. Get the code at a release

```bash
git clone https://github.com/proofwire/proofwire.git /opt/proofwire
cd /opt/proofwire
git checkout v0.4.0      # the latest release tag, not main
```

The kit needs 0.4.0 or later: `identity`, which prints the keys, arrived then.

## 5. Configure and start

```bash
cd /opt/proofwire/deploy
./setup.sh               # first run creates .env and stops
nano .env                # set PROOFWIRE_DOMAIN and PROOFWIRE_TLS
./setup.sh               # builds, starts, waits for HTTPS, prints the keys
```

In `.env`:

| Setting | What to put |
| --- | --- |
| `PROOFWIRE_DOMAIN` | The hostname from step 1, e.g. `witness1.yourdomain.com` |
| `PROOFWIRE_TLS` | An email address for Let's Encrypt expiry notices. Or `internal` for a self-signed certificate, to test before DNS is ready. |
| `PROOFWIRE_WITNESS_ONLY` | `1` for a witness node (the default). `0` for a full hub. |

`setup.sh` finishes by printing the node's public keys and the exact command
that publishes the witness key. If it can't reach the node over HTTPS within
three minutes, it prints the logs and explains the likely cause: DNS not
pointing here yet, or ports 80/443 blocked.

Check it from your own machine:

```bash
curl https://witness1.yourdomain.com/.well-known/proofwire
```

## 6. Publish the witness key

Auditors pin a witness by its public key, so the key has to be published
somewhere the node itself can't change. For Proofwire's own nodes, that's
[`witnesses/keys.json`](../witnesses/keys.json) in this repository. Take the key
from the **server**, not from the node's HTTP API:

```bash
docker compose exec node node packages/server/src/bin.js identity
```

It prints the command to run from a checkout of the repo on your own machine.
Commit the change on its own, and push:

```bash
node scripts/witness-record.mjs add --operator Proofwire --public-key <key> --node https://witness1.yourdomain.com
git commit -am "Publish witness1's key" && git push
```

The website picks it up on its next deploy.

## 7. Give a customer a key

```bash
docker compose exec node node packages/server/src/bin.js witness-key "Acme Corp"
```

It prints a token (shown once) and the commands the customer runs:

```bash
pw remote add --name witness --url https://witness1.yourdomain.com --token <token>
pw cosign --remote witness
```

Send the token over a private channel. Send the witness's public key separately,
or point them at `witnesses/keys.json`.

**For a full hub** (`PROOFWIRE_WITNESS_ONLY=0`), create the first organization
and admin instead, once:

```bash
docker compose exec -e PROOFWIRE_ORG="Acme" -e PROOFWIRE_ADMIN_EMAIL=you@acme.com \
  node node packages/server/src/bin.js bootstrap
```

It prints an admin password (change it after first sign-in at
`https://<domain>/login`) and two API keys.

---

## Operating it

### Backups

The node snapshots its database every `PROOFWIRE_BACKUP_HOURS` (default 6) into
its `backups` volume and keeps the last `PROOFWIRE_BACKUP_KEEP` (default 28).
Each one is verified when written. **Copy them off the server**; a backup on the
same disk doesn't survive losing the disk:

```bash
# On the server, e.g. from cron every 6 hours:
cd /opt/proofwire/deploy
docker compose cp node:/backups /var/backups/proofwire
# then ship /var/backups/proofwire elsewhere: rsync, rclone to object storage, etc.
```

Read [HUB.md → Backups](HUB.md#backups) before you ever restore. A restored
node can't tell it is stale, and for a witness that matters: a witness restored
to an older state would accept a checkpoint it had already seen superseded.

### Upgrades

```bash
cd /opt/proofwire
git fetch --tags
git checkout v0.5.0      # the new release
deploy/setup.sh
```

Data, keys and certificates live in Docker volumes and carry over. Read the
CHANGELOG's *Breaking* section for the release first.

### Logs and alerts

```bash
docker compose logs -f node      # the node: JSON lines
docker compose logs -f caddy     # access log and certificate renewals
```

Alert on these events in the node's log. Ship the logs anywhere that can match a
line, or run a cron job with `grep`:

| Event | Meaning |
| --- | --- |
| `selfcheck.failed` | A stored log failed re-verification. Treat it as an incident. |
| `split_view` | A witness refused a checkpoint that contradicts one it signed. Someone is showing different histories. |
| `backup.failed` | A scheduled snapshot didn't happen. |
| `auth.login_throttled` | Repeated failed sign-ins on one account (hub only). |

And monitor `https://<domain>/ready` from outside with any uptime checker. It
fails if the database stops answering.

### What `compose.yml` does for you

- **Only Caddy is exposed**, on 80 and 443. It gets and renews the Let's
  Encrypt certificate itself, redirects HTTP to HTTPS, adds HSTS, and strips the
  `Server` header. Caddy's admin API is off.
- **The node's port is never published.** Only Caddy can reach it, which is what
  makes trusting `X-Forwarded-For` safe.
- **Both containers are read-only**, with all Linux capabilities dropped
  (Caddy keeps only the one needed to bind ports 80 and 443) and
  `no-new-privileges`. The node runs as a non-root user.
- **Images are pinned.** Caddy is pinned by digest, and Dependabot proposes
  updates as pull requests.
- **Logs rotate** at 10 MB × 5 files per container, so they can't fill the disk.

### What it doesn't do yet

- **Signing keys live in the node's database**, the default `local` signer. For
  a paid service, move them to a KMS with `PROOFWIRE_SIGNER`; see
  [HUB.md → Keys](HUB.md#keys). That's a cost and a vendor decision.
- **One node is one point of failure.** The Team tier promises three
  witnesses; that means three servers, ideally with three providers.
- **No status page.** Point an external uptime monitor at `/ready` and publish
  its public page.
