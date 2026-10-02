#!/bin/sh
# Bring up, or upgrade, the Deedwrit node on this server.
#
#   ./setup.sh
#
# Safe to run again: after `git checkout <new tag>` it rebuilds and restarts
# with the same data, keys and certificates. See docs/DEPLOY.md.
set -eu
cd "$(dirname "$0")"

say() { printf '  %s\n' "$*"; }
fail() {
  printf '\n  x %s\n\n' "$*" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 ||
  fail "Docker is not installed. Install Docker Engine (https://docs.docker.com/engine/install/), then run this again."
docker compose version >/dev/null 2>&1 ||
  fail "The Docker Compose plugin is missing: 'docker compose version' failed."
command -v curl >/dev/null 2>&1 || fail "curl is needed to check the node once it is up."

if [ ! -f .env ]; then
  cp env.example .env
  chmod 600 .env
  fail "Created deploy/.env from env.example. Set DEEDWRIT_DOMAIN and DEEDWRIT_TLS in it, then run this again."
fi

set -a
. ./.env
set +a

# A .env from under an earlier name uses VOUCHWELL_* or PROOFWIRE_* names:
# read them as the DEEDWRIT_* ones they are, unless the new name is set too.
for old in VOUCHWELL PROOFWIRE; do
  for name in DOMAIN TLS WITNESS_ONLY JOURNAL_DIR BACKUP_HOURS BACKUP_KEEP; do
    eval "[ -n \"\${DEEDWRIT_$name+x}\" ] || [ -z \"\${${old}_$name+x}\" ] || export DEEDWRIT_$name=\"\$${old}_$name\""
  done
done

case "${DEEDWRIT_DOMAIN:-}" in
  '' | witness.example.com) fail "Set DEEDWRIT_DOMAIN in deploy/.env to this server's hostname." ;;
esac
case "${DEEDWRIT_TLS:-}" in
  '' | you@example.com) fail "Set DEEDWRIT_TLS in deploy/.env to your email (for Let's Encrypt), or to 'internal'." ;;
esac

if [ "$DEEDWRIT_TLS" != internal ] && command -v getent >/dev/null 2>&1; then
  getent hosts "$DEEDWRIT_DOMAIN" >/dev/null 2>&1 ||
    say "! $DEEDWRIT_DOMAIN does not resolve yet. The certificate cannot be issued until its DNS record points here."
fi

# Checked here, before Compose reads it: Compose takes anything else as the
# name of a volume that doesn't exist, and says so less helpfully.
case "${DEEDWRIT_JOURNAL_DIR:-}" in
  '' | /*) ;;
  *) fail "DEEDWRIT_JOURNAL_DIR must be an absolute path, or unset." ;;
esac

# Set up under an earlier name, this server's data is in the proofwire_* or
# vouchwell_* volumes. Compose would otherwise start the node on new, empty
# deedwrit_* ones: a hub without its logs, a witness without its keys.
if [ -z "${COMPOSE_PROJECT_NAME:-}" ] && ! docker volume inspect deedwrit_data >/dev/null 2>&1; then
  for old in vouchwell proofwire; do
    if docker volume inspect "${old}_data" >/dev/null 2>&1; then
      fail "This server was set up under an earlier name; its data is in the ${old}_data volume. Add COMPOSE_PROJECT_NAME=$old to deploy/.env so the node keeps it, then run this again."
    fi
  done
fi

say "Building. The first build takes a minute or two."
docker compose build

# The witness journal: everything the witness signed, kept apart from the
# database so a restore from backup can't make it forget (docs/DEPLOY.md).
# Its own Docker volume by default; DEEDWRIT_JOURNAL_DIR puts it on another
# disk, owned by the user the node runs as.
case "${DEEDWRIT_JOURNAL_DIR:-}" in
  '')
    say "! The witness journal is on the same disk as the database. A lost disk takes both;"
    say "  put it on a separate one with DEEDWRIT_JOURNAL_DIR in deploy/.env (see docs/DEPLOY.md)."
    ;;
  /*)
    dir="$DEEDWRIT_JOURNAL_DIR"
    owner="$(docker run --rm --entrypoint id deedwrit-node:local -u):$(docker run --rm --entrypoint id deedwrit-node:local -g)"
    if [ "$(id -u)" = 0 ]; then
      mkdir -p "$dir"
      chown "$owner" "$dir"
      chmod 700 "$dir"
    elif [ ! -d "$dir" ] || [ "$(stat -c %u:%g "$dir")" != "$owner" ]; then
      fail "The journal directory must exist and belong to the node's user. Run: sudo mkdir -p $dir && sudo chown $owner $dir && sudo chmod 700 $dir, then this again."
    fi
    root="$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || true)"
    if [ -n "$root" ] && [ "$(df -P "$dir" | awk 'NR==2 {print $1}')" = "$(df -P "$root" | awk 'NR==2 {print $1}')" ]; then
      say "! $dir is on the same disk as Docker's volumes, where the database is. Mount a separate disk there."
    else
      say "Witness journal: $dir"
    fi
    ;;
esac

say "Starting."
docker compose up -d

# Checked through Caddy, on this machine, so what passes is the real path:
# TLS, the proxy and the node. --resolve keeps it local without hairpinning
# out through the public address.
insecure=''
[ "$DEEDWRIT_TLS" = internal ] && insecure='-k'
i=0
until curl -fsS $insecure --max-time 5 --resolve "$DEEDWRIT_DOMAIN:443:127.0.0.1" \
  "https://$DEEDWRIT_DOMAIN/ready" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 90 ]; then
    docker compose logs --tail 40
    fail "https://$DEEDWRIT_DOMAIN never answered. If the certificate failed, check that DNS points here and ports 80 and 443 are open."
  fi
  sleep 2
done

say "https://$DEEDWRIT_DOMAIN is up."
docker compose exec -T node node packages/server/src/bin.js identity

if [ "${DEEDWRIT_WITNESS_ONLY:-1}" = 1 ]; then
  say "Give a customer a key:"
  say "  docker compose exec node node packages/server/src/bin.js witness-key \"<customer name>\""
else
  say "Create the first organization and admin (once):"
  say "  docker compose exec node node packages/server/src/bin.js bootstrap"
fi
say ""
