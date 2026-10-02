# Deedwrit hub.
#
# No build step and no dependencies to install: the hub is plain ESM against
# Node's standard library, including its built-in SQLite. That keeps the image
# small and, more to the point, keeps the supply chain of a process that holds
# other companies' audit trails down to Node itself.

FROM node:24-alpine

# Run as a non-root user. The only writable path the hub needs is its data
# directory, and it should not be able to modify its own code at runtime.
RUN addgroup -S deedwrit && adduser -S -G deedwrit deedwrit

WORKDIR /app
COPY package.json ./
COPY packages/core/package.json    packages/core/
COPY packages/proxy/package.json   packages/proxy/
COPY packages/cli/package.json     packages/cli/
COPY packages/server/package.json  packages/server/

# `npm install` here only links the workspaces together; there is nothing to
# fetch from the registry.
RUN npm install --omit=dev --no-audit --no-fund

COPY packages/core   packages/core
COPY packages/proxy  packages/proxy
COPY packages/cli    packages/cli
COPY packages/server packages/server

# /journal is the witness journal's home: a separate volume, ideally on a
# separate disk, so a restored database can't make the witness forget what it
# signed (see witness-journal.js and docs/DEPLOY.md).
RUN mkdir -p /data /backups /journal && chown -R deedwrit:deedwrit /data /backups /journal /app
USER deedwrit

ENV NODE_ENV=production \
    DEEDWRIT_DB=/data/deedwrit.db \
    DEEDWRIT_HOST=0.0.0.0 \
    DEEDWRIT_PORT=8787 \
    NODE_OPTIONS=--no-warnings=ExperimentalWarning

EXPOSE 8787
VOLUME ["/data"]

# Readiness, not liveness: this asks whether the database answers, so a hub
# with a wedged disk is taken out of rotation instead of serving errors.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.DEEDWRIT_PORT||8787)+'/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["node", "packages/server/src/bin.js"]
CMD ["serve"]
