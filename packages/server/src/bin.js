#!/usr/bin/env node
import fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import { identityFromPublicKey, checkpointDigest, verify as verifyBytes } from '@proof_wire/core';
import { Hub, VERSION } from './app.js';
import { Auth } from './auth.js';
import { selfTest } from './signer.js';
import {
  cmdBackup, cmdVerifyBackup, cmdRestore, cmdReconcile, scheduleBackups,
} from './backup-cmds.js';

/**
 * Hub entry point.
 *
 *   proofwire-hub serve                 start the server
 *   proofwire-hub bootstrap             create the first org, admin and keys
 *   proofwire-hub witness-key <name>    give a customer a key to this node's witness
 *   proofwire-hub witness-rebind <customer> <log> <public key>
 *                                       rebind a log to a rotated signing key
 *   proofwire-hub witness-release <customer> <log> --checkpoint <file> | --no-evidence
 *                                       resume co-signing a log held after a restore
 *   proofwire-hub check                 verify every stored log
 *   proofwire-hub identity [--json]     this node's public keys, for publishing
 *   proofwire-hub retention <org> [--days N|forever] [--cap N|none]
 *
 * PROOFWIRE_WITNESS_ONLY=1 turns the server into a witness and nothing else:
 * see WITNESS_ONLY_ROUTES in app.js for the whole of what it then answers.
 *
 * Configuration is environment-only. A hub reads secrets and binds ports; a
 * config file that can be edited by whoever can reach the filesystem is one
 * more thing to get wrong in a container.
 */

/** @returns {Partial<typeof import('./app.js').DEFAULT_CONFIG>} */
function configFromEnv() {
  const env = process.env;
  /** @type {any} */
  const config = {};
  if (env.PROOFWIRE_PORT) config.port = Number(env.PROOFWIRE_PORT);
  if (env.PROOFWIRE_HOST) config.host = env.PROOFWIRE_HOST;
  if (env.PROOFWIRE_DB) config.database = env.PROOFWIRE_DB;
  if (env.PROOFWIRE_PUBLIC_URL) config.publicUrl = env.PROOFWIRE_PUBLIC_URL;
  // Only honour X-Forwarded-For when explicitly told to: behind no proxy, it
  // is a header any client can set to evade a per-address rate limit.
  if (env.PROOFWIRE_TRUST_PROXY === '1') config.trustProxy = true;
  if (env.PROOFWIRE_CHECKPOINT_EVERY) config.checkpointEvery = Number(env.PROOFWIRE_CHECKPOINT_EVERY);
  if (env.PROOFWIRE_APPROVAL_TTL) config.approvalTtlSeconds = Number(env.PROOFWIRE_APPROVAL_TTL);
  if (env.PROOFWIRE_WITNESS_ONLY === '1') config.witnessOnly = true;
  // A self-hosted hub whose identity provider is on its own network. Never on
  // a hub whose tenants choose the issuer: see oidc.js.
  if (env.PROOFWIRE_OIDC_ALLOW_PRIVATE === '1') config.oidcAllowPrivate = true;
  if (env.PROOFWIRE_EGRESS_ALLOW_PRIVATE === '1') config.egressAllowPrivate = true;
  // Where the witness journal lives; `off` disables it. See witness-journal.js.
  if (env.PROOFWIRE_WITNESS_JOURNAL) {
    config.witnessJournal = env.PROOFWIRE_WITNESS_JOURNAL === 'off' ? false : env.PROOFWIRE_WITNESS_JOURNAL;
  }
  return config;
}

const B = (s) => `[1m${s}[0m`;
const DIM = (s) => `[90m${s}[0m`;
const GREEN = (s) => `[32m${s}[0m`;
const RED = (s) => `[31m${s}[0m`;
const CYAN = (s) => `[36m${s}[0m`;

async function serve() {
  const hub = new Hub(configFromEnv());
  const { url } = await hub.listen();

  const witnessOnly = hub.config.witnessOnly;
  console.error('');
  console.error(B(witnessOnly ? '  Proofwire witness' : '  Proofwire hub') + DIM(`  ${VERSION}`));
  console.error(DIM(`  ${url}`));
  console.error(DIM(`  db       ${hub.config.database}`));
  if (!witnessOnly) console.error(DIM(`  hub key  ${hub.hubSigner.kid}  [${hub.hubSigner.kind}]`));
  console.error(DIM(`  witness  ${hub.witnessSigner.kid}  [${hub.witnessSigner.kind}]`));
  if (witnessOnly) console.error(DIM('  mode     witness only — co-signing, key and health routes, nothing else'));

  // Prove the signers work now, with a real signature verified against the
  // configured public key. That catches a missing command, a denied KMS grant,
  // the wrong key wired up, and an unexpected output encoding — all at boot,
  // rather than at the first checkpoint hours later.
  const roles = witnessOnly
    ? [['witness', hub.witnessSigner]]
    : [['hub', hub.hubSigner], ['witness', hub.witnessSigner]];
  for (const [role, signer] of roles) {
    const res = await selfTest(signer);
    if (!res.ok) {
      console.error(RED(`  ${role} signer is not usable: ${res.error}`));
      console.error(
        DIM(
          witnessOnly
            ? '  Every co-signing request will be refused until this is fixed.'
            : '  Receipts will still be accepted and verified; checkpoints will not be signed.',
        ),
      );
    }
  }

  if (hub.store.holdsPrivateKeys()) {
    console.error('');
    console.error(
      DIM('  note: a signing key is stored in this database. For a hosted deployment set'),
    );
    console.error(DIM('        PROOFWIRE_SIGNER=command|http so key material stays out of it.'));
  }
  if (hub.witnessJournal) {
    console.error(DIM(`  witness journal  ${hub.witnessJournal.file}`));
    console.error(DIM('        keep it on a different volume from the database; see docs/HUB.md#backups'));
  } else {
    console.error('');
    console.error(RED('  warning: the witness journal is off. A restore from backup can make this witness'));
    console.error(RED('           forget what it signed and vouch for a conflicting history.'));
  }
  const held = hub.db.prepare('SELECT COUNT(*) AS n FROM witness_holds WHERE witness_kid = ?').get(hub.witnessSigner.kid);
  if (Number(held?.n) > 0) {
    console.error(RED(`  ${held.n} log(s) on hold after a restore; release each with proofwire-hub witness-release.`));
  }
  console.error('');

  // A hub that never re-reads its own storage is taking itself at its word.
  // Re-verifying every log on a schedule is cheap and is the difference
  // between detecting silent corruption in an hour and in a deposition.
  const interval = Number(process.env.PROOFWIRE_SELFCHECK_MINUTES ?? 60);
  if (interval > 0) {
    const timer = setInterval(() => {
      for (const org of hub.db.prepare('SELECT id FROM orgs').all()) {
        for (const log of hub.store.logs(org.id)) {
          const res = hub.store.audit(org.id, log.id);
          if (!res.ok) {
            console.error(
              JSON.stringify({
                level: 'error',
                event: 'selfcheck.failed',
                org: org.id,
                log: log.slug,
                issues: res.issues.slice(0, 5),
              }),
            );
          }
        }
      }
    }, interval * 60_000);
    timer.unref();
  }

  // Retention: clear the content of receipts past each organisation's
  // retention period. Hourly is plenty for a period measured in days; the
  // first run is a minute after start, not at start, so a restart loop can't
  // turn into a pruning loop.
  const sweepMinutes = Number(process.env.PROOFWIRE_RETENTION_SWEEP_MINUTES ?? 60);
  if (sweepMinutes > 0) {
    const sweep = () => {
      try {
        for (const r of hub.store.pruneExpired()) {
          if (r.pruned > 0) {
            console.error(JSON.stringify({ level: 'info', event: 'retention.pruned', org: r.orgId, pruned: r.pruned, before: r.before }));
          }
        }
      } catch (err) {
        console.error(JSON.stringify({ level: 'error', event: 'retention.failed', message: /** @type {Error} */ (err).message }));
      }
    };
    setTimeout(sweep, 60_000).unref();
    setInterval(sweep, sweepMinutes * 60_000).unref();
  }

  if (scheduleBackups(hub.config.database)) {
    console.error(
      DIM(`  backups  every ${process.env.PROOFWIRE_BACKUP_HOURS ?? 6}h to ${process.env.PROOFWIRE_BACKUP_DIR}`),
    );
  }

  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, async () => {
      console.error(DIM('\n  shutting down…'));
      await hub.close();
      process.exit(0);
    });
  }
}

/**
 * Create the first organization, an admin who can sign in, and the two API
 * keys a deployment actually needs on day one.
 */
async function bootstrap() {
  const config = configFromEnv();
  if (config.witnessOnly) {
    // bootstrap's admin password and agent/auditor keys are for a hub. On a
    // witness there is no console to sign in to and no log to push to, so it
    // would hand out credentials that can do nothing — or, worse, look like
    // they should.
    console.error(RED('  bootstrap is for a hub; this is a witness-only node.'));
    console.error(DIM('  Give each customer their own key instead:'));
    console.error(`    ${CYAN('proofwire-hub witness-key <customer name>')}`);
    process.exitCode = 1;
    return;
  }
  const hub = new Hub(config);
  const auth = new Auth(hub.store);

  const orgName = process.env.PROOFWIRE_ORG ?? 'Acme';
  const slug = (process.env.PROOFWIRE_ORG_SLUG ?? orgName).toLowerCase().replace(/[^a-z0-9-]+/g, '-');
  const email = process.env.PROOFWIRE_ADMIN_EMAIL ?? 'admin@example.com';
  const password = process.env.PROOFWIRE_ADMIN_PASSWORD ?? randomBytes(9).toString('base64url');

  if (hub.store.orgBySlug(slug)) {
    console.error(RED(`  an organization "${slug}" already exists`));
    await hub.close();
    process.exitCode = 1;
    return;
  }

  const org = hub.store.createOrg({ slug, name: orgName });
  const user = auth.userByEmail(email) ?? auth.createUser({ email, password });
  auth.addMember(org.id, user.id, 'owner');

  const agentKey = auth.createKey({
    orgId: org.id,
    name: 'agent-runtime',
    scopes: ['receipts:write', 'logs:write', 'logs:read', 'policies:read'],
    createdBy: 'bootstrap',
  });
  const auditKey = auth.createKey({
    orgId: org.id,
    name: 'auditor-readonly',
    scopes: ['receipts:read', 'logs:read', 'policies:read', 'approvals:read'],
    createdBy: 'bootstrap',
  });

  hub.store.recordEvent({
    orgId: org.id,
    actor: 'bootstrap',
    actorKind: 'system',
    action: 'org.create',
    subject: org.slug,
  });

  console.error('');
  console.error(B('  Organization created'));
  console.error(DIM('  ─────────────────────────────────────────────'));
  console.error(`  org        ${org.slug}  ${DIM(org.id)}`);
  console.error(`  admin      ${email}`);
  console.error(`  password   ${B(password)}`);
  console.error('');
  console.error(B('  API keys') + DIM('  (shown once — they are not stored in recoverable form)'));
  console.error(`  agent      ${CYAN(agentKey.token)}`);
  console.error(DIM('             receipts:write logs:write logs:read policies:read'));
  console.error(`  auditor    ${CYAN(auditKey.token)}`);
  console.error(DIM('             read-only: the credential to hand an outside firm'));
  console.error('');
  console.error(DIM('  Point an agent at it:'));
  console.error(`    ${CYAN(`pw remote add --url http://localhost:${hub.config.port} --token <agent token>`)}`);
  console.error('');

  await hub.close();
}

/**
 * Give one customer a key to this node's witness.
 *
 * Each customer gets an organization of their own, and that is load-bearing,
 * not tidiness. A witness binds each log name, per organization, to the key
 * that first signs a checkpoint for it — so two customers sharing an
 * organization could each bind the other's log name to their own key first,
 * and the second to arrive would be locked out of a log it owns.
 *
 * Running it again for the same customer adds a key rather than replacing
 * one, which is what a rotation needs: issue the new key, move the client
 * over, then revoke the old one.
 */
async function witnessKey() {
  const name = process.argv.slice(3).join(' ').trim();
  const slug = name.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '');
  if (!slug) {
    console.error(RED('  usage: proofwire-hub witness-key <customer name>'));
    process.exitCode = 2;
    return;
  }

  const hub = new Hub(configFromEnv());
  const existing = hub.store.orgBySlug(slug);
  const org = existing ?? hub.store.createOrg({ slug, name });

  const key = hub.auth.createKey({
    orgId: org.id,
    name: 'witness-client',
    // logs:read only so `pw remote add` can prove the key works via /v1/me.
    // On a witness-only node there are no logs for it to read.
    scopes: ['witness:sign', 'logs:read'],
    createdBy: 'witness-key',
  });
  hub.store.recordEvent({
    orgId: org.id,
    actor: 'witness-key',
    actorKind: 'system',
    action: 'key.create',
    subject: key.id,
    meta: { name: 'witness-client', scopes: ['witness:sign', 'logs:read'] },
  });

  const url = hub.config.publicUrl || `http://localhost:${hub.config.port}`;
  const { kid, publicKey } = hub.witnessSigner;

  console.error('');
  console.error(B(existing ? '  Additional witness key issued' : '  Witness customer created'));
  console.error(DIM('  ─────────────────────────────────────────────'));
  console.error(`  customer   ${org.slug}  ${DIM(org.id)}`);
  console.error(`  token      ${CYAN(key.token)}`);
  console.error(DIM('             witness:sign logs:read — shown once, not stored in recoverable form'));
  console.error('');
  console.error(B('  This witness') + DIM('  (send these through a channel other than this node)'));
  console.error(`  kid        ${kid}`);
  console.error(`  public key ${publicKey}`);
  console.error('');
  console.error(DIM('  The customer connects with:'));
  console.error(`    ${CYAN(`pw remote add --name witness --url ${url} --token <token>`)}`);
  console.error(`    ${CYAN('pw cosign --remote witness')}`);
  console.error(DIM('  and their auditors pin this witness with:'));
  console.error(`    ${CYAN(`pw check evidence.json --witnesses 1 --witness-key ${kid}=${publicKey}`)}`);
  console.error('');

  await hub.close();
}

/**
 * Show or set an organisation's retention, from the host.
 *
 *   proofwire-hub retention <org>                     show
 *   proofwire-hub retention <org> --cap 365           the plan's limit (operator only)
 *   proofwire-hub retention <org> --days 90           the organisation's own choice
 *   proofwire-hub retention <org> --days forever --cap none
 *
 * The cap exists only here, not in the API: an organisation's admins can
 * shorten what the hub keeps, but only the operator can decide how long the
 * hub is willing to keep it.
 */
async function retention() {
  const args = process.argv.slice(3);
  const slug = args[0];
  const flag = (/** @type {string} */ name) => {
    const i = args.indexOf(name);
    return i === -1 ? undefined : args[i + 1];
  };
  if (!slug || slug.startsWith('--')) {
    console.error(RED('  usage: proofwire-hub retention <org> [--days N|forever] [--cap N|none]'));
    process.exitCode = 2;
    return;
  }
  const parse = (/** @type {string | undefined} */ v, /** @type {string} */ none) => {
    if (v === undefined) return undefined;
    if (v === none) return null;
    const n = Number(v);
    if (!Number.isInteger(n) || n < 1 || n > 36_500) throw new Error(`expected a number of days (1 to 36500) or "${none}", got "${v}"`);
    return n;
  };

  const hub = new Hub(configFromEnv());
  try {
    const org = hub.store.orgBySlug(slug);
    if (!org) {
      console.error(RED(`  no organization "${slug}"`));
      process.exitCode = 1;
      return;
    }
    let days;
    let capDays;
    try {
      days = parse(flag('--days'), 'forever');
      capDays = parse(flag('--cap'), 'none');
    } catch (err) {
      console.error(RED(`  ${/** @type {Error} */ (err).message}`));
      process.exitCode = 2;
      return;
    }
    /** @type {{ days?: number | null, capDays?: number | null }} */
    const set = {};
    if (days !== undefined) set.days = days;
    if (capDays !== undefined) set.capDays = capDays;
    if (Object.keys(set).length) {
      hub.store.setRetention(org.id, set);
      hub.store.recordEvent({
        orgId: org.id,
        actor: 'operator',
        actorKind: 'system',
        action: 'retention.set',
        subject: slug,
        meta: set,
      });
    }
    const r = hub.store.retention(org.id);
    const show = (/** @type {number | null} */ d) => (d === null ? 'forever' : `${d} days`);
    console.error('');
    console.error(B(`  Retention · ${slug}`));
    console.error(DIM('  ─────────────────────────────────────────────'));
    console.error(`  org choice  ${show(r.days)}`);
    console.error(`  plan cap    ${r.capDays === null ? 'none' : `${r.capDays} days`}`);
    console.error(`  applied     ${B(show(r.effectiveDays))}`);
    console.error(`  pruned      ${r.pruned} receipt(s) so far`);
    console.error(`  oldest kept ${r.oldest ?? '—'}`);
    console.error('');
  } finally {
    await hub.close();
  }
}

/**
 * Print this node's public keys, from the host.
 *
 * Read-only apart from one thing: on a node that has never started, opening
 * it creates its keys, as `serve` would. The keys are what gets published in
 * `witnesses/keys.json` and handed to auditors, so they must come from here
 * rather than from the node's own HTTP API: a key a server serves about
 * itself is only as trustworthy as that server.
 *
 *   proofwire-hub identity          for people
 *   proofwire-hub identity --json   for scripts
 */
async function identity() {
  const hub = new Hub(configFromEnv());
  const witness = { kid: hub.witnessSigner.kid, publicKey: hub.witnessSigner.publicKey };
  const own = hub.config.witnessOnly ? null : { kid: hub.hubSigner.kid, publicKey: hub.hubSigner.publicKey };
  const url = hub.config.publicUrl || null;
  await hub.close();

  if (process.argv.includes('--json')) {
    process.stdout.write(JSON.stringify({ url, witnessOnly: hub.config.witnessOnly, witness, hub: own }, null, 2) + '\n');
    return;
  }

  const out = (/** @type {string} */ s = '') => process.stdout.write(s + '\n');
  out('');
  out(B(hub.config.witnessOnly ? '  This witness node' : '  This hub'));
  out(DIM('  ─────────────────────────────────────────────'));
  if (own) {
    out(`  hub kid      ${own.kid}`);
    out(`  hub key      ${own.publicKey}`);
  }
  out(`  witness kid  ${witness.kid}`);
  out(`  witness key  ${witness.publicKey}`);
  out('');
  out(DIM('  To publish the witness key, from a checkout of the proofwire repo, in a commit of its own:'));
  out(
    `    ${CYAN(
      `node scripts/witness-record.mjs add --operator Proofwire --public-key ${witness.publicKey}` +
        (url ? ` --node ${url}` : ''),
    )}`,
  );
  out('');
}

/**
 * Rebind a customer's log to a new signing key, after a rotation.
 *
 * This is the only way a witness's log-to-key binding changes after first
 * use, and it is deliberately not an HTTP endpoint: whoever can rebind a log
 * can decide whose checkpoints the witness accepts for it, so it takes someone
 * on the host, acting on a request confirmed out of band — the new public key
 * should reach the operator through a channel other than the customer's
 * witness credential, which is the one thing a thief would have.
 *
 * The recorded position is kept exactly as it was. The new key has to extend
 * the history the witness already attested to, with a consistency proof, like
 * any other checkpoint; rebinding is not a way to start the log over.
 */
async function witnessRebind() {
  const [customer, log, publicKey] = process.argv.slice(3);
  if (!customer || !log || !publicKey) {
    console.error(RED('  usage: proofwire-hub witness-rebind <customer> <log> <new public key>'));
    process.exitCode = 2;
    return;
  }
  let next;
  try {
    next = identityFromPublicKey(publicKey);
  } catch {
    console.error(RED('  that is not a raw 32-byte Ed25519 public key in canonical base64url'));
    process.exitCode = 2;
    return;
  }

  const hub = new Hub(configFromEnv());
  try {
    const slug = customer.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '');
    const org = hub.store.orgBySlug(slug);
    if (!org) {
      console.error(RED(`  no customer "${slug}" on this witness`));
      process.exitCode = 1;
      return;
    }

    const witnessKid = hub.witnessSigner.kid;
    const positionKey = `${org.id}:${log}`;
    const previous = hub.store.witnessBinding(witnessKid, positionKey);
    const position = hub.store.witnessPosition(witnessKid, positionKey);
    if (!previous && !position) {
      // Nothing to rebind: the log's next checkpoint binds on first use.
      console.error(RED(`  this witness has never co-signed for ${log} under ${slug}`));
      console.error(DIM('  Nothing to rebind — its next checkpoint will bind whichever key signs it.'));
      process.exitCode = 1;
      return;
    }
    if (previous?.kid === next.kid) {
      console.error(DIM(`  ${log} is already bound to ${next.kid}; nothing changed.`));
      return;
    }

    // Journal first: a rebind the database loses in a restore must come back.
    hub.witnessJournal?.append({
      t: 'bind', witness: witnessKid, log: positionKey, logKid: next.kid, logPublicKey: next.publicKey,
      by: 'operator', at: new Date().toISOString(),
    });
    hub.store.bindWitnessLogKey({
      witnessKid, positionKey, kid: next.kid, publicKey: next.publicKey, by: 'operator',
    });
    hub.store.recordEvent({
      orgId: org.id,
      actor: 'witness-rebind',
      actorKind: 'system',
      action: 'witness.rebind',
      subject: log,
      meta: { from: previous?.kid ?? null, to: next.kid, size: position?.size ?? null },
    });

    console.error('');
    console.error(B('  Log rebound'));
    console.error(DIM('  ─────────────────────────────────────────────'));
    console.error(`  customer   ${slug}`);
    console.error(`  log        ${log}`);
    console.error(`  from       ${previous?.kid ?? DIM('(no key bound yet)')}`);
    console.error(`  to         ${next.kid}`);
    if (position) {
      console.error(`  position   size ${position.size}, root ${position.root.slice(0, 16)}… ${DIM('— kept')}`);
    }
    console.error('');
  } finally {
    await hub.close();
  }
}

/**
 * Resume co-signing a log this witness put on hold after a restore.
 *
 * The safe way is with evidence: a checkpoint of the log carrying this
 * witness's own signature, as late as the customer has (a bundle from
 * `pw export` works: every checkpoint in it is considered). The signature
 * proves this witness vouched for that root, so the position moves up to it
 * and the witness carries on from where it really was. `--no-evidence`
 * resumes from the restored position instead, accepting that a later
 * signature may have been forgotten; `--all` does that for every held log of
 * the customer.
 */
async function witnessRelease() {
  const argv = process.argv.slice(3);
  const flag = (/** @type {string} */ name) => argv.includes(name);
  const value = (/** @type {string} */ name) => {
    const i = argv.indexOf(name);
    return i === -1 ? undefined : argv[i + 1];
  };
  const positional = argv.filter((a, i) => !a.startsWith('--') && argv[i - 1] !== '--checkpoint');
  const [customer, log] = positional;
  const evidenceFile = value('--checkpoint');
  const noEvidence = flag('--no-evidence');
  const all = flag('--all');
  if (!customer || (!log && !all) || (!evidenceFile && !noEvidence) || (all && !noEvidence)) {
    console.error(RED('  usage: proofwire-hub witness-release <customer> <log> --checkpoint <checkpoint or bundle.json>'));
    console.error(RED('         proofwire-hub witness-release <customer> <log> --no-evidence'));
    console.error(RED('         proofwire-hub witness-release <customer> --all --no-evidence'));
    process.exitCode = 2;
    return;
  }

  const hub = new Hub(configFromEnv());
  try {
    const slug = customer.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '');
    const org = hub.store.orgBySlug(slug);
    if (!org) {
      console.error(RED(`  no customer "${slug}" on this witness`));
      process.exitCode = 1;
      return;
    }
    const kid = hub.witnessSigner.kid;
    const held = hub.db
      .prepare('SELECT log_id FROM witness_holds WHERE witness_kid = ? AND log_id LIKE ?')
      .all(kid, `${org.id}:%`)
      .map((r) => String(r.log_id).slice(org.id.length + 1));
    const logs = all ? held : [log];
    if (!all && !held.includes(log)) {
      console.error(DIM(`  ${log} is not on hold for ${slug}; nothing to release.`));
      return;
    }

    for (const name of logs) {
      const positionKey = `${org.id}:${name}`;
      const pos = hub.store.witnessPosition(kid, positionKey);
      /** @type {any} */
      let best = null;
      if (evidenceFile) {
        const doc = JSON.parse(fs.readFileSync(evidenceFile, 'utf8'));
        const candidates = Array.isArray(doc?.checkpoints) ? doc.checkpoints : [doc];
        for (const cp of candidates) {
          if (cp?.body?.log !== name || !Number.isInteger(cp.body.size) || typeof cp.body.root !== 'string') continue;
          const mine = (Array.isArray(cp.sigs) ? cp.sigs : []).some((sg) =>
            sg?.role === 'witness' && sg.kid === kid && typeof sg.sig === 'string' &&
            verifyBytes(hub.witnessSigner.publicKey, checkpointDigest(cp.body), sg.sig));
          if (mine && (!best || cp.body.size > best.body.size)) best = cp;
        }
        if (!best) {
          console.error(RED(`  ${evidenceFile} holds no checkpoint of ${name} signed by this witness (${kid}).`));
          console.error(DIM('  Ask the customer for their latest witnessed checkpoint, or a bundle from pw export.'));
          process.exitCode = 1;
          return;
        }
        if (pos && best.body.size === pos.size && best.body.root !== pos.root) {
          console.error(RED(`  this witness signed a different root of ${name} at size ${pos.size} than its database holds.`));
          console.error(RED('  Its records are inconsistent; investigate before releasing anything.'));
          process.exitCode = 1;
          return;
        }
      }

      const moved = Boolean(best && (!pos || best.body.size > pos.size));
      if (moved) {
        const bound = hub.store.witnessBinding(kid, positionKey);
        if (hub.witnessJournal && bound) {
          hub.witnessJournal.append({
            t: 'sign', witness: kid, log: positionKey, size: best.body.size, root: best.body.root,
            logKid: bound.kid, logPublicKey: bound.public_key, at: new Date().toISOString(),
          });
        }
        hub.store.setWitnessPosition(kid, positionKey, best.body.size, best.body.root);
      }
      hub.store.releaseWitnessLog(kid, positionKey);
      hub.store.recordEvent({
        orgId: org.id,
        actor: 'witness-release',
        actorKind: 'system',
        action: 'witness.released',
        subject: name,
        meta: {
          evidence: best ? { size: best.body.size, root: best.body.root } : null,
          from: pos?.size ?? null,
          to: moved ? best.body.size : pos?.size ?? null,
        },
      });
      const now = hub.store.witnessPosition(kid, positionKey);
      console.error(`  ${GREEN('✓')} ${name}: co-signing again from size ${now?.size ?? 0}` +
        (moved ? DIM(` (moved up from ${pos?.size ?? 0} on this witness's own signature)`) : ''));
    }
    if (noEvidence) {
      console.error('');
      console.error(DIM('  Released without evidence: if this witness signed later checkpoints before the'));
      console.error(DIM('  restore, it can no longer tell whether a new one conflicts with them.'));
    }
    console.error('');
  } finally {
    await hub.close();
  }
}

/** Verify every stored log and exit non-zero if any fails. */
async function check() {
  const hub = new Hub(configFromEnv());
  let bad = 0;
  let total = 0;

  for (const org of hub.db.prepare('SELECT * FROM orgs').all()) {
    for (const log of hub.store.logs(org.id)) {
      total++;
      const res = hub.store.audit(org.id, log.id);
      const label = `${org.slug}/${log.slug}`.padEnd(34);
      if (res.ok) {
        console.log(`  ${GREEN('✓')} ${label} ${DIM(`${res.size} entries · ${res.root.slice(0, 16)}…`)}`);
      } else {
        bad++;
        console.log(`  ${RED('✗')} ${label} ${RED(`${res.issues.length} problem(s)`)}`);
        for (const i of res.issues.slice(0, 5)) console.log(`      ${DIM(i.message)}`);
      }
    }
    const events = hub.store.auditEvents(org.id);
    if (!events.ok) {
      bad++;
      console.log(`  ${RED('✗')} ${org.slug}: control-plane audit chain broken`);
    }
  }

  console.log('');
  console.log(bad === 0 ? `  ${GREEN(`All ${total} log(s) verify.`)}` : `  ${RED(`${bad} of ${total} failed.`)}`);
  await hub.close();
  process.exitCode = bad === 0 ? 0 : 1;
}

const command = process.argv[2] ?? 'serve';
const COMMANDS = {
  serve,
  bootstrap,
  'witness-key': witnessKey,
  'witness-rebind': witnessRebind,
  'witness-release': witnessRelease,
  identity,
  retention,
  check,
  backup: cmdBackup,
  'verify-backup': cmdVerifyBackup,
  restore: cmdRestore,
  reconcile: cmdReconcile,
};

if (!COMMANDS[command]) {
  console.error(`unknown command "${command}" — try: ${Object.keys(COMMANDS).join(', ')}`);
  process.exitCode = 2;
} else {
  await COMMANDS[command]();
}
