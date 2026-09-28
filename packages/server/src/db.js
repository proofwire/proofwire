import { DatabaseSync } from 'node:sqlite';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/**
 * Storage for the Vouchwell hub.
 *
 * SQLite, via Node's built-in driver, because the hub's correctness depends on
 * transactional appends and this brings no supply chain with it. A receipt
 * that lands without its chain head advancing atomically is a corrupt log, and
 * "we append to two files and hope" is not a design.
 *
 * The schema carries one rule everywhere: **every row that belongs to a tenant
 * names its org_id directly**, even where it could be derived by joining. A
 * query that forgets the tenant filter then fails loudly at the schema rather
 * than quietly returning another customer's data.
 */

/** Prefixes make a leaked identifier self-describing in a log or a bug report. */
export const ID_PREFIX = {
  org: 'org',
  user: 'usr',
  key: 'pwk',
  log: 'lg',
  checkpoint: 'cp',
  policy: 'pol',
  approval: 'apr',
  witness: 'wit',
  event: 'ev',
  session: 'ses',
};

/**
 * @param {keyof typeof ID_PREFIX} kind
 * @returns {string}
 */
export function newId(kind) {
  return `${ID_PREFIX[kind]}_${randomBytes(12).toString('hex')}`;
}

/**
 * Migrations run in order and are recorded, so an existing deployment upgrades
 * without a separate tool. Each entry is append-only once shipped: editing a
 * migration that has already run somewhere is how schemas drift apart.
 *
 * @type {{ id: string, sql: string }[]}
 */
const MIGRATIONS = [
  {
    id: '001_core',
    sql: `
      CREATE TABLE orgs (
        id          TEXT PRIMARY KEY,
        slug        TEXT NOT NULL UNIQUE,
        name        TEXT NOT NULL,
        plan        TEXT NOT NULL DEFAULT 'open',
        settings    TEXT NOT NULL DEFAULT '{}',
        created_at  TEXT NOT NULL,
        suspended_at TEXT
      );

      CREATE TABLE users (
        id          TEXT PRIMARY KEY,
        email       TEXT NOT NULL UNIQUE,
        name        TEXT NOT NULL DEFAULT '',
        password_hash TEXT,
        created_at  TEXT NOT NULL,
        last_seen_at TEXT
      );

      CREATE TABLE memberships (
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role        TEXT NOT NULL,
        created_at  TEXT NOT NULL,
        PRIMARY KEY (org_id, user_id)
      );

      CREATE TABLE sessions (
        id          TEXT PRIMARY KEY,
        user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash  TEXT NOT NULL UNIQUE,
        created_at  TEXT NOT NULL,
        expires_at  TEXT NOT NULL,
        revoked_at  TEXT
      );

      CREATE TABLE api_keys (
        id          TEXT PRIMARY KEY,
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name        TEXT NOT NULL,
        secret_hash TEXT NOT NULL,
        scopes      TEXT NOT NULL,
        log_id      TEXT,
        created_at  TEXT NOT NULL,
        created_by  TEXT,
        last_used_at TEXT,
        expires_at  TEXT,
        revoked_at  TEXT
      );
      CREATE INDEX idx_keys_org ON api_keys(org_id);

      CREATE TABLE logs (
        id          TEXT PRIMARY KEY,
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        slug        TEXT NOT NULL,
        name        TEXT NOT NULL DEFAULT '',
        kid         TEXT NOT NULL,
        public_key  TEXT NOT NULL,
        size        INTEGER NOT NULL DEFAULT 0,
        head        TEXT NOT NULL,
        root        TEXT NOT NULL,
        created_at  TEXT NOT NULL,
        last_seen_at TEXT,
        archived_at TEXT,
        UNIQUE (org_id, slug)
      );

      CREATE TABLE receipts (
        log_id      TEXT NOT NULL REFERENCES logs(id) ON DELETE CASCADE,
        seq         INTEGER NOT NULL,
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        hash        TEXT NOT NULL,
        prev        TEXT NOT NULL,
        ts          TEXT NOT NULL,
        phase       TEXT NOT NULL,
        ref         TEXT,
        kind        TEXT NOT NULL,
        target      TEXT NOT NULL,
        outcome     TEXT NOT NULL,
        principal   TEXT NOT NULL,
        agent       TEXT NOT NULL,
        session     TEXT NOT NULL,
        status      TEXT,
        latency_ms  INTEGER,
        metrics     TEXT NOT NULL DEFAULT '{}',
        body        TEXT NOT NULL,
        received_at TEXT NOT NULL,
        PRIMARY KEY (log_id, seq)
      );
      CREATE INDEX idx_receipts_org_ts   ON receipts(org_id, ts DESC);
      CREATE INDEX idx_receipts_outcome  ON receipts(org_id, outcome, ts DESC);
      CREATE INDEX idx_receipts_target   ON receipts(org_id, target);
      CREATE INDEX idx_receipts_session  ON receipts(org_id, session);
      CREATE UNIQUE INDEX idx_receipts_hash ON receipts(log_id, hash);

      CREATE TABLE checkpoints (
        id          TEXT PRIMARY KEY,
        log_id      TEXT NOT NULL REFERENCES logs(id) ON DELETE CASCADE,
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        size        INTEGER NOT NULL,
        root        TEXT NOT NULL,
        head        TEXT NOT NULL,
        ts          TEXT NOT NULL,
        body        TEXT NOT NULL,
        sigs        TEXT NOT NULL,
        witness_count INTEGER NOT NULL DEFAULT 0,
        UNIQUE (log_id, size)
      );

      CREATE TABLE witnesses (
        id          TEXT PRIMARY KEY,
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        kid         TEXT NOT NULL,
        public_key  TEXT NOT NULL,
        name        TEXT NOT NULL,
        url         TEXT,
        operator    TEXT NOT NULL DEFAULT '',
        created_at  TEXT NOT NULL,
        removed_at  TEXT,
        UNIQUE (org_id, kid)
      );

      CREATE TABLE witness_state (
        witness_kid TEXT NOT NULL,
        log_id      TEXT NOT NULL,
        size        INTEGER NOT NULL,
        root        TEXT NOT NULL,
        updated_at  TEXT NOT NULL,
        PRIMARY KEY (witness_kid, log_id)
      );

      CREATE TABLE policies (
        id          TEXT PRIMARY KEY,
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        slug        TEXT NOT NULL,
        version     INTEGER NOT NULL,
        doc         TEXT NOT NULL,
        hash        TEXT NOT NULL,
        note        TEXT NOT NULL DEFAULT '',
        created_at  TEXT NOT NULL,
        created_by  TEXT,
        active      INTEGER NOT NULL DEFAULT 0,
        UNIQUE (org_id, slug, version)
      );
      CREATE INDEX idx_policies_active ON policies(org_id, slug, active);

      CREATE TABLE approvals (
        id          TEXT PRIMARY KEY,
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        log_id      TEXT NOT NULL REFERENCES logs(id) ON DELETE CASCADE,
        target      TEXT NOT NULL,
        params      TEXT NOT NULL,
        reason      TEXT NOT NULL,
        rules       TEXT NOT NULL DEFAULT '[]',
        principal   TEXT NOT NULL,
        agent       TEXT NOT NULL,
        session     TEXT NOT NULL,
        status      TEXT NOT NULL DEFAULT 'pending',
        requested_at TEXT NOT NULL,
        expires_at  TEXT NOT NULL,
        decided_at  TEXT,
        decided_by  TEXT,
        note        TEXT
      );
      CREATE INDEX idx_approvals_pending ON approvals(org_id, status, requested_at DESC);

      CREATE TABLE audit_events (
        id          TEXT PRIMARY KEY,
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        seq         INTEGER NOT NULL,
        prev        TEXT NOT NULL,
        hash        TEXT NOT NULL,
        actor       TEXT NOT NULL,
        actor_kind  TEXT NOT NULL,
        action      TEXT NOT NULL,
        subject     TEXT NOT NULL DEFAULT '',
        meta        TEXT NOT NULL DEFAULT '{}',
        at          TEXT NOT NULL,
        UNIQUE (org_id, seq)
      );
      CREATE INDEX idx_audit_org_at ON audit_events(org_id, at DESC);

      CREATE TABLE server_keys (
        kid         TEXT PRIMARY KEY,
        role        TEXT NOT NULL,
        public_key  TEXT NOT NULL,
        private_pem TEXT NOT NULL,
        created_at  TEXT NOT NULL,
        retired_at  TEXT
      );
    `,
  },
  {
    id: '002_ingest_idempotency',
    sql: `
      -- A client that retries after a timeout must not create a second copy or
      -- a chain gap. The batch id makes the whole submission replayable.
      CREATE TABLE ingest_batches (
        id          TEXT PRIMARY KEY,
        log_id      TEXT NOT NULL REFERENCES logs(id) ON DELETE CASCADE,
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        accepted    INTEGER NOT NULL,
        first_seq   INTEGER NOT NULL,
        last_seq    INTEGER NOT NULL,
        head        TEXT NOT NULL,
        root        TEXT NOT NULL,
        size        INTEGER NOT NULL,
        at          TEXT NOT NULL
      );
    `,
  },
  {
    id: '003_usage_counters',
    sql: `
      -- Per-day counters, so billing and quota checks never scan the receipt
      -- table. Written in the same transaction as the append.
      CREATE TABLE usage_daily (
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        day         TEXT NOT NULL,
        receipts    INTEGER NOT NULL DEFAULT 0,
        denials     INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (org_id, day)
      );
    `,
  },
  {
    id: '004_canonical_log_id',
    sql: `
      -- The receipt's own "log" field is signed, so it is what ingest must
      -- check against. The slug is a human-facing name the operator chooses
      -- and can differ; conflating the two made every receipt unacceptable.
      ALTER TABLE logs ADD COLUMN canonical TEXT NOT NULL DEFAULT '';
      UPDATE logs SET canonical = slug WHERE canonical = '';
      CREATE UNIQUE INDEX idx_logs_canonical ON logs(org_id, canonical);
    `,
  },
  {
    id: '005_external_signers',
    sql: `
      -- With an external signer the hub holds only the public half, so
      -- private_pem must be nullable. SQLite cannot relax a NOT NULL in place,
      -- hence the rebuild.
      CREATE TABLE server_keys_new (
        kid         TEXT PRIMARY KEY,
        role        TEXT NOT NULL,
        public_key  TEXT NOT NULL,
        private_pem TEXT,
        backend     TEXT NOT NULL DEFAULT 'local',
        created_at  TEXT NOT NULL,
        retired_at  TEXT
      );
      INSERT INTO server_keys_new(kid, role, public_key, private_pem, backend, created_at, retired_at)
        SELECT kid, role, public_key, private_pem, 'local', created_at, retired_at FROM server_keys;
      DROP TABLE server_keys;
      ALTER TABLE server_keys_new RENAME TO server_keys;

      -- Retired keys are kept forever: a checkpoint signed by a key that has
      -- since been rotated must stay verifiable, or rotation would silently
      -- invalidate history.
      CREATE INDEX idx_server_keys_role ON server_keys(role, retired_at);
    `,
  },
  {
    id: '006_invites_and_resets',
    sql: `
      -- One table for both invitations and password resets: they are the same
      -- object — a single-use, expiring capability to establish a credential —
      -- and splitting them would duplicate every consumption rule, which is
      -- exactly where this kind of flow goes wrong.
      CREATE TABLE tokens (
        id          TEXT PRIMARY KEY,
        kind        TEXT NOT NULL,          -- 'invite' | 'reset'
        token_hash  TEXT NOT NULL UNIQUE,
        user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        org_id      TEXT REFERENCES orgs(id) ON DELETE CASCADE,
        role        TEXT,
        created_at  TEXT NOT NULL,
        created_by  TEXT,
        expires_at  TEXT NOT NULL,
        used_at     TEXT
      );
      CREATE INDEX idx_tokens_user ON tokens(user_id, kind, used_at);
    `,
  },
  {
    id: '007_witness_log_keys',
    sql: `
      -- The key a log's checkpoints must be signed with, as far as this witness
      -- is concerned. Bound the first time the witness co-signs for the log,
      -- changed afterwards only by an operator on the host. Kept apart from
      -- witness_state because the two change for different reasons: a rebind
      -- replaces the key and must leave the recorded position exactly as it was.
      CREATE TABLE witness_log_keys (
        witness_kid TEXT NOT NULL,
        log_id      TEXT NOT NULL,
        kid         TEXT NOT NULL,
        public_key  TEXT NOT NULL,
        bound_at    TEXT NOT NULL,
        bound_by    TEXT NOT NULL,      -- 'first-use' | 'operator'
        PRIMARY KEY (witness_kid, log_id)
      );
    `,
  },
  {
    id: '008_integrations',
    sql: `
      -- Per-organisation connections to other services (Slack approvals, for
      -- now). The config holds credentials: treat this table like the keys
      -- table, and a backup of it like a backup of them.
      CREATE TABLE integrations (
        org_id     TEXT NOT NULL REFERENCES orgs(id),
        kind       TEXT NOT NULL,
        config     TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (org_id, kind)
      );
    `,
  },
  {
    id: '009_retention',
    sql: `
      -- How long the hub keeps the content of receipts, per organisation. NULL
      -- is forever. The cap is the operator's (a hosted plan's limit); the
      -- organisation's admins may choose anything up to it.
      ALTER TABLE orgs ADD COLUMN retention_days INTEGER;
      ALTER TABLE orgs ADD COLUMN retention_cap_days INTEGER;

      -- A pruned receipt keeps its place in the log (seq, hash, prev) and the
      -- non-identifying facts (ts, phase, kind, outcome); its body and every
      -- column that could name a person or a customer are cleared. The Merkle
      -- tree is built from the hashes, so roots, checkpoints and witness
      -- signatures stay verifiable after pruning.
      ALTER TABLE receipts ADD COLUMN pruned_at TEXT;
      CREATE INDEX idx_receipts_unpruned ON receipts(org_id, ts) WHERE pruned_at IS NULL;
    `,
  },
  {
    id: '010_sso',
    sql: `
      -- An OpenID Connect sign-in in progress: single use, ten minutes, and
      -- bound to the browser that started it by a cookie holding the id.
      CREATE TABLE sso_states (
        id          TEXT PRIMARY KEY,
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        nonce       TEXT NOT NULL,
        verifier    TEXT NOT NULL,
        created_at  TEXT NOT NULL
      );

      -- Which identity-provider account is which user. Bound to the
      -- provider's stable subject, not to an email address, so an address the
      -- provider later reassigns can't sign in as the person who had it.
      CREATE TABLE sso_identities (
        org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        issuer        TEXT NOT NULL,
        subject       TEXT NOT NULL,
        user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at    TEXT NOT NULL,
        last_login_at TEXT,
        PRIMARY KEY (org_id, issuer, subject)
      );

      -- How a session was started: 'password', or 'sso:<org id>'. An
      -- organisation that requires SSO accepts only its own.
      ALTER TABLE sessions ADD COLUMN via TEXT NOT NULL DEFAULT 'password';
    `,
  },
  {
    id: '011_receipt_links',
    sql: `
      -- An outcome names its intent by hash in \`ref\`. Finding the intents
      -- nothing answered joins on it; the other direction uses the existing
      -- unique index on (log_id, hash).
      CREATE INDEX idx_receipts_ref ON receipts(log_id, ref) WHERE ref IS NOT NULL;
    `,
  },
  {
    id: '012_stream_cursors',
    sql: `
      -- How far each event-stream destination has got. Receipts and audit
      -- events are already durable, so a destination is only a place in them:
      -- per log, the last receipt seq it has accepted (JSON, log id to seq; a
      -- log not named starts at its beginning), and the last audit seq. Seqs,
      -- not rowids, because a seq is part of the signed receipt and a rowid
      -- can change under VACUUM, which backups use. Moved only after the
      -- destination accepts a batch, which is what makes delivery at least
      -- once across outages and restarts.
      CREATE TABLE stream_cursors (
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name        TEXT NOT NULL,
        receipts    TEXT NOT NULL DEFAULT '{}',
        audit_after INTEGER NOT NULL,
        PRIMARY KEY (org_id, name)
      );
    `,
  },
  {
    id: '013_witness_holds',
    sql: `
      -- Logs a witness will not co-sign for until its operator releases them.
      -- A restore with no witness journal to catch up from puts every log on
      -- hold: the witness may have signed later checkpoints it no longer
      -- remembers, and signing again from the restored position could vouch
      -- for a conflicting history. See witness-journal.js.
      CREATE TABLE witness_holds (
        witness_kid TEXT NOT NULL,
        log_id      TEXT NOT NULL,
        reason      TEXT NOT NULL,
        since       TEXT NOT NULL,
        PRIMARY KEY (witness_kid, log_id)
      );
    `,
  },
];

/**
 * Open (and migrate) the hub database.
 *
 * @param {string} file  Path, or `:memory:` for tests.
 * @returns {DatabaseSync}
 */
export function openDatabase(file) {
  if (file !== ':memory:') {
    fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  }
  const db = new DatabaseSync(file);

  // WAL lets readers (the console, exports) run while ingest writes.
  // `busy_timeout` turns the inevitable concurrent-write collision into a short
  // wait instead of an immediate SQLITE_BUSY thrown at a customer's agent.
  if (file !== ':memory:') db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA foreign_keys = ON');
  db.exec('PRAGMA busy_timeout = 5000');
  db.exec('PRAGMA synchronous = FULL');

  db.exec(`CREATE TABLE IF NOT EXISTS migrations (
    id TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
  )`);

  const applied = new Set(db.prepare('SELECT id FROM migrations').all().map((r) => r.id));
  for (const m of MIGRATIONS) {
    if (applied.has(m.id)) continue;
    db.exec('BEGIN');
    try {
      db.exec(m.sql);
      db.prepare('INSERT INTO migrations(id, applied_at) VALUES(?, ?)').run(
        m.id,
        new Date().toISOString(),
      );
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw new Error(`migration ${m.id} failed: ${err.message}`);
    }
  }

  return db;
}

/**
 * Open a database without touching it.
 *
 * Opening a SQLite file read-write is not a passive act: it applies
 * migrations, writes PRAGMAs, and can leave WAL sidecars behind. Doing that to
 * a *backup* changes its bytes and invalidates the very digest that proves it
 * is intact — which is how backup verification managed to fail every backup it
 * had just taken.
 *
 * Use this for anything being inspected rather than operated: backups,
 * forensic copies, an auditor's snapshot.
 *
 * @param {string} file
 * @returns {DatabaseSync}
 */
export function openReadOnly(file) {
  return new DatabaseSync(file, { readOnly: true });
}

/**
 * Run `fn` inside a transaction, rolling back on any throw.
 *
 * Nested calls join the outer transaction rather than opening a second one,
 * which SQLite does not support and which would otherwise commit half a batch.
 *
 * @template T
 * @param {DatabaseSync} db
 * @param {() => T} fn
 * @returns {T}
 */
export function transact(db, fn) {
  if (db.isTransaction) return fn();

  // IMMEDIATE takes the write lock up front. A deferred transaction that
  // upgrades mid-way can lose the race and fail after half the work is done.
  db.exec('BEGIN IMMEDIATE');
  try {
    const out = fn();
    db.exec('COMMIT');
    return out;
  } catch (err) {
    try {
      db.exec('ROLLBACK');
    } catch {
      // A rollback failure must not mask the original error.
    }
    throw err;
  }
}

/** @returns {string} */
export function now() {
  return new Date().toISOString();
}

/** @returns {string} YYYY-MM-DD in UTC, for daily counters. */
export function today() {
  return new Date().toISOString().slice(0, 10);
}
