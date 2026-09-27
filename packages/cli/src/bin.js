#!/usr/bin/env node
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { ProofLog, verifyBundle, Policy, verifyInclusion, unhex, generateIdentity, findUnfinished } from '@proof_wire/core';
import { McpProxy, auditPolicyMetrics } from '@proof_wire/proxy';
import { cmdPolicyTest } from './policy-test.js';
import { cmdReport } from './report.js';
import { cmdPolicyTemplates, cmdPolicyTemplate, templatePolicyText } from './policy-templates.js';
import { RemoteSink, hubApprover, fetchPolicy } from '@proof_wire/proxy/remote';
import { approverFrom } from '@proof_wire/proxy/approve';
import { c, out, err, ok, bad, warn, info, heading, kv, table, outcomeBadge, parseArgs } from './ui.js';
import { witnessKeysFrom } from './witness-keys.js';
import { cmdWitnesses, cmdStreams } from './hub-integrations.js';
import {
  cmdRemote, cmdPush, cmdRemoteVerify, cmdPolicy, cmdCosign, cmdSlack, loadRemotes, resolveRemote,
  witnessWith, explainRefusal,
} from './remote-cmds.js';

// Read from the package, not written here: a version typed into source is one
// more place for a release to forget, and `pw --version` lying is worse than
// it saying nothing.
const { version: VERSION } = createRequire(import.meta.url)('../package.json');
const CONFIG = 'proofwire.config.json';
const POLICY = 'proofwire.policy.json';

/**
 * @param {any} args
 * @returns {{ dir: string, config: any }}
 */
function loadConfig(args) {
  const configPath = path.resolve(args.config ?? CONFIG);
  const config = fs.existsSync(configPath)
    ? JSON.parse(fs.readFileSync(configPath, 'utf8'))
    : {};
  const dir = path.resolve(args.log ?? config.log ?? '.proofwire');
  return { dir, config };
}

/**
 * @param {any} config
 * @param {any} args
 * @returns {Policy}
 */
function loadPolicy(config, args) {
  const file = path.resolve(args.policy ?? config.policy ?? POLICY);
  if (!fs.existsSync(file)) {
    // No policy is a real choice — record everything, block nothing — but it
    // should be a visible one rather than a silent default.
    warn(`no policy file at ${path.relative(process.cwd(), file)}; recording without enforcement`);
    return new Policy({ version: 1, name: 'permissive', rules: [] });
  }
  return Policy.parse(fs.readFileSync(file, 'utf8'));
}

const STARTER_POLICY = `{
  "version": 1,
  "name": "starter",

  // Rules run top to bottom. The first rule with a "then" decides.
  // A rule with no "then" just tags the call and evaluation continues.
  "rules": [
    {
      "id": "deny.destructive-sql",
      "when": { "params.sql": { "matches": "(?i)\\\\b(drop|truncate|delete\\\\s+from)\\\\b" } },
      "then": "deny",
      "reason": "destructive SQL from an agent is not permitted"
    },
    {
      "id": "escalate.outbound-mail",
      "when": { "target": "*.send*" },
      "then": "escalate",
      "reason": "anything that leaves the building gets a human"
    }
  ],

  // Budgets aggregate the clear-text metrics your config extracts.
  "budgets": [
    {
      "id": "spend.daily",
      "match": { "target": "*" },
      "field": "metrics.amount_usd",
      "limit": 1000,
      "window": "24h",
      "then": "escalate"
    }
  ],

  // Rate limits count allowed calls only; denials cost nothing.
  "rateLimits": [
    { "id": "burst.any-tool", "match": { "target": "*" }, "limit": 500, "window": "1h", "then": "escalate" }
  ],

  // Refuse to hand credentials or card numbers to a tool, whatever the rules say.
  "egress": { "denySecrets": true }
}
`;

const STARTER_CONFIG = {
  log: '.proofwire',
  policy: POLICY,
  actor: {
    agent: 'claude-opus-5',
    principal: process.env.USER || process.env.USERNAME || 'unknown',
  },
  approval: { mode: 'deny' },
  metrics: {
    'stripe.*': { amount_usd: { from: 'params.amount', scale: 0.01 } },
  },
};

// ──────────────────────────────────────────────────────────── commands ──

/**
 * Create a file, or leave it alone if it exists. One call, so nothing can
 * appear between the check and the write and be overwritten.
 *
 * @param {string} file
 * @param {string} text
 */
function writeIfAbsent(file, text) {
  try {
    fs.writeFileSync(file, text, { flag: 'wx' });
    return true;
  } catch (err) {
    if (/** @type {NodeJS.ErrnoException} */ (err).code !== 'EEXIST') throw err;
    return false;
  }
}

/** @param {string} file */
function readIfPresent(file) {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch (err) {
    if (/** @type {NodeJS.ErrnoException} */ (err).code === 'ENOENT') return '';
    throw err;
  }
}

/** @param {any} args */
function cmdInit(args) {
  const dir = path.resolve(args.log ?? '.proofwire');
  if (fs.existsSync(path.join(dir, 'config.json'))) {
    bad(`a log already exists at ${path.relative(process.cwd(), dir) || '.'}`);
    return 1;
  }

  // Compose first: an unknown template name should fail before anything is created.
  const policyText = args.template ? templatePolicyText(args.template) : STARTER_POLICY;
  const log = ProofLog.create(dir);
  const wrotePolicy = writeIfAbsent(POLICY, policyText);
  writeIfAbsent(CONFIG, JSON.stringify(STARTER_CONFIG, null, 2) + '\n');

  const gitignore = '.gitignore';
  const rules = ['.proofwire/key.pem', '.proofwire/salts.jsonl'];
  const existing = readIfPresent(gitignore);
  const missing = rules.filter((r) => !existing.includes(r));
  if (missing.length) {
    fs.appendFileSync(
      gitignore,
      (existing && !existing.endsWith('\n') ? '\n' : '') +
        '\n# Proofwire: the signing key and the commitment salts never get committed\n' +
        missing.join('\n') +
        '\n',
    );
  }

  heading('Proofwire initialised');
  kv([
    ['log', log.logId],
    ['key', log.identity.kid],
    ['dir', path.relative(process.cwd(), dir) || '.'],
    ['policy', `${POLICY}${wrotePolicy ? '' : c.grey(' (already there; left unchanged)')}`],
    ['config', CONFIG],
  ]);
  out('');
  if (args.template && !wrotePolicy) {
    info(`--template was not applied: ${POLICY} already exists. ${c.cyan('pw policy template <ids> --out <file>')} writes one elsewhere.`);
    out('');
  }
  info('Commit entries.jsonl and checkpoints.jsonl. Never commit key.pem or salts.jsonl.');
  out('');
  out(`  Next: wrap an MCP server so every call it makes gets a receipt.`);
  out('');
  out(c.cyan('    pw proxy --namespace crm -- npx -y @acme/mcp-crm'));
  out('');
  return 0;
}

/** @param {any} args */
async function cmdProxy(args) {
  if (args.rest.length === 0) {
    bad('nothing to wrap. Put the MCP server command after `--`:');
    out(c.cyan('  pw proxy --namespace crm -- npx -y @acme/mcp-crm'));
    return 2;
  }
  const { dir, config } = loadConfig(args);
  const log = ProofLog.open(dir);

  // A hub, when one is configured, supplies the policy and the approvals
  // inbox and receives a copy of every receipt. The local log stays
  // authoritative throughout: if the hub is unreachable the agent keeps
  // running and keeps recording, and the backlog ships when it returns.
  const remoteName = args.remote ?? (args['no-remote'] ? null : 'default');
  const remote = remoteName && loadRemotes()[remoteName] ? resolveRemote({ remote: remoteName }) : null;
  const logSlug = args.name ?? remote?.log ?? config.remoteLog ?? log.logId;

  let policy = null;
  if (remote && !args.policy) {
    const slug = args['policy-name'] ?? config.policyName ?? 'default';
    try {
      const active = await fetchPolicy({ url: remote.url, token: remote.token, slug });
      if (active) {
        policy = new Policy(active.policy);
        err(c.grey(`proofwire: policy ${slug} v${active.version} (${active.hash.slice(0, 8)}) from ${remote.url}`));
      }
    } catch (e) {
      // Falling back to the local policy is right; falling back to *no* policy
      // would quietly turn enforcement off because a network call failed.
      err(c.yellow(`proofwire: could not fetch policy from the hub (${e.message}); using the local file`));
    }
  }
  if (!policy) policy = loadPolicy(config, args);

  // A budget nobody can compute is worse than no budget: it reads as
  // protection in the policy document while enforcing nothing.
  for (const w of auditPolicyMetrics(policy, config.metrics ?? {})) {
    err(c.yellow(`proofwire: ${w}`));
  }

  // Monitor mode is chosen per machine, never by the hub: a policy pushed from
  // elsewhere must not be able to switch a gate off without the operator
  // seeing it. `--enforce` wins over a config file that says otherwise.
  const monitor = !args.enforce && (args.monitor === true || config.monitor === true);

  let sink = null;
  if (remote) {
    sink = new RemoteSink({
      url: remote.url,
      token: remote.token,
      log: logSlug,
      localLog: log,
      onLog: (level, msg) => err(level === 'error' ? c.red(`proofwire: ${msg}`) : c.grey(`proofwire: ${msg}`)),
    });
    if (await sink.connect()) sink.start();
  }

  const proxy = new McpProxy({
    log,
    policy,
    actor: {
      agent: args.agent ?? config.actor?.agent ?? 'unknown-agent',
      session: args.session ?? 'sess_' + Date.now().toString(36),
      principal: args.principal ?? config.actor?.principal ?? 'unknown',
    },
    approver:
      remote && (args.approve ?? config.approval?.mode) !== 'tty'
        ? hubApprover({ url: remote.url, token: remote.token, log: logSlug })
        : approverFrom(args.approve ? { mode: args.approve } : config.approval),
    command: args.rest[0],
    args: args.rest.slice(1),
    namespace: args.namespace ?? config.namespace,
    metrics: config.metrics,
    monitor,
  });

  // Diagnostics go to stderr: stdout is the MCP channel and must carry
  // nothing but protocol.
  err(
    c.grey(
      `proofwire ${VERSION} · log ${log.logId} · policy ${policy.name} ` +
        `(${policy.hash.slice(0, 8)}) · wrapping: ${args.rest.join(' ')}`,
    ),
  );
  if (monitor) {
    err(
      c.yellow(
        'proofwire: MONITOR MODE — nothing will be blocked. Every call is forwarded; ' +
          'what the policy would have stopped is recorded, not enforced. Use --enforce to gate.',
      ),
    );
  }
  proxy.on('denied', ({ target, decision }) => {
    err(`${c.red('blocked')} ${target} — ${decision.reason}`);
  });
  proxy.on('monitored', ({ target, wouldBe, reason }) => {
    err(`${c.yellow(`would ${wouldBe}`)} ${target} — ${reason}`);
  });

  const finish = () => {
    try {
      proxy.finalize();
    } catch (e) {
      err(`proofwire: could not finalize the log: ${e.message}`);
    }
  };

  /**
   * Ask each configured witness to sign the checkpoint the session ended on.
   * Best effort: the receipts are already durable, so a witness that is down
   * costs a warning, never the session. Everything goes to stderr, because
   * stdout is the MCP channel.
   */
  const witness = async () => {
    const names = Array.isArray(config.witnesses) ? config.witnesses.map(String) : [];
    if (names.length === 0 || log.size === 0) return;
    const remotes = loadRemotes();
    for (const name of names) {
      const remote = remotes[name];
      if (!remote) {
        err(c.yellow(`proofwire: witness "${name}" is not a configured remote; pw remote add --name ${name} …`));
        continue;
      }
      try {
        const res = await witnessWith(log, { name, ...remote });
        err(c.grey(`proofwire: witnessed by ${name} (${res.witness.kid}) at size ${res.checkpoint.body.size}`));
      } catch (e) {
        const refusal = /** @type {any} */ (e);
        err((refusal.alarming ? c.red : c.yellow)(`proofwire: witness ${name} refused: ${refusal.message}`));
        explainRefusal(refusal, log, (msg) => err(c.yellow(`proofwire: ${msg}`)));
      }
    }
  };

  /** Flush the tail to the hub, and have the end witnessed, before the process goes away. */
  let drained = false;
  const drain = async () => {
    if (drained) return;
    drained = true;
    finish();
    if (sink) await sink.stop();
    await witness();
  };
  for (const [signal, code] of [['SIGINT', 130], ['SIGTERM', 143]]) {
    process.on(signal, async () => {
      await drain();
      process.exit(code);
    });
  }

  const code = await proxy.start();
  await drain();
  const s = proxy.stats;
  err(
    c.grey(
      `proofwire · ${log.size} receipts · ${s.forwarded} allowed · ${s.denied} blocked · ` +
        `${s.approved}/${s.escalated} approvals · ` +
        (monitor ? `${s.wouldDeny + s.wouldEscalate} would have been stopped (monitor mode) · ` : '') +
        `root ${log.root.slice(0, 16)}…` +
        (sink ? ` · hub ${sink.status().behind === 0 ? 'in sync' : `${sink.status().behind} behind`}` : ''),
    ),
  );
  return code;
}

/** @param {any} args */
function cmdVerify(args) {
  const { dir } = loadConfig(args);
  const log = ProofLog.open(dir, { readOnly: true });
  const res = log.audit();

  heading(`Audit · ${log.logId}`);
  kv([
    ['entries', String(res.size)],
    ['root', res.root],
    ['head', log.head],
    ['checkpoints', String(log.checkpoints().length)],
    ['keys', Object.keys(log.keyring).join(', ')],
  ]);
  out('');

  if (res.ok) {
    ok(c.bold('Every receipt verifies. The chain is unbroken and extends every checkpoint.'));
    out('');
    const open = reportUnfinished(log.entries);
    return open && args['fail-on-unfinished'] ? 3 : 0;
  }

  bad(c.bold(`${res.issues.length} problem(s) found:`));
  out('');
  for (const i of res.issues) {
    const where = i.seq !== undefined ? c.grey(`entry ${i.seq}`) : c.grey('log');
    out(`  ${c.red(i.kind.padEnd(10))} ${where}  ${i.message}`);
  }
  out('');
  warn('This log has been altered since it was written. Treat it as evidence of tampering,');
  warn('not as a corrupted file to repair.');
  out('');
  return 1;
}

/**
 * Say which actions were authorised and sent but never came back.
 *
 * The log is intact either way, so this is a warning and not a verification
 * failure; `--fail-on-unfinished` turns it into exit code 3 for monitoring.
 *
 * @param {any[]} entries
 * @returns {number} How many were found.
 */
function reportUnfinished(entries) {
  const found = findUnfinished(entries);
  const all = [
    ...found.unfinished.map((u) => ({ ...u, why: 'no result recorded' })),
    ...found.abandoned.map((u) => ({ ...u, why: 'recorder stopped before the reply' })),
  ].sort((a, b) => a.seq - b.seq);

  if (found.inFlight.length) {
    info(`${found.inFlight.length} call(s) are still out, started in the last few minutes.`);
    out('');
  }
  if (found.orphans.length) {
    warn(`${found.orphans.length} result receipt(s) name an intent this log does not hold: ` +
      `entries ${found.orphans.slice(0, 10).map((o) => o.seq).join(', ')}.`);
    out('');
  }
  if (all.length === 0) return 0;

  warn(c.bold(`${all.length} action(s) were authorised and sent, but never finished:`));
  out('');
  table(
    ['#', 'when', 'tool', 'principal', 'session', 'why'],
    all.slice(0, 20).map((u) => [
      c.grey(String(u.seq)), u.ts, u.target, c.grey(u.principal), c.grey(u.session), c.yellow(u.why),
    ]),
  );
  if (all.length > 20) out(c.grey(`  …and ${all.length - 20} more: pw log --unfinished`));
  out('');
  warn('Whether these happened is not in the log: check each with the system it called.');
  out('');
  return all.length;
}

/** @param {any} args */
function cmdLog(args) {
  const { dir } = loadConfig(args);
  const log = ProofLog.open(dir, { readOnly: true });
  const limit = Number(args.tail ?? args.n ?? 20);
  let entries = log.entries;

  if (args.target) entries = entries.filter((r) => r.action.target.includes(args.target));
  if (args.principal) entries = entries.filter((r) => r.actor.principal === args.principal);
  if (args.denied) entries = entries.filter((r) => r.decision.outcome !== 'allow');
  if (args['would-block']) entries = entries.filter((r) => r.decision.wouldBe && r.phase !== 'outcome');
  if (args.session) entries = entries.filter((r) => r.actor.session === args.session);
  if (args.unfinished) {
    const found = findUnfinished(log.entries);
    const open = new Set([...found.unfinished, ...found.abandoned].map((u) => u.seq));
    entries = entries.filter((r) => open.has(r.seq));
  }

  const shown = entries.slice(-limit);

  if (args.json) {
    out(JSON.stringify(shown, null, 2));
    return 0;
  }

  heading(`${log.logId} · showing ${shown.length} of ${entries.length}`);
  if (shown.length === 0) {
    out('  ' + c.grey('nothing recorded yet'));
    out('');
    return 0;
  }

  table(
    ['#', 'when', 'outcome', 'tool', 'principal', 'detail'],
    shown.map((r) => [
      c.grey(String(r.seq)),
      r.ts.slice(11, 19),
      r.decision.wouldBe ? c.yellow(`would ${r.decision.wouldBe}`) : outcomeBadge(r.decision.outcome),
      r.action.target,
      c.grey(r.actor.principal),
      r.decision.outcome === 'allow' && !(r.decision.wouldBe && !r.result)
        ? c.grey(
            r.result
              ? `${r.result.status}${r.result.latencyMs !== undefined ? ` ${r.result.latencyMs}ms` : ''}`
              // An intent receipt is the record that the call was authorised
              // and sent, written before the reply could exist.
              : 'committed, awaiting result',
          )
        : c.yellow(r.decision.reason.slice(0, 60)),
    ]),
  );
  out('');
  return 0;
}

/** @param {any} args */
function cmdExport(args) {
  const { dir } = loadConfig(args);
  const log = ProofLog.open(dir, { readOnly: true });
  const file = args._[1] ?? `proofwire-${log.logId}-${Date.now()}.bundle.json`;

  /** @type {((r: any) => boolean)|undefined} */
  let filter;
  if (args.since) {
    const since = new Date(args.since).toISOString();
    filter = (r) => r.ts >= since;
  }
  if (args.session) {
    const prev = filter;
    filter = (r) => r.actor.session === args.session && (!prev || prev(r));
  }

  const bundle = log.bundle(filter ? { filter } : {});
  fs.writeFileSync(file, JSON.stringify(bundle, null, 2) + '\n');

  heading('Evidence bundle written');
  kv([
    ['file', file],
    ['entries', `${bundle.entries.length}${bundle.partial ? ` (of ${bundle.treeSize})` : ''}`],
    ['root', bundle.root],
    ['size', `${(fs.statSync(file).size / 1024).toFixed(1)} KB`],
  ]);
  out('');
  info('This bundle contains no payloads and no salts — it is safe to send.');
  info(`The recipient verifies it with:  ${c.cyan(`pw check ${path.basename(file)}`)}`);
  out('');
  return 0;
}

/** @param {any} args */
function cmdCheck(args) {
  const file = args._[1];
  if (!file) {
    bad('which bundle? `pw check <file.bundle.json>`');
    return 2;
  }
  // Strict: `Number('abc')` is NaN, and a NaN minimum used to compare false
  // against every count, silently turning the witness requirement off.
  const minWitnesses = args.witnesses === undefined ? 0 : Number(args.witnesses);
  if (!Number.isInteger(minWitnesses) || minWitnesses < 0) {
    bad(`--witnesses must be a whole number, got ${JSON.stringify(args.witnesses)}`);
    return 2;
  }
  const bundle = JSON.parse(fs.readFileSync(file, 'utf8'));
  const trustedWitnesses = witnessKeysFrom(args);
  const res = verifyBundle(bundle, {
    expectRoot: args.root,
    minWitnesses,
    trustedWitnesses,
  });

  heading(`Bundle · ${bundle.log}`);
  kv([
    ['exported', bundle.exported ?? '—'],
    ['entries', `${res.checked}${bundle.partial ? ` (a subset of ${bundle.treeSize})` : ''}`],
    ['root', bundle.root],
    ['checkpoints', String((bundle.checkpoints ?? []).length)],
  ]);
  out('');

  if (res.ok) {
    ok(c.bold('Verified. Every receipt is signed and provably part of this log.'));
    const claimsWitnesses = (bundle.checkpoints ?? []).some((cp) =>
      (cp.sigs ?? []).some((s) => s.role === 'witness'),
    );
    if (res.witnessedSize !== undefined && res.witnessedSize < bundle.treeSize) {
      out('');
      const covered = res.witnessedSize === 0 ? 'none' : `entries 0–${res.witnessedSize - 1}`;
      warn(`Witnesses vouch for ${covered} of ${bundle.treeSize}. Entries from ${res.witnessedSize} on are`);
      warn('signed by the log alone; a newer witnessed checkpoint would cover them.');
    }
    if (claimsWitnesses && !trustedWitnesses) {
      out('');
      warn('This bundle carries witness signatures, but none were checked against keys you chose.');
      warn('The bundle\'s own keyring cannot vouch for its witnesses. Pin the ones you trust:');
      warn(`  ${c.cyan('pw check <file> --witnesses N --witness-key <kid>=<publicKey>')}`);
    }
    if (bundle.partial) {
      out('');
      warn('This is a filtered export. Each entry shown is proven genuine, but the');
      warn('bundle cannot prove that nothing relevant was left out. Ask for a full');
      warn(`export, or compare the root against a witness: ${c.cyan('pw check --root <root>')}`);
    }
    out('');
    return 0;
  }

  bad(c.bold(`${res.issues.length} problem(s):`));
  out('');
  for (const i of res.issues) out(`  ${c.red('✗')} ${i}`);
  out('');
  return 1;
}

/** @param {any} args */
function cmdProve(args) {
  const { dir } = loadConfig(args);
  const log = ProofLog.open(dir, { readOnly: true });
  const seq = Number(args._[1]);
  if (!Number.isInteger(seq)) {
    bad('which entry? `pw prove <seq>`');
    return 2;
  }
  const proof = log.proofFor(seq);
  if (args.json) {
    out(JSON.stringify({ ...proof, receipt: log.entries[seq] }, null, 2));
    return 0;
  }

  const r = log.entries[seq];
  heading(`Inclusion proof · entry ${seq}`);
  kv([
    ['tool', r.action.target],
    ['outcome', outcomeBadge(r.decision.outcome)],
    ['when', r.ts],
    ['principal', r.actor.principal],
    ['leaf', proof.leaf],
    ['root', proof.root],
    ['tree size', String(proof.treeSize)],
    ['path', `${proof.proof.length} hashes`],
  ]);
  out('');
  const good = verifyInclusion({
    leafHash: unhex(proof.leaf),
    index: proof.seq,
    treeSize: proof.treeSize,
    proof: proof.proof.map(unhex),
    root: unhex(proof.root),
  });
  if (good) ok('Proof checks out against the current root.');
  else bad('Proof does not verify — the log is inconsistent.');
  out('');
  return good ? 0 : 1;
}

/** @param {any} args */
function cmdShred(args) {
  const { dir } = loadConfig(args);
  const log = ProofLog.open(dir);

  /** @type {((r: any) => boolean)|null} */
  let predicate = null;
  /** @type {string} */
  let described = '';

  if (args.before) {
    const cutoff = new Date(args.before).toISOString();
    predicate = (r) => r.ts < cutoff;
    described = `recorded before ${cutoff}`;
  } else if (args.principal) {
    predicate = (r) => r.actor.principal === args.principal;
    described = `acting for ${args.principal}`;
  } else if (args.session) {
    predicate = (r) => r.actor.session === args.session;
    described = `from session ${args.session}`;
  } else if (args.seq !== undefined) {
    const seq = Number(args.seq);
    predicate = (r) => r.seq === seq;
    described = `entry ${seq}`;
  }

  if (!predicate) {
    bad('specify what to shred: --before <date>, --principal <id>, --session <id>, or --seq <n>');
    return 2;
  }

  const matching = log.entries.filter(predicate);
  if (matching.length === 0) {
    info(`nothing matches ${described}`);
    return 0;
  }

  if (!args.yes) {
    heading('Crypto-shred (dry run)');
    out(`  This would destroy the commitment salts for ${c.bold(String(matching.length))} entries ${described}.`);
    out('');
    out('  After shredding, those payloads cannot be confirmed by anyone — including you,');
    out('  including under subpoena. Signatures, chain links and inclusion proofs all');
    out('  keep verifying, so the audit trail survives intact.');
    out('');
    out(`  Re-run with ${c.cyan('--yes')} to proceed. This cannot be undone.`);
    out('');
    return 0;
  }

  const n = log.shred(predicate);
  ok(`shredded ${n} payload commitment(s) ${described}`);
  const audit = log.audit();
  if (audit.ok) ok('the audit trail still verifies end to end');
  else bad('the log no longer verifies — investigate before relying on it');
  out('');
  return audit.ok ? 0 : 1;
}

/** @param {any} args */
function cmdKeys(args) {
  const { dir } = loadConfig(args);
  const log = ProofLog.open(dir, { readOnly: true });
  heading(`Keys · ${log.logId}`);
  for (const [kid, pub] of Object.entries(log.keyring)) {
    const role = kid === log.config.kid ? c.green('this log') : c.grey('trusted');
    out(`  ${c.bold(kid)}  ${role}`);
    out(`  ${c.grey(pub)}`);
    out('');
  }
  info('Publish these public keys wherever your auditors will look for them.');
  info('A verifier that gets its keys from the same place it gets the log proves nothing.');
  out('');
  return 0;
}

/** @param {any} args */
function cmdWitness(args) {
  const dir = path.resolve(args.out ?? '.proofwire-witness');
  if (args._[1] === 'keygen') {
    const { identity, privateKeyPem } = generateIdentity();
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'key.pem'), privateKeyPem, { mode: 0o600 });
    fs.writeFileSync(
      path.join(dir, 'public.json'),
      JSON.stringify({ kid: identity.kid, publicKey: identity.publicKey }, null, 2) + '\n',
    );
    heading('Witness identity created');
    kv([['kid', identity.kid], ['dir', dir]]);
    out('');
    info('Give the kid and public key to every log that should be witnessed:');
    out(`  ${c.cyan(`pw trust ${identity.kid} ${identity.publicKey}`)}`);
    out('');
    return 0;
  }
  bad('usage: pw witness keygen [--out <dir>]');
  return 2;
}

/** @param {any} args */
function cmdTrust(args) {
  const { dir } = loadConfig(args);
  const [, kid, pub] = args._;
  if (!kid || !pub) {
    bad('usage: pw trust <kid> <publicKey>');
    return 2;
  }
  const log = ProofLog.open(dir);
  log.trustKey(kid, pub);
  ok(`now trusting ${kid}`);
  return 0;
}

/** @param {any} args */
function cmdStats(args) {
  const { dir } = loadConfig(args);
  const log = ProofLog.open(dir, { readOnly: true });
  const e = log.entries;

  const byOutcome = { allow: 0, deny: 0, escalate: 0 };
  /** @type {Record<string, number>} */
  const byTool = {};
  /** @type {Record<string, number>} */
  const spend = {};
  let errors = 0;
  let unenforced = 0;
  /** @type {Record<string, number>} */
  const wouldBlock = {};
  let latency = 0;
  let timed = 0;

  for (const r of e) {
    byOutcome[r.decision.outcome] = (byOutcome[r.decision.outcome] ?? 0) + 1;
    byTool[r.action.target] = (byTool[r.action.target] ?? 0) + 1;
    if (r.result?.status === 'error') errors++;
    // Counted per call, not per receipt: a monitored call that ran has an
    // intent and an outcome, and both carry the verdict.
    if (r.phase !== 'outcome') {
      if (r.decision.enforced === false) unenforced++;
      if (r.decision.wouldBe) {
        for (const rule of r.decision.rules.length ? r.decision.rules : ['(default)']) {
          wouldBlock[rule] = (wouldBlock[rule] ?? 0) + 1;
        }
      }
    }
    if (r.result?.latencyMs !== undefined) {
      latency += r.result.latencyMs;
      timed++;
    }
    for (const [k, v] of Object.entries(r.action.metrics ?? {})) {
      if (r.decision.outcome === 'allow') spend[k] = (spend[k] ?? 0) + Number(v);
    }
  }

  heading(`${log.logId}`);
  kv([
    ['receipts', String(e.length)],
    ['allowed', c.green(String(byOutcome.allow))],
    ['blocked', byOutcome.deny ? c.red(String(byOutcome.deny)) : '0'],
    ...(unenforced ? [['not enforced', c.yellow(`${unenforced} calls ran in monitor mode`)]] : []),
    ['tool errors', String(errors)],
    ['avg latency', timed ? `${Math.round(latency / timed)} ms` : '—'],
    ['root', log.root.slice(0, 32) + '…'],
  ]);

  if (Object.keys(spend).length) {
    heading('Committed spend');
    kv(Object.entries(spend).map(([k, v]) => [k, v.toFixed(2)]));
  }

  if (Object.keys(wouldBlock).length) {
    heading('Would have been stopped (monitor mode)');
    kv(Object.entries(wouldBlock).sort((a, b) => b[1] - a[1]).map(([rule, n]) => [rule, c.yellow(String(n))]));
  }

  const top = Object.entries(byTool).sort((a, b) => b[1] - a[1]).slice(0, 10);
  if (top.length) {
    heading('Busiest tools');
    kv(top.map(([t, n]) => [t, String(n)]));
  }
  out('');
  return 0;
}

/** @param {any} args */
async function cmdDash(args) {
  const { dir } = loadConfig(args);
  const { serve } = await import('@proof_wire/dashboard');
  const port = Number(args.port ?? 7788);
  const url = await serve({ dir, port });
  heading('Proofwire dashboard');
  kv([['url', c.cyan(url)], ['log', path.relative(process.cwd(), dir) || '.']]);
  out('');
  info('Ctrl-C to stop.');
  return new Promise(() => {});
}

function cmdHelp() {
  out('');
  out(`  ${c.bold('proofwire')} ${c.grey(VERSION)} — tamper-evident receipts for AI agent actions`);
  out('');
  out(`  ${c.bold('Setup')}`);
  out(`    ${c.cyan('pw init')}                        create a log, a starter policy, and a config  ${c.grey('[--template a,b]')}`);
  out('');
  out(`  ${c.bold('Run')}`);
  out(`    ${c.cyan('pw proxy -- <cmd...>')}           wrap an MCP server; enforce policy, write receipts`);
  out(`      ${c.grey('--namespace <ns>')}            prefix tool names in receipts`);
  out(`      ${c.grey('--principal <id>')}            who the agent is acting for`);
  out(`      ${c.grey('--approve tty|webhook|deny')}  how escalations get resolved`);
  out(`      ${c.grey('--no-remote')}                 record locally only, ignore the hub`);
  out(`      ${c.grey('--monitor')}                   block nothing; record what policy would block`);
  out(`      ${c.grey('--enforce')}                   gate even if the config says "monitor": true`);
  out('');
  out(`  ${c.bold('Inspect')}`);
  out(`    ${c.cyan('pw log')}                         recent receipts  ${c.grey('[--tail N --denied --would-block --unfinished --target X --json]')}`);
  out(`    ${c.cyan('pw stats')}                       totals, spend, busiest tools`);
  out(`    ${c.cyan('pw policy templates')}            ready-made policies: secrets, destructive SQL, payments…`);
  out(`    ${c.cyan('pw policy template <id...>')}     print or write a policy from templates  ${c.grey('[--out file --explain]')}`);
  out(`    ${c.cyan('pw policy test [file]')}          replay the log against a policy  ${c.grey('[--since --fail-on-change --json]')}`);
  out(`    ${c.cyan('pw dash')}                        browsable dashboard  ${c.grey('[--port 7788]')}`);
  out('');
  out(`  ${c.bold('Prove')}`);
  out(`    ${c.cyan('pw verify')}                      audit the local log end to end  ${c.grey('[--fail-on-unfinished]')}`);
  out(`    ${c.cyan('pw prove <seq>')}                 inclusion proof for one receipt`);
  out(`    ${c.cyan('pw export [file]')}               evidence bundle for a third party  ${c.grey('[--since --session]')}`);
  out(`    ${c.cyan('pw check <file>')}                verify a bundle with nothing but itself`);
  out(`    ${c.cyan('pw report')}                      evidence pack for auditors: AI Act, SOC 2  ${c.grey('[--since --until --out --framework]')}`);
  out('');
  out(`  ${c.bold('Hub')}   ${c.grey('connect to a Proofwire hub for your team')}`);
  out(`    ${c.cyan('pw remote add --url <hub> --token <key>')}   connect this machine ${c.grey('[--insecure for plain http]')}`);
  out(`    ${c.cyan('pw push')}                        ship local receipts the hub is missing`);
  out(`    ${c.cyan('pw remote-verify <log>')}         verify a hosted log from outside`);
  out(`    ${c.cyan('pw policy push|pull|list')}       manage the org's shared policy`);
  out(`    ${c.cyan('pw cosign')}                      have the hub's witness counter-sign`);
  out(`    ${c.cyan('pw slack connect|status|test')}   approve escalations from Slack (admin key)`);
  out(`    ${c.cyan('pw witnesses list|add|remove')}   outside witnesses for every hub checkpoint (admin key)`);
  out(`    ${c.cyan('pw streams list|add|test')}       receipts and audit events to Splunk, Datadog, OTel, a webhook (admin key)`);
  out('');
  out(`  ${c.bold('Govern')}`);
  out(`    ${c.cyan('pw keys')}                        public keys to publish for verifiers`);
  out(`    ${c.cyan('pw witness keygen')}              create an independent witness identity`);
  out(`    ${c.cyan('pw trust <kid> <pubkey>')}        trust a witness or another signer`);
  out(`    ${c.cyan('pw shred --before <date>')}       destroy payload commitments, keep the audit trail`);
  out('');
  return 0;
}

// ─────────────────────────────────────────────────────────────── main ──

const COMMANDS = {
  init: cmdInit,
  remote: cmdRemote,
  push: cmdPush,
  'remote-verify': cmdRemoteVerify,
  // `test` replays the local log and templates are built in, so neither
  // needs a hub; the rest talk to one.
  policy: (/** @type {any} */ args) =>
    args._[1] === 'test' ? cmdPolicyTest(args, loadConfig(args))
      : args._[1] === 'templates' ? cmdPolicyTemplates(args)
        : args._[1] === 'template' ? cmdPolicyTemplate(args)
          : cmdPolicy(args),
  cosign: (/** @type {any} */ args) => cmdCosign(args, loadConfig(args)),
  slack: cmdSlack,
  witnesses: cmdWitnesses,
  streams: cmdStreams,
  report: (/** @type {any} */ args) => cmdReport(args, loadConfig(args), VERSION),
  proxy: cmdProxy,
  verify: cmdVerify,
  audit: cmdVerify,
  log: cmdLog,
  ls: cmdLog,
  export: cmdExport,
  check: cmdCheck,
  prove: cmdProve,
  shred: cmdShred,
  keys: cmdKeys,
  witness: cmdWitness,
  trust: cmdTrust,
  stats: cmdStats,
  dash: cmdDash,
  help: cmdHelp,
};

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const name = args._[0];

  if (args.version || args.v) {
    out(VERSION);
    return 0;
  }
  if (!name || args.help || args.h) return cmdHelp();

  const command = COMMANDS[name];
  if (!command) {
    bad(`unknown command "${name}"`);
    out(`  try ${c.cyan('pw help')}`);
    return 2;
  }

  try {
    return await command(args);
  } catch (e) {
    bad(/** @type {Error} */ (e).message);
    if (process.env.PROOFWIRE_DEBUG) err(String(/** @type {Error} */ (e).stack));
    return 1;
  }
}

process.exitCode = await main();
