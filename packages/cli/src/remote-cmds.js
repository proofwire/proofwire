import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { ProofLog, Policy, verifyBundle, witnessCheckpoint } from '@deedwrit/core';
import { RemoteSink, fetchPolicy, trimSlashes } from '@deedwrit/proxy/remote';
import { c, out, ok, bad, warn, info, heading, kv, table } from './ui.js';
import { witnessKeysFrom } from './witness-keys.js';
import { LOG_DIR, POLICY_FILE, credentialsToRead } from './legacy-paths.js';

/**
 * Commands that connect a local log to a Deedwrit hub.
 *
 * Credentials live in `~/.deedwrit/credentials.json`, not in the project, so
 * a token cannot be committed by accident and one machine's credentials serve
 * every project on it.
 */

const CRED_DIR = path.join(os.homedir(), '.deedwrit');
const CRED_FILE = path.join(CRED_DIR, 'credentials.json');

/** @returns {Record<string, { url: string, token: string, log?: string }>} */
export function loadRemotes() {
  // Read from ~/.proofwire if that's all there is (set up before the rename);
  // saving always writes ~/.deedwrit, which is read from then on.
  const file = credentialsToRead();
  if (!fs.existsSync(file)) return {};
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return {};
  }
}

/** @param {Record<string, object>} remotes */
function saveRemotes(remotes) {
  fs.mkdirSync(CRED_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(CRED_FILE, JSON.stringify(remotes, null, 2) + '\n', { mode: 0o600 });
}

/**
 * The remote a command should use: the one named, or the default.
 *
 * @param {any} args
 * @returns {{ name: string, url: string, token: string, log?: string }}
 */
export function resolveRemote(args) {
  const remotes = loadRemotes();
  const name = args.remote ?? 'default';
  const remote = remotes[name];
  if (!remote) {
    const known = Object.keys(remotes);
    throw new Error(
      known.length
        ? `no remote "${name}" (have: ${known.join(', ')})`
        : 'no hub configured — run `dw remote add --url <hub> --token <key>`',
    );
  }
  return { name, ...remote };
}

/**
 * Whether a hub URL is safe to send a bearer token to.
 *
 * @param {string} raw
 * @returns {null | 'invalid' | 'cleartext'}
 */
export function urlProblem(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    return 'invalid';
  }
  if (url.protocol === 'https:') return null;
  if (url.protocol !== 'http:') return 'invalid';
  // Loopback traffic never leaves the machine.
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const loopback = host === 'localhost' || host.endsWith('.localhost') || host === '::1' || /^127(\.\d{1,3}){3}$/.test(host);
  return loopback ? null : 'cleartext';
}

/** @param {any} args */
export async function cmdRemote(args) {
  const action = args._[1] ?? 'list';

  if (action === 'list') {
    const remotes = loadRemotes();
    const names = Object.keys(remotes);
    heading('Hubs');
    if (names.length === 0) {
      out('  ' + c.grey('none configured'));
      out('');
      info(`add one:  ${c.cyan('dw remote add --url https://hub.acme.com --token <key>')}`);
      out('');
      return 0;
    }
    table(
      ['name', 'url', 'log', 'token'],
      names.map((n) => [
        c.bold(n),
        remotes[n].url,
        remotes[n].log ?? c.grey('—'),
        // Enough to tell two keys apart, not enough to use one.
        c.grey(remotes[n].token.slice(0, 12) + '…'),
      ]),
    );
    out('');
    return 0;
  }

  if (action === 'add') {
    if (!args.url || !args.token) {
      bad('usage: dw remote add --url <hub url> --token <api key> [--name default] [--log <slug>]');
      return 2;
    }
    const name = args.name ?? 'default';

    // The token rides on every request to this URL. Over plain HTTP anyone on
    // the path can read it and act as this machine, so it is refused unless
    // the hub is on this machine, or the operator says they know.
    const problem = urlProblem(String(args.url));
    if (problem === 'invalid') {
      bad(`not a URL: ${args.url}`);
      return 2;
    }
    if (problem === 'cleartext' && !args.insecure) {
      bad(`${args.url} is plain HTTP: the API key would cross the network unencrypted.`);
      info('use https://, or pass --insecure if this network is one you trust (a lab, a private VPN).');
      return 2;
    }

    // Prove the credential works before storing it, so a typo surfaces now
    // rather than as silent shipping failures during a live agent session.
    let who;
    try {
      const res = await fetch(trimSlashes(String(args.url)) + '/v1/me', {
        headers: { authorization: `Bearer ${args.token}` },
        signal: AbortSignal.timeout(15_000),
      });
      if (res.status === 401) {
        bad('the hub rejected that token');
        return 1;
      }
      if (!res.ok) {
        bad(`the hub returned HTTP ${res.status}`);
        return 1;
      }
      who = await res.json();
    } catch (err) {
      bad(`could not reach ${args.url}: ${err.message}`);
      return 1;
    }

    const remotes = loadRemotes();
    remotes[name] = { url: trimSlashes(String(args.url)), token: String(args.token) };
    if (args.log) remotes[name].log = String(args.log);
    saveRemotes(remotes);

    heading(`Connected to ${who.org.name ?? who.org.id}`);
    kv([
      ['remote', name],
      ['url', remotes[name].url],
      ['identity', who.label],
      ['scopes', who.scopes.join(' ')],
      ['stored', CRED_FILE],
    ]);
    out('');
    if (who.scopes.includes('witness:sign') && !who.scopes.includes('receipts:write')) {
      info(`A witness key: it co-signs this log's checkpoints with ${c.cyan(`dw cosign --remote ${name}`)}.`);
      out('');
    } else if (!who.scopes.includes('receipts:write')) {
      warn('This key cannot push receipts. That is right for an auditor, wrong for an agent.');
      out('');
    }
    return 0;
  }

  if (action === 'remove') {
    const name = args._[2] ?? args.name ?? 'default';
    const remotes = loadRemotes();
    if (!remotes[name]) {
      bad(`no remote "${name}"`);
      return 1;
    }
    delete remotes[name];
    saveRemotes(remotes);
    ok(`removed remote "${name}"`);
    return 0;
  }

  bad('usage: dw remote <list|add|remove>');
  return 2;
}

/**
 * Ship everything the hub has not confirmed.
 *
 * @param {any} args
 */
export async function cmdPush(args) {
  const remote = resolveRemote(args);
  const dir = path.resolve(args.log ?? LOG_DIR());
  const localLog = ProofLog.open(dir, { readOnly: true });
  const slug = args.name ?? remote.log ?? localLog.logId;

  const sink = new RemoteSink({
    url: remote.url,
    token: remote.token,
    log: slug,
    localLog,
    onLog: (level, msg) => {
      if (level === 'error') bad(msg);
      else if (level === 'warn') warn(msg);
      else info(msg);
    },
  });

  if (!(await sink.connect())) return 1;

  heading(`Pushing to ${remote.name}`);
  const sent = await sink.flush();
  const status = sink.status();

  kv([
    ['hub', status.url],
    ['log', slug],
    ['local', String(localLog.size)],
    ['sent', String(sent)],
    ['behind', status.behind === 0 ? c.green('0') : c.yellow(String(status.behind))],
  ]);
  out('');

  if (status.fatal) {
    bad(status.lastError ?? 'the hub refused these receipts');
    out('');
    return 1;
  }
  if (status.behind > 0) {
    warn(`${status.behind} receipt(s) still local. They are safe; retry when the hub is reachable.`);
    out('');
    return 1;
  }
  ok('the hub holds every local receipt');
  out('');
  return 0;
}

/**
 * Verify a hosted log — from the outside, the way an auditor would.
 *
 * @param {any} args
 */
export async function cmdRemoteVerify(args) {
  const remote = resolveRemote(args);
  const slug = args._[1] ?? args.name ?? remote.log;
  if (!slug) {
    bad('which log? `dw remote-verify <log>`');
    return 2;
  }

  const get = async (p) => {
    const res = await fetch(`${remote.url}${p}`, {
      headers: { authorization: `Bearer ${remote.token}` },
      signal: AbortSignal.timeout(60_000),
    });
    if (!res.ok) throw new Error(`GET ${p} → HTTP ${res.status}`);
    return res.json();
  };

  heading(`Verifying ${slug} on ${remote.url}`);

  const bundle = await get(`/v1/logs/${encodeURIComponent(slug)}/bundle`);
  const result = verifyBundle(bundle, {
    minWitnesses: Number(args.witnesses ?? 0),
    trustedWitnesses: witnessKeysFrom(args),
  });

  kv([
    ['entries', String(bundle.entries.length)],
    ['root', bundle.root],
    ['checkpoints', String((bundle.checkpoints ?? []).length)],
    ['keys', Object.keys(bundle.keyring).join(', ')],
  ]);
  out('');

  if (!result.ok) {
    bad(`${result.issues.length} problem(s):`);
    for (const i of result.issues) out(`  ${c.red('✗')} ${i}`);
    out('');
    return 1;
  }

  ok('Verified independently of the hub: every receipt is signed and provably in the tree.');

  // A hub could still show two histories. Comparing against a local copy is
  // the cheapest way to catch that, and costs nothing when one exists.
  const dir = path.resolve(args.compare ?? LOG_DIR());
  if (fs.existsSync(path.join(dir, 'config.json'))) {
    const localLog = ProofLog.open(dir, { readOnly: true });
    if (localLog.size === bundle.treeSize && localLog.root !== bundle.root) {
      out('');
      bad('The hub is showing a different history than your local log holds at the same size.');
      bad('This is what a split view looks like. Do not dismiss it.');
      out('');
      return 1;
    }
    if (localLog.size === bundle.treeSize) {
      ok('the hub root matches your local log exactly');
    } else {
      info(`local holds ${localLog.size}, hub holds ${bundle.treeSize}`);
    }
  }
  out('');
  return 0;
}

/**
 * Publish or fetch a policy.
 *
 * @param {any} args
 */
export async function cmdPolicy(args) {
  const action = args._[1] ?? 'list';
  const remote = resolveRemote(args);
  const headers = { authorization: `Bearer ${remote.token}`, 'content-type': 'application/json' };

  if (action === 'push') {
    const file = args._[2] ?? POLICY_FILE();
    const slug = args.name ?? path.basename(file).replace(/\.policy\.json$|\.json$/, '');
    const text = fs.readFileSync(file, 'utf8');

    // Compile locally first: a policy rejected here never reaches the hub,
    // and the error arrives while the author is still looking at the file.
    let policy;
    try {
      policy = Policy.parse(text);
    } catch (err) {
      bad(`${file} will not load: ${err.message}`);
      return 1;
    }

    const res = await fetch(`${remote.url}/v1/policies/${encodeURIComponent(slug)}`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        policy: policy.doc,
        note: args.note ?? '',
        activate: args.draft !== true,
      }),
    });
    const body = await res.json();
    if (!res.ok) {
      bad(body.error?.message ?? `HTTP ${res.status}`);
      return 1;
    }

    heading(`Published ${slug} v${body.version}`);
    kv([
      ['hash', body.hash],
      ['rules', String(policy.rules.length)],
      ['budgets', String(policy.budgets.length)],
      ['state', body.active ? c.green('active') : c.grey('draft')],
    ]);
    out('');
    if (body.active) info('Agents pick this up the next time they start.');
    out('');
    return 0;
  }

  if (action === 'pull') {
    const slug = args._[2] ?? args.name;
    if (!slug) {
      bad('usage: dw policy pull <slug> [--out file]');
      return 2;
    }
    const active = await fetchPolicy({ url: remote.url, token: remote.token, slug });
    if (!active) {
      bad(`no active policy "${slug}" on ${remote.name}`);
      return 1;
    }
    const file = args.out ?? `${slug}.policy.json`;
    fs.writeFileSync(file, JSON.stringify(active.policy, null, 2) + '\n');
    ok(`wrote ${file} (v${active.version}, ${active.hash.slice(0, 12)}…)`);
    return 0;
  }

  if (action === 'list') {
    const res = await fetch(`${remote.url}/v1/policies`, { headers });
    const body = await res.json();
    if (!res.ok) {
      bad(body.error?.message ?? `HTTP ${res.status}`);
      return 1;
    }
    heading(`Policies on ${remote.name}`);
    if (body.policies.length === 0) {
      out('  ' + c.grey('none published'));
      out('');
      return 0;
    }
    table(
      ['policy', 'version', 'hash', 'state', 'published'],
      body.policies.map((p) => [
        p.slug,
        `v${p.version}`,
        c.grey(p.hash.slice(0, 12) + '…'),
        p.active ? c.green('active') : c.grey('superseded'),
        c.grey(p.created_at.slice(0, 10)),
      ]),
    );
    out('');
    return 0;
  }

  bad('usage: dw policy <list|push|pull>');
  return 2;
}

/**
 * The witnesses a command should ask: `--remote a,b`, else the config's
 * `witnesses` list, else the default remote.
 *
 * @param {any} args
 * @param {any} [config]
 * @returns {string[]}
 */
export function witnessNames(args, config = {}) {
  if (typeof args.remote === 'string' && args.remote) return args.remote.split(',').map((s) => s.trim()).filter(Boolean);
  if (Array.isArray(config.witnesses) && config.witnesses.length) return config.witnesses.map(String);
  return ['default'];
}

/**
 * Have one witness counter-sign a local log's latest checkpoint, and keep the
 * signature with the log.
 *
 * Trusting the witness's key *and* storing its signature are both needed:
 * without the second the signature exists only in this process, and the
 * bundle an auditor is later handed carries no witness attestation at all.
 *
 * @param {ProofLog} localLog
 * @param {{ name: string, url: string, token: string }} remote
 */
export async function witnessWith(localLog, remote) {
  const cp = localLog.checkpoints().at(-1) ?? localLog.checkpoint();
  const prior = localLog.checkpoints().filter((c2) => c2.body.size < cp.body.size).at(-1);
  const res = await witnessCheckpoint({
    url: remote.url,
    token: remote.token,
    checkpoint: cp,
    tree: localLog.tree,
    logPublicKey: localLog.identity.publicKey,
    guessPriorSize: prior?.body.size,
  });
  localLog.trustKey(res.witness.kid, res.witness.publicKey);
  const updated = localLog.addSignature(cp.body.size, res.signature);
  return { ...res, checkpoint: updated };
}

/**
 * Explain a refusal. Most are operational; the alarming ones mean two
 * histories disagree, and say so.
 *
 * @param {any} e
 * @param {ProofLog} localLog
 * @param {(msg: string) => void} say
 */
export function explainRefusal(e, localLog, say) {
  if (e?.code === 'log_key_mismatch') {
    say(`The witness holds this log to ${e.detail?.bound ?? 'a different key'}; this log signs with ${localLog.identity.kid}.`);
    say('If you rotated the key on purpose, send the witness operator the new public key through a channel');
    say(`other than this witness credential, so they can rebind it: ${localLog.identity.publicKey}`);
    say('If you did not, the witness is holding this log to a key you do not control. Investigate.');
  } else if (e?.alarming) {
    say('A witness refusing on these grounds means the history it was shown does not match the history');
    say('it saw before. Investigate before doing anything else.');
  }
}

/**
 * `dw cosign`: have witnesses counter-sign the latest checkpoint of a local
 * log. Asks every witness named by `--remote a,b`, or listed in the config's
 * `witnesses`, or the default remote.
 *
 * @param {any} args
 * @param {{ dir: string, config: any }} where
 */
export async function cmdCosign(args, where) {
  const localLog = ProofLog.open(where.dir);
  const names = witnessNames(args, where.config);
  let failed = 0;

  for (const name of names) {
    let remote;
    try {
      remote = resolveRemote({ remote: name });
    } catch (e) {
      bad(/** @type {Error} */ (e).message);
      failed++;
      continue;
    }
    try {
      const res = await witnessWith(localLog, remote);
      const witnesses = res.checkpoint.sigs.filter((/** @type {any} */ s) => s.role === 'witness').length;
      heading(`Checkpoint witnessed · ${name}`);
      kv([
        ['log', localLog.logId],
        ['size', String(res.checkpoint.body.size)],
        ['root', res.checkpoint.body.root],
        ['witness', res.witness.kid],
        ['signatures', `${witnesses} witness${witnesses === 1 ? '' : 'es'} on this root`],
        // Older witnesses do not bind, and say nothing here.
        ...(res.logKey
          ? [['log key', res.logKey.newlyBound
              ? `${res.logKey.kid} ${c.grey('— bound now; this witness will accept no other key for this log')}`
              : `${res.logKey.kid} ${c.grey(`— bound since ${String(res.logKey.boundAt).slice(0, 10)}`)}`]]
          : []),
      ]);
      out('');
      info('An auditor can now require this signature, pinning the witness they trust:');
      out(`  ${c.cyan(`dw check evidence.json --witnesses 1 --witness-key ${res.witness.kid}=${res.witness.publicKey}`)}`);
      out('');
    } catch (e) {
      failed++;
      heading(`Witness refused · ${name}`);
      bad(/** @type {Error} */ (e).message);
      out('');
      explainRefusal(e, localLog, warn);
      out('');
    }
  }
  return failed ? 1 : 0;
}

/**
 * `dw slack connect|status|test|disconnect` — Slack approvals for the hub's
 * organization. Needs an admin key.
 *
 * The webhook URL and signing secret are credentials, so they can come from
 * the environment rather than the command line, where they would land in
 * shell history: DEEDWRIT_SLACK_WEBHOOK_URL and DEEDWRIT_SLACK_SIGNING_SECRET.
 *
 * @param {any} args
 */
export async function cmdSlack(args) {
  const action = args._[1] ?? 'status';
  const remote = resolveRemote(args);
  const call = async (/** @type {string} */ method, /** @type {string} */ p, /** @type {any} */ body) => {
    const res = await fetch(`${remote.url}/v1/integrations/slack${p}`, {
      method,
      headers: { authorization: `Bearer ${remote.token}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(json.error?.message ?? `HTTP ${res.status}`);
    return json;
  };

  try {
    if (action === 'connect') {
      const webhookUrl = args['webhook-url'] ?? process.env.DEEDWRIT_SLACK_WEBHOOK_URL;
      const signingSecret = args['signing-secret'] ?? process.env.DEEDWRIT_SLACK_SIGNING_SECRET;
      if (!webhookUrl || !signingSecret) {
        bad('usage: dw slack connect --webhook-url <url> --signing-secret <secret> [--approver U123,U456]');
        info('or set DEEDWRIT_SLACK_WEBHOOK_URL and DEEDWRIT_SLACK_SIGNING_SECRET, to keep them out of shell history.');
        info('See docs/SLACK.md for creating the Slack app.');
        return 2;
      }
      const approvers = args.approver ? String(args.approver).split(',').map((s) => s.trim()).filter(Boolean) : [];
      const res = await call('PUT', '', { webhookUrl, signingSecret, approvers });
      heading('Slack connected');
      kv([
        ['approvers', approvers.length ? approvers.join(', ') : c.yellow('anyone in the channel')],
        ['interactivity URL', c.cyan(res.interactionsUrl)],
      ]);
      out('');
      info('Set that URL as the Request URL under Interactivity in the Slack app, then:');
      out(`    ${c.cyan('dw slack test')}`);
      if (!approvers.length) {
        warn('With no --approver list, anyone who can see the channel can approve. Keep the channel private,');
        warn('or name the Slack user IDs allowed to decide.');
      }
      out('');
      return 0;
    }
    if (action === 'status') {
      const res = await call('GET', '');
      heading('Slack approvals');
      if (!res.configured) {
        kv([['status', c.grey('not connected')]]);
        out('');
        info(`connect with ${c.cyan('dw slack connect')} — see docs/SLACK.md`);
        out('');
        return 0;
      }
      kv([
        ['status', c.green('connected')],
        ['webhook', res.webhookHost],
        ['approvers', res.approvers.length ? res.approvers.join(', ') : c.yellow('anyone in the channel')],
        ['interactivity URL', res.interactionsUrl],
        ['updated', res.updatedAt],
      ]);
      out('');
      return 0;
    }
    if (action === 'test') {
      await call('POST', '/test', {});
      ok('Sent a test message. It should be in the channel now.');
      return 0;
    }
    if (action === 'disconnect') {
      const res = await call('DELETE', '');
      ok(res.removed ? 'Slack disconnected. Approvals stay in the console.' : 'Slack was not connected.');
      return 0;
    }
    bad(`unknown action "${action}": try connect, status, test or disconnect`);
    return 2;
  } catch (err) {
    bad(`Slack: ${/** @type {Error} */ (err).message}`);
    return 1;
  }
}
