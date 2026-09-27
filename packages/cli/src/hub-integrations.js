import { resolveRemote } from './remote-cmds.js';
import { c, out, ok, bad, warn, info, heading, table } from './ui.js';

/**
 * Admin commands for two of the hub's per-organisation integrations:
 *
 *   pw witnesses list|add|remove   outside witnesses for every hub checkpoint
 *   pw streams list|add|remove|test|flush   receipts and audit events to a SIEM
 *
 * Tokens and secrets can come from the environment rather than the command
 * line, where they would land in shell history: PROOFWIRE_WITNESS_TOKEN,
 * PROOFWIRE_STREAM_TOKEN, PROOFWIRE_STREAM_SECRET, PROOFWIRE_STREAM_HEADERS
 * (a JSON object).
 */

/** @param {any} args @param {string} base */
function caller(args, base) {
  const remote = resolveRemote(args);
  return async (/** @type {string} */ method, /** @type {string} */ p, /** @type {any} */ body) => {
    const res = await fetch(`${remote.url}${base}${p}`, {
      method,
      headers: { authorization: `Bearer ${remote.token}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(json.error?.message ?? `HTTP ${res.status}`);
    return json;
  };
}

/** @param {any} args */
export async function cmdWitnesses(args) {
  const action = args._[1] ?? 'list';
  const call = caller(args, '/v1/integrations/witnesses');
  try {
    if (action === 'list') {
      const { witnesses } = await call('GET', '');
      heading('Outside witnesses');
      if (!witnesses.length) {
        out(`  ${c.grey('none: checkpoints carry only the hub\'s own signature')}`);
        out('');
        info(`add one with ${c.cyan('pw witnesses add <name> --url <witness> --token <key it issued you>')}`);
        out('');
        return 0;
      }
      table(['name', 'url', 'kid'], witnesses.map((/** @type {any} */ w) => [w.name, w.url, w.kid ?? c.grey('?')]));
      out('');
      return 0;
    }
    if (action === 'add') {
      const name = args._[2];
      const token = args.token ?? process.env.PROOFWIRE_WITNESS_TOKEN;
      if (!name || !args.url || !token) {
        bad('usage: pw witnesses add <name> --url <witness> --token <key>   (or PROOFWIRE_WITNESS_TOKEN)');
        return 2;
      }
      const { witnesses } = await call('GET', '');
      // The others go back without tokens; the hub keeps theirs.
      const next = [
        ...witnesses.filter((/** @type {any} */ w) => w.name !== name).map((/** @type {any} */ w) => ({ name: w.name, url: w.url })),
        { name, url: String(args.url), token: String(token) },
      ];
      const res = await call('PUT', '', { witnesses: next });
      const added = res.witnesses.find((/** @type {any} */ w) => w.name === name);
      ok(`${name} answers as ${added?.kid ?? '?'}; every new checkpoint goes to it for co-signing.`);
      info('Auditors should pin that key from the witness operator, not from this hub:');
      out(`    ${c.cyan(`pw check bundle.json --witnesses ${res.witnesses.length} --witness-key <kid>=<publicKey>`)}`);
      return 0;
    }
    if (action === 'remove') {
      const name = args._[2];
      if (!name) {
        bad('usage: pw witnesses remove <name>');
        return 2;
      }
      const { witnesses } = await call('GET', '');
      if (!witnesses.some((/** @type {any} */ w) => w.name === name)) {
        bad(`no witness named "${name}"`);
        return 1;
      }
      const rest = witnesses.filter((/** @type {any} */ w) => w.name !== name).map((/** @type {any} */ w) => ({ name: w.name, url: w.url }));
      await (rest.length ? call('PUT', '', { witnesses: rest }) : call('DELETE', ''));
      ok(`${name} removed. Checkpoints it already signed keep its signature.`);
      return 0;
    }
    bad(`unknown action "${action}": try list, add or remove`);
    return 2;
  } catch (err) {
    bad(`witnesses: ${/** @type {Error} */ (err).message}`);
    return 1;
  }
}

/** @param {any} args */
export async function cmdStreams(args) {
  const action = args._[1] ?? 'list';
  const call = caller(args, '/v1/integrations/streams');
  try {
    if (action === 'list' || action === 'status') {
      const { destinations } = await call('GET', '');
      heading('Event streams');
      if (!destinations.length) {
        out(`  ${c.grey('none')}`);
        out('');
        info(`add one with ${c.cyan('pw streams add <name> --type webhook|splunk|datadog|otlp --url <url>')}`);
        out('');
        return 0;
      }
      table(
        ['name', 'type', 'host', 'sends', 'pending', 'state'],
        destinations.map((/** @type {any} */ d) => [
          d.name,
          d.type,
          d.host,
          [d.receipts === 'none' ? '' : `receipts (${d.receipts})`, d.audit ? 'audit' : ''].filter(Boolean).join(', '),
          String(d.pending),
          d.retrying ? c.red(`retrying: ${d.lastError}`) : d.lastOkAt ? c.green(`ok ${d.lastOkAt}`) : c.grey('waiting'),
        ]),
      );
      out('');
      return 0;
    }
    if (action === 'add') {
      const name = args._[2];
      if (!name || !args.type) {
        bad('usage: pw streams add <name> --type webhook|splunk|datadog|otlp --url <url>');
        info('  [--token <HEC token or Datadog key>] [--secret <webhook secret>] [--header "name=value"]');
        info('  [--receipts all|blocked|none] [--no-audit] [--backfill]');
        return 2;
      }
      /** @type {any} */
      const body = { type: String(args.type), receipts: args.receipts ?? 'all', audit: !args['no-audit'] };
      if (args.url) body.url = String(args.url);
      const token = args.token ?? process.env.PROOFWIRE_STREAM_TOKEN;
      if (token) body.token = String(token);
      const secret = args.secret ?? process.env.PROOFWIRE_STREAM_SECRET;
      if (secret) body.secret = String(secret);
      if (args.header) {
        const h = String(args.header);
        const eq = h.indexOf('=');
        if (eq < 1) {
          bad('--header takes "name=value"');
          return 2;
        }
        body.headers = { [h.slice(0, eq)]: h.slice(eq + 1) };
      } else if (process.env.PROOFWIRE_STREAM_HEADERS) {
        body.headers = JSON.parse(process.env.PROOFWIRE_STREAM_HEADERS);
      }
      if (args.backfill) body.backfill = true;
      const res = await call('PUT', `/${encodeURIComponent(name)}`, body);
      ok(`${name} added: new ${body.receipts === 'none' ? '' : 'receipts and '}events go to it within a second.`);
      if (res.secrets?.[name]) {
        out('');
        warn('Webhook signing secret, shown once. Verify each delivery\'s proofwire-signature header with it:');
        out(`    ${c.bold(res.secrets[name])}`);
      }
      out('');
      info(`check it with ${c.cyan('pw streams test')}`);
      return 0;
    }
    if (action === 'remove') {
      const name = args._[2];
      if (!name) {
        bad('usage: pw streams remove <name>');
        return 2;
      }
      await call('DELETE', `/${encodeURIComponent(name)}`);
      ok(`${name} removed.`);
      return 0;
    }
    if (action === 'test') {
      const { results } = await call('POST', '/test', {});
      let failed = 0;
      for (const r of results) {
        if (r.ok) ok(`${r.name}: delivered a test event`);
        else {
          bad(`${r.name}: ${r.error}`);
          failed++;
        }
      }
      return failed ? 1 : 0;
    }
    if (action === 'flush') {
      const { destinations } = await call('POST', '/flush', {});
      let behind = 0;
      for (const d of destinations) {
        if (d.pending === 0) ok(`${d.name}: caught up`);
        else {
          bad(`${d.name}: ${d.pending} pending, ${d.lastError ?? 'not sent'}`);
          behind++;
        }
      }
      return behind ? 1 : 0;
    }
    bad(`unknown action "${action}": try list, add, remove, test or flush`);
    return 2;
  } catch (err) {
    bad(`streams: ${/** @type {Error} */ (err).message}`);
    return 1;
  }
}
