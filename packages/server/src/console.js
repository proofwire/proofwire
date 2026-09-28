import { StoreError } from './store.js';

/**
 * The operator console.
 *
 * Server-rendered, no client JavaScript, forms that work with the browser's
 * own submit. That is not nostalgia: the console's Content-Security-Policy is
 * `default-src 'none'`, so this page has no script execution to hijack at all.
 * For a screen whose whole job is to display strings that an AI agent chose —
 * tool names, arguments, policy reasons — removing the script surface entirely
 * is worth more than any convenience it costs.
 *
 * Everything interpolated goes through `esc`. No exceptions, including values
 * that "came from us", because half of them came from a receipt.
 */

/**
 * @param {unknown} s
 * @returns {string}
 */
function esc(s) {
  return String(s ?? '').replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );
}

/**
 * @param {string} h
 * @param {number} [n]
 */
const short = (h, n = 12) => (h ? esc(String(h).slice(0, n)) + '…' : '—');

/** @param {string|null} iso */
function ago(iso) {
  if (!iso) return '—';
  const secs = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (secs < 60) return `${Math.floor(secs)}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

const STYLE = `
:root {
  --ground:#eef0ea; --panel:#f7f8f4; --raised:#e3e7dc; --line:#ccd2c3;
  --ink:#141810; --ink-2:#4b5346; --ink-3:#7b8375;
  --verify:#0b6e4f; --alarm:#a3301c; --hold:#8a6512;
  --mono:"JetBrains Mono",ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --ground:#0f1310; --panel:#161b17; --raised:#1e241f; --line:#2b332c;
    --ink:#dfe5dc; --ink-2:#a3ada0; --ink-3:#727c70;
    --verify:#47a882; --alarm:#d4674f; --hold:#c19a3d;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--ground);color:var(--ink);font:14px/1.55 var(--sans)}
a{color:var(--verify);text-underline-offset:3px}
.wrap{max-width:1180px;margin-inline:auto;padding-inline:20px}
header{border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:env(safe-area-inset-top,0px);z-index:9}
.bar{display:flex;align-items:center;gap:20px;flex-wrap:wrap;padding-block:13px}
.brand{font-family:var(--mono);font-weight:700;letter-spacing:-.02em;text-decoration:none;color:var(--ink)}
.brand em{font-style:normal;color:var(--verify)}
nav{display:flex;gap:16px;flex-wrap:wrap}
nav a{color:var(--ink-2);text-decoration:none;font-size:13.5px;padding-block:3px;border-bottom:2px solid transparent}
nav a.on{color:var(--ink);border-bottom-color:var(--verify);font-weight:600}
.who{margin-left:auto;display:flex;align-items:center;gap:12px;font-size:12.5px;color:var(--ink-3)}
main{padding-block:26px 56px}
h1{font-size:20px;letter-spacing:-.02em;margin:0 0 4px}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.13em;color:var(--ink-3);margin:30px 0 10px;font-weight:700}
h2:first-of-type{margin-top:0}
p.sub{color:var(--ink-2);margin:0 0 22px;font-size:13.5px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(168px,1fr))}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:14px 16px}
.tile b{display:block;font-size:23px;letter-spacing:-.02em;font-variant-numeric:tabular-nums;line-height:1.2}
.tile span{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--ink-3)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:4px;overflow:hidden}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px;min-width:640px}
th{font-size:10.5px;text-transform:uppercase;letter-spacing:.11em;color:var(--ink-3);text-align:left;
   padding:9px 14px;background:var(--raised);border-bottom:1px solid var(--line);font-weight:700;white-space:nowrap}
td{padding:10px 14px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:none}
.mono{font-family:var(--mono);font-size:11.5px}
.dim{color:var(--ink-3)}
.pill{display:inline-block;font-size:10.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;
      padding:2px 7px;border-radius:3px;white-space:nowrap}
.allow{background:color-mix(in srgb,var(--verify) 15%,transparent);color:var(--verify)}
.deny{background:color-mix(in srgb,var(--alarm) 16%,transparent);color:var(--alarm)}
.escalate,.pending{background:color-mix(in srgb,var(--hold) 18%,transparent);color:var(--hold)}
.banner{border:1px solid var(--line);border-left:3px solid var(--verify);background:var(--panel);
        padding:11px 14px;border-radius:4px;margin-bottom:18px;font-size:13px}
.banner.bad{border-left-color:var(--alarm)}
.banner.warn{border-left-color:var(--hold)}
form.inline{display:inline}
button{font:inherit;font-size:12.5px;font-weight:600;padding:6px 12px;border-radius:3px;cursor:pointer;
       border:1px solid var(--line);background:var(--raised);color:var(--ink)}
button.go{background:var(--verify);border-color:var(--verify);color:var(--ground)}
button.no{background:transparent;border-color:var(--alarm);color:var(--alarm)}
button:focus-visible,input:focus-visible{outline:2px solid var(--verify);outline-offset:1px}
input,select{font:inherit;font-size:13px;padding:8px 10px;border:1px solid var(--line);
             border-radius:3px;background:var(--ground);color:var(--ink);width:100%}
.login{max-width:360px;margin:9vh auto;padding-inline:20px}
.field{margin-bottom:12px}
label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--ink-3);margin-bottom:5px}
.empty{padding:40px 16px;text-align:center;color:var(--ink-3)}
.kv{display:grid;grid-template-columns:130px minmax(0,1fr);gap:5px 14px;font-size:13px}
.kv dt{color:var(--ink-3)}
.kv dd{margin:0;overflow-wrap:anywhere}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:end}
.filters .f{min-width:130px}
.filters button{height:35px}
.subnav{display:flex;gap:6px;margin:0 0 22px;flex-wrap:wrap}
.subnav a{font-size:13px;text-decoration:none;color:var(--ink-2);padding:5px 11px;border:1px solid var(--line);border-radius:3px;background:var(--panel)}
.subnav a.on{color:var(--ink);border-color:var(--verify);font-weight:600}
.formgrid{display:grid;gap:10px 14px;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));padding:16px;align-items:end}
.formgrid .field{margin:0}
.check{display:flex;gap:7px;align-items:center;text-transform:none;letter-spacing:0;font-size:13px;color:var(--ink-2);margin:0}
.check input{width:auto}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 0}
.secret{font-family:var(--mono);font-size:12.5px;background:var(--ground);border:1px solid var(--line);padding:6px 9px;border-radius:3px;overflow-wrap:anywhere;display:block;margin-top:6px}
.args{font-family:var(--mono);font-size:11px;background:var(--ground);border:1px solid var(--line);
      border-radius:3px;padding:8px 10px;margin:6px 0 0;white-space:pre-wrap;overflow-wrap:anywhere;max-height:130px;overflow:auto}
`;

/**
 * @param {object} args
 * @param {string} args.title
 * @param {string} args.body
 * @param {object|null} args.principal
 * @param {string} args.path
 * @param {number} [args.pending]
 */
function layout(args) {
  const nav = [
    ['/', 'Overview'],
    ['/approvals', args.pending ? `Approvals (${args.pending})` : 'Approvals'],
    ['/policies', 'Policies'],
    ['/events', 'Activity'],
    ['/settings', 'Settings'],
  ];
  const here = args.path.startsWith('/logs') ? '/logs' : args.path.startsWith('/settings') ? '/settings' : args.path;

  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>${esc(args.title)} · Vouchwell</title><style>${STYLE}</style></head><body>
${args.principal ? `<header><div class="wrap bar">
  <a class="brand" href="/">proof<em>wire</em></a>
  <nav>${nav
    .map(([href, label]) => `<a href="${esc(href)}"${href === here ? ' class="on"' : ''}>${esc(label)}</a>`)
    .join('')}</nav>
  <div class="who">
    <span>${esc(args.principal.org?.name ?? args.principal.orgId)} · ${esc(args.principal.role ?? '')}</span>
    <span>${esc(args.principal.label)}</span>
    <form class="inline" method="post" action="/logout"><button>Sign out</button></form>
  </div>
</div></header>` : ''}
<main class="wrap">${args.body}</main></body></html>`;
}

/**
 * @param {string} html
 * @param {number} [status]
 * @param {Record<string,string>} [headers]
 */
const page = (html, status = 200, headers = {}) => ({ __html: html, status, headers });

/**
 * Render a console page.
 *
 * @param {import('./app.js').Hub} hub
 * @param {import('./http.js').Ctx} ctx
 * @param {string} route
 * @param {Extra} [extra]  What a form action wants shown once on the page it lands on.
 */
export function renderConsole(hub, ctx, route, extra = {}) {
  if (route === '/login') return loginPage(hub, ctx);
  if (route === '/forgot') return forgotPage(hub, ctx);
  if (route === '/accept' || route === '/reset') return credentialPage(hub, ctx, route);

  if (!ctx.principal || ctx.principal.kind !== 'user') {
    // An API key is a machine credential; it has no console session and should
    // be told so rather than silently redirected into a login loop.
    return page(
      layout({
        title: 'Sign in',
        path: '/login',
        principal: null,
        body: `<div class="login"><h1>Sign in</h1>
          <p class="sub">The console is for people. Machine credentials use the API.</p>
          <p><a href="/login">Go to sign in →</a></p></div>`,
      }),
      401,
    );
  }

  const pending = hub.db
    .prepare("SELECT count(*) AS n FROM approvals WHERE org_id = ? AND status = 'pending' AND expires_at > ?")
    .get(ctx.principal.orgId, new Date().toISOString()).n;

  const common = { principal: ctx.principal, path: route, pending };

  switch (route) {
    case '/':         return page(layout({ ...common, title: 'Overview',  body: overview(hub, ctx) }));
    case '/logs/:log':return page(layout({ ...common, title: 'Log',       body: logPage(hub, ctx) }));
    case '/approvals':return page(layout({ ...common, title: 'Approvals', body: approvals(hub, ctx) }));
    case '/policies': return page(layout({ ...common, title: 'Policies',  body: policies(hub, ctx) }));
    case '/events':   return page(layout({ ...common, title: 'Activity',  body: events(hub, ctx) }));
    case '/settings': return page(layout({ ...common, title: 'Settings',  body: settings(hub, ctx) }));
    case '/settings/integrations':
      return page(layout({ ...common, title: 'Integrations', body: integrations(hub, ctx, extra) }));
    default:          return page(layout({ ...common, title: 'Not found', body: '<h1>Not found</h1>' }), 404);
  }
}

/**
 * @param {import('./app.js').Hub} hub
 * @param {import('./http.js').Ctx} ctx
 */
function loginPage(hub, ctx) {
  const failed = ctx.query.get('e') === '1';
  const throttled = ctx.query.get('e') === '2';
  const ssoFailed = ctx.query.get('e') === 'sso';
  const ssoDenied = ctx.query.get('e') === 'sso_denied';
  return page(
    layout({
      title: 'Sign in',
      path: '/login',
      principal: null,
      body: `<div class="login">
        <p style="font-family:var(--mono);font-weight:700;margin:0 0 20px">proof<span style="color:var(--verify)">wire</span></p>
        <h1>Sign in</h1>
        <p class="sub">Operator console</p>
        ${failed ? '<div class="banner bad">Email or password is incorrect.</div>' : ''}
        ${throttled ? '<div class="banner bad">Too many failed sign-ins for this account. Wait a few minutes, or reset your password.</div>' : ''}
        <form method="post" action="/login">
          <div class="field"><label for="email">Email</label>
            <input id="email" name="email" type="email" autocomplete="username" required></div>
          <div class="field"><label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="current-password" required></div>
          <button class="go" type="submit" style="width:100%;padding:10px">Sign in</button>
        </form>
        <p style="margin-top:16px;font-size:13px"><a href="/forgot">Forgotten your password?</a></p>

        <h2 style="margin-top:28px">Single sign-on</h2>
        ${ssoFailed ? '<div class="banner bad">Single sign-on didn\'t complete. Try again, or ask your administrator whether SSO is set up.</div>' : ''}
        ${ssoDenied ? '<div class="banner bad">Your identity provider signed you in, but this account can\'t use this organization. Ask an administrator to invite you.</div>' : ''}
        <form method="get" action="/sso">
          <div class="field"><label for="org">Organization</label>
            <input id="org" name="org" autocomplete="organization" placeholder="acme" required></div>
          <button type="submit" style="width:100%;padding:10px">Continue with SSO</button>
        </form>
        </div>`,
    }),
  );
}

/**
 * Request a reset.
 *
 * The confirmation is identical whether or not the address exists — anything
 * else turns this page into a way to test which emails have accounts.
 *
 * @param {import('./app.js').Hub} hub
 * @param {import('./http.js').Ctx} ctx
 */
function forgotPage(hub, ctx) {
  const sent = ctx.query.get('sent') === '1';
  return page(
    layout({
      title: 'Reset password',
      path: '/login',
      principal: null,
      body: `<div class="login">
        <p style="font-family:var(--mono);font-weight:700;margin:0 0 20px">proof<span style="color:var(--verify)">wire</span></p>
        <h1>Reset password</h1>
        ${sent
          ? `<div class="banner">If that address has an account, a reset link has been issued.
             It is good for one hour and can be used once.</div>
             <p style="font-size:13px"><a href="/login">Back to sign in</a></p>`
          : `<p class="sub">We will issue a single-use link, good for one hour.</p>
             <form method="post" action="/forgot">
               <div class="field"><label for="email">Email</label>
                 <input id="email" name="email" type="email" autocomplete="username" required></div>
               <button class="go" type="submit" style="width:100%;padding:10px">Send reset link</button>
             </form>
             <p style="margin-top:16px;font-size:13px"><a href="/login">Back to sign in</a></p>`}
      </div>`,
    }),
  );
}

/**
 * Accept an invitation, or complete a reset. One form, two framings.
 *
 * @param {import('./app.js').Hub} hub
 * @param {import('./http.js').Ctx} ctx
 * @param {string} route
 */
function credentialPage(hub, ctx, route) {
  const invite = route === '/accept';
  const token = ctx.query.get('token') ?? '';
  const error = ctx.query.get('e');
  const row = hub.tokens.peek(token, invite ? 'invite' : 'reset');
  const title = invite ? 'Accept invitation' : 'Choose a new password';

  // A dead link says so plainly and offers the way forward, rather than
  // presenting a form that cannot possibly work.
  if (!row) {
    return page(
      layout({
        title,
        path: '/login',
        principal: null,
        body: `<div class="login">
          <p style="font-family:var(--mono);font-weight:700;margin:0 0 20px">proof<span style="color:var(--verify)">wire</span></p>
          <h1>${esc(title)}</h1>
          <div class="banner bad">This link is invalid, has already been used, or has expired.</div>
          <p style="font-size:13px">
            ${invite
              ? 'Ask an administrator for a fresh invitation.'
              : '<a href="/forgot">Request a new reset link</a>'}
          </p>
          <p style="font-size:13px"><a href="/login">Back to sign in</a></p>
        </div>`,
      }),
      400,
    );
  }

  const messages = {
    mismatch: 'Those passwords did not match.',
    weak_password: 'Use at least 12 characters.',
    invalid_token: 'That link is no longer valid.',
  };

  return page(
    layout({
      title,
      path: '/login',
      principal: null,
      body: `<div class="login">
        <p style="font-family:var(--mono);font-weight:700;margin:0 0 20px">proof<span style="color:var(--verify)">wire</span></p>
        <h1>${esc(title)}</h1>
        <p class="sub">${esc(row.email)}${invite && row.role ? ` · joining as ${esc(row.role)}` : ''}</p>
        ${error ? `<div class="banner bad">${esc(messages[error] ?? 'That did not work.')}</div>` : ''}
        <form method="post" action="${esc(route)}">
          <input type="hidden" name="token" value="${esc(token)}">
          <div class="field"><label for="password">New password</label>
            <input id="password" name="password" type="password" autocomplete="new-password"
                   minlength="12" required></div>
          <div class="field"><label for="confirm">Confirm</label>
            <input id="confirm" name="confirm" type="password" autocomplete="new-password"
                   minlength="12" required></div>
          <button class="go" type="submit" style="width:100%;padding:10px">
            ${invite ? 'Join' : 'Set password'}
          </button>
        </form>
        <p class="dim" style="font-size:12px;margin-top:14px">
          At least 12 characters. Setting a password signs out every other session.
        </p>
      </div>`,
    }),
  );
}

/**
 * @param {import('./app.js').Hub} hub
 * @param {import('./http.js').Ctx} ctx
 */
function overview(hub, ctx) {
  const orgId = ctx.principal.orgId;
  const logs = hub.store.logs(orgId);
  const usage = hub.db
    .prepare('SELECT day, receipts, denials FROM usage_daily WHERE org_id = ? ORDER BY day DESC LIMIT 30')
    .all(orgId);
  const totals = usage.reduce(
    (a, d) => ({ receipts: a.receipts + d.receipts, denials: a.denials + d.denials }),
    { receipts: 0, denials: 0 },
  );
  const recent = hub.store.receipts(orgId, { denied: true, limit: 12 }).entries;

  // A log that has never been checkpointed can have its tail rewritten without
  // contradicting anything published, so surface it rather than hide it.
  const unwitnessed = logs.filter((l) => {
    const cp = hub.db
      .prepare('SELECT max(witness_count) AS w FROM checkpoints WHERE log_id = ?')
      .get(l.id);
    return l.size > 0 && (!cp || !cp.w);
  });

  return `<h1>${esc(ctx.principal.org?.name ?? 'Overview')}</h1>
  <p class="sub">${logs.length} log${logs.length === 1 ? '' : 's'} · plan ${esc(ctx.principal.org?.plan ?? 'open')}</p>

  ${unwitnessed.length
    ? `<div class="banner warn"><b>${unwitnessed.length} log${unwitnessed.length === 1 ? ' has' : 's have'} no witnessed checkpoint.</b>
       Until a root is counter-signed by an independent witness, entries added since the last
       checkpoint can be removed without contradicting anything published.</div>`
    : ''}

  <div class="grid">
    <div class="tile"><b>${totals.receipts.toLocaleString()}</b><span>receipts · 30d</span></div>
    <div class="tile"><b style="color:var(--alarm)">${totals.denials.toLocaleString()}</b><span>actions blocked</span></div>
    <div class="tile"><b>${logs.length}</b><span>logs</span></div>
    <div class="tile"><b>${logs.reduce((a, l) => a + l.size, 0).toLocaleString()}</b><span>total entries</span></div>
  </div>

  <h2>Logs</h2>
  <div class="panel scroll"><table>
    <thead><tr><th>Log</th><th>Key</th><th>Entries</th><th>Root</th><th>Last receipt</th></tr></thead>
    <tbody>${logs.length === 0
      ? '<tr><td colspan="5" class="empty">No logs yet. Register one with <span class="mono">vw remote add</span>.</td></tr>'
      : logs.map((l) => `<tr>
          <td><a href="/logs/${esc(l.slug)}"><b>${esc(l.slug)}</b></a>
              ${l.name && l.name !== l.slug ? `<div class="dim">${esc(l.name)}</div>` : ''}</td>
          <td class="mono dim">${esc(l.kid.slice(0, 18))}…</td>
          <td style="font-variant-numeric:tabular-nums">${l.size.toLocaleString()}</td>
          <td class="mono dim">${short(l.root, 16)}</td>
          <td class="dim">${esc(ago(l.last_seen_at))}</td>
        </tr>`).join('')}
    </tbody></table></div>

  <h2>Recently blocked</h2>
  <div class="panel scroll"><table>
    <thead><tr><th>When</th><th>Tool</th><th>Decision</th><th>Reason</th><th>For</th></tr></thead>
    <tbody>${recent.length === 0
      ? '<tr><td colspan="5" class="empty">Nothing has been blocked. That is either very good news or a policy that is not doing anything.</td></tr>'
      : recent.map((e) => {
          const body = JSON.parse(e.body);
          return `<tr>
            <td class="dim">${esc(ago(e.ts))}</td>
            <td class="mono">${esc(e.target)}</td>
            <td><span class="pill ${esc(e.outcome)}">${esc(e.outcome)}</span></td>
            <td>${esc(body.decision.reason ?? '')}</td>
            <td class="dim">${esc(e.principal)}</td>
          </tr>`;
        }).join('')}
    </tbody></table></div>`;
}

/**
 * @param {import('./app.js').Hub} hub
 * @param {import('./http.js').Ctx} ctx
 */
function logPage(hub, ctx) {
  const ref = ctx.params.log;
  const log =
    hub.store.logBySlug(ctx.principal.orgId, ref) ?? hub.store.log(ctx.principal.orgId, ref);
  if (!log) throw new StoreError(404, 'no_such_log', `no log "${ref}" in this organization`);

  const audit = hub.store.audit(ctx.principal.orgId, log.id);
  const found = hub.store.unfinished(ctx.principal.orgId, log.id);
  const never = [...found.unfinished, ...found.abandoned].sort((a, b) => a.seq - b.seq);
  const checkpoints = hub.store.checkpoints(ctx.principal.orgId, log.id, 6);
  const q = {
    logId: log.id,
    limit: 60,
    denied: ctx.query.get('denied') === '1' || undefined,
    target: ctx.query.get('target') || undefined,
    session: ctx.query.get('session') || undefined,
  };
  const { entries, total } = hub.store.receipts(ctx.principal.orgId, q);

  return `<h1>${esc(log.slug)}</h1>
  <p class="sub">${log.size.toLocaleString()} entries · signed by <span class="mono">${esc(log.kid)}</span></p>

  <div class="banner ${audit.ok ? '' : 'bad'}">
    ${audit.ok
      ? `<b style="color:var(--verify)">✓ Verified.</b> Every stored receipt's signature, chain link and
         inclusion proof checks out${
           checkpoints.length === 0
             ? ', but nothing has been checkpointed yet, so there is no published root this could be measured against.'
             : `, and the log still extends ${
                 checkpoints.length === 1 ? 'the checkpoint' : `all ${checkpoints.length} checkpoints`
               }.`
         }`
      : `<b style="color:var(--alarm)">✗ ${audit.issues.length} problem(s).</b> This log has been altered since it
         was written.<br>${audit.issues.slice(0, 6).map((i) => esc(`${i.kind}${i.seq !== undefined ? ` @ ${i.seq}` : ''}: ${i.message}`)).join('<br>')}`}
  </div>

  ${never.length ? `<div class="banner">
    <b>${never.length} action(s) were authorised and sent, but never finished.</b> The agent stopped while
    they were out, so whether they took effect is not in the log: check each with the system it called.
    <br>${never.slice(0, 8).map((u) => esc(`#${u.seq} · ${u.ts.slice(0, 19).replace('T', ' ')} · ${u.target || '(pruned)'}${u.principal ? ` · ${u.principal}` : ''}`)).join('<br>')}${
      never.length > 8 ? `<br><span class="dim">…and ${never.length - 8} more (GET /v1/logs/${esc(log.slug)}/unfinished)</span>` : ''}
  </div>` : ''}

  <div class="grid">
    <div class="tile"><b class="mono" style="font-size:12px">${short(log.root, 24)}</b><span>merkle root</span></div>
    <div class="tile"><b class="mono" style="font-size:12px">${short(log.head, 24)}</b><span>head</span></div>
    <div class="tile"><b>${checkpoints.length}</b><span>checkpoints</span></div>
    <div class="tile"><b>${checkpoints[0]?.sigs.filter((s) => s.role === 'witness').length ?? 0}</b><span>witnesses on latest</span></div>
  </div>

  <h2>Receipts${total > entries.length ? ` <span class="dim">(${entries.length} of ${total.toLocaleString()})</span>` : ''}</h2>
  <form method="get" class="filters">
    <div class="f"><label for="target">Tool</label>
      <input id="target" name="target" value="${esc(ctx.query.get('target') ?? '')}" placeholder="stripe.refund"></div>
    <div class="f"><label for="session">Session</label>
      <input id="session" name="session" value="${esc(ctx.query.get('session') ?? '')}" placeholder="sess_…"></div>
    <div class="f"><label for="denied">Show</label>
      <select id="denied" name="denied">
        <option value="">everything</option>
        <option value="1"${ctx.query.get('denied') === '1' ? ' selected' : ''}>blocked only</option>
      </select></div>
    <button type="submit">Filter</button>
  </form>

  <div class="panel scroll"><table>
    <thead><tr><th>#</th><th>When</th><th>Decision</th><th>Tool</th><th>Phase</th><th>For</th><th>Detail</th></tr></thead>
    <tbody>${entries.length === 0
      ? '<tr><td colspan="7" class="empty">Nothing matches.</td></tr>'
      : entries.map((e) => {
          const body = JSON.parse(e.body);
          return `<tr>
            <td class="mono dim">${e.seq}</td>
            <td class="dim mono">${esc(e.ts.slice(5, 19).replace('T', ' '))}</td>
            <td>${body.decision.wouldBe
              ? `<span class="pill escalate" title="monitor mode: ran, not enforced">would ${esc(body.decision.wouldBe)}</span>`
              : `<span class="pill ${esc(e.outcome)}">${esc(e.outcome)}</span>`}</td>
            <td class="mono">${esc(e.target)}</td>
            <td class="dim mono">${esc(e.phase)}</td>
            <td class="dim">${esc(e.principal)}</td>
            <td>${e.outcome === 'allow' && !body.decision.wouldBe
              ? `<span class="dim">${esc(e.status ?? 'committed')}${e.latency_ms != null ? ` · ${e.latency_ms}ms` : ''}</span>`
              : `<span style="color:var(--hold)">${esc((body.decision.reason ?? '').slice(0, 90))}</span>`}
              ${body.action.params?.redacted?.length
                ? `<div class="dim" style="font-size:11px">masked: ${esc(body.action.params.redacted.join(', '))}</div>`
                : ''}</td>
          </tr>`;
        }).join('')}
    </tbody></table></div>

  <h2>Checkpoints</h2>
  <div class="panel scroll"><table>
    <thead><tr><th>Size</th><th>Root</th><th>Signed</th><th>Witnesses</th></tr></thead>
    <tbody>${checkpoints.length === 0
      ? '<tr><td colspan="4" class="empty">No checkpoints yet.</td></tr>'
      : checkpoints.map((c) => `<tr>
          <td style="font-variant-numeric:tabular-nums">${c.body.size.toLocaleString()}</td>
          <td class="mono dim">${short(c.body.root, 20)}</td>
          <td class="dim">${esc(ago(c.body.ts))}</td>
          <td>${c.sigs.filter((s) => s.role === 'witness').length === 0
            ? '<span class="pill pending">none</span>'
            : `<span class="pill allow">${c.sigs.filter((s) => s.role === 'witness').length}</span>`}</td>
        </tr>`).join('')}
    </tbody></table></div>`;
}

/**
 * @param {import('./app.js').Hub} hub
 * @param {import('./http.js').Ctx} ctx
 */
function approvals(hub, ctx) {
  const status = ctx.query.get('status') ?? 'pending';
  const rows = hub.db
    .prepare(
      `SELECT a.*, l.slug AS log_slug FROM approvals a JOIN logs l ON l.id = a.log_id
       WHERE a.org_id = ? AND a.status = ? ORDER BY a.requested_at DESC LIMIT 100`,
    )
    .all(ctx.principal.orgId, status);

  const canDecide = ctx.principal.scopes.includes('approvals:write');

  return `<h1>Approvals</h1>
  <p class="sub">Actions the policy escalated. An undecided request expires and is refused —
  it never becomes an approval by default.</p>

  <div class="filters">
    ${['pending', 'approved', 'denied', 'expired']
      .map((s) => `<a href="/approvals?status=${s}" class="pill ${s === status ? 'allow' : ''}"
            style="text-decoration:none;padding:5px 11px;${s === status ? '' : 'background:var(--raised);color:var(--ink-2)'}">${s}</a>`)
      .join(' ')}
  </div>

  ${!canDecide && status === 'pending'
    ? '<div class="banner warn">Your role can view these but not decide them.</div>' : ''}

  <div class="panel">${rows.length === 0
    ? `<div class="empty">Nothing ${esc(status)}.</div>`
    : rows.map((a) => {
        const expired = a.status === 'pending' && a.expires_at <= new Date().toISOString();
        return `<div style="padding:16px;border-bottom:1px solid var(--line)">
          <div style="display:flex;gap:12px;align-items:baseline;flex-wrap:wrap">
            <span class="mono" style="font-weight:700">${esc(a.target)}</span>
            <span class="pill ${expired ? 'deny' : esc(a.status === 'pending' ? 'pending' : a.status === 'approved' ? 'allow' : 'deny')}">
              ${esc(expired ? 'expired' : a.status)}</span>
            <span class="dim" style="font-size:12px">${esc(ago(a.requested_at))} · ${esc(a.log_slug)}</span>
          </div>
          <dl class="kv" style="margin:10px 0 0">
            <dt>reason</dt><dd>${esc(a.reason)}</dd>
            <dt>for</dt><dd>${esc(a.principal)} <span class="dim">via ${esc(a.agent)}</span></dd>
            <dt>rules</dt><dd class="mono">${esc(JSON.parse(a.rules).join(', ') || '—')}</dd>
            ${a.decided_by ? `<dt>decided by</dt><dd>${esc(a.decided_by)}${a.note ? ` — ${esc(a.note)}` : ''}</dd>` : ''}
          </dl>
          <pre class="args">${esc(JSON.stringify(JSON.parse(a.params), null, 2))}</pre>
          <p class="dim" style="font-size:11.5px;margin:6px 0 0">
            Arguments are shown redacted. Approving does not reveal the original payload.</p>
          ${a.status === 'pending' && !expired && canDecide
            ? `<div style="display:flex;gap:8px;margin-top:12px">
                 <form class="inline" method="post" action="/approvals/${esc(a.id)}/decide">
                   <input type="hidden" name="approved" value="1"><button class="go">Approve</button></form>
                 <form class="inline" method="post" action="/approvals/${esc(a.id)}/decide">
                   <input type="hidden" name="approved" value="0"><button class="no">Deny</button></form>
               </div>` : ''}
        </div>`;
      }).join('')}</div>`;
}

/**
 * @param {import('./app.js').Hub} hub
 * @param {import('./http.js').Ctx} ctx
 */
function policies(hub, ctx) {
  const rows = hub.db
    .prepare(
      `SELECT slug, version, hash, note, created_at, created_by, active
       FROM policies WHERE org_id = ? ORDER BY slug, version DESC`,
    )
    .all(ctx.principal.orgId);

  return `<h1>Policies</h1>
  <p class="sub">Versioned and immutable. Agents fetch the active version at startup and record its
  hash in every receipt, so a decision can always be traced to the exact rules in force.</p>
  <div class="panel scroll"><table>
    <thead><tr><th>Policy</th><th>Version</th><th>Hash</th><th>Published</th><th>By</th><th></th></tr></thead>
    <tbody>${rows.length === 0
      ? '<tr><td colspan="6" class="empty">No policies yet. Publish one with <span class="mono">vw policy push</span>.</td></tr>'
      : rows.map((p) => `<tr>
          <td class="mono"><b>${esc(p.slug)}</b></td>
          <td style="font-variant-numeric:tabular-nums">v${p.version}</td>
          <td class="mono dim">${short(p.hash, 16)}</td>
          <td class="dim">${esc(ago(p.created_at))}</td>
          <td class="dim">${esc(p.created_by ?? '—')}</td>
          <td>${p.active ? '<span class="pill allow">active</span>' : '<span class="dim">superseded</span>'}</td>
        </tr>`).join('')}
    </tbody></table></div>`;
}

/**
 * @param {import('./app.js').Hub} hub
 * @param {import('./http.js').Ctx} ctx
 */
function events(hub, ctx) {
  if (!ctx.principal.scopes.includes('admin')) {
    return '<h1>Activity</h1><div class="banner warn">Your role cannot read the control-plane audit trail.</div>';
  }
  const rows = hub.store.events(ctx.principal.orgId, 200);
  const integrity = hub.store.auditEvents(ctx.principal.orgId);

  return `<h1>Activity</h1>
  <p class="sub">Every administrative action on this workspace, hash-chained. We ask you to trust a
  tamper-evident record, so ours is one too.</p>
  <div class="banner ${integrity.ok ? '' : 'bad'}">
    ${integrity.ok
      ? `<b style="color:var(--verify)">✓ Chain intact</b> across ${integrity.count} events.`
      : `<b style="color:var(--alarm)">✗ ${integrity.issues.length} problem(s):</b> ${esc(integrity.issues.slice(0, 5).join('; '))}`}
  </div>
  <div class="panel scroll"><table>
    <thead><tr><th>#</th><th>When</th><th>Actor</th><th>Action</th><th>Subject</th></tr></thead>
    <tbody>${rows.length === 0
      ? '<tr><td colspan="5" class="empty">Nothing yet.</td></tr>'
      : rows.map((e) => `<tr>
          <td class="mono dim">${e.seq}</td>
          <td class="dim mono">${esc(e.at.slice(5, 19).replace('T', ' '))}</td>
          <td>${esc(e.actor)} <span class="dim">${esc(e.actor_kind)}</span></td>
          <td class="mono">${esc(e.action)}</td>
          <td class="dim">${esc(e.subject)}</td>
        </tr>`).join('')}
    </tbody></table></div>`;
}

/**
 * @param {import('./app.js').Hub} hub
 * @param {import('./http.js').Ctx} ctx
 */
function settings(hub, ctx) {
  const isAdmin = ctx.principal.scopes.includes('admin');
  const org = hub.store.org(ctx.principal.orgId);

  const identity = `<h2>Verification</h2>
    <div class="panel" style="padding:16px">
      <p style="margin:0 0 12px;font-size:13px;color:var(--ink-2)">
        Publish these wherever your auditors will look. A verifier that gets its keys from the same
        place it gets the log is not verifying anything.</p>
      <dl class="kv">
        <dt>hub key</dt><dd class="mono">${esc(hub.hubIdentity.kid)}</dd>
        <dt>hub public</dt><dd class="mono">${esc(hub.hubIdentity.publicKey)}</dd>
        <dt>witness key</dt><dd class="mono">${esc(hub.witnessIdentity.kid)}</dd>
        <dt>witness public</dt><dd class="mono">${esc(hub.witnessIdentity.publicKey)}</dd>
        <dt>discovery</dt><dd class="mono">/.well-known/vouchwell</dd>
      </dl>
    </div>`;

  if (!isAdmin) {
    return `<h1>Settings</h1><p class="sub">${esc(org?.name ?? '')}</p>${identity}`;
  }
  const tabs = settingsTabs('/settings');

  const keys = hub.auth.keys(ctx.principal.orgId);
  const members = hub.auth.members(ctx.principal.orgId);

  return `<h1>Settings</h1>
  <p class="sub">${esc(org?.name ?? '')} · <span class="mono">${esc(org?.id ?? '')}</span></p>
  ${tabs}

  <h2>API keys</h2>
  <div class="panel scroll"><table>
    <thead><tr><th>Name</th><th>Id</th><th>Scopes</th><th>Pinned log</th><th>Last used</th><th></th></tr></thead>
    <tbody>${keys.length === 0
      ? '<tr><td colspan="6" class="empty">No keys yet.</td></tr>'
      : keys.map((k) => `<tr style="${k.revoked_at ? 'opacity:.5' : ''}">
          <td><b>${esc(k.name)}</b></td>
          <td class="mono dim">${esc(k.id)}</td>
          <td class="mono" style="font-size:11px">${esc(k.scopes.join(' '))}</td>
          <td class="mono dim">${k.log_id ? short(k.log_id, 14) : '<span class="dim">any</span>'}</td>
          <td class="dim">${esc(ago(k.last_used_at))}</td>
          <td>${k.revoked_at
            ? '<span class="pill deny">revoked</span>'
            : `<form class="inline" method="post" action="/settings/keys/${esc(k.id)}/revoke">
                 <button class="no">Revoke</button></form>`}</td>
        </tr>`).join('')}
    </tbody></table></div>

  <h2>Members</h2>
  <div class="panel scroll"><table>
    <thead><tr><th>Email</th><th>Role</th><th>Added</th><th>Last seen</th><th>State</th></tr></thead>
    <tbody>${members.map((m) => {
      const pending = !hub.db
        .prepare('SELECT password_hash FROM users WHERE id = ?')
        .get(m.id)?.password_hash;
      return `<tr>
        <td><b>${esc(m.email)}</b></td>
        <td class="mono">${esc(m.role)}</td>
        <td class="dim">${esc(ago(m.created_at))}</td>
        <td class="dim">${esc(ago(m.last_seen_at))}</td>
        <td>${pending
          ? '<span class="pill pending">invited</span>'
          : '<span class="pill allow">active</span>'}</td>
      </tr>`;
    }).join('')}
    </tbody></table></div>
  <p class="dim" style="font-size:12px;margin-top:10px">
    An <span class="mono">auditor</span> can read everything and change nothing — that is the role to
    hand an outside firm. Invite one with <span class="mono">POST /v1/invites</span>; the link is
    returned once and never stored.</p>

  ${retentionPanel(hub, ctx)}

  ${identity}`;
}

/**
 * @typedef {object} Extra
 * @property {{ kind: 'ok' | 'bad', text: string } | undefined} [flash]
 * @property {{ name: string, secret: string } | undefined} [secret]  A webhook secret, shown this once.
 * @property {{ name: string, ok: boolean, error?: string }[] | undefined} [results]  Test deliveries.
 */

/** What a form action did, by code, so nothing a request sent is echoed into the page. */
const DONE = {
  'witness-added': 'Witness added. The latest checkpoint of each log has gone to it.',
  'witness-removed': 'Witness removed. Checkpoints it already signed keep its signature.',
  'witnesses-sent': 'Sent the latest checkpoint of each log to every witness.',
  'stream-added': 'Destination added. New events go to it within a second.',
  'stream-removed': 'Destination removed.',
  'streams-flushed': 'Sent everything pending.',
  'slack-tested': 'Sent a test message to Slack.',
};

/** @param {'/settings' | '/settings/integrations'} here */
function settingsTabs(here) {
  return `<div class="subnav">${[['/settings', 'General'], ['/settings/integrations', 'Integrations']]
    .map(([href, label]) => `<a href="${esc(href)}"${href === here ? ' class="on"' : ''}>${esc(label)}</a>`)
    .join('')}</div>`;
}

/**
 * Where the organisation's evidence and events go: outside witnesses, event
 * streams, Slack and single sign-on. Admins only, like the API behind it;
 * credentials are shown as set, never as what they are.
 *
 * @param {import('./app.js').Hub} hub
 * @param {import('./http.js').Ctx} ctx
 * @param {Extra} extra
 */
function integrations(hub, ctx, extra) {
  if (!ctx.principal.scopes.includes('admin')) {
    return `<h1>Integrations</h1><p class="sub">Only admins can see and change integrations.</p>`;
  }
  const code = ctx.query.get('done') ?? '';
  const done = Object.hasOwn(DONE, code) ? DONE[/** @type {keyof typeof DONE} */ (code)] : undefined;
  const flash = extra.flash ?? (done ? { kind: 'ok', text: done } : undefined);
  return `<h1>Settings</h1>
  <p class="sub">Where this organisation's evidence and events go.</p>
  ${settingsTabs('/settings/integrations')}
  ${flash ? `<div class="banner${flash.kind === 'bad' ? ' bad' : ''}" role="status">${esc(flash.text)}</div>` : ''}
  ${extra.secret ? `<div class="banner warn" role="status"><b>Webhook signing secret for ${esc(extra.secret.name)}, shown once.</b>
    Copy it now: verify each delivery's <span class="mono">vouchwell-signature</span> header with it (see docs/STREAMING.md).
    <span class="secret">${esc(extra.secret.secret)}</span></div>` : ''}
  ${extra.results ? `<div class="banner${extra.results.every((r) => r.ok) ? '' : ' bad'}" role="status">${extra.results.length
    ? extra.results.map((r) => `<div><b>${esc(r.name)}</b>: ${r.ok ? 'delivered a test event' : esc(r.error ?? 'failed')}</div>`).join('')
    : 'There are no destinations to test.'}</div>` : ''}
  ${witnessesPanel(hub, ctx)}
  ${streamsPanel(hub, ctx)}
  ${slackPanel(hub, ctx)}
  ${ssoPanel(hub, ctx)}`;
}

/**
 * @param {import('./app.js').Hub} hub
 * @param {import('./http.js').Ctx} ctx
 */
function witnessesPanel(hub, ctx) {
  const orgId = ctx.principal.orgId;
  /** @type {any[]} */
  const configured = hub.store.integration(orgId, 'witnesses')?.config.witnesses ?? [];
  const logs = hub.store.logs(orgId);
  // The latest checkpoint each witness signed, from the stored signatures:
  // it survives restarts, unlike the error state below.
  const signed = (/** @type {string} */ kid) => {
    let best = null;
    for (const log of logs) {
      for (const cp of hub.store.checkpoints(orgId, log.id, 20)) {
        const sig = cp.sigs.find((/** @type {any} */ x) => x.role === 'witness' && x.kid === kid);
        if (sig && (!best || String(sig.ts ?? '') > String(best.ts ?? ''))) best = { log: log.slug, size: cp.body.size, ts: sig.ts };
        if (sig) break;
      }
    }
    return best;
  };
  const held = hub.db
    .prepare('SELECT log_id, reason, since FROM witness_holds WHERE witness_kid = ? AND substr(log_id, 1, length(?)) = ?')
    .all(hub.witnessSigner.kid, `${orgId}:`, `${orgId}:`);

  const rows = configured.map((w) => {
    const st = hub._witnessStatus.get(`${orgId}:${w.name}`) ?? {};
    const last = signed(w.kid);
    const state = st.lastError
      ? `<span class="pill ${st.alarming ? 'deny' : 'pending'}">${st.alarming ? 'refused' : 'failing'}</span>
         <div class="dim" style="font-size:12px;margin-top:4px">${esc(st.lastError)} · ${esc(ago(st.lastErrorAt))}</div>`
      : last ? '<span class="pill allow">signing</span>' : '<span class="pill pending">waiting</span>';
    return `<tr>
      <td><b>${esc(w.name)}</b></td>
      <td class="mono">${esc(new URL(w.url).host)}</td>
      <td class="mono dim">${short(w.kid, 14)}</td>
      <td>${last ? `${esc(last.log)} at ${esc(last.size)} <span class="dim">· ${esc(ago(last.ts))}</span>` : '<span class="dim">nothing yet</span>'}</td>
      <td>${state}</td>
      <td><form class="inline" method="post" action="/settings/integrations/witnesses/${encodeURIComponent(w.name)}/remove">
        <button class="no">Remove</button></form></td>
    </tr>`;
  }).join('');

  return `<h2>Outside witnesses</h2>
  <p class="dim" style="font-size:13px;margin:-4px 0 10px">Every checkpoint of your logs goes to each of these for co-signing, so this
  hub alone can't show two people two histories. Pick witnesses run by someone other than you; auditors pin their keys
  from the witness operator, not from here.</p>
  <div class="panel scroll"><table>
    <thead><tr><th>Name</th><th>Witness</th><th>Key</th><th>Last signed</th><th>State</th><th></th></tr></thead>
    <tbody>${rows || '<tr><td colspan="6" class="empty">No outside witnesses. Checkpoints carry only this hub\'s signature.</td></tr>'}</tbody>
  </table></div>
  ${configured.length ? `<div class="actions"><form class="inline" method="post" action="/settings/integrations/witnesses/send">
    <button>Send the latest checkpoints now</button></form></div>` : ''}
  ${held.length ? `<div class="banner bad" style="margin-top:12px"><b>This hub's own witness is holding ${held.length} log(s)</b>
    after a restore from backup, and co-signs nothing for them until its operator releases them on the host:
    <span class="secret">vouchwell-hub witness-release &lt;customer&gt; &lt;log&gt; --checkpoint latest.json</span>
    ${held.map((h) => `<span class="mono">${esc(String(h.log_id).slice(orgId.length + 1))}</span>`).join(', ')}.
    It is deliberately not a button here: a hold protects against the log's operator, which is this organisation.</div>` : ''}
  ${configured.length < 5 ? `<div class="panel" style="margin-top:12px">
    <form method="post" action="/settings/integrations/witnesses/add" class="formgrid">
      <div class="field"><label for="w-name">Name</label>
        <input id="w-name" name="name" required maxlength="32" pattern="[a-z0-9][a-z0-9\\-]{0,31}" placeholder="e.g. auditor"></div>
      <div class="field"><label for="w-url">Witness URL</label>
        <input id="w-url" name="url" type="url" required placeholder="https://witness.example.org"></div>
      <div class="field"><label for="w-token">Key it issued you</label>
        <input id="w-token" name="token" type="password" required autocomplete="off"></div>
      <div class="field"><button class="go" type="submit">Add witness</button></div>
    </form></div>` : ''}`;
}

/**
 * @param {import('./app.js').Hub} hub
 * @param {import('./http.js').Ctx} ctx
 */
function streamsPanel(hub, ctx) {
  const status = hub.streams.status(ctx.principal.orgId);
  const rows = status.map((d) => {
    const sends = [d.receipts === 'none' ? '' : `receipts (${d.receipts})`, d.audit ? 'audit' : ''].filter(Boolean).join(', ') || 'nothing';
    const state = d.retrying
      ? `<span class="pill deny">retrying</span><div class="dim" style="font-size:12px;margin-top:4px">${esc(d.lastError ?? '')} · ${esc(ago(d.lastErrorAt))}</div>`
      : d.lastOkAt ? `<span class="pill allow">delivering</span> <span class="dim">${esc(ago(d.lastOkAt))}</span>`
        : '<span class="pill pending">waiting</span>';
    return `<tr>
      <td><b>${esc(d.name)}</b></td>
      <td class="mono">${esc(d.type)}</td>
      <td class="mono">${esc(d.host)}</td>
      <td>${esc(sends)}</td>
      <td class="mono">${esc(d.pending)}</td>
      <td>${state}</td>
      <td><form class="inline" method="post" action="/settings/integrations/streams/${encodeURIComponent(d.name)}/remove">
        <button class="no">Remove</button></form></td>
    </tr>`;
  }).join('');

  return `<h2>Event streams</h2>
  <p class="dim" style="font-size:13px;margin:-4px 0 10px">Receipts and this hub's audit trail, sent to your SIEM. Nothing is lost
  while a destination is down: it catches up when it's back. What an agent sent to a tool never leaves the hub.</p>
  <div class="panel scroll"><table>
    <thead><tr><th>Name</th><th>Type</th><th>Host</th><th>Sends</th><th>Pending</th><th>State</th><th></th></tr></thead>
    <tbody>${rows || '<tr><td colspan="7" class="empty">No destinations.</td></tr>'}</tbody>
  </table></div>
  ${status.length ? `<div class="actions">
    <form class="inline" method="post" action="/settings/integrations/streams/test"><button>Send a test event</button></form>
    <form class="inline" method="post" action="/settings/integrations/streams/flush"><button>Send pending now</button></form>
  </div>` : ''}
  ${status.length < 5 ? `<div class="panel" style="margin-top:12px">
    <form method="post" action="/settings/integrations/streams/add" class="formgrid">
      <div class="field"><label for="s-name">Name</label>
        <input id="s-name" name="name" required maxlength="32" pattern="[a-z0-9][a-z0-9\\-]{0,31}" placeholder="e.g. splunk"></div>
      <div class="field"><label for="s-type">Type</label>
        <select id="s-type" name="type"><option value="splunk">Splunk HEC</option><option value="datadog">Datadog Logs</option>
          <option value="otlp">OpenTelemetry (OTLP/HTTP)</option><option value="webhook">Signed webhook</option></select></div>
      <div class="field"><label for="s-url">URL</label>
        <input id="s-url" name="url" type="url" placeholder="https://splunk.example.com:8088"></div>
      <div class="field"><label for="s-token">Token or API key</label>
        <input id="s-token" name="token" type="password" autocomplete="off" placeholder="Splunk and Datadog"></div>
      <div class="field"><label for="s-header">Header (OTLP)</label>
        <input id="s-header" name="header" autocomplete="off" placeholder="authorization=Bearer …"></div>
      <div class="field"><label for="s-receipts">Receipts</label>
        <select id="s-receipts" name="receipts"><option value="all">All</option><option value="blocked">Only denied and escalated</option>
          <option value="none">None</option></select></div>
      <div class="field"><label class="check"><input type="checkbox" name="audit" value="1" checked> Audit trail too</label>
        <label class="check"><input type="checkbox" name="backfill" value="1"> Send history first</label></div>
      <div class="field"><button class="go" type="submit">Add destination</button></div>
    </form>
    <p class="dim" style="font-size:12px;margin:0;padding:0 16px 14px">Datadog's URL defaults to the US intake. A webhook gets a
    signing secret, shown once after you add it.</p></div>` : ''}`;
}

/**
 * @param {import('./app.js').Hub} hub
 * @param {import('./http.js').Ctx} ctx
 */
function ssoPanel(hub, ctx) {
  const sso = hub.store.integration(ctx.principal.orgId, 'oidc');
  if (!sso) {
    return `<h2>Single sign-on</h2>
    <div class="panel" style="padding:16px;font-size:13px">
      <span class="pill pending">not configured</span>
      <p style="margin:10px 0 0;color:var(--ink-2)">Sign in through Okta, Microsoft Entra ID, Google Workspace or any
      OpenID Connect provider. Set it up with <span class="mono">PUT /v1/integrations/oidc</span>; see
      <span class="mono">docs/SSO.md</span>.</p>
    </div>`;
  }
  const c = sso.config;
  return `<h2>Single sign-on</h2>
    <div class="panel" style="padding:16px">
      <dl class="kv">
        <dt>status</dt><dd><span class="pill allow">configured</span>${c.requireSso ? ' <span class="pill escalate">required</span>' : ''}</dd>
        <dt>provider</dt><dd class="mono">${esc(c.issuer)}</dd>
        <dt>domains</dt><dd>${c.domains.length ? c.domains.map((d) => `<span class="mono">${esc(d)}</span>`).join(', ') : '<span class="dim">any</span>'}</dd>
        <dt>new people</dt><dd>${c.autoProvision ? `join as <span class="mono">${esc(c.autoProvision)}</span>` : 'must be invited first'}</dd>
      </dl>
    </div>`;
}

/**
 * How long the hub keeps receipt content, and what that does and doesn't
 * affect.
 *
 * @param {import('./app.js').Hub} hub
 * @param {import('./http.js').Ctx} ctx
 */
function retentionPanel(hub, ctx) {
  const r = hub.store.retention(ctx.principal.orgId);
  const show = (/** @type {number | null} */ d) => (d === null ? 'forever' : `${d} days`);
  return `<h2>Retention</h2>
    <div class="panel" style="padding:16px">
      <dl class="kv">
        <dt>kept on the hub</dt><dd><b>${esc(show(r.effectiveDays))}</b>${r.capDays !== null ? ` <span class="dim">(plan limit ${esc(r.capDays)} days)</span>` : ''}</dd>
        <dt>pruned so far</dt><dd>${esc(r.pruned)} receipt(s)</dd>
        <dt>oldest kept</dt><dd class="dim">${esc(r.oldest ?? '—')}</dd>
      </dl>
      <p class="dim" style="font-size:12px;margin:12px 0 0">After this period the hub clears what a receipt says and keeps
      its hash, so the log's root, checkpoints and witness signatures still verify. Your agents' local logs are not
      affected. Change it with <span class="mono">PUT /v1/settings/retention</span>.</p>
    </div>`;
}

/**
 * Whether escalations go to Slack, and who may decide them there. Shows that
 * credentials are set, never what they are.
 *
 * @param {import('./app.js').Hub} hub
 * @param {import('./http.js').Ctx} ctx
 */
function slackPanel(hub, ctx) {
  const slack = hub.store.integration(ctx.principal.orgId, 'slack');
  if (!slack) {
    return `<h2>Slack approvals</h2>
    <div class="panel" style="padding:16px;font-size:13px">
      <span class="pill pending">not connected</span>
      <p style="margin:10px 0 0;color:var(--ink-2)">Escalations wait here in <a href="/approvals">Approvals</a>.
      To get them in a Slack channel with Approve and Deny buttons, run
      <span class="mono">vw slack connect</span> with an admin key. See <span class="mono">docs/SLACK.md</span>.</p>
    </div>`;
  }
  const approvers = slack.config.approvers ?? [];
  return `<h2>Slack approvals</h2>
    <div class="panel" style="padding:16px">
      <dl class="kv">
        <dt>status</dt><dd><span class="pill allow">connected</span></dd>
        <dt>webhook</dt><dd class="mono">${esc(new URL(slack.config.webhookUrl).host)}</dd>
        <dt>approvers</dt><dd>${approvers.length
          ? approvers.map((a) => `<span class="mono">${esc(a)}</span>`).join(', ')
          : '<span style="color:var(--hold)">anyone in the channel</span>'}</dd>
        <dt>since</dt><dd class="dim">${esc(ago(slack.updatedAt))}</dd>
      </dl>
      <div class="actions"><form class="inline" method="post" action="/settings/integrations/slack/test">
        <button>Send a test message</button></form></div>
    </div>`;
}

export { esc, page, layout };
