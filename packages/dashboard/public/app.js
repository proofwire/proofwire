const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
const short = (h, n = 12) => (h ? esc(h.slice(0, n)) + '…' : '—');

let state = { entries: [], selected: null, open: new Set() };

async function load() {
  const data = await (await fetch('/api/log')).json();
  state.entries = data.entries;
  const never = [...data.unfinished.unfinished, ...data.unfinished.abandoned];
  state.open = new Set(never.map((u) => u.seq));

  $('s-log').textContent = data.log;
  $('s-size').textContent = data.size;
  $('s-blocked').textContent = data.entries.filter((e) => e.outcome !== 'allow').length;
  $('s-root').textContent = data.root.slice(0, 12) + '…';
  $('s-root').title = data.root;

  const v = $('verdict');
  v.className = 'verdict ' + (data.audit.ok ? 'ok' : 'bad');
  v.textContent = data.audit.ok ? '✓ verified' : `✗ ${data.audit.issues.length} problem(s)`;

  $('alert').innerHTML = data.audit.ok
    ? (data.checkpoints.length === 0
        ? `<div class="banner">No checkpoints yet. A signed checkpoint is what lets an outside party detect a later rewrite — one is written when a proxy session ends.</div>`
        : '') + (never.length
        ? `<div class="banner"><b>${never.length} action(s) were authorised and sent, but never finished.</b> ` +
          `The recorder stopped while they were out, so whether they took effect is not in the log: ` +
          `check each with the system it called. Choose <i>never finished</i> below to list them.</div>`
        : '')
    : `<div class="banner bad"><b>This log has been altered since it was written.</b><br>` +
      data.audit.issues.map((i) => esc(`${i.kind}${i.seq !== undefined ? ` @ ${i.seq}` : ''}: ${i.message}`)).join('<br>') +
      `</div>`;

  render();
}

function render() {
  const q = $('q').value.toLowerCase();
  const outcome = $('outcome').value;
  const phase = $('phase').value;

  const list = state.entries.filter((e) => {
    if (outcome === 'deny' && e.outcome === 'allow') return false;
    if (outcome === 'allow' && e.outcome !== 'allow') return false;
    if (outcome === 'would' && !e.wouldBe) return false;
    if (outcome === 'unfinished' && !state.open.has(e.seq)) return false;
    if (phase && e.phase !== phase) return false;
    if (!q) return true;
    return [e.target, e.principal, e.reason, e.agent].join(' ').toLowerCase().includes(q);
  });

  $('rows').innerHTML = list.length === 0
    ? '<div class="empty">Nothing matches.</div>'
    : list.map((e) => `
      <div class="row" role="option" data-seq="${e.seq}" aria-selected="${state.selected === e.seq}">
        <span class="seq">${e.seq}</span>
        <span class="time">${esc(e.ts.slice(11, 19))}</span>
        <span>${e.wouldBe
          ? `<span class="pill escalate" title="monitor mode: ran, not enforced">would ${esc(e.wouldBe)}</span>`
          : `<span class="pill ${esc(e.outcome)}">${esc(e.outcome)}</span>`}</span>
        <span class="target">${esc(e.target)}
          ${e.phase !== 'atomic' ? `<span class="phase">${esc(e.phase)}</span>` : ''}
          ${state.open.has(e.seq) ? '<span class="pill escalate" title="authorised and sent; no result was recorded">never finished</span>' : ''}
        </span>
        <span class="meta">${
          e.outcome === 'allow' && !(e.wouldBe && !e.status)
            ? esc(e.status ?? '—') + (e.latencyMs != null ? ` · ${e.latencyMs}ms` : '')
            : esc((e.reason ?? '').slice(0, 44))
        }</span>
      </div>`).join('');

  for (const row of document.querySelectorAll('.row')) {
    row.onclick = () => select(Number(row.dataset.seq));
  }
}

async function select(seq) {
  state.selected = seq;
  render();
  const { receipt, proof } = await (await fetch(`/api/entry/${seq}`)).json();
  const d = receipt.decision;

  $('detail').innerHTML = `
    <h2>Receipt ${receipt.seq}</h2>
    <dl>
      <dt>tool</dt><dd><code>${esc(receipt.action.target)}</code></dd>
      <dt>decision</dt><dd><span class="pill ${esc(d.outcome)}">${esc(d.outcome)}</span>${
        d.enforced === false
          ? ` <span class="pill escalate">${d.wouldBe ? `would ${esc(d.wouldBe)} · ` : ''}not enforced</span>`
          : ''}</dd>
      <dt>reason</dt><dd>${esc(d.reason ?? '—')}</dd>
      <dt>rules</dt><dd>${(d.rules ?? []).map((r) => `<span class="chip">${esc(r)}</span>`).join('') || '—'}</dd>
      ${d.approval ? `<dt>approved by</dt><dd>${esc(d.approval.by)}${d.approval.note ? ` — ${esc(d.approval.note)}` : ''}</dd>` : ''}
      <dt>when</dt><dd>${esc(receipt.ts)}</dd>
      <dt>agent</dt><dd>${esc(receipt.actor.agent)}</dd>
      <dt>for</dt><dd>${esc(receipt.actor.principal)}</dd>
      <dt>session</dt><dd><code>${esc(receipt.actor.session)}</code></dd>
      <dt>policy</dt><dd class="hash" title="${esc(d.policy)}">${short(d.policy, 16)}</dd>
      ${receipt.result ? `<dt>result</dt><dd>${esc(receipt.result.status)}${receipt.result.latencyMs != null ? ` · ${receipt.result.latencyMs}ms` : ''}</dd>` : ''}
    </dl>

    <h2>Arguments (redacted preview)</h2>
    ${(receipt.action.params.redacted ?? []).length
      ? `<p style="color:var(--muted);font-size:12px;margin:0 0 6px">
           Masked before storage: ${receipt.action.params.redacted.map((t) => `<span class="chip">${esc(t)}</span>`).join('')}
         </p>` : ''}
    <pre>${esc(JSON.stringify(receipt.action.params.preview, null, 2))}</pre>
    <p style="color:var(--muted);font-size:12px">
      The log holds a salted commitment, not the payload:
      <code>${short(receipt.action.params.hash, 20)}</code> over ${receipt.action.params.size} bytes.
    </p>

    <h2>Chain</h2>
    <dl>
      <dt>this entry</dt><dd class="hash">${short(proof.leaf, 24)}</dd>
      <dt>previous</dt><dd class="hash">${short(receipt.prev, 24)}</dd>
      <dt>signed by</dt><dd class="hash">${esc(receipt.attest.kid)}</dd>
      ${receipt.ref ? `<dt>follows</dt><dd class="hash">${short(receipt.ref, 24)}</dd>` : ''}
    </dl>

    <h2>Inclusion proof</h2>
    <dl>
      <dt>tree size</dt><dd>${proof.treeSize}</dd>
      <dt>root</dt><dd class="hash">${short(proof.root, 24)}</dd>
      <dt>path</dt><dd>${proof.proof.length} sibling hashes</dd>
    </dl>
    <pre>${proof.proof.map((h) => esc(h)).join('\n') || '(single-entry tree)'}</pre>
    <p style="color:var(--muted);font-size:12px">
      Anyone can recompute the root from this entry and these hashes.
      Verify it offline with <code>pw prove ${receipt.seq}</code>.
    </p>`;
}

for (const el of ['q', 'outcome', 'phase']) $(el).oninput = render;
load();
setInterval(load, 4000);
