/* Kar-Warden — page wiring. Uses the REAL kernel functions concatenated above this in the module,
   so what you see run here is exactly what the mutation gate proves. No framework, no backend. */
const $ = (s) => document.querySelector(s);
const el = (t, c, txt) => { const e = document.createElement(t); if (c) e.className = c; if (txt !== undefined) e.textContent = txt; return e; };
const now = () => new Date().toISOString();

// ── baseline warrant + a matching observation (both start INTACT) ─────────────────────────────────
const CFG = sha256('agent-alpha · config · v1').hash;
const H_POLICY = sha256('policy.json · v1').hash;
const H_WEIGHTS = sha256('weights.bin · v1').hash;

const WARRANT = {
  id: 'agent-alpha',
  configHash: CFG,
  caps: ['read:memory', 'net:none', 'tool:search'],
  files: [{ path: 'policy.json', hash: H_POLICY }, { path: 'weights.bin', hash: H_WEIGHTS }],
  invariants: [{ name: 'sandbox-on', severity: 'severe' }, { name: 'telemetry-off', severity: 'warn' }],
};
let observed = freshObserved();
function freshObserved() {
  return {
    id: 'agent-alpha',
    configHash: CFG,
    caps: ['read:memory', 'net:none', 'tool:search'],
    files: [{ path: 'policy.json', hash: H_POLICY }, { path: 'weights.bin', hash: H_WEIGHTS }],
    invariants: { 'sandbox-on': true, 'telemetry-off': true },
  };
}
const short = (h) => (typeof h === 'string' && h.length === 64) ? h.slice(0, 10) + '…' + h.slice(-6) : String(h);

// ── render the two declarations ───────────────────────────────────────────────────────────────────
function renderDeclarations() {
  $('#warrantView').innerHTML =
    `id · <b>${WARRANT.id}</b><br>configHash · <b>${short(WARRANT.configHash)}</b><br>` +
    `caps · <b>${WARRANT.caps.join(', ')}</b><br>` +
    `files · <b>${WARRANT.files.map((f) => f.path).join(', ')}</b><br>` +
    `invariants · <b>sandbox-on (severe), telemetry-off (warn)</b>`;
  const capStr = observed.caps.join(', ');
  const invStr = Object.entries(observed.invariants).map(([k, v]) => `${k}=${v}`).join(', ');
  $('#observedView').innerHTML =
    `id · <b>${observed.id}</b><br>configHash · <b>${short(observed.configHash)}</b><br>` +
    `caps · <b>${capStr || '—'}</b><br>` +
    `files · <b>${observed.files.map((f) => f.path).join(', ') || '—'}</b><br>` +
    `invariants · <b>${invStr}</b>`;
}

// ── the verdict ─────────────────────────────────────────────────────────────────────────────────
let currentVerdict = null;
function renderVerdict() {
  const r = verifyIntegrity(WARRANT, observed);
  if (!r.ok) { $('#verdictBox').innerHTML = `<div class="verdict"><span class="st">error</span><span class="meta">${r.why}</span></div>`; $('#brokenList').innerHTML = ''; currentVerdict = null; return; }
  const v = currentVerdict = r.verdict;
  $('#verdictBox').innerHTML =
    `<div class="verdict"><span class="dot bg-${v.status}"></span>` +
    `<span class="st st-${v.status}">${v.status}</span>` +
    `<span class="meta">${v.brokenCount} broken · ${v.severeCount} severe<br>${v.checked.caps} caps · ${v.checked.files} files · ${v.checked.invariants} invariants checked</span></div>`;
  const list = $('#brokenList'); list.innerHTML = '';
  if (v.broken.length === 0) {
    const ok = el('div', 'ok-line', '✓ Every declared invariant holds. The component matches its warrant.');
    list.appendChild(ok); return;
  }
  for (const b of v.broken) {
    const li = el('li');
    li.appendChild(el('span', 'sev sev-' + b.severity, b.severity));
    li.appendChild(el('span', 'nm', b.invariant));
    const ex = el('span', 'ex', `expected ${short(b.expected)} · got ${short(b.observed)}`);
    li.appendChild(ex);
    list.appendChild(li);
  }
}

// ── mutation buttons ──────────────────────────────────────────────────────────────────────────────
const mutations = {
  config() { observed.configHash = sha256('tampered-config-' + Math.random()).hash; },
  cap() { if (!observed.caps.includes('net:all')) observed.caps.push('net:all'); },
  sandbox() { observed.invariants['sandbox-on'] = false; },
  telemetry() { observed.invariants['telemetry-off'] = false; },
  file() { observed.files = observed.files.filter((f) => f.path !== 'weights.bin'); },
  extra() { if (!observed.files.some((f) => f.path === 'shadow.so')) observed.files.push({ path: 'shadow.so', hash: sha256('shadow-' + Math.random()).hash }); },
};
document.querySelectorAll('[data-mut]').forEach((btn) => {
  btn.addEventListener('click', () => { const m = mutations[btn.dataset.mut]; if (m) m(); renderDeclarations(); renderVerdict(); });
});
$('#resetBtn').addEventListener('click', () => { observed = freshObserved(); renderDeclarations(); renderVerdict(); });

// ── the fleet (monitorStatus over a preset set) ──────────────────────────────────────────────────
function buildFleet() {
  const mk = (id, over) => ({ id, configHash: CFG, caps: ['read:memory'], files: [{ path: 'policy.json', hash: H_POLICY }], invariants: [{ name: 'sandbox-on', severity: 'severe' }], ...over });
  const warrants = [
    mk('router-01'),
    mk('summarizer-02'),
    mk('planner-03'),
    mk('scraper-04'),
    mk('retriever-05'),
  ];
  const ob = (id, over) => ({ id, configHash: CFG, caps: ['read:memory'], files: [{ path: 'policy.json', hash: H_POLICY }], invariants: { 'sandbox-on': true }, ...over });
  const observations = [
    ob('router-01'),                                                           // intact
    ob('summarizer-02', { caps: [] }),                                         // drifted (dropped a cap)
    ob('planner-03', { configHash: sha256('planner drift').hash }),           // breached
    // scraper-04 sends nothing → UNREPORTED
    ob('retriever-05', { caps: ['read:memory', 'net:all'] }),                 // breached (ungranted cap)
    ob('rogue-99'),                                                            // undeclared
  ];
  const r = monitorStatus(warrants, observations);
  if (!r.ok) return;
  const tb = $('#fleetTable tbody'); tb.innerHTML = '';
  for (const c of r.report.perComponent) {
    const tr = el('tr');
    tr.appendChild(Object.assign(el('td', 'mono'), { textContent: c.id }));
    const td = el('td'); td.appendChild(Object.assign(el('span', 'pill pill-' + c.status), { textContent: c.status })); tr.appendChild(td);
    tr.appendChild(Object.assign(el('td', 'mono'), { textContent: c.brokenCount }));
    tr.appendChild(Object.assign(el('td', 'mono'), { textContent: c.severeCount }));
    tb.appendChild(tr);
  }
  if (r.report.undeclared.length) {
    const tr = el('tr');
    tr.appendChild(Object.assign(el('td', 'mono'), { textContent: r.report.undeclared.join(', ') }));
    const td = el('td'); td.appendChild(Object.assign(el('span', 'pill pill-BREACHED'), { textContent: 'UNDECLARED' })); tr.appendChild(td);
    tr.appendChild(Object.assign(el('td', 'mono faint'), { textContent: '—' }));
    tr.appendChild(Object.assign(el('td', 'mono faint'), { textContent: '—' }));
    tb.appendChild(tr);
  }
  const rep = r.report;
  const cell = (n, lbl, cls) => `<div><span class="n ${n === 0 ? 'zero' : ''} ${cls || ''}">${n}</span>${lbl}</div>`;
  $('#fleetReport').innerHTML =
    `<div><span class="n st-${rep.worst}">${rep.worst}</span><span>worst status</span></div>` +
    cell(rep.intact, '<span>intact</span>', 'st-INTACT') +
    cell(rep.drifted, '<span>drifted</span>', 'st-DRIFTED') +
    cell(rep.breached, '<span>breached</span>', 'st-BREACHED') +
    cell(rep.unreported, '<span>unreported</span>', 'st-UNREPORTED') +
    cell(rep.undeclared.length, '<span>undeclared</span>', 'st-BREACHED');
}

// ── the anomaly log ─────────────────────────────────────────────────────────────────────────────
let chain = [];
function renderChain() {
  const view = $('#chainView');
  if (chain.length === 0) { view.innerHTML = '<span class="faint mono">No anomalies logged yet.</span>'; return; }
  view.innerHTML = '';
  chain.forEach((e, i) => {
    const d = el('div', 'entry' + (e._tampered ? ' bad' : ''));
    d.innerHTML = `<div class="row1"><span class="pill pill-${e.status}">${e.status}</span> #${e.seq} · ${e.componentID} · <span class="faint">${e.ts}</span></div>` +
      `<div class="h">hash ${short(e.hash)} · prev ${short(e.prevHash)}${e._tampered ? ' · <span class="st-BREACHED">edited</span>' : ''}</div>`;
    view.appendChild(d);
  });
}
$('#logCurrent').addEventListener('click', () => {
  if (!currentVerdict) return;
  const desc = currentVerdict.broken.length ? currentVerdict.broken.map((b) => b.invariant).join('; ') : 'intact snapshot';
  const r = appendAnomaly(chain, { componentID: currentVerdict.id, description: desc, status: currentVerdict.status, ts: now() });
  if (r.ok) { chain = r.chain; renderChain(); $('#chainResult').innerHTML = ''; }
});
$('#tamperLog').addEventListener('click', () => {
  if (chain.length === 0) { $('#chainResult').innerHTML = '<div class="result muted">Nothing logged to tamper with yet.</div>'; return; }
  chain = chain.map((e, i) => (i === 0 ? { ...e, description: 'silently edited after the fact', status: 'INTACT', _tampered: true } : e));
  renderChain();
  $('#chainResult').innerHTML = '<div class="result muted">Entry #0 was edited in place (its stored hash left untouched). Now verify the chain.</div>';
});
$('#verifyChainBtn').addEventListener('click', () => {
  const v = verifyChain(chain.map((e) => { const c = { ...e }; delete c._tampered; return c; }));
  if (chain.length === 0) { $('#chainResult').innerHTML = '<div class="result muted">Log something first.</div>'; return; }
  $('#chainResult').innerHTML = v.valid
    ? `<div class="result good">✓ Chain intact — ${v.length} ent​ries, every link recomputed and matched.</div>`
    : `<div class="result bad">✗ Chain BROKEN at entry #${v.brokenAt} — ${v.why}. The tamper is provable, not just suspected.</div>`;
});

// ── the receipt: issue, sign (Ed25519), download, verify ─────────────────────────────────────────
let lastReceipt = null;
function hex(buf) { return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join(''); }
async function trySign(receipt) {
  try {
    const s = wardenSignable(receipt);
    if (!s.ok) return receipt;
    const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const sig = await crypto.subtle.sign({ name: 'Ed25519' }, kp.privateKey, new TextEncoder().encode(s.payload));
    const pub = await crypto.subtle.exportKey('raw', kp.publicKey);
    return { ...receipt, signature: { alg: 'Ed25519', pub: hex(pub), sig: hex(sig) } };
  } catch (_) { return receipt; } // hash-only fallback where WebCrypto Ed25519 is unavailable
}
$('#issueBtn').addEventListener('click', async () => {
  const r = wardenReceipt({ warrant: WARRANT, observed, createdAt: now() });
  if (!r.ok) { $('#issueResult').innerHTML = `<div class="result bad">${r.why}</div>`; return; }
  lastReceipt = await trySign(r.receipt);
  const signed = !!lastReceipt.signature;
  $('#issueResult').innerHTML =
    `<div class="result ${lastReceipt.status === 'INTACT' ? 'good' : 'bad'}">` +
    `status <b class="st-${lastReceipt.status}">${lastReceipt.status}</b> · hash ${short(lastReceipt.hash)}<br>` +
    `${signed ? '✎ Ed25519-signed (' + short(lastReceipt.signature.pub) + ')' : 'hash-only (this browser has no Ed25519)'} · re-runnable by anyone</div>`;
  $('#downloadBtn').disabled = false;
});
$('#downloadBtn').addEventListener('click', () => {
  if (!lastReceipt) return;
  const blob = new Blob([JSON.stringify(lastReceipt, null, 2)], { type: 'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = 'warden-receipt-' + lastReceipt.id + '.json'; a.click(); URL.revokeObjectURL(a.href);
});

async function verifyReceiptObj(r) {
  const v = verifyWardenReceipt(r);
  if (!v.ok) return { cls: 'bad', html: `✗ Not a Kar-Warden receipt — ${v.why}` };
  if (!v.valid) return { cls: 'bad', html: `✗ CHANGED — ${v.why}` };
  // hash + re-run both hold. If a signature is present, check it too (WebCrypto).
  let sigLine = 'no signature (hash + re-run verified)';
  if (r.signature && r.signature.alg === 'Ed25519') {
    try {
      const s = wardenSignable(r);
      const key = await crypto.subtle.importKey('raw', Uint8Array.from(r.signature.pub.match(/../g).map((h) => parseInt(h, 16))), { name: 'Ed25519' }, false, ['verify']);
      const good = await crypto.subtle.verify({ name: 'Ed25519' }, key, Uint8Array.from(r.signature.sig.match(/../g).map((h) => parseInt(h, 16))), new TextEncoder().encode(s.payload));
      sigLine = good ? '✎ Ed25519 signature verified' : '⚠ signature does NOT verify';
      if (!good) return { cls: 'bad', html: `✗ signature does not verify — the receipt was re-signed or altered` };
    } catch (_) { sigLine = 'signature present (this browser cannot check Ed25519)'; }
  }
  return { cls: 'good', html: `✓ GENUINE · status <b class="st-${v.status}">${v.status}</b> for <b>${r.id}</b><br>${sigLine}<br><span class="faint">Verdict reproduced by re-running verifyIntegrity on the receipt's own warrant + observed — no trust in the issuer.</span>` };
}
async function doVerify(text) {
  let r; try { r = JSON.parse(text); } catch (_) { $('#verifyResult').innerHTML = '<div class="result bad">✗ Not valid JSON.</div>'; return; }
  const out = await verifyReceiptObj(r);
  $('#verifyResult').innerHTML = `<div class="result ${out.cls}">${out.html}</div>`;
}
$('#verifyReceiptBtn').addEventListener('click', () => {
  const t = $('#pasteArea').value.trim();
  if (!t) { $('#verifyResult').innerHTML = '<div class="result muted">Paste or drop a receipt first.</div>'; return; }
  doVerify(t);
});
const drop = $('#drop'), fileIn = $('#fileIn');
drop.addEventListener('click', () => fileIn.click());
fileIn.addEventListener('change', () => { const f = fileIn.files[0]; if (f) f.text().then((t) => { $('#pasteArea').value = t; doVerify(t); }); });
['dragover', 'dragenter'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', (e) => { const f = e.dataTransfer.files[0]; if (f) f.text().then((t) => { $('#pasteArea').value = t; doVerify(t); }); });

// ── gate badge + first paint ──────────────────────────────────────────────────────────────────────
const GATE = 'witness 72/73 · score 0.986 · 1 reviewed-equivalent';
$('#gateScore').textContent = 'witness 0.986';
$('#footGate').textContent = 'Kernel: ' + GATE + '. CI re-runs node --test + the mutation gate on GitHub’s runner.';
renderDeclarations();
renderVerdict();
buildFleet();
