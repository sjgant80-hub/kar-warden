// Kar-Warden — the integrity core. Kar's build (karma-didy), gated by claudedidy.
//
// A WARDEN answers one question, provably and with no LLM judge: does an AI component still match
// what it was DECLARED to be? You write a WARRANT — the signed statement of what a component is
// allowed to be (its baseline config hash, the capabilities it may hold, the files it must carry,
// the named invariants that must hold). You present the component's OBSERVED state. Warden compares
// them deterministically and returns a verdict — INTACT / DRIFTED / BREACHED — naming exactly what
// broke. One SEVERE break (a changed config, an ungranted capability, a missing file, a severe
// invariant) is a BREACH and cannot be averaged away by everything that still passes.
//
// Three primitives, from Kar's three functions:
//   verifyIntegrity(warrant, observed) → a full verdict          (his VerifyIntegrity, bool → verdict)
//   monitorStatus(warrants, observations) → a StatusReport        (his MonitorSystemStatus, a pure fold)
//   appendAnomaly(chain, entry) / verifyChain(chain)              (his LogAnomaly, a tamper-evident log)
// Plus a portable receipt any third party can RE-RUN: wardenReceipt / verifyWardenReceipt.
//
// No I/O. Pure and total: garbage in → { ok:false, why }, never a throw. The signature bytes are
// checked at the edge (WebCrypto / node:crypto) over wardenSignable(); the kernel pins WHAT is signed.

export const STATUS = ['INTACT', 'DRIFTED', 'BREACHED', 'UNREPORTED'];
export const SEVERITIES = ['warn', 'severe'];
// worst-first ranking, pinned numerically (a warden must never let a breach read as merely drifted):
export const STATUS_RANK = { INTACT: 0, DRIFTED: 1, UNREPORTED: 2, BREACHED: 3 };
export const GENESIS = '0'.repeat(64);

export const MAX_ID = 200;
export const MAX_CAPS = 200;
export const MAX_FILES = 500;
export const MAX_INVARIANTS = 200;
export const MAX_DESC = 2000;

const isStr = (v) => typeof v === 'string';
const isBool = (v) => typeof v === 'boolean';
const isObj = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const isArr = (v) => Array.isArray(v);
const HEX = /^[0-9a-f]+$/;
const isHash = (v) => isStr(v) && v.length === 64 && HEX.test(v);

// ── SHA-256 + canonical JSON (the estate's proven pair — the same bytes the gate runs on) ─────────
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export function sha256(text) {
  if (!isStr(text)) return { ok: false, why: 'sha256 takes a string' };
  const data = new TextEncoder().encode(text);
  const len = data.length;
  const padded = new Uint8Array((((len + 8) >> 6) << 6) + 64);
  padded.set(data);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  const bitLen = len * 8;
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 4294967296));
  dv.setUint32(padded.length - 4, bitLen >>> 0);
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);
  for (let i = 0; i < padded.length; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4);
    for (let t = 16; t < 64; t++) {
      const x = w[t - 15], y = w[t - 2];
      const s0 = (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) >>> 0;
      const s1 = (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10)) >>> 0;
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (let t = 0; t < 64; t++) {
      const S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (hh + S1 + ch + K256[t] + w[t]) >>> 0;
      const S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + hh) >>> 0;
  }
  const hex = (n) => n.toString(16).padStart(8, '0');
  return { ok: true, hash: hex(h0) + hex(h1) + hex(h2) + hex(h3) + hex(h4) + hex(h5) + hex(h6) + hex(h7) };
}

export function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  return '"?"';
}

// ── the warrant: what a component is DECLARED to be ───────────────────────────────────────────────
function validFileList(files, label) {
  if (!isArr(files)) return { ok: false, why: label + ' must be an array' };
  if (files.length > MAX_FILES) return { ok: false, why: label + ' exceeds ' + MAX_FILES + ' entries' };
  const seen = new Set();
  for (const [i, f] of files.entries()) {
    if (!isObj(f)) return { ok: false, why: label + ' ' + i + ' must be an object { path, hash }' };
    if (!isStr(f.path)) return { ok: false, why: label + ' ' + i + ' needs a string path' };
    if (f.path.trim().length === 0) return { ok: false, why: label + ' ' + i + ' has an empty path' };
    if (!isHash(f.hash)) return { ok: false, why: label + ' ' + i + ' needs a 64-char hex hash' };
    if (seen.has(f.path)) return { ok: false, why: label + ' has a duplicate path: ' + f.path };
    seen.add(f.path);
  }
  return { ok: true };
}

export function validWarrant(w) {
  if (!isObj(w)) return { ok: false, why: 'a warrant is an object' };
  if (!isStr(w.id)) return { ok: false, why: 'a warrant needs a string id' };
  if (w.id.trim().length === 0) return { ok: false, why: 'a warrant needs a non-empty id' };
  if (w.id.length > MAX_ID) return { ok: false, why: 'the id exceeds ' + MAX_ID + ' characters' };
  if (!isHash(w.configHash)) return { ok: false, why: 'configHash must be a 64-char hex hash (the baseline)' };
  if (!isArr(w.caps)) return { ok: false, why: 'caps must be an array of capability strings' };
  if (w.caps.length > MAX_CAPS) return { ok: false, why: 'caps exceeds ' + MAX_CAPS + ' entries' };
  const capSeen = new Set();
  for (const [i, c] of w.caps.entries()) {
    if (!isStr(c)) return { ok: false, why: 'cap ' + i + ' must be a string' };
    if (c.trim().length === 0) return { ok: false, why: 'cap ' + i + ' is empty' };
    if (capSeen.has(c)) return { ok: false, why: 'duplicate cap: ' + c };
    capSeen.add(c);
  }
  const fv = validFileList(w.files, 'files');
  if (!fv.ok) return fv;
  if (!isArr(w.invariants)) return { ok: false, why: 'invariants must be an array of { name, severity }' };
  if (w.invariants.length > MAX_INVARIANTS) return { ok: false, why: 'invariants exceeds ' + MAX_INVARIANTS + ' entries' };
  const invSeen = new Set();
  for (const [i, inv] of w.invariants.entries()) {
    if (!isObj(inv)) return { ok: false, why: 'invariant ' + i + ' must be an object { name, severity }' };
    if (!isStr(inv.name)) return { ok: false, why: 'invariant ' + i + ' needs a string name' };
    if (inv.name.trim().length === 0) return { ok: false, why: 'invariant ' + i + ' has an empty name' };
    if (!SEVERITIES.includes(inv.severity)) return { ok: false, why: 'invariant ' + i + ' severity must be warn or severe' };
    if (invSeen.has(inv.name)) return { ok: false, why: 'duplicate invariant name: ' + inv.name };
    invSeen.add(inv.name);
  }
  return { ok: true };
}

export function validObserved(o) {
  if (!isObj(o)) return { ok: false, why: 'an observation is an object' };
  if (!isStr(o.id)) return { ok: false, why: 'an observation needs a string id' };
  if (o.id.trim().length === 0) return { ok: false, why: 'an observation needs a non-empty id' };
  if (!isHash(o.configHash)) return { ok: false, why: 'observed configHash must be a 64-char hex hash' };
  if (!isArr(o.caps)) return { ok: false, why: 'observed caps must be an array of strings' };
  for (const [i, c] of o.caps.entries()) {
    if (!isStr(c)) return { ok: false, why: 'observed cap ' + i + ' must be a string' };
  }
  const fv = validFileList(o.files, 'observed files');
  if (!fv.ok) return fv;
  if (!isObj(o.invariants)) return { ok: false, why: 'observed invariants must be an object { name: boolean }' };
  for (const k of Object.keys(o.invariants)) {
    if (!isBool(o.invariants[k])) return { ok: false, why: 'observed invariant "' + k + '" must be a boolean reading' };
  }
  return { ok: true };
}

// ── verifyIntegrity: the core comparison. One severe break ⇒ BREACHED, unaveraged. ────────────────
export function verifyIntegrity(warrant, observed) {
  const wv = validWarrant(warrant);
  if (!wv.ok) return { ok: false, why: 'warrant invalid: ' + wv.why };
  const ov = validObserved(observed);
  if (!ov.ok) return { ok: false, why: 'observation invalid: ' + ov.why };
  if (warrant.id !== observed.id) return { ok: false, why: 'the observation id does not match the warrant id' };

  const broken = [];
  // config hash — the baseline. A changed config is always severe.
  if (observed.configHash !== warrant.configHash) {
    broken.push({ invariant: 'config-hash', severity: 'severe', expected: warrant.configHash, observed: observed.configHash });
  }
  // capabilities — an UNGRANTED capability appearing is severe (privilege escalation);
  // a granted capability that vanished is warn-level drift (the component narrowed itself).
  const granted = new Set(warrant.caps);
  const present = new Set(observed.caps);
  for (const c of observed.caps) {
    if (!granted.has(c)) broken.push({ invariant: 'cap-ungranted:' + c, severity: 'severe', expected: 'not present', observed: 'present' });
  }
  for (const c of warrant.caps) {
    if (!present.has(c)) broken.push({ invariant: 'cap-missing:' + c, severity: 'warn', expected: 'present', observed: 'absent' });
  }
  // files — a declared file that is missing or whose hash changed is severe; an undeclared extra file is warn.
  const obsByPath = new Map();
  for (const f of observed.files) obsByPath.set(f.path, f.hash);
  const decByPath = new Map();
  for (const f of warrant.files) decByPath.set(f.path, f.hash);
  for (const f of warrant.files) {
    if (!obsByPath.has(f.path)) broken.push({ invariant: 'file-missing:' + f.path, severity: 'severe', expected: f.hash, observed: 'absent' });
    else if (obsByPath.get(f.path) !== f.hash) broken.push({ invariant: 'file-hash:' + f.path, severity: 'severe', expected: f.hash, observed: obsByPath.get(f.path) });
  }
  for (const f of observed.files) {
    if (!decByPath.has(f.path)) broken.push({ invariant: 'file-extra:' + f.path, severity: 'warn', expected: 'not declared', observed: f.hash });
  }
  // named invariants — each must be reported true; a false or missing reading breaks it at its declared severity.
  for (const inv of warrant.invariants) {
    const reading = observed.invariants[inv.name];
    if (reading !== true) broken.push({ invariant: inv.name, severity: inv.severity, expected: true, observed: reading === undefined ? 'unreported' : reading });
  }

  let severeCount = 0;
  for (const b of broken) {
    if (b.severity === 'severe') severeCount++;
  }
  let status = 'INTACT';
  if (severeCount > 0) status = 'BREACHED';
  else if (broken.length > 0) status = 'DRIFTED';

  return {
    ok: true,
    verdict: {
      id: warrant.id,
      status,
      broken,
      brokenCount: broken.length,
      severeCount,
      checked: { caps: warrant.caps.length, files: warrant.files.length, invariants: warrant.invariants.length },
    },
  };
}

// ── monitorStatus: a pure fold over many components (the "continuous" part is the caller's loop) ───
export function monitorStatus(warrants, observations) {
  if (!isArr(warrants)) return { ok: false, why: 'warrants must be an array' };
  if (!isArr(observations)) return { ok: false, why: 'observations must be an array' };
  const obsById = new Map();
  for (const [i, o] of observations.entries()) {
    if (!isObj(o) || !isStr(o.id)) return { ok: false, why: 'observation ' + i + ' needs a string id' };
    obsById.set(o.id, o);
  }
  const warrantIds = new Set();
  const perComponent = [];
  let intact = 0, drifted = 0, breached = 0, unreported = 0, worstRank = 0;
  for (const [i, w] of warrants.entries()) {
    if (!isObj(w) || !isStr(w.id)) return { ok: false, why: 'warrant ' + i + ' needs a string id' };
    if (warrantIds.has(w.id)) return { ok: false, why: 'duplicate warrant id: ' + w.id };
    warrantIds.add(w.id);
    const o = obsById.get(w.id);
    let status, brokenCount = 0, severeCount = 0;
    if (o === undefined) {
      status = 'UNREPORTED';
      unreported++;
    } else {
      const r = verifyIntegrity(w, o);
      if (!r.ok) return { ok: false, why: 'component ' + w.id + ': ' + r.why };
      status = r.verdict.status;
      brokenCount = r.verdict.brokenCount;
      severeCount = r.verdict.severeCount;
      if (status === 'INTACT') intact++;
      else if (status === 'DRIFTED') drifted++;
      else breached++;
    }
    worstRank = Math.max(worstRank, STATUS_RANK[status]);
    perComponent.push({ id: w.id, status, brokenCount, severeCount });
  }
  // components reporting that we never declared — a rogue/undeclared component is its own signal.
  const undeclared = [];
  for (const o of observations) {
    if (!warrantIds.has(o.id)) undeclared.push(o.id);
  }
  const worst = Object.keys(STATUS_RANK).find((k) => STATUS_RANK[k] === worstRank) || 'INTACT';
  const problems = breached + drifted + unreported + undeclared.length;
  const allClear = problems === 0;
  return {
    ok: true,
    report: {
      total: warrants.length,
      intact, drifted, breached, unreported,
      undeclared,
      worst,
      allClear,
      perComponent,
    },
  };
}

// ── the anomaly log: hash-chained, so the record itself is tamper-evident (Kar's LogAnomaly) ───────
export function appendAnomaly(chain, entry) {
  if (!isArr(chain)) return { ok: false, why: 'the chain must be an array (it may be empty)' };
  if (!isObj(entry)) return { ok: false, why: 'an anomaly entry is an object' };
  if (!isStr(entry.componentID) || entry.componentID.trim().length === 0) return { ok: false, why: 'an anomaly needs a non-empty componentID' };
  if (!isStr(entry.description)) return { ok: false, why: 'an anomaly needs a description string' };
  if (entry.description.length > MAX_DESC) return { ok: false, why: 'the description exceeds ' + MAX_DESC + ' characters' };
  if (!STATUS.includes(entry.status)) return { ok: false, why: 'the status must be one of ' + STATUS.join('/') };
  if (!isStr(entry.ts) || entry.ts.trim().length === 0) return { ok: false, why: 'an anomaly needs a ts timestamp string' };
  const prevHash = chain.length === 0 ? GENESIS : chain[chain.length - 1].hash;
  if (!isHash(prevHash)) return { ok: false, why: 'the previous entry has no valid hash — the chain is malformed' };
  const body = {
    seq: chain.length,
    componentID: entry.componentID,
    description: entry.description,
    status: entry.status,
    ts: entry.ts,
    prevHash,
  };
  const h = sha256(canon(body));
  if (!h.ok) return { ok: false, why: h.why };
  return { ok: true, chain: [...chain, { ...body, hash: h.hash }] };
}

export function verifyChain(chain) {
  if (!isArr(chain)) return { ok: false, why: 'the chain must be an array' };
  for (let i = 0; i < chain.length; i++) {
    const e = chain[i];
    if (!isObj(e) || !isStr(e.hash)) return { ok: true, valid: false, brokenAt: i, why: 'entry ' + i + ' is malformed' };
    if (e.seq !== i) return { ok: true, valid: false, brokenAt: i, why: 'entry ' + i + ' is out of sequence' };
    const expectedPrev = i === 0 ? GENESIS : chain[i - 1].hash;
    if (e.prevHash !== expectedPrev) return { ok: true, valid: false, brokenAt: i, why: 'entry ' + i + ' does not link to the previous entry' };
    const body = { seq: e.seq, componentID: e.componentID, description: e.description, status: e.status, ts: e.ts, prevHash: e.prevHash };
    const h = sha256(canon(body));
    if (!h.ok) return { ok: false, why: h.why };
    if (h.hash !== e.hash) return { ok: true, valid: false, brokenAt: i, why: 'entry ' + i + ' was changed after it was logged' };
  }
  return { ok: true, valid: true, length: chain.length };
}

// ── the receipt: a portable verdict any third party can RE-RUN (the wedge) ─────────────────────────
export function wardenReceipt(input) {
  if (!isObj(input)) return { ok: false, why: 'wardenReceipt takes an object { warrant, observed, createdAt }' };
  const { warrant, observed, createdAt } = input;
  if (!isStr(createdAt) || createdAt.trim().length === 0) return { ok: false, why: 'the receipt needs a createdAt timestamp' };
  const r = verifyIntegrity(warrant, observed);
  if (!r.ok) return { ok: false, why: r.why };
  const wh = sha256(canon(warrant));
  if (!wh.ok) return { ok: false, why: wh.why };
  const oh = sha256(canon(observed));
  if (!oh.ok) return { ok: false, why: oh.why };
  const body = {
    v: 1,
    kind: 'kar-warden-receipt',
    id: r.verdict.id,
    warrantHash: wh.hash,
    observedHash: oh.hash,
    warrant,
    observed,
    status: r.verdict.status,
    brokenCount: r.verdict.brokenCount,
    severeCount: r.verdict.severeCount,
    createdAt,
    scope: 'A Warden verdict is a measurement against a declared warrant, re-runnable by anyone: verify the receipt, then re-run verifyIntegrity on its warrant + observed and confirm the verdict matches. No LLM judge.',
  };
  const h = sha256(canon(body));
  if (!h.ok) return { ok: false, why: h.why };
  return { ok: true, receipt: { ...body, hash: h.hash } };
}

/** verifyWardenReceipt(r) — the facts match their own hash AND re-running the check reproduces the verdict.
 *  Catches a receipt whose hash was recomputed to claim INTACT while its inputs actually verify BREACHED. */
export function verifyWardenReceipt(r) {
  if (!isObj(r) || r.kind !== 'kar-warden-receipt' || !isStr(r.hash)) return { ok: false, why: 'not a kar-warden receipt' };
  const body = { ...r };
  delete body.hash;
  delete body.signature;
  const h = sha256(canon(body));
  if (!h.ok) return { ok: false, why: h.why };
  if (h.hash !== r.hash) return { ok: true, valid: false, why: 'the receipt does not match its own fingerprint — it was changed after it was issued' };
  const re = verifyIntegrity(r.warrant, r.observed);
  if (!re.ok) return { ok: true, valid: false, why: 're-run failed: ' + re.why };
  if (re.verdict.status !== r.status) return { ok: true, valid: false, why: 'the recorded status does not match a fresh re-run of the check' };
  if (re.verdict.brokenCount !== r.brokenCount) return { ok: true, valid: false, why: 'the recorded broken count does not match a fresh re-run' };
  if (re.verdict.severeCount !== r.severeCount) return { ok: true, valid: false, why: 'the recorded severe count does not match a fresh re-run' };
  return { ok: true, valid: true, status: r.status, why: 'receipt intact and re-run reproduces the verdict' };
}

/** wardenSignable(receipt) — the EXACT canonical bytes an Ed25519 signature covers: the receipt minus
 *  its signature. Used to sign AND to verify, so both sides canonicalise identically. */
export function wardenSignable(receipt) {
  if (!isObj(receipt) || receipt.kind !== 'kar-warden-receipt' || !isStr(receipt.hash)) return { ok: false, why: 'not a kar-warden receipt' };
  const body = { ...receipt };
  delete body.signature;
  return { ok: true, payload: canon(body) };
}
