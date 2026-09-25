import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  sha256, canon, validWarrant, validObserved, verifyIntegrity, monitorStatus,
  appendAnomaly, verifyChain, wardenReceipt, verifyWardenReceipt, wardenSignable,
  STATUS, SEVERITIES, STATUS_RANK, GENESIS, MAX_ID, MAX_DESC, MAX_CAPS, MAX_FILES, MAX_INVARIANTS,
} from './kernel.mjs';

const H = (s) => sha256(s).hash;                       // a real 64-hex hash from a string
const CFG = H('baseline-config-v1');
const FA = H('file-a'), FB = H('file-b');

// a clean, matching pair
function warrant(over = {}) {
  return {
    id: 'agent-alpha',
    configHash: CFG,
    caps: ['read:memory', 'net:none'],
    files: [{ path: 'policy.json', hash: FA }, { path: 'weights.bin', hash: FB }],
    invariants: [{ name: 'sandbox-on', severity: 'severe' }, { name: 'telemetry-off', severity: 'warn' }],
    ...over,
  };
}
function observed(over = {}) {
  return {
    id: 'agent-alpha',
    configHash: CFG,
    caps: ['read:memory', 'net:none'],
    files: [{ path: 'policy.json', hash: FA }, { path: 'weights.bin', hash: FB }],
    invariants: { 'sandbox-on': true, 'telemetry-off': true },
    ...over,
  };
}

// ── crypto sanity (reused, proven — but the gate still runs on it here) ────────────────────────────
test('sha256 matches the published FIPS-180 known answers (pins the algorithm, not just determinism)', () => {
  assert.equal(sha256('').hash, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(sha256('abc').hash, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(sha256('The quick brown fox jumps over the lazy dog').hash, 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592');
  assert.equal(sha256(5).ok, false);
});
test('canon sorts keys so equal objects canonicalise identically', () => {
  assert.equal(canon({ b: 1, a: 2 }), canon({ a: 2, b: 1 }));
  assert.notEqual(canon({ a: 1 }), canon({ a: 2 }));
});

// ── validWarrant ─────────────────────────────────────────────────────────────────────────────────
test('validWarrant accepts a clean warrant', () => {
  assert.equal(validWarrant(warrant()).ok, true);
});
test('validWarrant refuses every malformed shape', () => {
  assert.equal(validWarrant(null).ok, false);
  assert.equal(validWarrant([]).ok, false);
  assert.equal(validWarrant(warrant({ id: 123 })).ok, false);
  assert.equal(validWarrant(warrant({ id: '   ' })).ok, false);
  assert.equal(validWarrant(warrant({ id: 'x'.repeat(MAX_ID + 1) })).ok, false);
  assert.equal(validWarrant(warrant({ configHash: 'short' })).ok, false);
  assert.equal(validWarrant(warrant({ configHash: 'Z'.repeat(64) })).ok, false); // non-hex
  assert.equal(validWarrant(warrant({ caps: 'read' })).ok, false);
  assert.equal(validWarrant(warrant({ caps: [123] })).ok, false);
  assert.equal(validWarrant(warrant({ caps: [''] })).ok, false);
  assert.equal(validWarrant(warrant({ caps: ['a', 'a'] })).ok, false);
  assert.equal(validWarrant(warrant({ files: 'x' })).ok, false);
  assert.equal(validWarrant(warrant({ files: [{ path: '', hash: FA }] })).ok, false);
  assert.equal(validWarrant(warrant({ files: [{ path: 'a', hash: 'bad' }] })).ok, false);
  assert.equal(validWarrant(warrant({ files: [{ path: 'a', hash: FA }, { path: 'a', hash: FB }] })).ok, false);
  assert.equal(validWarrant(warrant({ invariants: 'x' })).ok, false);
  assert.equal(validWarrant(warrant({ invariants: [{ name: '', severity: 'warn' }] })).ok, false);
  assert.equal(validWarrant(warrant({ invariants: [{ name: 'x', severity: 'critical' }] })).ok, false);
  assert.equal(validWarrant(warrant({ invariants: [{ name: 'x', severity: 'warn' }, { name: 'x', severity: 'severe' }] })).ok, false);
});
test('validWarrant accepts empty caps/files/invariants (a minimal declaration is legal)', () => {
  assert.equal(validWarrant(warrant({ caps: [], files: [], invariants: [] })).ok, true);
});
test('validWarrant accepts inputs EXACTLY at the limits (boundary is > not >=)', () => {
  assert.equal(validWarrant(warrant({ id: 'x'.repeat(MAX_ID) })).ok, true);
  assert.equal(validWarrant(warrant({ caps: Array.from({ length: MAX_CAPS }, (_, i) => 'c' + i) })).ok, true);
  assert.equal(validWarrant(warrant({ files: Array.from({ length: MAX_FILES }, (_, i) => ({ path: 'f' + i, hash: H('f' + i) })) })).ok, true);
  assert.equal(validWarrant(warrant({ invariants: Array.from({ length: MAX_INVARIANTS }, (_, i) => ({ name: 'i' + i, severity: 'warn' })) })).ok, true);
});
test('appendAnomaly accepts a description EXACTLY at MAX_DESC (boundary is > not >=)', () => {
  const r = appendAnomaly([], { componentID: 'a', description: 'x'.repeat(MAX_DESC), status: 'INTACT', ts: 't' });
  assert.equal(r.ok, true);
});

// ── validObserved ────────────────────────────────────────────────────────────────────────────────
test('validObserved accepts a clean observation and refuses malformed ones', () => {
  assert.equal(validObserved(observed()).ok, true);
  assert.equal(validObserved(null).ok, false);
  assert.equal(validObserved(observed({ id: '' })).ok, false);
  assert.equal(validObserved(observed({ configHash: 'nope' })).ok, false);
  assert.equal(validObserved(observed({ caps: 'x' })).ok, false);
  assert.equal(validObserved(observed({ caps: [1] })).ok, false);
  assert.equal(validObserved(observed({ invariants: [] })).ok, false); // must be an object map
  assert.equal(validObserved(observed({ invariants: { x: 'yes' } })).ok, false); // must be boolean
});

// ── verifyIntegrity ──────────────────────────────────────────────────────────────────────────────
test('a matching pair is INTACT with zero broken', () => {
  const r = verifyIntegrity(warrant(), observed());
  assert.equal(r.ok, true);
  assert.equal(r.verdict.status, 'INTACT');
  assert.equal(r.verdict.brokenCount, 0);
  assert.equal(r.verdict.severeCount, 0);
  assert.deepEqual(r.verdict.checked, { caps: 2, files: 2, invariants: 2 });
});
test('a changed config hash is a severe BREACH', () => {
  const r = verifyIntegrity(warrant(), observed({ configHash: H('tampered') }));
  assert.equal(r.verdict.status, 'BREACHED');
  assert.equal(r.verdict.severeCount, 1);
  assert.ok(r.verdict.broken.some((b) => b.invariant === 'config-hash' && b.severity === 'severe'));
});
test('an UNGRANTED capability is a severe BREACH (privilege escalation)', () => {
  const r = verifyIntegrity(warrant(), observed({ caps: ['read:memory', 'net:none', 'net:all'] }));
  assert.equal(r.verdict.status, 'BREACHED');
  assert.ok(r.verdict.broken.some((b) => b.invariant === 'cap-ungranted:net:all' && b.severity === 'severe'));
});
test('a MISSING granted capability is warn-level DRIFT, not a breach', () => {
  const r = verifyIntegrity(warrant(), observed({ caps: ['read:memory'] }));
  assert.equal(r.verdict.status, 'DRIFTED');
  assert.equal(r.verdict.severeCount, 0);
  assert.ok(r.verdict.broken.some((b) => b.invariant === 'cap-missing:net:none' && b.severity === 'warn'));
});
test('a missing declared file is a severe BREACH', () => {
  const r = verifyIntegrity(warrant(), observed({ files: [{ path: 'policy.json', hash: FA }] }));
  assert.equal(r.verdict.status, 'BREACHED');
  assert.ok(r.verdict.broken.some((b) => b.invariant === 'file-missing:weights.bin' && b.severity === 'severe'));
});
test('a changed file hash is a severe BREACH', () => {
  const r = verifyIntegrity(warrant(), observed({ files: [{ path: 'policy.json', hash: FA }, { path: 'weights.bin', hash: H('swapped') }] }));
  assert.equal(r.verdict.status, 'BREACHED');
  assert.ok(r.verdict.broken.some((b) => b.invariant === 'file-hash:weights.bin' && b.severity === 'severe'));
});
test('an undeclared extra file is warn-level DRIFT', () => {
  const r = verifyIntegrity(warrant(), observed({ files: [{ path: 'policy.json', hash: FA }, { path: 'weights.bin', hash: FB }, { path: 'extra.log', hash: H('extra') }] }));
  assert.equal(r.verdict.status, 'DRIFTED');
  assert.equal(r.verdict.severeCount, 0);
  assert.ok(r.verdict.broken.some((b) => b.invariant === 'file-extra:extra.log' && b.severity === 'warn'));
});
test('a false SEVERE invariant is a BREACH; a false WARN invariant is DRIFT', () => {
  const sev = verifyIntegrity(warrant(), observed({ invariants: { 'sandbox-on': false, 'telemetry-off': true } }));
  assert.equal(sev.verdict.status, 'BREACHED');
  assert.ok(sev.verdict.broken.some((b) => b.invariant === 'sandbox-on' && b.severity === 'severe'));
  const warn = verifyIntegrity(warrant(), observed({ invariants: { 'sandbox-on': true, 'telemetry-off': false } }));
  assert.equal(warn.verdict.status, 'DRIFTED');
});
test('an UNREPORTED invariant breaks at its declared severity, marked unreported', () => {
  const r = verifyIntegrity(warrant(), observed({ invariants: { 'telemetry-off': true } }));
  assert.equal(r.verdict.status, 'BREACHED'); // sandbox-on is severe and unreported
  const b = r.verdict.broken.find((x) => x.invariant === 'sandbox-on');
  assert.equal(b.observed, 'unreported');
  assert.equal(b.severity, 'severe');
});
test('a true invariant reading does NOT break (=== true, not merely truthy)', () => {
  const r = verifyIntegrity(warrant({ invariants: [{ name: 'x', severity: 'severe' }] }), observed({ invariants: { x: true } }));
  assert.equal(r.verdict.status, 'INTACT');
});
test('ONE severe break cannot be averaged away by many passes', () => {
  // lots of clean invariants + one severe fail ⇒ still BREACHED
  const invs = Array.from({ length: 8 }, (_, i) => ({ name: 'ok' + i, severity: 'warn' }));
  invs.push({ name: 'kill', severity: 'severe' });
  const reads = {}; invs.forEach((x) => { reads[x.name] = true; }); reads['kill'] = false;
  const r = verifyIntegrity(warrant({ invariants: invs }), observed({ invariants: reads }));
  assert.equal(r.verdict.status, 'BREACHED');
  assert.equal(r.verdict.severeCount, 1);
  assert.equal(r.verdict.brokenCount, 1);
});
test('an id mismatch is refused (cannot verify a component against another warrant)', () => {
  const r = verifyIntegrity(warrant(), observed({ id: 'agent-beta' }));
  assert.equal(r.ok, false);
});
test('verifyIntegrity refuses invalid warrant or observation', () => {
  assert.equal(verifyIntegrity({}, observed()).ok, false);
  assert.equal(verifyIntegrity(warrant(), {}).ok, false);
});

// ── monitorStatus ────────────────────────────────────────────────────────────────────────────────
test('monitorStatus folds mixed components into a correct report', () => {
  const wa = warrant({ id: 'a' });
  const wb = warrant({ id: 'b' });
  const wc = warrant({ id: 'c' });
  const wd = warrant({ id: 'd' }); // will be UNREPORTED
  const oa = observed({ id: 'a' }); // intact
  const ob = observed({ id: 'b', caps: ['read:memory'] }); // drifted (missing cap)
  const oc = observed({ id: 'c', configHash: H('x') }); // breached
  const oe = observed({ id: 'rogue' }); // undeclared
  const r = monitorStatus([wa, wb, wc, wd], [oa, ob, oc, oe]);
  assert.equal(r.ok, true);
  assert.equal(r.report.total, 4);
  assert.equal(r.report.intact, 1);
  assert.equal(r.report.drifted, 1);
  assert.equal(r.report.breached, 1);
  assert.equal(r.report.unreported, 1);
  assert.deepEqual(r.report.undeclared, ['rogue']);
  assert.equal(r.report.worst, 'BREACHED');
  assert.equal(r.report.allClear, false);
});
test('monitorStatus counts drifted and breached distinctly (asymmetric counts catch a swap)', () => {
  const r = monitorStatus(
    [warrant({ id: 'a' }), warrant({ id: 'b' }), warrant({ id: 'c' })],
    [
      observed({ id: 'a', caps: ['read:memory'] }),          // drifted
      observed({ id: 'b', caps: ['read:memory'] }),          // drifted
      observed({ id: 'c', configHash: H('x') }),             // breached
    ],
  );
  assert.equal(r.report.drifted, 2);
  assert.equal(r.report.breached, 1);
  assert.equal(r.report.intact, 0);
});
test('monitorStatus is allClear only when everything is intact and nothing undeclared', () => {
  const r = monitorStatus([warrant({ id: 'a' })], [observed({ id: 'a' })]);
  assert.equal(r.report.allClear, true);
  assert.equal(r.report.worst, 'INTACT');
});
test('each single problem class alone breaks allClear (guards are independent)', () => {
  const breach = monitorStatus([warrant({ id: 'a' })], [observed({ id: 'a', configHash: H('x') })]);
  assert.equal(breach.report.allClear, false);
  const drift = monitorStatus([warrant({ id: 'a' })], [observed({ id: 'a', caps: ['read:memory'] })]);
  assert.equal(drift.report.allClear, false);
  const unrep = monitorStatus([warrant({ id: 'a' })], []);
  assert.equal(unrep.report.allClear, false);
  const undecl = monitorStatus([warrant({ id: 'a' })], [observed({ id: 'a' }), observed({ id: 'ghost' })]);
  assert.equal(undecl.report.allClear, false);
});
test('worst is the MAX severity regardless of order (breach before intact still worst=breach)', () => {
  const r = monitorStatus(
    [warrant({ id: 'a' }), warrant({ id: 'b' })],
    [observed({ id: 'a', configHash: H('x') }), observed({ id: 'b' })], // breach first, intact second
  );
  assert.equal(r.report.worst, 'BREACHED');
});
test('UNREPORTED ranks worse than DRIFTED but better than BREACHED', () => {
  assert.equal(STATUS_RANK.INTACT, 0);
  assert.equal(STATUS_RANK.DRIFTED, 1);
  assert.equal(STATUS_RANK.UNREPORTED, 2);
  assert.equal(STATUS_RANK.BREACHED, 3);
  const r = monitorStatus([warrant({ id: 'a' }), warrant({ id: 'b' })], [observed({ id: 'a', caps: ['read:memory'] })]);
  // a: drifted(1), b: unreported(2) ⇒ worst UNREPORTED
  assert.equal(r.report.worst, 'UNREPORTED');
});
test('monitorStatus refuses non-arrays and duplicate warrant ids', () => {
  assert.equal(monitorStatus('x', []).ok, false);
  assert.equal(monitorStatus([], 'x').ok, false);
  assert.equal(monitorStatus([warrant({ id: 'a' }), warrant({ id: 'a' })], []).ok, false);
  assert.equal(monitorStatus([{ noId: 1 }], []).ok, false);
  assert.equal(monitorStatus([], [{ noId: 1 }]).ok, false);
});

// ── the anomaly log ──────────────────────────────────────────────────────────────────────────────
test('appendAnomaly starts from GENESIS and chains each entry to the last', () => {
  const e1 = appendAnomaly([], { componentID: 'a', description: 'config drift', status: 'DRIFTED', ts: '2026-09-25T00:00:00Z' });
  assert.equal(e1.ok, true);
  assert.equal(e1.chain[0].seq, 0);
  assert.equal(e1.chain[0].prevHash, GENESIS);
  const e2 = appendAnomaly(e1.chain, { componentID: 'a', description: 'breach', status: 'BREACHED', ts: '2026-09-25T00:01:00Z' });
  assert.equal(e2.chain[1].seq, 1);
  assert.equal(e2.chain[1].prevHash, e1.chain[0].hash);
});
test('appendAnomaly refuses malformed entries', () => {
  assert.equal(appendAnomaly('x', { componentID: 'a', description: 'd', status: 'INTACT', ts: 't' }).ok, false);
  assert.equal(appendAnomaly([], { componentID: '', description: 'd', status: 'INTACT', ts: 't' }).ok, false);
  assert.equal(appendAnomaly([], { componentID: 'a', description: 5, status: 'INTACT', ts: 't' }).ok, false);
  assert.equal(appendAnomaly([], { componentID: 'a', description: 'x'.repeat(MAX_DESC + 1), status: 'INTACT', ts: 't' }).ok, false);
  assert.equal(appendAnomaly([], { componentID: 'a', description: 'd', status: 'NOPE', ts: 't' }).ok, false);
  assert.equal(appendAnomaly([], { componentID: 'a', description: 'd', status: 'INTACT', ts: '' }).ok, false);
});
test('verifyChain accepts a genuine chain and an empty one', () => {
  let chain = [];
  for (let i = 0; i < 4; i++) chain = appendAnomaly(chain, { componentID: 'a', description: 'e' + i, status: 'DRIFTED', ts: 't' + i }).chain;
  assert.equal(verifyChain(chain).valid, true);
  assert.equal(verifyChain(chain).length, 4);
  assert.equal(verifyChain([]).valid, true);
  assert.equal(verifyChain([]).length, 0);
});
test('verifyChain catches a tampered entry and reports where', () => {
  let chain = [];
  for (let i = 0; i < 3; i++) chain = appendAnomaly(chain, { componentID: 'a', description: 'e' + i, status: 'DRIFTED', ts: 't' + i }).chain;
  const tampered = chain.map((e, i) => (i === 1 ? { ...e, description: 'edited' } : e));
  const v = verifyChain(tampered);
  assert.equal(v.valid, false);
  assert.equal(v.brokenAt, 1);
});
test('verifyChain stays TOTAL on malformed entries (null / non-object / missing hash), never throws', () => {
  assert.equal(verifyChain([null]).valid, false);        // would throw under a && mutation of the guard
  assert.equal(verifyChain(['x']).valid, false);
  const noHash = { seq: 0, componentID: 'a', description: 'd', status: 'INTACT', ts: 't', prevHash: GENESIS };
  const v = verifyChain([noHash]);
  assert.equal(v.valid, false);
  assert.equal(v.brokenAt, 0);
  assert.match(v.why, /malformed/); // the malformed-guard path, distinct from the hash-mismatch path
});
test('verifyChain catches a re-linked / out-of-sequence entry', () => {
  let chain = [];
  for (let i = 0; i < 3; i++) chain = appendAnomaly(chain, { componentID: 'a', description: 'e' + i, status: 'DRIFTED', ts: 't' + i }).chain;
  const dropped = [chain[0], chain[2]]; // entry 1 removed ⇒ seq + link both wrong at index 1
  assert.equal(verifyChain(dropped).valid, false);
  const badseq = chain.map((e, i) => (i === 2 ? { ...e, seq: 9 } : e));
  assert.equal(verifyChain(badseq).valid, false);
});

// ── the re-runnable receipt (the wedge) ───────────────────────────────────────────────────────────
test('wardenReceipt binds inputs + verdict and verifies genuine', () => {
  const r = wardenReceipt({ warrant: warrant(), observed: observed(), createdAt: '2026-09-25T00:00:00Z' });
  assert.equal(r.ok, true);
  assert.equal(r.receipt.status, 'INTACT');
  assert.equal(r.receipt.kind, 'kar-warden-receipt');
  assert.match(r.receipt.hash, /^[0-9a-f]{64}$/);
  const v = verifyWardenReceipt(r.receipt);
  assert.equal(v.valid, true);
  assert.equal(v.status, 'INTACT');
});
test('wardenReceipt refuses a missing or non-string createdAt (guard is total)', () => {
  assert.equal(wardenReceipt({ warrant: warrant(), observed: observed(), createdAt: '' }).ok, false);
  assert.equal(wardenReceipt({ warrant: warrant(), observed: observed(), createdAt: 5 }).ok, false);
  assert.equal(wardenReceipt({ warrant: warrant(), observed: observed() }).ok, false);
});
test('a receipt for a breach records BREACHED and verifies', () => {
  const r = wardenReceipt({ warrant: warrant(), observed: observed({ configHash: H('x') }), createdAt: 't' });
  assert.equal(r.receipt.status, 'BREACHED');
  assert.equal(verifyWardenReceipt(r.receipt).valid, true);
});
test('a plain field edit is caught by the hash', () => {
  const r = wardenReceipt({ warrant: warrant(), observed: observed(), createdAt: 't' }).receipt;
  const edited = { ...r, status: 'INTACT', createdAt: 'later' };
  assert.equal(verifyWardenReceipt(edited).valid, false);
});
test('THE WEDGE: forging the verdict to INTACT and re-hashing is still caught by the re-run', () => {
  // build a genuine BREACHED receipt, then lie: claim INTACT and RECOMPUTE the hash so the hash check passes.
  const r = wardenReceipt({ warrant: warrant(), observed: observed({ configHash: H('x') }), createdAt: 't' }).receipt;
  const forgedBody = { ...r, status: 'INTACT', severeCount: 0, brokenCount: 0 };
  delete forgedBody.hash;
  const rehashed = { ...forgedBody, hash: sha256(canon(forgedBody)).hash };
  const v = verifyWardenReceipt(rehashed);
  assert.equal(v.valid, false); // re-running verifyIntegrity on the receipt's own inputs reproduces BREACHED
  assert.match(v.why, /re-run/);
});
test('verifyWardenReceipt refuses non-receipts (guard is total across all clauses)', () => {
  assert.equal(verifyWardenReceipt({}).ok, false);
  assert.equal(verifyWardenReceipt(null).ok, false);                              // would throw under a && mutation
  assert.equal(verifyWardenReceipt({ kind: 'kar-warden-receipt' }).ok, false);   // no hash
  assert.equal(verifyWardenReceipt({ kind: 'wrong', hash: 'abcd' }).ok, false);  // wrong kind but has a hash → must still refuse
});
test('wardenSignable strips only the signature and is deterministic', () => {
  const r = wardenReceipt({ warrant: warrant(), observed: observed(), createdAt: 't' }).receipt;
  const signed = { ...r, signature: { alg: 'Ed25519', pub: 'ab', sig: 'cd' } };
  const a = wardenSignable(r);
  const b = wardenSignable(signed);
  assert.equal(a.ok, true);
  assert.equal(a.payload, b.payload); // signature removed ⇒ identical bytes to sign and to verify
  assert.equal(wardenSignable({}).ok, false);
  assert.equal(wardenSignable(null).ok, false);                             // would throw under a && mutation
  assert.equal(wardenSignable({ kind: 'wrong', hash: 'abcd' }).ok, false);  // wrong kind but has a hash → must still refuse
});

// ── exported vocab is what the page and callers rely on ────────────────────────────────────────────
test('exported vocab is stable', () => {
  assert.deepEqual(STATUS, ['INTACT', 'DRIFTED', 'BREACHED', 'UNREPORTED']);
  assert.deepEqual(SEVERITIES, ['warn', 'severe']);
  assert.equal(GENESIS, '0'.repeat(64));
});
