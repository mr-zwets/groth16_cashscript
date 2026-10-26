// Build the BLS12-381 native bch-2026 verifier (4 P2SH32 inputs, one shared program) deterministically, and check it.
//   node build.mjs      -> writes redeem.hex (R, the identical redeem of every input), program.hex (the blob) and build.json
// Every baked constant is recomputed and asserted against noble when math.mjs loads; the degree bound, the quotient cap and
// floor are derived from the schedule and the chunking in protocol.mjs (asserted); the build is run twice and must be
// byte-identical; fixture `committed` must be accepted by every input in consensus and standard mode, and a tampered state
// must be rejected.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {BITS, NE, ADD_EVENTS, FACTS, FIXTURES} from './math.mjs';
import {NQ_MAX, N_MIN, BOUNDS, NSTATES, K_IDS, LAYOUT, CHUNK_END, chunkDegP, degDBound, ROLES, CUTS, PLACE, TAG, K_HASH, pushesOf, prove, txPushes} from './protocol.mjs';
import {buildAll, FLAGS} from './script.mjs';
import {p2sh32, txOf, unlockingsFor, evalTx, verifyTx, txSize} from './vm.mjs';

const sha = (b) => createHash('sha256').update(b).digest('hex');
// ---- degree bound (adversarial: every nibble 15) and the n_q cap, from the schedule ----
const worstD = LAYOUT.map((_, k) => degDBound(k, () => 8)); const dDmax = Math.max(...worstD); const dD = dDmax % 2 ? dDmax : dDmax - 1;
assert.equal(NQ_MAX, (dD - 12 + 1) / 2, 'NQ_MAX from the schedule');
const degBound = {chunkDegPmax: Math.max(...LAYOUT.map((_, k) => chunkDegP(k, () => 8))), degDmax: dD, degQmax: dD - 12, NQ_MAX, N_MIN, worstChunk: worstD.indexOf(dDmax),
  szDegree: Math.max(dD, 2 * NQ_MAX - 1 + 12), batchDegreeInRho: K_IDS - 1};
degBound.epsilonLog2 = Math.log2((degBound.szDegree + degBound.batchDegreeInRho) / 2 ** 256);
// ---- build twice: byte-identical ----
const t0 = Date.now();
const b1 = buildAll(), b2 = buildAll();
assert.deepEqual(Buffer.from(b1.R), Buffer.from(b2.R), 'deterministic R'); assert.deepEqual(Buffer.from(b1.blob), Buffer.from(b2.blob), 'deterministic program');
const R = Buffer.from(b1.R), blob = Buffer.from(b1.blob), locking = Buffer.from(p2sh32(R));
// ---- smoke: fixture `committed` accepted (both modes, every input); a tampered state rejected ----
const w = prove(FIXTURES.committed); const un = unlockingsFor(txPushes(w, blob), R); const ctx = txOf(un, un.map(() => locking));
const runs = {};
for (const mode of ['consensus', 'standard']) { assert.equal(verifyTx(ctx, mode), true, mode); runs[mode] = evalTx(ctx, mode).map((x) => ({op: x.op, budget: x.budget, margin: +(1 - x.op / x.budget).toFixed(4)})); }
{ const ps = txPushes(w, blob); const g = Buffer.from(ps[2][1]); g[100] ^= 1; ps[2][1] = g; const c2 = txOf(unlockingsFor(ps, R), un.map(() => locking)); assert.notEqual(verifyTx(c2, 'standard'), true, 'tampered state accepted'); }
const out = {
  inputs: 4, R: {bytes: R.length, hex: R.toString('hex'), sha256: sha(R)}, locking: {hex: locking.toString('hex'), sha256: sha(locking)},
  program: {bytes: blob.length, sha256: sha(blob), parts: b1.parts}, tag: TAG.toString('hex'),
  layout: {cuts: CUTS, place: PLACE, roles: ROLES.map((ro) => ({chunks: [ro.c0, ro.c1], events: [ro.e0, ro.e1], states: ro.states.length, slopes: ro.nslopes, region: ro.regionSize, claims: ro.claimSize, kBlock: ro.kSize})),
    pushes: [0, 1, 2, 3].map((h) => pushesOf(h)), kHash: K_HASH.map((h) => h.toString('hex'))},
  committed: {nq: w.nq, unlocking: un.map((u) => u.length), sumUnlocking: un.reduce((s, u) => s + u.length, 0), txBytes: txSize(ctx), score: un.reduce((s, u) => s + u.length, 0) + 4 * (35 + 43) + 20, ...runs},
  functions: b1.info.funcs, roleBodies: b1.info.roles, sections: b1.info.sections,
  schedule: {events: NE, bits: BITS.join(''), additions: ADD_EVENTS, flags: FLAGS.join(','), states: NSTATES, bounds: BOUNDS, chunkEnds: CHUNK_END, identities: K_IDS}, degreeBound: degBound, facts: FACTS,
};
writeFileSync(new URL('./redeem.hex', import.meta.url), R.toString('hex') + '\n');
writeFileSync(new URL('./program.hex', import.meta.url), blob.toString('hex') + '\n');
writeFileSync(new URL('./build.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
console.log(`R ${R.length} B sha256 ${out.R.sha256}; program ${blob.length} B sha256 ${out.program.sha256} (${((Date.now() - t0) / 1000).toFixed(0)} s)`);
console.log(`committed: unlocking ${out.committed.unlocking.join(' + ')} = ${out.committed.sumUnlocking} B, score ${out.committed.score}; std margins ${runs.standard.map((x) => (100 * x.margin).toFixed(2) + '%').join(' ')}`);
console.log(`degree bound: max deg P ${degBound.chunkDegPmax}, deg D ${dD}, n_q in [${N_MIN}, ${NQ_MAX}]; epsilon 2^${degBound.epsilonLog2.toFixed(1)}`);
