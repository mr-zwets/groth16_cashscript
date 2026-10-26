// Build the BLS12-381 SI-GLS redeem (bch-spec, one P2SH32 input), deterministically, and check it.
//   node build.mjs            -> writes redeem.hex and build.json, prints the sha256
// Every baked constant is recomputed and asserted against noble when math.mjs loads; the degree bound and the
// quotient cap are derived from the schedule and the chunking here; the build is run twice and must be
// byte-identical; fixture `committed` must be accepted in consensus and standard mode, and a tampered state rejected.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {BITS, NE, ADD_EVENTS, FACTS, FIXTURES} from './math.mjs';
import {NQ_MAX, BOUNDS, NSTATES, K_IDS, LAYOUT, CHUNK_END, chunkDegP, degDBound, WS_SIZE, WS_LAYOUT, NSLOPES, E_A, TAG, prove} from './protocol.mjs';
import {buildRedeem, FLAGS} from './script.mjs';
import {p2sh32, unlockingFor, spend} from './vm.mjs';

const sha = (b) => createHash('sha256').update(b).digest('hex');
// ---- degree bound (adversarial: every nibble 15) and the n_q cap, from the schedule ----
const worstP = LAYOUT.map((_, k) => chunkDegP(k, () => 8)), worstD = LAYOUT.map((_, k) => degDBound(k, () => 8));
const dDmax = Math.max(...worstD); const dD = dDmax % 2 ? dDmax : dDmax - 1;
assert.equal(NQ_MAX, (dD - 12 + 1) / 2, 'NQ_MAX from the schedule');
const degBound = {chunkDegPmax: Math.max(...worstP), degDmax: dD, degQmax: dD - 12, NQ_MAX, worstChunk: worstD.indexOf(dDmax),
  szDegree: Math.max(dD, 2 * NQ_MAX - 1 + 12), batchDegreeInRho: K_IDS - 1, epsilonLog2: Math.log2((Math.max(dD, 2 * NQ_MAX - 1 + 12) + K_IDS - 1) / 2 ** 256)};
// ---- build twice: byte-identical ----
const t0 = Date.now();
const b1 = buildRedeem(); const b2 = buildRedeem();
assert.deepEqual(Buffer.from(b1.redeem), Buffer.from(b2.redeem), 'deterministic build');
const redeem = Buffer.from(b1.redeem), locking = Buffer.from(p2sh32(redeem));
// ---- smoke: fixture `committed` accepted (both modes); a tampered state rejected ----
const w = prove(FIXTURES.committed); const u = unlockingFor(w.WS, w.WQ, redeem);
const runs = Object.fromEntries(['consensus', 'standard'].map((m) => { const r = spend(locking, u, m); assert.ok(r.accepted, m + ': ' + r.error); return [m, {opCost: r.opCost, budget: r.budget}]; }));
{ const bad = Buffer.from(w.WS); bad[WS_LAYOUT.states + 100] ^= 1; assert.ok(!spend(locking, unlockingFor(bad, w.WQ, redeem)).accepted, 'tampered state accepted'); }
const out = {
  redeemBytes: redeem.length, redeemSha256: sha(redeem), lockingHex: locking.toString('hex'), lockingSha256: sha(locking),
  tag: TAG.toString('hex'), E_A, witness: {WS: WS_SIZE, slopes: NSLOPES, WQ_committed: w.WQ.length, nq_committed: w.nq, NQ_MAX},
  unlockingBytes_committed: u.length, committed: runs,
  sections: b1.info.sections, functions: b1.info.funcs, prologue: b1.info.prologue,
  schedule: {events: NE, bits: BITS.join(''), additions: ADD_EVENTS, flags: FLAGS.join(','), states: NSTATES, bounds: BOUNDS, chunkEnds: CHUNK_END, identities: K_IDS}, degreeBound: degBound, facts: FACTS,
};
writeFileSync(new URL('./redeem.hex', import.meta.url), redeem.toString('hex') + '\n');
writeFileSync(new URL('./build.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
console.log(`redeem ${redeem.length} B sha256 ${out.redeemSha256} (E_A ${E_A}, ${((Date.now() - t0) / 1000).toFixed(0)} s)`);
console.log(`committed: unlocking ${u.length} B, op ${runs.consensus.opCost} (consensus) / ${runs.standard.opCost} (standard) of ${runs.consensus.budget} (${(100 * runs.standard.opCost / runs.standard.budget).toFixed(2)}%)`);
console.log(`degree bound: max deg P ${degBound.chunkDegPmax}, deg D ${dD}, n_q cap ${NQ_MAX}; epsilon 2^${degBound.epsilonLog2.toFixed(1)}`);
