// Build the SI-GLS redeem (bch-spec, one P2SH32 input), deterministically, and check it.
//   node build.mjs            -> writes redeem.hex and build.json, prints the sha256
// Every baked constant is recomputed and asserted against noble when math.mjs loads; the degree bound and the
// quotient cap are derived from the NAF schedule and the chunking here; the build is run twice and must be
// byte-identical; fixture 0 must be accepted in consensus and standard mode, and a tampered state rejected.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {DIGITS, NE, FACTS, FIXTURES, p} from './math.mjs';
import {NQ_MAX, BOUNDS, NSTATES, K_IDS, chunkDegP, WS_SIZE, prove} from './protocol.mjs';
import {buildRedeem} from './script.mjs';
import {p2sh32, unlockingFor, spend} from './vm.mjs';

const sha = (b) => createHash('sha256').update(b).digest('hex');
// ---- degree bound (adversarial: every nibble 15) and the n_q cap, from the schedule ----
const worst = BOUNDS.map((_, k) => chunkDegP(k, () => 8));
const degDmax = Math.max(...worst) + 6; const dD = degDmax % 2 ? degDmax : degDmax - 1;
assert.equal(NQ_MAX, (dD - 12 + 1) / 2, 'NQ_MAX from the schedule');
const firstAdds = BOUNDS.map((b, k) => (k ? BOUNDS[k - 1] : 0)).filter((a, k) => BOUNDS[k] - a === 2 && DIGITS[a]);
const degBound = {chunkDegPmax: Math.max(...worst), degDmax: dD, degQmax: dD - 12, NQ_MAX, chunksWithAddFirst: firstAdds,
  szDegree: Math.max(dD, 2 * NQ_MAX - 1 + 12), batchDegreeInRho: K_IDS - 1};
// ---- build twice: byte-identical ----
const b1 = buildRedeem(); const b2 = buildRedeem();
assert.deepEqual(Buffer.from(b1.redeem), Buffer.from(b2.redeem), 'deterministic build');
const redeem = Buffer.from(b1.redeem), locking = Buffer.from(p2sh32(redeem));
// ---- smoke: fixture 0 accepted (both modes); a tampered state rejected ----
const w = prove(FIXTURES.fixtures[0]); const u = unlockingFor(w.WS, w.WQ, redeem);
const runs = Object.fromEntries(['consensus', 'standard'].map((m) => { const r = spend(locking, u, m); assert.ok(r.accepted, m + ': ' + r.error); return [m, {opCost: r.opCost, budget: r.budget}]; }));
{ const bad = Buffer.from(w.WS); bad[WS_SIZE - 100] ^= 1; assert.ok(!spend(locking, unlockingFor(bad, w.WQ, redeem)).accepted, 'tampered state accepted'); }
const out = {
  redeemBytes: redeem.length, redeemSha256: sha(redeem), lockingHex: locking.toString('hex'), lockingSha256: sha(locking),
  witness: {WS: WS_SIZE, WQ_fixture0: w.WQ.length, nq_fixture0: w.nq, NQ_MAX},
  unlockingBytes_fixture0: u.length, fixture0: runs,
  sections: b1.info.sections, functions: b1.info.funcs, prologue: b1.info.prologue,
  schedule: {events: NE, digits: DIGITS.join(''), states: NSTATES, bounds: BOUNDS, identities: K_IDS}, degreeBound: degBound, facts: FACTS,
};
writeFileSync(new URL('./redeem.hex', import.meta.url), redeem.toString('hex') + '\n');
writeFileSync(new URL('./build.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
console.log(`redeem ${redeem.length} B sha256 ${out.redeemSha256}`);
console.log(`fixture 0: unlocking ${u.length} B, op ${runs.consensus.opCost} (consensus) / ${runs.standard.opCost} (standard) of ${runs.consensus.budget}`);
console.log(`degree bound: max deg P ${degBound.chunkDegPmax}, deg D ${dD}, n_q cap ${NQ_MAX}; add-first chunks at events ${firstAdds.join(',')}`);
