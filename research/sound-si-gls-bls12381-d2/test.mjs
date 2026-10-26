// protocol self-test: honest proofs accepted by the value-level verifier; tampering rejected.
import assert from 'node:assert/strict';
import {mintProof, groth16Holds, r} from './math.mjs';
import {layoutFor, prove, verifyValues, nqMax} from './protocol.mjs';
const BOUNDS = (process.env.BOUNDS ?? Array.from({length: 31}, (_, i) => 2 * i + 1).join(',')).split(',').map(Number);
const L = layoutFor(BOUNDS);
console.log('states', L.NSTATES, 'WS', L.WS_SIZE, 'NQ_MAX', nqMax(L));
const cases = [[123n, 456n], [0n, 0n], [r - 1n, 1n], [2n ** 200n + 12345n, r - 2n]];
for (const ns of cases) {
  const pr = mintProof(ns, {b: 1n + ns[0] % 97n, c: 13n + ns[1] % 89n}); assert.ok(groth16Holds(pr));
  const t0 = Date.now(); const w = prove(pr, L); const v = verifyValues(w.WS, w.WQ, L);
  console.log(ns.map(String).map((s) => s.slice(0, 12)).join(','), 'nq', w.nq, 'bound', w.nqBound, v.ok ? 'ACCEPT' : 'REJECT ' + v.why, (Date.now() - t0) + 'ms', 'maxDegD', Math.max(...w.debug.ids.map((i) => i.degD)));
  assert.ok(v.ok);
  const bad = Buffer.from(w.WS); bad[L.WS_SIZE - 7] ^= 1; assert.equal(verifyValues(bad, w.WQ, L).ok, false);
  const badq = Buffer.from(w.WQ); badq[5] ^= 1; assert.equal(verifyValues(w.WS, badq, L).ok, false);
}
// a false statement (wrong n) has no honest witness: the prover's own Groth16 assertion fires
{ const pr = mintProof([123n, 456n]); pr.ns = [124n, 456n]; assert.throws(() => prove(pr, L), /Groth16/); }
console.log('ok');
