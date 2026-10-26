// Forced extreme witnesses for liveness/degree: statements whose base-|x| digits set every GLS bit at the
// events of the cap chunk [4,5] (bits 58, 57), and the all-zero statement (minimum n_q).
import assert from 'node:assert/strict';
import {mintProof, groth16Holds, T, r} from './math.mjs';
import {layoutFor, prove, verifyValues, nqMax, DEFAULT_BOUNDS} from './protocol.mjs';
const L = layoutFor(DEFAULT_BOUNDS);
const fromDigits = (d) => d.reduce((s, v, i) => s + v * T ** BigInt(i), 0n);
const full = (bits) => bits.reduce((s, b) => s | (1n << BigInt(b)), 0n);
const cases = {
  'cap chunk [4,5] all bits': [0, 1].map(() => fromDigits([0, 1, 2, 3].map(() => full([58, 57])))),
  'chunk [13,14] all bits': [0, 1].map(() => fromDigits([0, 1, 2, 3].map(() => full([49, 48])))),
  'zero': [0n, 0n],
};
for (const [name, ns] of Object.entries(cases)) {
  ns.forEach((n) => assert.ok(n < r));
  const pr = mintProof(ns); assert.ok(groth16Holds(pr)); const w = prove(pr, L); const v = verifyValues(w.WS, w.WQ, L);
  console.log(name.padEnd(28), 'n_q', w.nq, 'of cap', nqMax(L), v.ok ? 'ACCEPT' : 'REJECT ' + v.why);
}
