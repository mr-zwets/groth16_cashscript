// Value-level protocol test: honest proofs (bench fixture VK) verify input by input; simple rejections.
import assert from 'node:assert/strict';
import {mintProof, prove, finish, verifySplit, NQ_MAX_FOR, nqOf} from './protocol.mjs';
import {r} from './math.mjs';
const ranges = [[0, 8], [8, 16], [16, 24], [24, 32]];
const cases = [
  ['fixture0 (123,456), B=G2', mintProof(123n, 456n), () => true],
  ['fixture0 projective', mintProof(123n, 456n), () => false],
  ['random inputs, B=7G2', mintProof(r - 98765432123456789n, 2n ** 250n + 12345n, 17n, 7n), () => true],
  ['mixed (affine e<=30)', mintProof(5n, 9n, 19n, 3n), (e) => e <= 30],
];
console.log('NQ_MAX affine', NQ_MAX_FOR(() => true), 'projective', NQ_MAX_FOR(() => false));
for (const [name, pf, affOf] of cases) {
  const t0 = Date.now(); const w = prove(pf, {affOf}); const fin = finish(w, affOf);
  const v = verifySplit(w, fin, ranges, affOf);
  console.log(name.padEnd(28), 'ok', v.ok, 'nq', fin.nq, 'bound', fin.nqBound, 'WS', fin.WS.length, 'WQ', fin.WQ.length, 'maxDegP', Math.max(...w.ids.map((i) => i.degP)), (Date.now() - t0) + 'ms');
  assert.ok(v.ok);
  // rejections: wrong public input (binding), tampered state (final identity)
  const w2 = {...w, ns: [w.ns[0] + 1n, w.ns[1]]}; assert.equal(verifySplit(w2, fin, ranges, affOf).ok, false);
  const w3 = {...w, states: w.states.map((s, i) => (i === 5 ? [s[0] + 1n, ...s.slice(1)] : s))}; assert.equal(verifySplit(w3, fin, ranges, affOf).okFinal, false);
}
console.log('all ok');
