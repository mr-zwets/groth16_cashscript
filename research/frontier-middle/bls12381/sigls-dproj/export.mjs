// Bench vectors (one P2SH32 input, bch-spec): valid = fixture `committed`, extraValidProofs = proof1, dense, zero, max,
// msm-identity; worstCaseProof = the forced liveness extreme (worst.mjs: the statement with the smallest op margin in
// standard mode); invalid = one tamper per push class.
//   node export.mjs vectors.json
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {FIXTURES, mint} from './math.mjs';
import {WS_LAYOUT, NSTATES} from './protocol.mjs';
import {redeem, locking, unlocking} from './transaction.mjs';
import {encodeUnlocking, spend, unlockingFor} from './vm.mjs';
import {worstWitness} from './worst.mjs';
assert.equal(process.argv.length, 3, 'usage: node export.mjs vectors.json');
export const WORST_NQ = 53; // the forced pattern with the smallest standard margin (worst.mjs, sweep.json)
export const WORST_PROOFS = 40; // proof samples searched for that pattern (the one with the smallest standard margin is exported)
const step = (u) => ({label: 'single', locking: locking.toString('hex'), unlocking: Buffer.from(u).toString('hex'), checkpoint: 'pairing-close'});
const run = (fx) => { const {unlocking: u} = unlocking(fx); for (const m of ['consensus', 'standard']) assert.ok(spend(locking, u, m).accepted, m); return [step(u)]; };
const extra = ['proof1', 'dense', 'zero', 'max', 'msm-identity'].map((n) => FIXTURES[n]);
const ww = worstWitness(WORST_NQ, WORST_PROOFS, redeem, locking, spend, unlockingFor); const worst = ww.fx;
console.log(`worst case: n_q ${ww.nq}, standard margin ${ww.m} (${(100 * ww.m / ww.rs[1].budget).toFixed(3)}%), consensus ${ww.mc}, proof ${ww.bc ? ww.bc.map((x) => x.toString(16)).join(' / ') : 'default'}`);
const {w} = unlocking(FIXTURES.committed);
const flip = (buf, at) => { const b = Buffer.from(buf); b[at] ^= 0x01; return b; };
const S0 = WS_LAYOUT.states;
const classes = [
  ['WQ: leading word', () => [flip(w.WQ, 3), w.WS]], ['WQ: middle word', () => [flip(w.WQ, w.WQ.length >> 1), w.WS]], ['WQ: one word short', () => [w.WQ.subarray(48), w.WS]],
  ['WS: A.x', () => [w.WQ, flip(w.WS, 5)]], ['WS: B.y.c1', () => [w.WQ, flip(w.WS, 5 * 48 + 5)]], ['WS: C.y', () => [w.WQ, flip(w.WS, 7 * 48 + 5)]],
  ['WS: n0', () => [w.WQ, flip(w.WS, WS_LAYOUT.n0)]], ['WS: n1', () => [w.WQ, flip(w.WS, WS_LAYOUT.n1)]],
  ['WS: GLS nibble N0', () => [w.WQ, flip(w.WS, WS_LAYOUT.N0 + 30)]], ['WS: GLS nibble N1', () => [w.WQ, flip(w.WS, WS_LAYOUT.N1 + 63)]],
  ['WS: residue root s^c', () => [w.WQ, flip(w.WS, WS_LAYOUT.sc + 70)]], ['WS: state 1', () => [w.WQ, flip(w.WS, S0 + 10)]],
  ['WS: state 16', () => [w.WQ, flip(w.WS, S0 + 15 * 288 + 100)]], [`WS: state ${NSTATES}`, () => [w.WQ, flip(w.WS, S0 + (NSTATES - 1) * 288 + 280)]],
  ['redeem byte', () => [w.WQ, w.WS, flip(redeem, redeem.length >> 1)]],
];
const invalid = classes.map(([label, f]) => { const [WQ, WS, R = redeem] = f(); const u = encodeUnlocking([WQ, WS, R]); for (const m of ['consensus', 'standard']) assert.ok(!spend(locking, u, m).accepted, label + ' accepted'); return [{...step(u), label: 'single: ' + label}]; });
writeFileSync(process.argv[2], JSON.stringify({steps: run(FIXTURES.committed), invalid, extraValidProofs: extra.map(run), worstCaseProof: run(worst)}, null, 2) + '\n');
console.log('wrote', process.argv[2], 'invalid classes', invalid.length, 'extra proofs', extra.length);
