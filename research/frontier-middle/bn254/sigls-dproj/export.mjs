// Bench vectors (one P2SH32 input, bch-spec): valid = fixture 0, extraValidProofs = fixtures 1-3,
// worstCaseProof = fixture 4 (dense near-r inputs); invalid = one tamper per push class.
//   node export.mjs vectors.json
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {FIXTURES} from './math.mjs';
import {WS_LAYOUT, NSTATES} from './protocol.mjs';
import {redeem, locking, unlocking} from './transaction.mjs';
import {encodeUnlocking, spend} from './vm.mjs';
assert.equal(process.argv.length, 3, 'usage: node export.mjs vectors.json');
const step = (u) => ({label: 'single', locking: locking.toString('hex'), unlocking: Buffer.from(u).toString('hex'), checkpoint: 'pairing-close'});
const run = (fx) => [step(unlocking(fx).unlocking)];
const [primary, ...rest] = FIXTURES.fixtures;
const {w} = unlocking(primary);
const flip = (buf, at) => { const b = Buffer.from(buf); b[at] ^= 0x01; return b; };
const S0 = WS_LAYOUT.states;
const classes = [
  ['WQ: leading word', () => [flip(w.WQ, 3), w.WS]], ['WQ: middle word', () => [flip(w.WQ, w.WQ.length >> 1), w.WS]], ['WQ: one word short', () => [w.WQ.subarray(32), w.WS]],
  ['WS: A.x', () => [w.WQ, flip(w.WS, 5)]], ['WS: B.y.c1', () => [w.WQ, flip(w.WS, 5 * 32 + 5)]], ['WS: C.y', () => [w.WQ, flip(w.WS, 7 * 32 + 5)]],
  ['WS: n0', () => [w.WQ, flip(w.WS, WS_LAYOUT.n0)]], ['WS: n1', () => [w.WQ, flip(w.WS, WS_LAYOUT.n1)]],
  ['WS: GLS nibble N0', () => [w.WQ, flip(w.WS, WS_LAYOUT.N0 + 30)]], ['WS: GLS nibble N1', () => [w.WQ, flip(w.WS, WS_LAYOUT.N1 + 64)]],
  ['WS: residue root s^c', () => [w.WQ, flip(w.WS, WS_LAYOUT.sc + 70)]], ['WS: state 1', () => [w.WQ, flip(w.WS, S0 + 10)]],
  ['WS: state 17', () => [w.WQ, flip(w.WS, S0 + 16 * 192 + 100)]], ['WS: state 33', () => [w.WQ, flip(w.WS, S0 + (NSTATES - 1) * 192 + 180)]],
  ['redeem byte', () => [w.WQ, w.WS, flip(redeem, redeem.length >> 1)]],
];
const invalid = classes.map(([label, f]) => { const [WQ, WS, R = redeem] = f(); const u = encodeUnlocking([WQ, WS, R]); assert.ok(!spend(locking, u).accepted, label + ' accepted'); return [{...step(u), label: 'single: ' + label}]; });
writeFileSync(process.argv[2], JSON.stringify({steps: run(primary), invalid, extraValidProofs: rest.slice(0, 3).map(run), worstCaseProof: run(rest[3])}, null, 2) + '\n');
console.log('wrote', process.argv[2], 'invalid classes', invalid.length);
