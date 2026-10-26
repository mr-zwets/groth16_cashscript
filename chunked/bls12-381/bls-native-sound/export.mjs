// Bench vectors (4 P2SH32 inputs, one bch-2026 transaction): valid = fixture `committed`, extraValidProofs = proof1, dense,
// zero, max, msm-identity and the forced floor witness `forced n_q<=44, random B and C #28` (the smallest input-0
// margin of the sweep, 6.18% standard); worstCaseProof = `ALL15, random B and C #32` (every nibble 15 on bytes 8..63,
// n_q = NQ_MAX = 116: the largest total op cost, the heaviest input and the largest transaction of the liveness sweep,
// and the smallest margin of inputs 1-3, 6.19%; its overall minimum margin is within 0.02% of the sweep minimum).
// invalid = ordinary rejection vectors (one mutation per push class, each input).
//   node export.mjs vectors.json
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {FIXTURES} from './math.mjs';
import {sweepCases} from './sweep.mjs';
import {locking, LABELS, CHECKPOINTS, pushesFor, unlockingsOf, ctxOf, encodeWith, R} from './transaction.mjs';
import {verifyTx} from './vm.mjs';
assert.equal(process.argv.length, 3, 'usage: node export.mjs vectors.json');
const steps = (unl) => unl.map((u, i) => ({label: LABELS[i], locking: locking.toString('hex'), unlocking: Buffer.from(u).toString('hex'), checkpoint: CHECKPOINTS[i]}));
const runOf = (fx) => { const {pushes} = pushesFor(fx); const unl = unlockingsOf(pushes); for (const m of ['consensus', 'standard']) assert.equal(verifyTx(ctxOf(unl), m), true, m); return steps(unl); };
const {pushes} = pushesFor(FIXTURES.committed);
const flip = (buf, at) => { const b = Buffer.from(buf); b[at] ^= 0x01; return b; };
// one tamper per push class: [label, input, push index, byte offset]
const classes = [];
const names = pushes.map((ps) => ps.map(() => null));
const pnames = [['ZR', 'G', 'CL'], ['G', 'CL'], ['G', 'CL'], ['G', 'CL']];
for (let h = 0; h < 4; h++) pnames[h].forEach((n, k) => { const len = pushes[h][k].length; classes.push([`in${h} ${n}: first word`, h, k, 3], [`in${h} ${n}: middle`, h, k, len >> 1], [`in${h} ${n}: last byte`, h, k, len - 1]); });
for (let h = 0; h < 4; h++) for (let k = pnames[h].length; k < pushes[h].length; k++) classes.push([`in${h} push ${k} (constant piece / program part / filler / WQ)`, h, k, pushes[h][k].length >> 1]);
const invalid = [];
for (const [label, h, k, at] of classes) {
  const ps = pushes.map((x) => x.slice()); ps[h][k] = flip(ps[h][k], at);
  const unl = unlockingsOf(ps); assert.notEqual(verifyTx(ctxOf(unl), 'consensus'), true, label + ' accepted'); assert.notEqual(verifyTx(ctxOf(unl), 'standard'), true, label + ' accepted (std)');
  invalid.push(steps(unl).map((s, i) => ({...s, label: `${s.label} [${i === h ? 'tampered: ' + label : 'honest'}]`})));
}
{ const ps = pushes.map((x) => x.slice()); const unl = unlockingsOf(ps); unl[1] = encodeWith(ps[1], flip(R, R.length >> 1)); assert.notEqual(verifyTx(ctxOf(unl), 'consensus'), true); invalid.push(steps(unl).map((s, i) => ({...s, label: s.label + (i === 1 ? ' [tampered: redeem byte]' : '')}))); }
const SW = sweepCases(); const sweepCase = (label) => SW.find((c) => c.label === label).fx;
const extra = [...['proof1', 'dense', 'zero', 'max', 'msm-identity'].map((n) => runOf(FIXTURES[n])), runOf(sweepCase('forced n_q<=44, random B and C #28'))];
const worst = runOf(sweepCase('ALL15, random B and C #32'));
writeFileSync(process.argv[2], JSON.stringify({steps: runOf(FIXTURES.committed), invalid, extraValidProofs: extra, worstCaseProof: worst}, null, 1) + '\n');
console.log('wrote', process.argv[2], 'invalid', invalid.length, 'extra', extra.length);
void names;
