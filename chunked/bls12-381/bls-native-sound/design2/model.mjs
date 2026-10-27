// native-bls-design2 (ANGLE B): score model for the structural changes of DESIGN-2.md.
// Inputs are the measured worst-witness op per input (breakdown/opcat.json, standard mode) and the measured byte
// inventory of origin/main 17b05a7 (BREAKDOWN.md §1). Every change is entered as (dN natural bytes, dW worst op).
//   S_op = sum worst op / 750 (6.2% tuning margin, 800 op per byte) - 4*41 + locking + 192 (tx) + CAL
//   N    = natural bytes (everything except the zero fillers), locking and tx overhead included
//   score = max(N, S_op): the fillers make up the difference when op binds.
// usage: node model.mjs
import {readFileSync} from 'node:fs';
const here = new URL('.', import.meta.url);
const opcat = JSON.parse(readFileSync(new URL('../breakdown/opcat.json', here)));
const worst = [opcat['forced:44d3'].inputs[0].op, ...[1, 2, 3].map((i) => opcat.all15.inputs[i].op)];
const W0 = worst.reduce((a, b) => a + b, 0);
const RATE = 800 * (1 - 0.062);
const SCORE0 = 34229, FILL0 = 311, N0 = SCORE0 - FILL0;
const lock = (pkg) => (pkg === 'p2s' ? 4 * 65 : 4 * 35);
const sopRaw = (W, pkg) => W / RATE - 4 * 41 + lock(pkg) + 192;
const CAL = SCORE0 - sopRaw(W0, 'p2sh32');                 // in0's fixture WQ word (+48) and push granularity
const sop = (W, pkg) => sopRaw(W, pkg) + CAL;
const fmt = (x) => Math.round(x).toLocaleString('en-US');

// ---- changes (dN bytes, dW op); ranges in DESIGN-2.md ----
const C = {
  C1_bindingIntoProgram: {dN: -4 * 16 - 4 * 1 + 16, dW: 0},        // R 81 -> 65 B (push header 2 -> 1), +16 B once in the program
  C2_rawChallenges: {dN: -32, dW: -15e3},                           // ZR 96 -> 64 B; three consumers skip 2 word decodes
  C3_descriptorPins: {dN: -200, dW: +10e3},                         // table-driven layout/K pins + shared delta-start decode
  C4_oneReadPerSibling: {dN: -10, dW: -35e3},                       // in1: in0 read once; in0: in3 read once
};
const P2S = {dN: -4 * 36};                                           // locking 35 -> 65, R push (66 B) leaves the unlocking
const tail = (k) => (k === 0 ? {dN: 0, dW: 0} : {dN: 445 + 60 + 48 - 96 * k, dW: 89e3 * k + 10e3}); // SI-GLS projective tail in in3

function evaluate({stage1 = true, A = 0, p2s = false, k = 0}) {
  let N = N0, W = W0;
  if (stage1) for (const c of Object.values(C)) { N += c.dN; W += c.dW; }
  W -= A;
  if (p2s) N += P2S.dN;
  const t = tail(k); N += t.dN; W += t.dW;
  const pkg = p2s ? 'p2s' : 'p2sh32';
  const S = sop(W, pkg);
  return {N, S, score: Math.max(N, S), fill: Math.max(0, S - N), W};
}
function best(opts) {
  let b = null;
  for (const p2s of [false, true]) for (let k = 0; k <= 16; k++) {
    const r = {...evaluate({...opts, p2s, k}), p2s, k};
    if (!b || r.score < b.score - 0.5) b = r;
  }
  return b;
}

console.log(`worst op per input: ${worst.map((x) => (x / 1e6).toFixed(3)).join(' / ')} M; total ${(W0 / 1e6).toFixed(3)} M; CAL ${CAL.toFixed(0)}`);
console.log(`base: N ${fmt(N0)}, S_op ${fmt(sop(W0, 'p2sh32'))}, score ${fmt(Math.max(N0, sop(W0, 'p2sh32')))}`);
const rows = [];
for (const A of [0, 0.5e6, 1.0e6, 1.5e6, 2.0e6]) {
  const s1 = evaluate({A});
  const s0 = evaluate({stage1: false, A});
  const b = best({A});
  rows.push({A, base: s0.score, stage1: s1.score, best: b.score, p2s: b.p2s, k: b.k, fill: b.fill});
}
console.log('\nA = op saved by angle A (or any other op lever) at the worst witnesses, bytes unchanged');
console.log('A (M)  | no angle B | stage 1 | stage 1 + best of {P2S, projective tail k} | choice');
for (const r of rows) console.log(`${(r.A / 1e6).toFixed(1).padStart(5)}  | ${fmt(r.base).padStart(10)} | ${fmt(r.stage1).padStart(7)} | ${fmt(r.best).padStart(7)} | ${r.p2s ? 'P2S' : 'P2SH32'}, k=${r.k}, filler ${fmt(r.fill)}`);
// sensitivity of stage 1 alone
const lo = {dN: -200, dW: -0.03e6}, hi = {dN: -340, dW: -0.08e6};
for (const [nm, d] of [['stage 1 low', lo], ['stage 1 high', hi]]) {
  const N = N0 + d.dN, S = sop(W0 + d.dW, 'p2sh32');
  console.log(`${nm}: N ${fmt(N)}, S_op ${fmt(S)}, score ${fmt(Math.max(N, S))}`);
}
// break-even of the projective tail: smallest A at which k > 0 wins
for (let A = 0; A <= 3e6; A += 0.05e6) { const b = best({A}); if (b.k > 0) { console.log(`projective tail first pays at A = ${(A / 1e6).toFixed(2)} M (k = ${b.k})`); break; } }
for (let A = 0; A <= 3e6; A += 0.05e6) { const b = best({A}); if (b.p2s) { console.log(`P2S first pays at A = ${(A / 1e6).toFixed(2)} M`); break; } }
// scenario rows of DESIGN-2.md §6
for (const [nm, o] of [['stage 1, A=0', {A: 0}], ['stage 1, A=0.5M', {A: 0.5e6}], ['stage 1 + P2S, A=1.0M', {A: 1.0e6, p2s: true}],
  ['stage 1 + P2S + k=8, A=1.5M', {A: 1.5e6, p2s: true, k: 8}], ['stage 1 + P2S + k=11, A=2.0M', {A: 2.0e6, p2s: true, k: 11}]]) {
  const r = evaluate(o); console.log(`${nm}: N ${fmt(r.N)}, S_op ${fmt(r.S)}, score ${fmt(r.score)}, worst op ${(r.W / 1e6).toFixed(2)} M`);
}
