// Revised SI-GLS total from measured kernels (kernels.json, gls.json, transcript.json; bch-spec standard)
// and the prototype witness shape (proto-gls-rep6-2-f0.json from proto.mjs).
// Includes the review's required fixes (fixed-width transcript items with size checks, n_q cap, unsigned
// hash-to-Fp) and the grouped GLS evaluation (nibble strings + 16-entry tables). Knobs: B mode (projective
// vs affine witness slopes) and the delta-line mix (4 baked words vs baked lambda + on-chain x, c).
// score = max(bytes, ceil(op*GLUE/800 - 10000)); liveness: worst witness (Q at the cap, proto.worst.qWords = 132 words) <= 98% budget.
//   GLUE=1.05 node total.mjs   (GLUE = multiplier on summed kernel op for invocation/stack glue)
//   QWORDS=114 node total.mjs  (honest Q odd-word count; default proto-gls-rep6-2-f0.json = fixture 0, 105; fixture 4 = 114, the largest of the 5)
import {readFileSync} from 'node:fs';
const J = (f) => JSON.parse(readFileSync(new URL(f, import.meta.url)));
const K = J('./kernels.json'), G = J('./gls.json'), TR = J('./transcript.json');
const k = (n) => K[n].opCost, kb = (n) => K[n].bytes;
const GLUE = Number(process.env.GLUE ?? 1.05);
const W = 33, NE = 65, NADD = 21, NDL = 88; // 65 dbl + 21 add + 2 Frobenius steps
const proto = J('./proto-gls-rep6-2-f0.json');
const STATES = proto.states;
const Q_CAP = proto.worst.qWords; // 132: every GLS bit set, NAF addition on the squared event of a 2-event chunk
const PUSH_WORD = 132, SLOPE_FETCH = 2 * 350; // in-code 32-B push; witness slope pair fetched from depth (ROLL ~350 each)

function evaluate({bMode, n4, qWords, tail = 0}) {
  // tail: the last `tail` delta steps (of the 86 loop steps) use on-chain projective tracking instead of baked lambda;
  // the tail's start point is baked (4 words); about 1 in 4 tail steps is an addition.
  const tailAdd = Math.round(tail * NADD / (NE + NADD)), tailDbl = tail - tailAdd;
  const n2 = NDL - 2 - n4 - tail; // the 2 Frobenius delta lines are always 4-word bakes
  const qPad = Math.ceil(qWords / 4) * 4, qBlobs = Math.ceil(qPad / 8);
  const bytes = {}, ops = {};
  // ---- witness ----
  bytes.proofAndInputs = 10 * W;                    // A, B, C, n0, n1 (numbers; NUM2BIN 32 before hashing)
  bytes.glsWitness = 2 * (65 + 1) + 2;              // two 65-byte nibble strings (1-byte push opcode) + sign byte
  bytes.residueRoot = 192 + 2;                      // s^c as one 192-byte blob
  bytes.states = STATES * (192 + 2);                // fixed-width 192-byte blobs
  bytes.quotient = qPad * 32 + qBlobs * 3 + 2;      // 8-word blobs + explicit blob count
  bytes.bSlopes = bMode === 'affine' ? NDL * 2 * W : 0;
  // ---- code + constants ----
  bytes.deltaData = n2 * 2 * W + (n4 + 2) * 4 * W + 4 * W + (tail ? 4 * W + 20 : 0); // per-step pushes; + start (x0, c0); tail start point + square split
  bytes.kernelCode = (bMode === 'proj' ? kb('B proj dbl + line + F^2 accum (hand)') + kb('B proj mixed add + line + accum + c-mul (hand)')
      : kb('B affine dbl, witness slope (hand) [+2 VERIFY ~400]') + kb('B affine add + c-mul, witness slope (hand) [+2 VERIFY]') + 10)
    + (n2 ? kb('delta step, baked lambda, dbl (hand)') + 4 : 0) + kb('delta line, 4 baked words (hand)')
    + kb('state eval + residual + rho fold (hand)') + TR.parseState.bytes + 40 /* absorb loop */ + 90 /* Q loop */
    + G.glsEventLoop65.bytesPerEventUnrolled + G.glsTable.bytes + G.repEval.bytes + G.glsSignsTBandBinding.bytes
    + TR.frobSc.bytes + TR.fp2Const.bytes;
  bytes.vkConstants = (6 /* Rconst */ + 24 /* R_k0, R_k1 */ + 3 /* p^i mod r */ + 2 /* p, r */ + 2 /* eta, eta^2 */ + 2 /* 3b' */
    + 12 /* psi, psi^2, psi^3 */ + 10 /* Frob(S_c) alpha, beta */ + 2 /* x_delta */) * W + 66 /* 0x0f mask */;
  bytes.kernelLayoutAllowance = Math.round(0.25 * bytes.kernelCode); // deeper env => 2-byte PICK indices
  bytes.setupAndTerminalCode = 900;                 // curve/range checks, challenges, powers, terminal glue, final check
  bytes.eventFunctionAndSchedule = 500;
  bytes.tx = 63 + 3;
  // ---- op ----
  if (bMode === 'proj') ops.B = NE * k('B proj dbl + line + F^2 accum (hand)') + NADD * k('B proj mixed add + line + accum + c-mul (hand)') + 2 * k('B proj mixed add + line + accum (hand)');
  else ops.B = NE * (k('B affine dbl, witness slope (hand) [+2 VERIFY ~400]') + 400 + SLOPE_FETCH) + (NADD + 2) * (k('B affine add + c-mul, witness slope (hand) [+2 VERIFY]') + 400 + SLOPE_FETCH);
  ops.deltaTail = tailDbl * k('proj dbl + line, no square (delta tail)') + tailAdd * k('B proj mixed add + line + accum (hand)') + (tail ? NE * 1500 : 0);
  ops.delta = n2 * (k('delta step, baked lambda, dbl (hand)') + 2 * PUSH_WORD) + (n4 + 2) * (k('delta line, 4 baked words (hand)') + 4 * PUSH_WORD);
  ops.gls = G.glsEventLoop65.opCost + G.glsTable.opCost * 4 + G.repEval.opCost * 8 + 4 * 3800 + 2 * G.glsSignsTBandBinding.opCost + 2000;
  ops.states = STATES * (TR.absorbStates.perState + TR.parseState.opCost + k('state eval + residual + rho fold (hand)') + 700);
  ops.residueRoot = TR.absorbStates.perState + TR.parseState.opCost + 2 * G.repEval.opCost;
  ops.quotient = qPad * TR.quotient_W8.perWord + 4000;
  ops.terminal = 2 * TR.frobSc.opCost + G.repEval.opCost + 6 * 3800 + 10000 + 6 * TR.fp2Const.opCost + 2 * 13000 + 20000;
  ops.setup = 250000 + 2 * TR.challenge.opCost + 10 * 250;
  const B = Object.values(bytes).reduce((a, b) => a + b, 0);
  const O = Math.round(Object.values(ops).reduce((a, b) => a + b, 0) * GLUE);
  const budget = (10000 + B - 63) * 800;
  return {bytes, ops, B, O, budget, score: Math.max(B, Math.ceil(O / 800 - 10000))};
}
function best(bMode, qWords, worstQ = Q_CAP, allowTail = false) {
  let b = null;
  for (let n4 = 0; n4 <= NDL - 2; n4++) for (let tail = 0; tail <= (allowTail ? NDL - 2 - n4 : 0); tail++) {
    const w = evaluate({bMode, n4, qWords: worstQ, tail}); if (w.O > 0.98 * w.budget) continue;
    const r = evaluate({bMode, n4, qWords, tail});
    if (!b || r.score < b.score) b = {...r, n4, tail, worst: {bytes: w.B, opM: +(w.O / 1e6).toFixed(2), budgetM: +(w.budget / 1e6).toFixed(2), pct: +(100 * w.O / w.budget).toFixed(1)}};
  }
  return b;
}
const Q_WORDS = Number(process.env.QWORDS ?? proto.quotientWords);
const res = {GLUE, qWords: Q_WORDS, qCapWords: Q_CAP};
for (const [name, bMode, allowTail] of [['proj', 'proj', false], ['proj+deltaTail', 'proj', true], ['affine', 'affine', false]]) {
  const r = best(bMode, Q_WORDS, Q_CAP, allowTail);
  res[name] = {score: r.score, bytes: r.B, opM: +(r.O / 1e6).toFixed(2), budgetM: +(r.budget / 1e6).toFixed(2), deltaMix: {bake4: r.n4 + 2, bakeLambda: NDL - 2 - r.n4 - r.tail, projectiveTail: r.tail},
    worstCase: r.worst, bytesBreakdown: r.bytes, opsM: Object.fromEntries(Object.entries(r.ops).map(([a, x]) => [a, +(x / 1e6).toFixed(3)]))};
}
console.log(JSON.stringify(res, null, 1));
