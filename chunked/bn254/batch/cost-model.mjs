// Batch Groth16 cost model (DESIGN.md section 4). Not an implementation: it prices the batched verifier from the
// MEASURED per-phase op costs of ../bn-native-sound (profile.mjs, fixture 0, standard, BCHN accounting) and from
// static op-cost estimates of new G1 kernels (asm.mjs scheduler), and prints the N = 1..6 tables.
//   node cost-model.mjs            (KMUL=1.0: uncalibrated kernel estimates). Rows over 100,000 B do not fit one standard
//   tx; a multi-tx batch needs a cross-tx design that DESIGN.md does not cover.
import {Asm, Kernel} from '../bn-native-sound/asm.mjs';
import {kADblN, kDStep} from '../bn-native-sound/kernels.mjs';
import {DIGITS, NE} from '../sound-si-gls/math.mjs';
const k = 1e3, M = 1e6;
// ---------------- G1 kernel estimates (static model) ----------------
const est = (K, stack, outs) => new Asm(['p', ...stack]).kernel(K, outs, {iters: 3000}).cost;
const ops = (q) => ({I: (n) => q.in(n), E: (n) => q.env(n), m: (x) => q.mod(x), mul: (a, b) => q.mul(a, b), add: (a, b) => q.add(a, b), sub: (a, b) => q.sub(a, b)});
function jdbl() { // Jacobian doubling, a = 0 (EFD dbl-2009-l): 2M + 5S
  const q = new Kernel(); const {I, m, mul, add, sub} = ops(q); const [X, Y, Z] = ['X', 'Y', 'Z'].map(I);
  const A = m(mul(X, X)), B = m(mul(Y, Y)), C = m(mul(B, B)); const XB = add(X, B); const D = m(q.small(sub(sub(mul(XB, XB), A), C), 2));
  const E = q.small(A, 3); const F = m(mul(E, E)); const X3 = m(sub(F, add(D, D)));
  return q.output(X3, m(sub(mul(E, sub(D, X3)), q.small(C, 8))), m(q.small(mul(Y, Z), 2))); }
function jmadd() { // Jacobian + affine (EFD madd-2007-bl): 7M + 4S
  const q = new Kernel(); const {I, E, m, mul, add, sub} = ops(q); const [X, Y, Z] = ['X', 'Y', 'Z'].map(I); const xq = E('xq'), yq = E('yq');
  const Z2 = m(mul(Z, Z)); const U2 = m(mul(xq, Z2)); const S2 = m(mul(mul(yq, Z), Z2)); const H = sub(U2, X); const HH = m(mul(H, H));
  const I4 = q.small(HH, 4); const J = m(mul(H, I4)); const r = q.small(sub(S2, Y), 2); const V = m(mul(X, I4));
  const X3 = m(sub(sub(mul(r, r), J), add(V, V))); const ZH = add(Z, H);
  return q.output(X3, m(sub(mul(r, sub(V, X3)), q.small(mul(Y, J), 2))), m(sub(sub(mul(ZH, ZH), Z2), HH))); }
function aadd() { // affine G1 addition with a witnessed inverse t: lambda = (y - yq) t, check t (x - xq) - 1
  const q = new Kernel(); const {I, E, m, mul, sub} = ops(q); const [x, y, t] = ['x', 'y', 't'].map(I); const xq = E('xq'), yq = E('yq');
  const l = m(mul(sub(y, yq), t)); const chk = m(sub(mul(t, sub(x, xq)), q.c(1n))); const x3 = m(sub(sub(mul(l, l), x), xq));
  return q.output(x3, m(sub(mul(l, sub(x, x3)), y)), chk); }
const KEST = {
  kADblN: est(kADblN(), ['X0', 'X1', 'Y0', 'Y1', 't', 'Fp', 'Fm', 'z3', 'z3t', 'xz', 'xzt', 'yP'], ['a', 'b', 'c', 'd', 'e', 'f', 'g']),
  kDStep: est(kDStep(), ['yC', 'cz', 'czt', 'z3', 'z3t', 'dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'n0', 'n1', 's0', 's1', 'Fp', 'Fm'], ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']),
  jdbl: est(jdbl(), ['X', 'Y', 'Z'], ['X', 'Y', 'Z']), jmadd: est(jmadd(), ['xq', 'yq', 'X', 'Y', 'Z'], ['X', 'Y', 'Z']), aadd: est(aadd(), ['xq', 'yq', 'x', 'y', 't'], ['x', 'y', 'c']),
};
const BASE_OP = 7036431 + 6995632 + 6642322, BASE_UNLOCK = 9316 + 9262 + 8792;
const BDBL = 2.585 * M / 24, BADD = 0.796 * M / 8, BTERM = (0.103 + 0.105) * M / 2, RDW = 0.180 * M / 104, ENDPT = 0.016 * M;
const SQ_SAVE = 7.4 * k, LOOP_TAB = 10 * k, TAB_SETUP = 157 * k, BIND_TAB = 0.16 * M, QW = 0.753 * M / 114;
const FIX_M = 0.47 * M + 0.109 * M + 0.30 * M, FIX_S = 0.109 * M + 0.30 * M;
const STATE_OP = (0.404 * M + 33 * 15.5 * k) / 33 + 6 * RDW;
const CAP = 0.94 * 800 * (41 + 10000);
const MUL = Number(process.env.KMUL ?? 1.1);
const JDBL = KEST.jdbl * MUL, JMADD = KEST.jmadd * MUL, AADD = (KEST.aadd + RDW) * MUL, STEP_OH = 1 * k;
function nqMax(N, chunk, tables) {
  const bounds = []; for (let e = chunk; e < NE; e += chunk) bounds.push(e); bounds.push(NE);
  const ev = (e) => 9 * N + 9 + (DIGITS[e] ? 9 * N + 9 + 6 : 0) + 6 * 4 * tables;
  const nqOf = (dD) => ((dD % 2 ? dD : dD - 1) - 12 + 1) / 2;
  let best = nqOf(76 + 18 * (N - 1) + 6 * (tables - 2));
  bounds.forEach((b, i) => { let d = 6; for (let e = i ? bounds[i - 1] : 0; e < b; e++) d = 2 * d + ev(e); best = Math.max(best, nqOf(d + 6)); });
  return {nq: best, states: bounds.length};
}
function model(N, {bits = 128, glv = false} = {}) {
  if (N === 1) return {N, op: BASE_OP, inputs: 3, nM: 3, nS: 0, unlock: BASE_UNLOCK, nq: 132, msm: 0, perExtra: 0};
  const halves = glv ? 2 : 1, sb = bits / halves;
  const adds = (bits / 4) * (15 / 16) * JMADD;                       // windows over all halves
  const tbl = halves * 14 * AADD + (glv ? 14 * 4 * k : 0) + 25 * k;   // table(s) + affine conversion
  const smul = sb * (JDBL + STEP_OH) + adds + tbl;
  const cpt = adds + tbl;
  const cshared = sb * (JDBL + STEP_OH) + 25 * k;
  const msm = (N - 1) * (smul + cpt) + cshared + JMADD + (N - 1) * 65 * k; // + per-proof checks, r_i, s_k, publish/compare
  const extraB = (N - 1) * (65 * (BDBL - SQ_SAVE) + 21 * BADD + 2 * BTERM + 88 * RDW + ENDPT + 65 * 3 * k);
  const {nq} = nqMax(N, 2, 3);
  const miller = BASE_OP - 3 * FIX_M + extraB + 65 * LOOP_TAB + BIND_TAB + (nq - 132) * QW;
  const fixM = FIX_M + TAB_SETUP + N * 30 * k;
  const nM = Math.ceil(miller / (CAP - fixM));
  const spare = nM * (CAP - fixM) - miller;
  const nS = Math.max(0, Math.ceil((msm - spare) / (CAP - FIX_S)));
  const op = miller + msm + nM * fixM + nS * FIX_S;
  const inputs = nM + nS;
  const unlock = Math.ceil(op / (0.94 * 800)) - 41 * inputs;
  return {N, op, inputs, nM, nS, unlock, nq, msm, smul, cpt, cshared, extraB};
}
console.log("kernel estimates (static op)", JSON.stringify(KEST), "measured BDBL", Math.round(BDBL), "DSTEP", Math.round(1.570 * M / 32));
const tx = (u, n) => u + 43 * n + 60;
const out = {};
for (const [name, opt] of [['baseline-128', {}], ['glv-128', {glv: true}], ['baseline-100', {bits: 100}], ['glv-100', {glv: true, bits: 100}]]) {
  out[name] = [];
  for (let N = 1; N <= 6; N++) { const m = model(N, opt); const t = tx(m.unlock, m.inputs);
    out[name].push({N, opM: +(m.op / M).toFixed(1), inputs: m.inputs, nM: m.nM, nS: m.nS, unlock: m.unlock, tx: t, perProof: Math.round(t / N), fitsOneStdTx: t <= 100000, nq: m.nq, msmM: +(m.msm / M).toFixed(2)}); }
}
for (const [n, rows] of Object.entries(out)) { console.log(n); for (const r of rows) console.log(' ', JSON.stringify(r)); }
const m2 = model(2); console.log('smul', (m2.smul / M).toFixed(2), 'cpt', (m2.cpt / M).toFixed(2), 'cshared', (m2.cshared / M).toFixed(2), 'extraB', (m2.extraB / M).toFixed(2));
const g2 = model(2, {glv: true}); console.log('glv smul', (g2.smul / M).toFixed(2), 'cpt', (g2.cpt / M).toFixed(2), 'cshared', (g2.cshared / M).toFixed(2));
// independent co-located instances (no shared math): N x base inputs in one tx
for (let N = 1; N <= 4; N++) console.log('colocated', N, 'tx', N * (BASE_UNLOCK + 3 * 43) + 60, 'inputs', 3 * N);
