// T2 "rolled residue singleton" redeem generator (BN254, one P2SH32 input, BCH 2026 script sizes).
// Unlocking: <W> <redeem>. W = 17 fixed-width 32-byte LE words (see protocol.mjs).
// A real Fp12 accumulator F in the SI-GLS polynomial basis (Fp12 = Fp[X]/M, M = X^12 - 18X^6 + 82) runs ONE
// rolled loop over the 65 NAF events of 6x+2 for the three pairs (-A, B), (vk_x, gamma), (C, delta): every G2 walk is
// projective and on-chain (one shared doubling and one shared addition kernel), the residue root c (monic class rep
// S_c, 6 words) is folded at the 21 addition events, e(alpha, beta) is a baked monic class rep, and the terminal checks
// the class identity [F * c^(p^2)] == [c^p c^(p^3)] EXACTLY (F * sigma(Frob(S_c)(X) Frob(S_c)(eta X)) has zero odd part).
// vk_x = IC0 + n0 IC1 + n1 IC2 by a joint (Shamir) Jacobian double-and-add with one witnessed zInv.
import assert from 'node:assert/strict';
import {Asm, Kernel, OP, pushNum} from '../sigls-dproj/asm.mjs';
import {p, r, mod, ETA, GAMMA1, B_TWIST, DIGITS, NE, VKC, NBITS} from './math.mjs';
import {W_SIZE, WL} from './protocol.mjs';

const ITERS = Number(process.env.SCHED_ITERS ?? 3000);
const SQR_MODE = process.env.T2_SQR ?? 'inline'; // inline: dedicated squaring kernel; mulc: F^2 via two MULC calls + glue (smaller, more op)

// ---------------- polynomial kernels (mod M) ----------------
// reduce a coefficient array (node ids or undefined) of degree <= 22 mod M: X^12 = 18 X^6 - 82
function reduceM(k, c) {
  for (let d = c.length - 1; d >= 12; d--) {
    if (c[d] === undefined) continue;
    c[d - 6] = c[d - 6] === undefined ? k.small(c[d], 18) : k.add(c[d - 6], k.small(c[d], 18));
    const t = k.small(c[d], 82); c[d - 12] = c[d - 12] === undefined ? k.neg(t) : k.sub(c[d - 12], t);
  }
  return c.slice(0, 12);
}
const addTo = (k, c, d, x) => { c[d] = c[d] === undefined ? x : k.add(c[d], x); };
// F (12) * sparse G: G_j for j in js (inputs named G<j> / L<j>), plus X^6 if monic6
export function kMulSparse(js, prefix, monic6) {
  const k = new Kernel(); const F = Array.from({length: 12}, (_, i) => k.in('F' + i)); const G = Object.fromEntries(js.map((j) => [j, k.in(prefix + j)]));
  const c = [];
  for (let i = 0; i < 12; i++) { for (const j of js) addTo(k, c, i + j, k.mul(F[i], G[j])); if (monic6) addTo(k, c, i + 6, F[i]); }
  return k.output(reduceM(k, c).map((x) => k.mod(x)));
}
export function kSqr() {
  const k = new Kernel(); const F = Array.from({length: 12}, (_, i) => k.in('F' + i)); const cross = [], c = [];
  for (let i = 0; i < 12; i++) for (let j = i + 1; j < 12; j++) addTo(k, cross, i + j, k.mul(F[i], F[j]));
  for (let d = 0; d < 23; d++) { if (cross[d] !== undefined) c[d] = k.add(cross[d], cross[d]); if (d % 2 === 0 && d / 2 < 12) addTo(k, c, d, k.mul(F[d / 2], F[d / 2])); }
  return k.output(reduceM(k, c).map((x) => k.mod(x)));
}
// F * G for a general G = A + X^6 B given U = MULC(F, A) = F A + X^6 F and V = MULC(F, B) = F B + X^6 F:
// F G = U + X^6 (V - 19 F) + 82 F   (X^6 H mod M: coefficient k < 6: -82 H_(k+6); k >= 6: H_(k-6) + 18 H_k)
export function kGlue(oddOnly) {
  const k = new Kernel(); const U = [], V = [], F = []; for (let i = 0; i < 12; i++) { U.push(k.in('U' + i)); V.push(k.in('V' + i)); F.push(k.in('F' + i)); }
  const H = V.map((v, i) => k.sub(v, k.small(F[i], 19)));
  const out = []; for (let d = 0; d < 12; d++) { if (oddOnly && d % 2 === 0) continue;
    const S = d < 6 ? k.neg(k.small(H[d + 6], 82)) : k.add(H[d - 6], k.small(H[d], 18));
    out.push(k.mod(k.sum(U[d], k.small(F[d], 82), S))); }
  return k.output(out);
}
// ---------------- G2 kernels: projective step + the 6 nonzero line-polynomial coefficients at P ----------------
// line l0 yP + l1 xP X + l3 X^3 with Phi(a) = (a0 - 9 a1) + a1 X^6: coefficients at X^0,1,3,6,7,9
// doubling: (l0, l1, l3) = (H, -3X^2, B - E); env passed in: xP3 = -3 xP, yP
export function kDbl() {
  const k = new Kernel(); const I = (n) => k.in(n), m = (x) => k.mod(x), mul = (a, b) => k.mul(a, b), add = (a, b) => k.add(a, b), sub = (a, b) => k.sub(a, b);
  const [X0, X1, Y0, Y1, Z0, Z1, xP3, yP, b0, b1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'xP3', 'yP', 'b30', 'b31'].map(I);
  const B0 = m(mul(add(Y0, Y1), sub(Y0, Y1))), B1 = m(mul(add(Y0, Y0), Y1));
  const C0 = m(mul(add(Z0, Z1), sub(Z0, Z1))), C1 = m(mul(add(Z0, Z0), Z1));
  const E0 = m(sub(mul(b0, C0), mul(b1, C1))), E1 = m(add(mul(b0, C1), mul(b1, C0)));
  const F0 = k.small(E0, 3), F1 = k.small(E1, 3);
  const t0 = mul(X0, Y0), t1 = mul(X1, Y1), t2 = mul(add(X0, X1), add(Y0, Y1));
  const XY0 = m(sub(t0, t1)), XY1 = m(sub(sub(t2, t0), t1));
  const D0 = k.small(sub(B0, F0), 2), D1 = k.small(sub(B1, F1), 2);
  const X30 = m(sub(mul(XY0, D0), mul(XY1, D1))), X31 = m(add(mul(XY0, D1), mul(XY1, D0)));
  const G0 = add(B0, F0), G1 = add(B1, F1);
  const Y30 = m(sub(mul(add(G0, G1), sub(G0, G1)), k.small(mul(add(E0, E1), sub(E0, E1)), 12)));
  const Y31 = m(sub(k.small(mul(G0, G1), 2), k.small(mul(E0, E1), 24)));
  const S0 = add(Y0, Z0), S1 = add(Y1, Z1);
  const H0 = m(sub(sub(mul(add(S0, S1), sub(S0, S1)), B0), C0)), H1 = m(sub(sub(mul(add(S0, S0), S1), B1), C1));
  const B40 = k.small(B0, 4), B41 = k.small(B1, 4);
  const Z30 = m(sub(mul(B40, H0), mul(B41, H1))), Z31 = m(add(mul(B40, H1), mul(B41, H0)));
  const X20 = mul(add(X0, X1), sub(X0, X1)), X21 = mul(add(X0, X0), X1);
  const l30 = sub(B0, E0), l31 = sub(B1, E1);
  return k.output(X30, X31, Y30, Y31, Z30, Z31,
    m(mul(yP, sub(H0, k.small(H1, 9)))), m(mul(xP3, sub(X20, k.small(X21, 9)))), m(sub(l30, k.small(l31, 9))), m(mul(yP, H1)), m(mul(xP3, X21)), m(l31));
}
// mixed addition with affine (xq, yq): (l0, l1, l3) = (lam', -theta, theta xq - lam' yq); env passed in: mxP = -xP, yP
export function kAdd() {
  const k = new Kernel(); const I = (n) => k.in(n), m = (x) => k.mod(x), mul = (a, b) => k.mul(a, b), add = (a, b) => k.add(a, b), sub = (a, b) => k.sub(a, b);
  const [X0, X1, Y0, Y1, Z0, Z1, xq0, xq1, yq0, yq1, mxP, yP] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'xq0', 'xq1', 'yq0', 'yq1', 'mxP', 'yP'].map(I);
  const fm = (a0, a1, b0, b1) => { const u0 = mul(a0, b0), u1 = mul(a1, b1), u2 = mul(add(a0, a1), add(b0, b1)); return [sub(u0, u1), sub(sub(u2, u0), u1)]; };
  const fs = (a0, a1, b0, b1) => [sub(mul(a0, b0), mul(a1, b1)), add(mul(a0, b1), mul(a1, b0))];
  const [qz0, qz1] = fs(yq0, yq1, Z0, Z1); const th0 = m(sub(Y0, qz0)), th1 = m(sub(Y1, qz1));
  const [xz0, xz1] = fs(xq0, xq1, Z0, Z1); const la0 = m(sub(X0, xz0)), la1 = m(sub(X1, xz1));
  const Cc0 = m(mul(add(th0, th1), sub(th0, th1))), Cc1 = m(mul(add(th0, th0), th1));
  const D0 = m(mul(add(la0, la1), sub(la0, la1))), D1 = m(mul(add(la0, la0), la1));
  const [e0, e1] = fm(la0, la1, D0, D1); const E0 = m(e0), E1 = m(e1);
  const [f0, f1] = fm(Z0, Z1, Cc0, Cc1); const F0 = m(f0), F1 = m(f1);
  const [g0, g1] = fm(X0, X1, D0, D1); const G0 = m(g0), G1 = m(g1);
  const H0 = sub(add(E0, F0), k.small(G0, 2)), H1 = sub(add(E1, F1), k.small(G1, 2));
  const [x30, x31] = fm(la0, la1, H0, H1);
  const [a0, a1] = fs(th0, th1, sub(G0, H0), sub(G1, H1)), [b0, b1] = fs(Y0, Y1, E0, E1);
  const [z30, z31] = fm(Z0, Z1, E0, E1);
  const [tx0, tx1] = fs(th0, th1, xq0, xq1), [ly0, ly1] = fs(la0, la1, yq0, yq1);
  const l30 = sub(tx0, ly0), l31 = sub(tx1, ly1);
  return k.output(m(x30), m(x31), m(sub(a0, b0)), m(sub(a1, b1)), m(z30), m(z31),
    m(mul(yP, sub(la0, k.small(la1, 9)))), m(mul(mxP, sub(th0, k.small(th1, 9)))), m(sub(l30, k.small(l31, 9))), m(mul(yP, la1)), m(mul(mxP, th1)), m(l31));
}
const conjMul = (k, a0, a1, g0, g1) => [k.mod(k.add(k.mul(a0, g0), k.mul(a1, g1))), k.mod(k.sub(k.mul(a0, g1), k.mul(a1, g0)))];
export function kPsi() { const k = new Kernel(); const [x0, x1, y0, y1, g20, g21, g30, g31] = ['x0', 'x1', 'y0', 'y1', 'g20', 'g21', 'g30', 'g31'].map((n) => k.in(n)); return k.output(...conjMul(k, x0, x1, g20, g21), ...conjMul(k, y0, y1, g30, g31)); }
// ---------------- G1 Jacobian (a = 0) for vk_x: dbl-2009-l and madd-2007-bl; Z = 0 is absorbing in both ----------------
export function kJDbl() {
  const k = new Kernel(); const m = (x) => k.mod(x), mul = (a, b) => k.mul(a, b), add = (a, b) => k.add(a, b), sub = (a, b) => k.sub(a, b);
  const [X, Y, Z] = ['VX', 'VY', 'VZ'].map((n) => k.in(n));
  const A = m(mul(X, X)), B = m(mul(Y, Y)), C = m(mul(B, B)); const XB = add(X, B);
  const D = k.small(sub(sub(mul(XB, XB), A), C), 2), E = k.small(A, 3); const Dm = m(D);
  const X3 = m(sub(mul(E, E), k.small(Dm, 2)));
  return k.output(X3, m(sub(mul(E, sub(Dm, X3)), k.small(C, 8))), m(k.small(mul(Y, Z), 2)));
}
export function kJAdd() {
  const k = new Kernel(); const m = (x) => k.mod(x), mul = (a, b) => k.mul(a, b), add = (a, b) => k.add(a, b), sub = (a, b) => k.sub(a, b);
  const [X, Y, Z, x2, y2] = ['VX', 'VY', 'VZ', 'xq', 'yq'].map((n) => k.in(n));
  const ZZ = m(mul(Z, Z)), U2 = mul(x2, ZZ), S2 = mul(y2, m(mul(Z, ZZ)));
  const H = m(sub(U2, X)), HH = m(mul(H, H)), I = k.small(HH, 4), J = m(mul(H, I)), R = k.small(sub(S2, Y), 2), Rm = m(R), V = m(mul(X, I));
  const X3 = m(sub(sub(mul(Rm, Rm), J), k.small(V, 2)));
  return k.output(X3, m(sub(mul(Rm, sub(V, X3)), k.small(mul(Y, J), 2))), m(k.small(mul(Z, H), 2)));
}

// ---------------- local-function call convention ----------------
// arguments go on top under the function's own input names: consumed items are rolled, everything else picked.
const CONSUMED = /^(F\d+|[BGD][XYZ][01]|L\d|xq[01]?|yq[01]?|G\d|U\d+|V\d+|px[01]|py[01])$/;
function call(s, fname, IN, map, outs) {
  for (const n of IN) { const src = map[n] ?? n; if (CONSUMED.test(src)) s.roll(src).rename(n); else s.pick(src, n); }
  s.invoke(fname, outs);
}
const FN = Array.from({length: 12}, (_, i) => 'F' + i);
const LN = ['L0', 'L1', 'L3', 'L6', 'L7', 'L9'];
const ST = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'];
const W_ST = (w) => ST.map((n) => w + n);
const wmap = (w) => Object.fromEntries([...ST.map((n) => [n, w + n]), ['xP3', 'xP3' + w], ['yP', 'yP' + w], ['mxP', 'mxP' + w]]);

export function buildRedeem({stop} = {}) {
  let L = {};
  for (let attempt = 0; attempt < 12; attempt++) {
    try { return gen(L, stop); } catch (e) { if (e.retryL) { L = {...L, [e.retryL.name]: e.retryL.nat}; continue; } throw e; }
  }
  throw new Error('loop layout did not converge');
}
function gen(Lg, stop) {
  const a = new Asm(['W']);
  const info = {sections: {}}; let mark = 0; const section = (name) => { info.sections[name] = (info.sections[name] ?? 0) + a.code.length - mark; mark = a.code.length; a.mark('end:' + name); };
  const STOP = (label) => { if (stop === label) throw {stopAt: label, asm: a}; };
  const U = (x) => a.pushBytes([0x00]).op(OP.CAT, 2, x + '#c').op(OP.BIN2NUM, 1, x);
  const fixLoop = (name, s, keepOrder) => { const L0 = Lg[name] ?? keepOrder; s.arrangeAll(L0); return L0; };
  const onExit = (name, L0) => (nat) => { if (nat.join() !== L0.join()) throw {retryL: {name, nat}}; };
  // ---- functions ----
  a.defLocal('P', 0, 1, (s) => s.push(p, 'p'));
  a.defLocal('RD', 1, 2, (s) => { s.push(32).op(OP.SPLIT, 2, 'w', 'rest').roll('w').pushBytes([0]).op(OP.CAT, 2, 'w0').op(OP.BIN2NUM, 1, 'v');
    s.pick('v').invoke('P', ['p']).op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1).roll('rest'); });
  a.defLocal('G1C', 2, 0, (s) => { const k = new Kernel(); const x = k.in('in0'), y = k.in('in1'); k.output(k.mod(k.sub(k.mul(y, y), k.add(k.mul(k.mul(x, x), x), k.c(3n))))); s.kernel(k, ['d'], {iters: 200}); s.op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); });
  const local = (name, IN, K, OUT) => a.defLocal(name, IN.length, OUT.length, (s) => { IN.forEach((n, i) => s.rename('in' + i, n)); s.kernel(K, OUT, {iters: ITERS}); s.drop('p'); });
  const DBL_IN = [...ST, 'xP3', 'yP', 'b30', 'b31', 'p'], ADD_IN = [...ST, 'xq0', 'xq1', 'yq0', 'yq1', 'mxP', 'yP', 'p'];
  const MULL_IN = [...FN, ...LN, 'p'], MULC_IN = [...FN, 'G0', 'G1', 'G2', 'G3', 'G4', 'G5', 'p'], PSI_IN = ['x0', 'x1', 'y0', 'y1', 'g20', 'g21', 'g30', 'g31', 'p'];
  local('DBL', DBL_IN, kDbl(), [...ST, ...LN]);
  local('ADD', ADD_IN, kAdd(), [...ST, ...LN]);
  local('MULL', MULL_IN, kMulSparse([0, 1, 3, 6, 7, 9], 'L', false), FN);
  local('MULC', MULC_IN, kMulSparse([0, 1, 2, 3, 4, 5], 'G', true), FN);
  local('PSI', PSI_IN, kPsi(), ['x0', 'x1', 'y0', 'y1']);
  const dbl = (s, w) => { call(s, 'DBL', DBL_IN, wmap(w), [...W_ST(w), ...LN]); call(s, 'MULL', MULL_IN, {}, FN); };
  const addQ = (s, w) => { call(s, 'ADD', ADD_IN, wmap(w), [...W_ST(w), ...LN]); call(s, 'MULL', MULL_IN, {}, FN); };
  const mulc = (s) => call(s, 'MULC', MULC_IN, {}, FN);
  const psi = (s, x0, x1, y0, y1, outs) => call(s, 'PSI', PSI_IN, {x0, x1, y0, y1}, outs);
  // F * G (G = A + X^6 B, A/B as G0..G5 named A0..A5 / B0..B5 on the stack): two MULC calls + glue
  const mul12 = (s, oddOnly, outs) => {
    for (let i = 0; i < 12; i++) s.pick('F' + i, 'U' + i); for (let j = 0; j < 6; j++) s.roll('A' + j).rename('G' + j);
    call(s, 'MULC', MULC_IN, Object.fromEntries(FN.map((f, i) => [f, 'U' + i])), FN.map((_, i) => 'U' + i));
    for (let i = 0; i < 12; i++) s.pick('F' + i, 'V' + i); for (let j = 0; j < 6; j++) s.roll('B' + j).rename('G' + j);
    call(s, 'MULC', MULC_IN, Object.fromEntries(FN.map((f, i) => [f, 'V' + i])), FN.map((_, i) => 'V' + i));
    s.kernel(kGlue(oddOnly), outs, {iters: ITERS});
  };
  section('init');

  // ---- 1. layout pin and parse: W = xA yA xB0 xB1 yB0 yB1 xC yC n0 n1 sc0..sc5 zInv ----
  a.emit(OP.DEPTH, ...pushNum(1), OP.NUMEQUALVERIFY);
  a.pick('W').emit(OP.SIZE); a.st.push('sz'); a.push(W_SIZE).op(OP.NUMEQUALVERIFY, 2).drop();
  for (const n of ['xA', 'yA', 'xB0', 'xB1', 'yB0', 'yB1', 'xC', 'yC']) a.invoke('RD', [n, 'W']);
  a.push(r, 'r');
  for (const n of ['n0', 'n1']) { a.roll('W').push(32).op(OP.SPLIT, 2, 'w', 'W').roll('w'); U(n); a.pick(n).pick('r').op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1); }
  a.drop('r');
  a.roll('W'); for (let j = 0; j < 6; j++) a.invoke('RD', ['sc' + j, 'W']);
  a.invoke('RD', ['zInv', 'W']); a.drop('W'); // SIZE pinned: nothing left
  a.invoke('P', ['p']);
  a.pick('xA').pick('yA').invoke('G1C', []); a.pick('xC').pick('yC').invoke('G1C', []);
  a.push(B_TWIST.c0, 'b0').push(B_TWIST.c1, 'b1');
  { const k = new Kernel(); const [x0, x1, y0, y1] = ['xB0', 'xB1', 'yB0', 'yB1'].map((n) => k.env(n)); const m = (x) => k.mod(x);
    const xx0 = m(k.mul(k.add(x0, x1), k.sub(x0, x1))), xx1 = m(k.mul(k.add(x0, x0), x1));
    const c0 = k.sub(k.mul(xx0, x0), k.mul(xx1, x1)), c1 = k.add(k.mul(xx0, x1), k.mul(xx1, x0));
    k.output(m(k.sub(k.sub(k.mul(k.add(y0, y1), k.sub(y0, y1)), c0), k.in('b0'))), m(k.sub(k.sub(k.mul(k.add(y0, y0), y1), c1), k.in('b1'))), k.small(k.in('b0'), 3), k.small(k.in('b1'), 3));
    a.kernel(k, ['tw0', 'tw1', 'b30', 'b31'], {iters: 300}); a.roll('tw1').roll('tw0'); a.op(OP.NOT, 1, 'ok1').op(OP.VERIFY, 1).op(OP.NOT, 1, 'ok0').op(OP.VERIFY, 1); }
  section('parse+checks');
  STOP('parsed');

  // ---- 2. vk_x = IC0 + n0 IC1 + n1 IC2: joint left-to-right double-and-add over 254 bits, accumulator starts at
  // Q0 = 2^-254 IC0 (baked). Jacobian; any exceptional step (equal / opposite / infinity) forces Z = 0, which is
  // absorbing; Z * zInv == 1 is checked, so every accepted vk_x is the true one.
  a.push(VKC.Q0.x, 'VX').push(VKC.Q0.y, 'VY').push(1, 'VZ');
  for (const j of [3, 2, 1]) a.push(VKC['T' + j].x, 'TX' + j); for (const j of [3, 2, 1]) a.push(VKC['T' + j].y, 'TY' + j);
  a.push(1n << 254n, 'K').pick('n0', 't0').pick('n1', 't1').push(NBITS, 'cnt');
  { const keep = a.st.slice(); const L0 = fixLoop('vkx', a, keep);
    a.loop((s) => {
      s.kernel(kJDbl(), ['VX', 'VY', 'VZ'], {iters: ITERS});
      for (const i of [0, 1]) { const t = 't' + i, b = 'b' + i;
        s.roll(t).pick(t, t + 'd').op(OP.ADD, 2, t); s.pick(t).pick('K').op(OP.GREATERTHANOREQUAL, 2, b);
        s.roll(t).pick(b).pick('K').op(OP.MUL, 2, 'bk').op(OP.SUB, 2, t); }
      s.roll('b1').pick('b1', 'b1d').op(OP.ADD, 2, 'b2').roll('b0').op(OP.ADD, 2, 'j');
      s.pick('j').ifElse((u) => {
        const lk = (tbl, out) => { u.pick('j', 'idx'); u.st.pop(); const d1 = u.depth(tbl + 1); for (const j of [2, 3]) assert.equal(u.depth(tbl + j), d1 + j - 1); u.emit(...pushNum(d1 - 1), OP.ADD, OP.PICK); u.st.push(out); };
        lk('TX', 'xq'); lk('TY', 'yq'); u.kernel(kJAdd(), ['VX', 'VY', 'VZ'], {iters: ITERS});
      });
      s.drop('j'); s.roll('cnt').op(OP.SUB1, 1, 'cnt'); s.pick('cnt').op(OP.NOT, 1, 'done');
    }, {onExit: onExit('vkx', L0)}); }
  for (const n of ['cnt', 't1', 't0', 'K', 'TY1', 'TY2', 'TY3', 'TX1', 'TX2', 'TX3']) a.drop(n);
  { const k = new Kernel(); const m = (x) => k.mod(x); const zi = k.in('zInv'); const zi2 = m(k.mul(zi, zi)), zi3 = m(k.mul(zi2, zi));
    k.output(m(k.sub(k.mul(k.in('VZ'), zi), k.c(1n))), m(k.mul(k.in('VX'), zi2)), m(k.mul(k.in('VY'), zi3)));
    a.kernel(k, ['zchk', 'xV', 'yV'], {iters: 300}); a.roll('zchk').op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); }
  section('vkx');
  STOP('vkx');

  // ---- 3. constants: psi = (gamma1^2, gamma1^3), Frobenius coefficients alpha_j/beta_j = Phi(gamma1^j), omega = eta^2 = eta - 1 ----
  { const k = new Kernel(); const m = (x) => k.mod(x); const g = [[k.c(GAMMA1.c0), k.c(GAMMA1.c1)]];
    const fm = (a0, a1, b0, b1) => [m(k.sub(k.mul(a0, b0), k.mul(a1, b1))), m(k.add(k.mul(a0, b1), k.mul(a1, b0)))];
    for (let j = 2; j <= 5; j++) g.push(fm(...g[j - 2], ...g[0]));
    const eta = k.c(ETA);
    // beta_2 = g21 and beta_3 = g31 are the same nodes as psi's constants: output once, alias below
    k.output(...g[1], ...g[2], ...g.flatMap(([g0, g1], i) => [m(k.sub(g0, k.small(g1, 9))), ...(i === 1 || i === 2 ? [] : [g1])]), eta, k.sub(eta, k.c(1n)));
    a.kernel(k, ['g20', 'g21', 'g30', 'g31', 'al1', 'be1', 'al2', 'al3', 'al4', 'be4', 'al5', 'be5', 'eta', 'om'], {iters: 800}); }
  const BE = {1: 'be1', 2: 'g21', 3: 'g31', 4: 'be4', 5: 'be5'};
  // pair environments: B with P = -A, gamma with P = vk_x, delta with P = C; walks start at the affine points
  { const k = new Kernel(); const neg3 = (x) => k.mul(x, k.c(-3n));
    k.output(neg3(k.env('xA')), k.neg(k.env('yA')), k.neg(k.env('xA')), neg3(k.env('xV')), k.neg(k.env('xV')), neg3(k.env('xC')), k.neg(k.env('xC')));
    a.kernel(k, ['xP3B', 'yPB', 'mxPB', 'xP3G', 'mxPG', 'xP3D', 'mxPD'], {iters: 200}); }
  a.roll('yV').rename('yPG'); a.pick('yC', 'yPD');
  a.push(VKC.gamma.x.c0, 'gx0').push(VKC.gamma.x.c1, 'gx1').push(VKC.gamma.y.c0, 'gy0').push(VKC.gamma.y.c1, 'gy1');
  a.push(VKC.delta.x.c0, 'dx0').push(VKC.delta.x.c1, 'dx1').push(VKC.delta.y.c0, 'dy0').push(VKC.delta.y.c1, 'dy1');
  const QX = {B: ['xB0', 'xB1', 'yB0', 'yB1'], G: ['gx0', 'gx1', 'gy0', 'gy1'], D: ['dx0', 'dx1', 'dy0', 'dy1']};
  for (const w of ['B', 'G', 'D']) { const [x0, x1, y0, y1] = QX[w]; a.pick(x0, w + 'X0').pick(x1, w + 'X1').pick(y0, w + 'Y0').pick(y1, w + 'Y1').push(1, w + 'Z0').push(0, w + 'Z1'); }
  // F = S_c(-X) (the leading NAF digit's c^-1): coefficients (-1)^j s_j, X^6 coefficient 1
  for (let j = 0; j < 6; j++) { a.pick('sc' + j, 'F' + j); if (j % 2) a.op(OP.NEGATE, 1, 'F' + j); }
  a.push(1, 'F6'); for (let j = 7; j < 12; j++) a.push(0, 'F' + j);
  a.pushBytes(Buffer.from(DIGITS.map((d) => (d < 0 ? 0x81 : d))), 'SCH');
  for (const n of ['xA', 'yA', 'xC', 'yC', 'xV', 'n0', 'n1', 'zchk']) if (a.has(n)) a.drop(n);
  section('setup');
  STOP('preloop');

  // ---- 4. the rolled Miller loop: 65 events ----
  { const keep = a.st.slice(); const L0 = fixLoop('miller', a, keep);
    a.loop((s) => {
      s.roll('SCH').push(1).op(OP.SPLIT, 2, 'db', 'SCH').roll('db').op(OP.BIN2NUM, 1, 'd');
      s.mark('sqr'); if (SQR_MODE === 'inline') s.kernel(kSqr(), FN, {iters: ITERS}); else throw new Error('T2_SQR=' + SQR_MODE + ' not implemented');
      s.mark('dbl'); for (const w of ['B', 'G', 'D']) dbl(s, w);
      s.mark('add'); s.pick('d').ifElse((t) => {
        for (const w of ['B', 'G', 'D']) { const [x0, x1, y0, y1] = QX[w];
          t.pick(x0, 'xq0').pick(x1, 'xq1').pick('d', 'dg'); { const k = new Kernel(); const g = k.in('dg'); k.output(k.mul(k.env(y0), g), k.mul(k.env(y1), g)); t.kernel(k, ['yq0', 'yq1'], {iters: 50}); }
          addQ(t, w); }
        // c-fold: d = +1 -> S_c(-X) (c^-1), d = -1 -> S_c(X) (c): G_j = (-d)^j s_j
        { const k = new Kernel(); const nd = k.neg(k.in('dg')); k.output(k.env('sc0'), k.mul(k.env('sc1'), nd), k.env('sc2'), k.mul(k.env('sc3'), nd), k.env('sc4'), k.mul(k.env('sc5'), nd));
          t.pick('d', 'dg'); t.kernel(k, ['G0', 'G1', 'G2', 'G3', 'G4', 'G5'], {iters: 100}); }
        mulc(t);
      });
      s.drop('d'); s.pick('SCH').op(OP.SIZE, 1, 'SCH_', 'n').op(OP.NIP, 2, 'n').op(OP.NOT, 1, 'done');
    }, {onExit: onExit('miller', L0)}); }
  a.drop('SCH');
  section('loop');
  STOP('postloop');

  // ---- 5. terminal: Frobenius additions of all three walks; B endpoint (exact G2 membership) ----
  psi(a, 'xB0', 'xB1', 'yB0', 'yB1', ['xq0', 'xq1', 'yq0', 'yq1']);
  for (const n of ['xq0', 'xq1', 'yq0', 'yq1']) a.pick(n, 'p' + n[0] + n[2]); // keep psi(B) as px0 px1 py0 py1 for the endpoint
  addQ(a, 'B');
  { const k = new Kernel(); k.output(k.mod(k.mul(k.env('xB0'), k.env('om'))), k.mod(k.mul(k.env('xB1'), k.env('om')))); a.kernel(k, ['xq0', 'xq1'], {iters: 50}); }
  a.pick('yB0', 'yq0').pick('yB1', 'yq1'); addQ(a, 'B');
  STOP('endpoint');
  // endpoint, exactly the reviewed SI-GLS terminal: (X : Y : Z) == -psi^3(B) = (omega px, py) with (px, py) = psi(B), and Z != 0
  { const k = new Kernel(); const [X0, X1, Y0, Y1, Z0, Z1] = W_ST('B').map((n) => k.in(n)); const [px0, px1, py0, py1] = ['px0', 'px1', 'py0', 'py1'].map((n) => k.in(n));
    const fs = (a0, a1, b0, b1) => [k.sub(k.mul(a0, b0), k.mul(a1, b1)), k.add(k.mul(a0, b1), k.mul(a1, b0))];
    const [u0, u1] = fs(px0, px1, Z0, Z1), [v0, v1] = fs(py0, py1, Z0, Z1);
    k.output(k.mod(k.sub(X0, k.mul(k.env('om'), u0))), k.mod(k.sub(X1, k.mul(k.env('om'), u1))), k.mod(k.sub(Y0, v0)), k.mod(k.sub(Y1, v1)), k.mod(Z0), k.mod(Z1));
    a.kernel(k, ['ex0', 'ex1', 'ey0', 'ey1', 'ez0', 'ez1'], {iters: 1000});
    a.op(OP.BOOLOR, 2, 'znz').op(OP.VERIFY, 1); for (let i = 0; i < 4; i++) a.op(OP.NOT, 1, 'q').op(OP.VERIFY, 1); }
  for (const w of ['G', 'D']) { const [x0, x1, y0, y1] = QX[w];
    psi(a, x0, x1, y0, y1, ['xq0', 'xq1', 'yq0', 'yq1']); addQ(a, w);
    { const k = new Kernel(); k.output(k.mod(k.mul(k.env(x0), k.env('om'))), k.mod(k.mul(k.env(x1), k.env('om')))); a.kernel(k, ['xq0', 'xq1'], {iters: 50}); }
    a.pick(y0, 'yq0').pick(y1, 'yq1'); addQ(a, w);
    for (const n of W_ST(w)) a.drop(n); }
  section('terminal-lines');
  STOP('termlines');
  // F *= m_alpha_beta (baked monic class rep) * S_c(eta X) ([c^(p^2)]): G_j = s_j eta^j, eta^(0..5) = 1, eta, om, -1, -eta, -om
  for (let j = 0; j < 6; j++) a.push(VKC.MAB[j], 'G' + j); mulc(a);
  { const k = new Kernel(); const s = [0, 1, 2, 3, 4, 5].map((j) => k.env('sc' + j)), e = k.env('eta'), o = k.env('om'), m = (x) => k.mod(x);
    k.output(s[0], m(k.mul(s[1], e)), m(k.mul(s[2], o)), k.neg(s[3]), k.neg(m(k.mul(s[4], e))), k.neg(m(k.mul(s[5], o)))); a.kernel(k, ['G0', 'G1', 'G2', 'G3', 'G4', 'G5'], {iters: 200}); }
  mulc(a);
  STOP('pfin');
  // residue: odd part of F * sigma(Fr1(X)) * sigma(Fr1(eta X)) == 0, Fr1 = Frob(S_c) = A + X^6 B with
  // A = (s0 + 18, s_j al_j), B = (-1, s_j be_j); sigma(Fr1)(X) = Fr1(-X): factor (-1)^j; sigma(Fr1(eta X)): factor (-eta)^j = 1, -eta, om, 1, -eta, om
  { const k = new Kernel(); const s = [0, 1, 2, 3, 4, 5].map((j) => k.env('sc' + j)), m = (x) => k.mod(x), E = (n) => k.env(n);
    const A = [k.add(s[0], k.c(18n)), ...[1, 2, 3, 4, 5].map((j) => m(k.mul(s[j], E('al' + j))))], B = [k.c(-1n), ...[1, 2, 3, 4, 5].map((j) => m(k.mul(s[j], E(BE[j]))))];
    const sg = (x, j) => (j % 2 ? k.neg(x) : x);
    const ne = k.neg(E('eta')), f2c = [null, ne, E('om'), null, ne, E('om')]; const tw = (x, j) => (f2c[j] ? m(k.mul(x, f2c[j])) : x);
    // j = 0 coefficients are shared by both factors: output once, copied below
    k.output(...A.map(sg), ...B.map(sg), ...A.slice(1).map((x, i) => tw(x, i + 1)), ...B.slice(1).map((x, i) => tw(x, i + 1)));
    a.kernel(k, ['A0', 'A1', 'A2', 'A3', 'A4', 'A5', 'B0', 'B1', 'B2', 'B3', 'B4', 'B5', 'a1', 'a2', 'a3', 'a4', 'a5', 'b1', 'b2', 'b3', 'b4', 'b5'], {iters: 1500});
    a.pick('A0', 'a0').pick('B0', 'b0'); }
  mul12(a, false, FN);
  STOP('p1');
  for (let j = 0; j < 6; j++) { a.rename('a' + j, 'A' + j); a.rename('b' + j, 'B' + j); }
  mul12(a, true, ['o1', 'o3', 'o5', 'o7', 'o9', 'o11']);
  for (let i = 0; i < 5; i++) a.op(OP.BOOLOR, 2, 'any'); // any odd coefficient nonzero (each reduced mod p: zero iff == 0 mod p)
  a.op(OP.NOT, 1, 'result');
  section('terminal-residue');
  assert.equal(a.alt.length, 0, 'altstack not empty');
  a.op(OP.TOALT, 1); a.emit(OP.BEGIN, OP.DROP, OP.DEPTH, OP.NOT, OP.UNTIL, OP.FROMALT); a.st = ['result'];
  section('cleanup');
  const code = Uint8Array.from([...a.prologue(), ...a.code]);
  info.marks = a.marks.map((m) => ({name: m.name, off: m.off + a.prologue().length}));
  info.prologue = a.prologue().length; info.funcs = Object.fromEntries([...a.ctx.funcs].filter(([, f]) => f.id !== null).map(([n, f]) => [n, f.code.length]));
  return {redeem: code, info};
}
export function buildPartial(label) {
  try { buildRedeem({stop: label}); } catch (e) { if (!e.stopAt) throw e; return {code: Uint8Array.from([...e.asm.prologue(), ...e.asm.code]), names: e.asm.st.slice()}; }
  throw new Error('label not reached: ' + label);
}
