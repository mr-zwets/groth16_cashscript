// BLS12-381 arithmetic kernels (DAGs for the scheduling assembler). Each one is checked against the blsmath reference
// and measured in the libauth VM by measure.mjs. Notation: t = z^6 - 1, so Phi(a0 + a1 u)(z) = a0 + a1 t.
import {Kernel} from './asm.mjs';

const ops = (k) => ({I: (n) => k.in(n), E: (n) => k.env(n), m: (x) => k.mod(x), mul: (a, b) => k.mul(a, b), add: (a, b) => k.add(a, b), sub: (a, b) => k.sub(a, b)});

// B projective doubling (3b' = 12 + 12u) + line (E - B, 3X^2, -H) at P = -A, evaluated at +-z, and F+- <- F+-^2 * L(+-z).
// env: t, xz23 = 3 xA z^2, xz23t = xz23 t, yz3 = yA z^3, yz3t = yz3 t   (yP = -yA, so the odd part is +yA z^3 Phi(H))
export function kBDbl() {
  const k = new Kernel(); const {I, E, m, mul, add, sub} = ops(k);
  const [X0, X1, Y0, Y1, Z0, Z1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'].map(I);
  const B0 = m(mul(add(Y0, Y1), sub(Y0, Y1))), B1 = m(mul(add(Y0, Y0), Y1));
  const C0 = mul(add(Z0, Z1), sub(Z0, Z1)), C1 = mul(add(Z0, Z0), Z1);
  const E0 = m(k.small(sub(C0, C1), 12)), E1 = m(k.small(add(C0, C1), 12));
  const F0 = k.small(E0, 3), F1 = k.small(E1, 3);
  const t0 = mul(X0, Y0), t1 = mul(X1, Y1), t2 = mul(add(X0, X1), add(Y0, Y1));
  const XY0 = m(sub(t0, t1)), XY1 = m(sub(sub(t2, t0), t1));
  const D0 = k.small(sub(B0, F0), 2), D1 = k.small(sub(B1, F1), 2);
  const X30 = m(sub(mul(XY0, D0), mul(XY1, D1))), X31 = m(add(mul(XY0, D1), mul(XY1, D0)));
  const G0 = add(B0, F0), G1 = add(B1, F1);
  const Y30 = m(sub(mul(add(G0, G1), sub(G0, G1)), k.small(mul(add(E0, E1), sub(E0, E1)), 12)));
  const Y31 = m(sub(k.small(mul(G0, G1), 2), k.small(mul(E0, E1), 24)));
  const S0 = add(Y0, Z0), S1 = add(Y1, Z1);
  const H0 = m(sub(sub(mul(add(S0, S1), sub(S0, S1)), B0), m(C0))), H1 = m(sub(sub(mul(add(S0, S0), S1), B1), m(C1)));
  const B40 = k.small(B0, 4), B41 = k.small(B1, 4);
  const Z30 = m(sub(mul(B40, H0), mul(B41, H1))), Z31 = m(add(mul(B40, H1), mul(B41, H0)));
  const X20 = mul(add(X0, X1), sub(X0, X1)), X21 = mul(add(X0, X0), X1);
  const e = m(k.sum(sub(E0, B0), mul(E('t'), sub(E1, B1)), mul(E('xz23'), X20), mul(E('xz23t'), X21)));
  const o = m(add(mul(E('yz3'), H0), mul(E('yz3t'), H1)));
  const Fp = I('Fp'), Fm = I('Fm');
  k.output(X30, X31, Y30, Y31, Z30, Z31, m(mul(mul(Fp, Fp), add(e, o))), m(mul(mul(Fm, Fm), sub(e, o))));
  return k;
}
// B projective mixed addition with B = (xq, yq) (noble pointAdd) + line (t0 xq - t1 yq, -t0, t1) at +-z, times c^-1(+-z).
// env: xq0 xq1 yq0 yq1 t xz2 xz2t (= xA z^2 (t)) yz3 yz3t cp cm
export function kBAdd() {
  const k = new Kernel(); const {I, E, m, mul, add, sub} = ops(k);
  const [X0, X1, Y0, Y1, Z0, Z1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'].map(I); const [xq0, xq1, yq0, yq1] = ['xq0', 'xq1', 'yq0', 'yq1'].map(E);
  const fm = (a0, a1, b0, b1) => { const u0 = mul(a0, b0), u1 = mul(a1, b1), u2 = mul(add(a0, a1), add(b0, b1)); return [sub(u0, u1), sub(sub(u2, u0), u1)]; };
  const fs = (a0, a1, b0, b1) => [sub(mul(a0, b0), mul(a1, b1)), add(mul(a0, b1), mul(a1, b0))];
  const [qz0, qz1] = fs(yq0, yq1, Z0, Z1); const T00 = m(sub(Y0, qz0)), T01 = m(sub(Y1, qz1));
  const [xz0, xz1] = fs(xq0, xq1, Z0, Z1); const T10 = m(sub(X0, xz0)), T11 = m(sub(X1, xz1));
  const T20 = m(mul(add(T10, T11), sub(T10, T11))), T21 = m(mul(add(T10, T10), T11));
  const [a0, a1] = fm(T20, T21, T10, T11); const T30 = m(a0), T31 = m(a1);
  const [b0, b1] = fm(T20, T21, X0, X1); const T40 = m(b0), T41 = m(b1);
  const S0 = m(mul(add(T00, T01), sub(T00, T01))), S1 = m(mul(add(T00, T00), T01));
  const [c0, c1] = fm(S0, S1, Z0, Z1);
  const T50 = m(add(sub(T30, k.small(T40, 2)), c0)), T51 = m(add(sub(T31, k.small(T41, 2)), c1));
  const [x30, x31] = fm(T10, T11, T50, T51);
  const [y0a, y1a] = fs(sub(T40, T50), sub(T41, T51), T00, T01), [y0b, y1b] = fs(T30, T31, Y0, Y1);
  const [z30, z31] = fm(Z0, Z1, T30, T31);
  // line: Phi(t0 xq - t1 yq)(z) - xz2 Phi(t0)(z) [even]; yP z^3 Phi(t1)(z) = -yA z^3 Phi(t1) [odd]
  const [l00, l01] = fs(T00, T01, xq0, xq1), [l10, l11] = fs(T10, T11, yq0, yq1);
  const e = m(k.sum(sub(l00, l10), mul(E('t'), sub(l01, l11)), k.neg(mul(E('xz2'), T00)), k.neg(mul(E('xz2t'), T01))));
  const o = m(add(mul(E('yz3'), T10), mul(E('yz3t'), T11)));
  k.output(m(x30), m(x31), m(sub(y0a, y0b)), m(sub(y1a, y1b)), m(z30), m(z31), m(mul(mul(I('Fp'), sub(e, o)), E('cp'))), m(mul(mul(I('Fm'), add(e, o)), E('cm'))));
  return k;
}
// delta step with the slope recursion (BN sound-si-gls style): reads lam_j (n0 n1); c_j = (lam_{j-1} + lam_j) x_j - c_{j-1};
// line (c_j, -lam_j, 1) at C: even = Phi(c_j)(z) - xC z^2 Phi(lam_j)(z), odd = yC z^3; x_{j+1} = lam_j^2 - x_j - s.
// env: t, cz2 (= xC z^2), cz2t, ycz3 (= yC z^3)
export function kDStep() {
  const k = new Kernel(); const {I, E, m, mul, add, sub} = ops(k);
  const [x0, x1, c0, c1, l0, l1, n0, n1, s0, s1] = ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'n0', 'n1', 's0', 's1'].map(I);
  const a0 = add(l0, n0), a1 = add(l1, n1);
  const u0 = mul(a0, x0), u1 = mul(a1, x1), u2 = mul(add(a0, a1), add(x0, x1));
  const nc0 = m(sub(sub(u0, u1), c0)), nc1 = m(sub(sub(sub(u2, u0), u1), c1));
  const e = m(k.sum(nc0, mul(E('t'), nc1), k.neg(mul(E('cz2'), n0)), k.neg(mul(E('cz2t'), n1))));
  const nx0 = m(sub(sub(mul(add(n0, n1), sub(n0, n1)), x0), s0)), nx1 = m(sub(sub(mul(add(n0, n0), n1), x1), s1));
  k.output(nx0, nx1, nc0, nc1, n0, n1, m(mul(I('Fp'), add(e, E('ycz3')))), m(mul(I('Fm'), sub(e, E('ycz3')))));
  return k;
}
// delta line fully baked: (c_j, lam_j) read as 4 constants; even = c0 + c1 t - cz2 l0 - cz2t l1, odd = yC z^3
export function kDBaked() {
  const k = new Kernel(); const {I, E, m, mul, add, sub} = ops(k);
  const [c0, c1, l0, l1] = ['c0', 'c1', 'l0', 'l1'].map(I);
  const e = m(k.sum(c0, mul(E('t'), c1), k.neg(mul(E('cz2'), l0)), k.neg(mul(E('cz2t'), l1))));
  k.output(m(mul(I('Fp'), add(e, E('ycz3')))), m(mul(I('Fm'), sub(e, E('ycz3')))));
  return k;
}
// delta line baked as its even part at the two predetermined combinations: e_j = a_j + b_j t + c_j cz2 + d_j cz2t is linear in
// (1, t, cz2, cz2t); same as kDBaked (kept for the record: no cheaper form without z-dependent precomputation)
// monic degree-6 evaluation at +-x: (Ev + Od, Ev - Od) from s0..s5 and x..x6
export function kEval() {
  const k = new Kernel(); const s = [0, 1, 2, 3, 4, 5].map((i) => k.in('in' + i)); const x = [6, 7, 8, 9, 10, 11].map((i) => k.in('in' + i));
  const ev = k.mod(k.sum(s[0], k.mul(s[2], x[1]), k.mul(s[4], x[3]), x[5]));
  const od = k.mod(k.sum(k.mul(s[1], x[0]), k.mul(s[3], x[2]), k.mul(s[5], x[4])));
  return k.output(k.add(ev, od), k.sub(ev, od));
}
// 16-entry subset-product table from v0..v3: T[n] = prod over bits of n; outputs T[15] .. T[0]
export function kTable() {
  const k = new Kernel(); const v = [0, 1, 2, 3].map((i) => k.in('in' + i)); const T = [k.c(1n)];
  for (let n = 1; n < 16; n++) { const lo = n & -n, b = Math.log2(lo); T[n] = n === lo ? v[b] : k.mod(k.mul(T[n ^ lo], v[b])); }
  return k.output(...T.slice().reverse());
}
// boundary: R <- R rho + F+ S(-z) - F- S(z); F+- <- S(+-z)
export function kBoundary() {
  const k = new Kernel(); const R = k.in('R');
  return k.output(k.in('Sp'), k.in('Sm'), k.mod(k.sub(k.add(k.mul(R, k.env('rho')), k.mul(k.in('Fp'), k.in('Sm'))), k.mul(k.in('Fm'), k.in('Sp')))));
}
// GLS fold of one event at one sign: F <- F * T0[i0] * T1[i1] (the two table entries already picked)
export function kGlsMul() {
  const k = new Kernel(); return k.output(k.mod(k.mul(k.mul(k.in('u'), k.in('v')), k.in('F'))));
}
// Horner over 4 quotient words: acc <- acc z^8 + q0 z^6 + q1 z^4 + q2 z^2 + q3
export function kHorner4() {
  const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n);
  return k.output(k.mod(k.sum(k.mul(I('acc'), E('z8')), k.mul(I('q0'), E('z6')), k.mul(I('q1'), E('z4')), k.mul(I('q2'), E('z2')), I('q3'))));
}
// z powers, t, and the per-input loop environment from (xA, yA, xC, yC)
export function kPowers() {
  const k = new Kernel(); const z = k.env('z'); const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
  const z2 = m(mul(z, z)), z3 = m(mul(z2, z)), z4 = m(mul(z2, z2)), z5 = m(mul(z4, z)), z6 = m(mul(z3, z3));
  const t = k.sub(z6, k.c(1n));
  const xz2 = m(mul(k.in('xA'), z2)), yz3 = m(mul(k.in('yA'), z3)), cz2 = m(mul(k.in('xC'), z2)), ycz3 = m(mul(k.in('yC'), z3));
  return k.output(z2, z3, z4, z5, z6, t, xz2, m(mul(xz2, t)), k.small(xz2, 3), m(mul(k.small(xz2, 3), t)), yz3, m(mul(yz3, t)), cz2, m(mul(cz2, t)), ycz3);
}
// G1 curve check y^2 - x^3 - 4 == 0 (mod p) and the twist check y^2 - x^3 - 4(1+u)
export function kG1Check() { const k = new Kernel(); const x = k.in('x'), y = k.in('y'); return k.output(k.mod(k.sub(k.mul(y, y), k.add(k.mul(k.mul(x, x), x), k.c(4n))))); }
export function kG2Check() {
  const k = new Kernel(); const [x0, x1, y0, y1] = ['x0', 'x1', 'y0', 'y1'].map((n) => k.env(n)); const m = (x) => k.mod(x);
  const xx0 = m(k.mul(k.add(x0, x1), k.sub(x0, x1))), xx1 = m(k.mul(k.add(x0, x0), x1));
  const c0 = k.sub(k.mul(xx0, x0), k.mul(xx1, x1)), c1 = k.add(k.mul(xx0, x1), k.mul(xx1, x0));
  return k.output(m(k.sub(k.sub(k.mul(k.add(y0, y1), k.sub(y0, y1)), c0), k.c(4n))), m(k.sub(k.sub(k.mul(k.add(y0, y0), y1), c1), k.c(4n))));
}
