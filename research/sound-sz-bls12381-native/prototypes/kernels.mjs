// BLS12-381 SI-GLS kernels (DAGs for the scheduling assembler) and their value-level references.
// Conventions (all evaluations at +-z; t = z^6 - 1 so Phi(a)(z) = a0 + a1 t; lines are M-type):
//   L(X) = Phi(c0) + xP Phi(c1) X^2 + yP Phi(c2) X^3  ->  L(+-z) = e +- o,
//   e = c0_0 + c0_1 t + xP z^2 (c1_0 + c1_1 t),  o = yP z^3 (c2_0 + c2_1 t).
// B pair: P = -A (xP = xA, yP = -yA); delta pair: P = C. Env names: t, xz2 = xA z^2, xz2t = xA z^2 t,
// yz3 = yA z^3, yz3t = yA z^3 t; cz2 = xC z^2, cz2t = xC z^2 t, cy3 = yC z^3.
import {Kernel} from './asm.mjs';

const ops = (k) => {
  const I = (n) => k.in(n), E = (n) => k.env(n), m = (x) => k.mod(x), mul = (a, b) => k.mul(a, b), add = (a, b) => k.add(a, b), sub = (a, b) => k.sub(a, b);
  const sq2 = (a0, a1) => [mul(add(a0, a1), sub(a0, a1)), mul(add(a0, a0), a1)];          // (a0+a1u)^2, u^2 = -1
  const km = (a0, a1, b0, b1) => { const u0 = mul(a0, b0), u1 = mul(a1, b1), u2 = mul(add(a0, a1), add(b0, b1)); return [sub(u0, u1), sub(sub(u2, u0), u1)]; }; // Karatsuba
  const sm = (a0, a1, b0, b1) => [sub(mul(a0, b0), mul(a1, b1)), add(mul(a0, b1), mul(a1, b0))]; // schoolbook
  return {I, E, m, mul, add, sub, sq2, km, sm};
};

// ---- projective doubling + line + F^2 accumulation (inputs X,Y,Z (Fp2), Fp, Fm) ----
export function kBDbl() {
  const k = new Kernel(); const {I, E, m, mul, add, sub, sq2, km} = ops(k);
  const [X0, X1, Y0, Y1, Z0, Z1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'].map(I);
  const [b0, b1] = sq2(Y0, Y1).map(m), [c0, c1] = sq2(Z0, Z1).map(m);
  // E = 3b' C = 12 (1+u)(C0 + C1 u) = 12 (C0 - C1) + 12 (C0 + C1) u ; F = 3E
  const E0 = k.small(sub(c0, c1), 12), E1 = k.small(add(c0, c1), 12);
  const F0 = k.small(E0, 3), F1 = k.small(E1, 3);
  const [s0, s1] = [add(Y0, Z0), add(Y1, Z1)]; const [ss0, ss1] = sq2(s0, s1);
  const H0 = m(sub(sub(ss0, b0), c0)), H1 = m(sub(sub(ss1, b1), c1));           // H = 2YZ
  const [xy0, xy1] = km(X0, X1, Y0, Y1).map(m);
  const D0 = k.small(sub(b0, F0), 2), D1 = k.small(sub(b1, F1), 2);
  const [X30, X31] = km(xy0, xy1, D0, D1).map(m);
  const G0 = add(b0, F0), G1 = add(b1, F1); const [g0, g1] = sq2(G0, G1); const [e0, e1] = sq2(E0, E1);
  const Y30 = m(sub(g0, k.small(e0, 12))), Y31 = m(sub(g1, k.small(e1, 12)));
  const [z0, z1] = km(k.small(b0, 4), k.small(b1, 4), H0, H1).map(m);
  const [xx0, xx1] = sq2(X0, X1);
  // line: c0 = E - B, c1 = 3X^2, c2 = -H; P = -A: o = (-yA z^3)(-H0 - H1 t) = yz3 H0 + yz3t H1
  const e = m(k.sum(sub(E0, b0), mul(sub(E1, b1), E('t')), mul(k.small(xx0, 3), E('xz2')), mul(k.small(xx1, 3), E('xz2t'))));
  const o = m(add(mul(H0, E('yz3')), mul(H1, E('yz3t'))));
  const Fp = I('Fp'), Fm = I('Fm');
  k.output(X30, X31, Y30, Y31, z0, z1, m(mul(mul(Fp, Fp), add(e, o))), m(mul(mul(Fm, Fm), sub(e, o))));
  return k;
}
export const refBDbl = (P, env, v) => { // v: {X0..Z1, Fp, Fm}
  const {mod} = env; const f = (a0, a1) => ({c0: a0, c1: a1});
  const F2 = env.F2; const T = [f(v.X0, v.X1), f(v.Y0, v.Y1), f(v.Z0, v.Z1)]; const o = env.projDbl(T);
  const [c0, c1, c2] = o.line; const e = mod(c0.c0 + c0.c1 * env.t + env.xz2 * (c1.c0 + c1.c1 * env.t)); const od = mod(-env.yA * env.z3 * (c2.c0 + c2.c1 * env.t));
  return [o.T[0].c0, o.T[0].c1, o.T[1].c0, o.T[1].c1, o.T[2].c0, o.T[2].c1, mod(v.Fp * v.Fp * (e + od)), mod(v.Fm * v.Fm * (e - od))];
};

// ---- projective mixed addition with affine (xq, yq) + line + accumulation * (cp, cm) ----
export function kBAdd() {
  const k = new Kernel(); const {I, E, m, mul, add, sub, sq2, km, sm} = ops(k);
  const [X0, X1, Y0, Y1, Z0, Z1, xq0, xq1, yq0, yq1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'xq0', 'xq1', 'yq0', 'yq1'].map(I);
  const [qz0, qz1] = sm(yq0, yq1, Z0, Z1); const th0 = m(sub(Y0, qz0)), th1 = m(sub(Y1, qz1));
  const [xz0, xz1] = sm(xq0, xq1, Z0, Z1); const la0 = m(sub(X0, xz0)), la1 = m(sub(X1, xz1));
  const [Cc0, Cc1] = sq2(th0, th1).map(m), [D0, D1] = sq2(la0, la1).map(m);
  const [E0, E1] = km(la0, la1, D0, D1).map(m), [F0, F1] = km(Z0, Z1, Cc0, Cc1).map(m), [G0, G1] = km(X0, X1, D0, D1).map(m);
  const H0 = sub(add(E0, F0), k.small(G0, 2)), H1 = sub(add(E1, F1), k.small(G1, 2));
  const [x30, x31] = km(la0, la1, H0, H1); const [a0, a1] = sm(th0, th1, sub(G0, H0), sub(G1, H1)), [b0, b1] = sm(Y0, Y1, E0, E1);
  const [z30, z31] = km(Z0, Z1, E0, E1);
  // line (theta xq - la yq, -theta, la): e = c0_0 + c0_1 t - xz2 th0 - xz2t th1 ; o = (-yA z^3)(la0 + la1 t)
  const [tx0, tx1] = sm(th0, th1, xq0, xq1), [ly0, ly1] = sm(la0, la1, yq0, yq1);
  const e = m(k.sum(sub(tx0, ly0), mul(sub(tx1, ly1), E('t')), k.neg(add(mul(th0, E('xz2')), mul(th1, E('xz2t'))))));
  const o = m(k.neg(add(mul(la0, E('yz3')), mul(la1, E('yz3t')))));
  k.output(m(x30), m(x31), m(sub(a0, b0)), m(sub(a1, b1)), m(z30), m(z31), m(mul(mul(I('Fp'), add(e, o)), I('cp'))), m(mul(mul(I('Fm'), sub(e, o)), I('cm'))));
  return k;
}

// ---- affine doubling with a witnessed slope (x, y, lam): checks 2 y lam = 3 x^2 (two residues output, to be tested == 0) ----
// line (lam x - y, -lam, 1): e = cc0 + cc1 t - xz2 lam0 - xz2t lam1, o = -yz3 (per-input constant, env 'nyz3')
export function kADbl() {
  const k = new Kernel(); const {I, E, m, mul, add, sub, sq2, km} = ops(k);
  const [x0, x1, y0, y1, l0, l1] = ['x0', 'x1', 'y0', 'y1', 'l0', 'l1'].map(I);
  const [xx0, xx1] = sq2(x0, x1); const [yl0, yl1] = km(y0, y1, l0, l1);
  const r0 = m(sub(k.small(yl0, 2), k.small(xx0, 3))), r1 = m(sub(k.small(yl1, 2), k.small(xx1, 3)));
  const [ll0, ll1] = sq2(l0, l1); const nx0 = m(sub(ll0, k.small(x0, 2))), nx1 = m(sub(ll1, k.small(x1, 2)));
  const [lx0, lx1] = km(l0, l1, x0, x1); const cc0 = m(sub(lx0, y0)), cc1 = m(sub(lx1, y1));
  const [ln0, ln1] = km(l0, l1, nx0, nx1); const ny0 = m(sub(cc0, ln0)), ny1 = m(sub(cc1, ln1));
  const e = m(k.sum(cc0, mul(cc1, E('t')), k.neg(add(mul(l0, E('xz2')), mul(l1, E('xz2t'))))));
  const o = E('nyz3');
  const Fp = I('Fp'), Fm = I('Fm');
  k.output(r0, r1, nx0, nx1, ny0, ny1, m(mul(mul(Fp, Fp), add(e, o))), m(mul(mul(Fm, Fm), sub(e, o))));
  return k;
}
// ---- affine addition T + Q with a witnessed slope: lam (xq - x) = yq - y ; needs xq != x (guard outside) ----
export function kAAdd() {
  const k = new Kernel(); const {I, E, m, mul, add, sub, km} = ops(k);
  const [x0, x1, y0, y1, l0, l1, xq0, xq1, yq0, yq1] = ['x0', 'x1', 'y0', 'y1', 'l0', 'l1', 'xq0', 'xq1', 'yq0', 'yq1'].map(I);
  const dx0 = sub(xq0, x0), dx1 = sub(xq1, x1); const [a0, a1] = km(l0, l1, dx0, dx1);
  const r0 = m(sub(a0, sub(yq0, y0))), r1 = m(sub(a1, sub(yq1, y1)));
  const [ll0, ll1] = [mul(add(l0, l1), sub(l0, l1)), mul(add(l0, l0), l1)];
  const nx0 = m(sub(sub(ll0, x0), xq0)), nx1 = m(sub(sub(ll1, x1), xq1));
  const [lx0, lx1] = km(l0, l1, x0, x1); const cc0 = m(sub(lx0, y0)), cc1 = m(sub(lx1, y1));
  const [ln0, ln1] = km(l0, l1, nx0, nx1); const ny0 = m(sub(cc0, ln0)), ny1 = m(sub(cc1, ln1));
  const e = m(k.sum(cc0, mul(cc1, E('t')), k.neg(add(mul(l0, E('xz2')), mul(l1, E('xz2t'))))));
  const o = E('nyz3');
  k.output(r0, r1, m(sub(dx0, k.c(0n))), m(dx1), nx0, nx1, ny0, ny1, m(mul(mul(I('Fp'), add(e, o)), I('cp'))), m(mul(mul(I('Fm'), sub(e, o)), I('cm'))));
  return k;
}

// ---- delta step j (baked slope n = lam_j; state x_j, c_{j-1}, lam_{j-1}; s = x_j for doubling, x_delta for addition) ----
// c_j = (lam_{j-1} + lam_j) x_j - c_{j-1}; line (c_j, -lam_j, 1) at C: e = c_j0 + c_j1 t - cz2 n0 - cz2t n1, o = cy3 (constant)
// x_{j+1} = lam_j^2 - x_j - s
export function kDStep() {
  const k = new Kernel(); const {I, E, m, mul, add, sub, km} = ops(k);
  const [x0, x1, c0, c1, l0, l1, n0, n1, s0, s1] = ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'n0', 'n1', 's0', 's1'].map(I);
  const [u0, u1] = km(add(l0, n0), add(l1, n1), x0, x1); const nc0 = m(sub(u0, c0)), nc1 = m(sub(u1, c1));
  const e = m(k.sum(nc0, mul(nc1, E('t')), k.neg(add(mul(n0, E('cz2')), mul(n1, E('cz2t'))))));
  const nx0 = m(sub(sub(mul(add(n0, n1), sub(n0, n1)), x0), s0)), nx1 = m(sub(sub(mul(add(n0, n0), n1), x1), s1));
  k.output(nx0, nx1, nc0, nc1, n0, n1, m(mul(I('Fp'), add(e, E('cy3')))), m(mul(I('Fm'), sub(e, E('cy3')))));
  return k;
}
// ---- delta step with a fully baked line (n = lam_j, cc = c_j both baked): no recursion ----
export function kDLine() {
  const k = new Kernel(); const {I, E, m, mul, add, sub} = ops(k);
  const [n0, n1, cc0, cc1] = ['n0', 'n1', 'cc0', 'cc1'].map(I);
  const e = m(k.sum(cc0, mul(cc1, E('t')), k.neg(add(mul(n0, E('cz2')), mul(n1, E('cz2t'))))));
  k.output(m(mul(I('Fp'), add(e, E('cy3')))), m(mul(I('Fm'), sub(e, E('cy3')))));
  return k;
}
// ---- monic degree-6 evaluation at +-x from s0..s5 and x..x6 ----
export function kEval() {
  const k = new Kernel(); const s = [0, 1, 2, 3, 4, 5].map((i) => k.in('in' + i)); const x = [6, 7, 8, 9, 10, 11].map((i) => k.in('in' + i));
  const ev = k.mod(k.sum(s[0], k.mul(s[2], x[1]), k.mul(s[4], x[3]), x[5]));
  const od = k.mod(k.sum(k.mul(s[1], x[0]), k.mul(s[3], x[2]), k.mul(s[5], x[4])));
  return k.output(k.add(ev, od), k.sub(ev, od));
}
// ---- 16-entry subset product table ----
export function kTable(mult = true) {
  const k = new Kernel(); const v = [0, 1, 2, 3].map((i) => k.in('in' + i)); const T = [k.c(mult ? 1n : 0n)];
  for (let n = 1; n < 16; n++) { const lo = n & -n, b = Math.log2(lo); T[n] = n === lo ? v[b] : mult ? k.mod(k.mul(T[n ^ lo], v[b])) : k.add(T[n ^ lo], v[b]); }
  return k.output(...T.slice().reverse());
}
// ---- boundary: R <- R rho + F+ S(-z) - F- S(+z) ----
export function kBound() {
  const k = new Kernel(); const R = k.in('R');
  return k.output(k.in('Sp'), k.in('Sm'), k.mod(k.sub(k.add(k.mul(R, k.env('rho')), k.mul(k.in('Fp'), k.in('Sm'))), k.mul(k.in('Fm'), k.in('Sp')))));
}

// ---- lazy-reduction variants (same outputs mod p) ----
// ADbl2: cc = lam x - y is not reduced (used only in a sum and in one product with t)
export function kADbl2() {
  const k = new Kernel(); const {I, E, m, mul, add, sub, sq2, km} = ops(k);
  const [x0, x1, y0, y1, l0, l1] = ['x0', 'x1', 'y0', 'y1', 'l0', 'l1'].map(I);
  const [xx0, xx1] = sq2(x0, x1); const [yl0, yl1] = km(y0, y1, l0, l1);
  const r0 = m(sub(k.small(yl0, 2), k.small(xx0, 3))), r1 = m(sub(k.small(yl1, 2), k.small(xx1, 3)));
  const [ll0, ll1] = sq2(l0, l1); const nx0 = m(sub(ll0, k.small(x0, 2))), nx1 = m(sub(ll1, k.small(x1, 2)));
  const [lx0, lx1] = km(l0, l1, x0, x1); const cc0 = sub(lx0, y0), cc1 = sub(lx1, y1);
  const [ln0, ln1] = km(l0, l1, nx0, nx1); const ny0 = m(sub(cc0, ln0)), ny1 = m(sub(cc1, ln1));
  const e = m(k.sum(cc0, mul(cc1, E('t')), k.neg(add(mul(l0, E('xz2')), mul(l1, E('xz2t'))))));
  const Fp = I('Fp'), Fm = I('Fm');
  k.output(r0, r1, nx0, nx1, ny0, ny1, m(mul(mul(Fp, Fp), add(e, E('nyz3')))), m(mul(mul(Fm, Fm), sub(e, E('nyz3')))));
  return k;
}
// DStep2: c_j kept unreduced across steps (bounded: |c| < 2^770)
export function kDStep2() {
  const k = new Kernel(); const {I, E, m, mul, add, sub, km} = ops(k);
  const [x0, x1, c0, c1, l0, l1, n0, n1, s0, s1] = ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'n0', 'n1', 's0', 's1'].map(I);
  const [u0, u1] = km(add(l0, n0), add(l1, n1), x0, x1); const nc0 = sub(u0, c0), nc1 = sub(u1, c1);
  const e = m(k.sum(nc0, mul(nc1, E('t')), k.neg(add(mul(n0, E('cz2')), mul(n1, E('cz2t'))))));
  const nx0 = m(sub(sub(mul(add(n0, n1), sub(n0, n1)), x0), s0)), nx1 = m(sub(sub(mul(add(n0, n0), n1), x1), s1));
  k.output(nx0, nx1, nc0, nc1, n0, n1, m(mul(I('Fp'), add(e, E('cy3')))), m(mul(I('Fm'), sub(e, E('cy3')))));
  return k;
}
