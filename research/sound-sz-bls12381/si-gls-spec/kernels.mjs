// BLS12-381 SI-GLS kernels (lazy-reduction DAGs), scheduled by dsl.mjs's local search and measured on the libauth
// bch-spec VM (standard mode). Every kernel's VM outputs are checked against the BigInt simulation, and the
// simulation against independent math (noble twist point ops, the line polynomials of blsmath.mjs evaluated at z).
//   node kernels.mjs [iters]     (writes kernels.json)
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {encodeDataPush} from '@bitauth/libauth';
import {Kernel, measureKernel, runBody, OP, pushNum, P} from './dsl.mjs';
import {Asm} from './asm.mjs';
import {F2, G1, G2, p, mod, f2, peval, lineAffPoly, lineGenPoly, B_TWIST, FROB, AX} from './blsmath.mjs';
assert.equal(P, p);
const ITERS = Number(process.argv[2] ?? 20000);
let ctr = 0; const rnd = () => BigInt('0x' + createHash('sha256').update('blsk:' + ctr++).digest('hex') + createHash('sha256').update('blsk2:' + ctr).digest('hex')) % P;
const md = (x) => mod(x);
const results = {};
const show = (m) => { results[m.label] = {opCost: m.opCost, bytes: m.bytes, naiveSim: m.naiveSim, breakdown: m.breakdown}; console.log(m.label.padEnd(56), 'op', String(m.opCost).padStart(7), ' (sched-sim', m.simCost, 'naive', m.naiveSim + ')  code', m.bytes, 'B'); return m; };
// sample data: P0 = -A, twist points, z, t = z^6 - 1
const A = G1.BASE.multiply(rnd() % (1n << 200n)).negate().toAffine();
const Bpt = G2.BASE.multiply(rnd() % (1n << 200n)), Tpt = Bpt.multiply(rnd() % (1n << 200n));
const z = rnd(), t = md(z ** 6n - 1n), z2 = md(z * z), z3 = md(z2 * z);
const Ta = Tpt.toAffine(), Ba = Bpt.toAffine();
const Zr = f2(rnd(), rnd()); const TX = F2.mul(Ta.x, Zr), TY = F2.mul(Ta.y, Zr);
const F = rnd(), Fm = rnd();
const ev = (poly, x) => peval(poly, x);
const sch = (k, a0, a1, b0, b1) => [k.sub(k.mul(a0, b0), k.mul(a1, b1)), k.add(k.mul(a0, b1), k.mul(a1, b0))];
const kar = (k, a0, a1, b0, b1) => { const u0 = k.mul(a0, b0), u1 = k.mul(a1, b1), u2 = k.mul(k.add(a0, a1), k.add(b0, b1)); return [k.sub(u0, u1), k.sub(k.sub(u2, u0), u1)]; };
const envAff = () => [P, t, md(A.x * z2), md(A.x * z2 * t), md(A.y * z3)];

// ---------- B affine doubling, witnessed slope lam: check 2 y lam = 3 x^2, x3 = lam^2 - 2x, y3 = lam (x - x3) - y ----------
// line (c, -lam, 1), c = lam x - y: L(+-z) = e +- oP, e = c0 + t c1 - xz2 lam0 - xz2t lam1, oP = yP z^3.  F+- <- F+-^2 L(+-z)
function bAffDbl() {
  const k = new Kernel(['p', 't', 'xz2', 'xz2t', 'oP'], ['Fp', 'Fm', 'x0', 'x1', 'y0', 'y1', 'l0', 'l1']);
  const E = k.E.bind(k), I = k.I.bind(k), m = k.mod.bind(k), mul = k.mul.bind(k), add = k.add.bind(k), sub = k.sub.bind(k);
  const [x0, x1, y0, y1, l0, l1] = ['x0', 'x1', 'y0', 'y1', 'l0', 'l1'].map(I);
  const d0 = m(sub(k.small(sub(mul(l0, y0), mul(l1, y1)), 2), k.small(mul(add(x0, x1), sub(x0, x1)), 3)));
  const d1 = m(sub(k.small(add(mul(l0, y1), mul(l1, y0)), 2), k.small(mul(x0, x1), 6)));
  const nx0 = m(sub(mul(add(l0, l1), sub(l0, l1)), k.small(x0, 2))), nx1 = m(sub(k.small(mul(l0, l1), 2), k.small(x1, 2)));
  const dx0 = sub(x0, nx0), dx1 = sub(x1, nx1);
  const [a0, a1] = sch(k, l0, l1, dx0, dx1); const ny0 = m(sub(a0, y0)), ny1 = m(sub(a1, y1));
  const [c0_, c1_] = sch(k, l0, l1, x0, x1); const c0 = sub(c0_, y0), c1 = sub(c1_, y1);
  const e = m(k.sum(c0, mul(E('t'), m(c1)), k.neg(mul(E('xz2'), l0)), k.neg(mul(E('xz2t'), l1))));
  const nFp = m(mul(mul(I('Fp'), I('Fp')), add(e, E('oP')))), nFm = m(mul(mul(I('Fm'), I('Fm')), sub(e, E('oP'))));
  k.output([nFp, nFm, nx0, nx1, ny0, ny1, d0, d1]);
  const lam = F2.div(F2.mul(f2(3n, 0n), F2.sqr(Ta.x)), F2.add(Ta.y, Ta.y));
  const r = show(measureKernel(k, envAff(), [F, Fm, Ta.x.c0, Ta.x.c1, Ta.y.c0, Ta.y.c1, lam.c0, lam.c1], {iters: ITERS, label: 'B affine dbl + line + F^2, witnessed slope'}));
  const o = r.outputs.map(md); assert.ok(o[6] === 0n && o[7] === 0n, 'slope check residues');
  const D = Tpt.double().toAffine(); assert.ok(o[2] === D.x.c0 && o[3] === D.x.c1 && o[4] === D.y.c0 && o[5] === D.y.c1, 'affine doubling');
  const L = lineAffPoly(A.x, A.y, lam, F2.sub(F2.mul(lam, Ta.x), Ta.y));
  assert.equal(o[0], md(F * F % P * ev(L, z))); assert.equal(o[1], md(Fm * Fm % P * ev(L, md(-z))));
  return r;
}
// ---------- B affine addition with B (affine, env) + c-multiply; check lam (xB - x) = yB - y; output x - xB for the != 0 test ----------
function bAffAdd() {
  const k = new Kernel(['p', 't', 'xz2', 'xz2t', 'oP', 'xq0', 'xq1', 'yq0', 'yq1', 'cp', 'cm'], ['Fp', 'Fm', 'x0', 'x1', 'y0', 'y1', 'l0', 'l1']);
  const E = k.E.bind(k), I = k.I.bind(k), m = k.mod.bind(k), mul = k.mul.bind(k), add = k.add.bind(k), sub = k.sub.bind(k);
  const [x0, x1, y0, y1, l0, l1] = ['x0', 'x1', 'y0', 'y1', 'l0', 'l1'].map(I);
  const [xq0, xq1, yq0, yq1] = ['xq0', 'xq1', 'yq0', 'yq1'].map(E);
  const ex0 = m(sub(xq0, x0)), ex1 = m(sub(xq1, x1));
  const [u0, u1] = sch(k, l0, l1, ex0, ex1); const d0 = m(sub(u0, sub(yq0, y0))), d1 = m(sub(u1, sub(yq1, y1)));
  const nx0 = m(sub(sub(mul(add(l0, l1), sub(l0, l1)), x0), xq0)), nx1 = m(sub(sub(k.small(mul(l0, l1), 2), x1), xq1));
  const [a0, a1] = sch(k, l0, l1, sub(x0, nx0), sub(x1, nx1)); const ny0 = m(sub(a0, y0)), ny1 = m(sub(a1, y1));
  const [c0_, c1_] = sch(k, l0, l1, x0, x1); const c0 = sub(c0_, y0), c1 = sub(c1_, y1);
  const e = m(k.sum(c0, mul(E('t'), m(c1)), k.neg(mul(E('xz2'), l0)), k.neg(mul(E('xz2t'), l1))));
  const nFp = m(mul(mul(I('Fp'), add(e, E('oP'))), E('cp'))), nFm = m(mul(mul(I('Fm'), sub(e, E('oP'))), E('cm')));
  k.output([nFp, nFm, nx0, nx1, ny0, ny1, d0, d1, ex0, ex1]);
  const lam = F2.div(F2.sub(Ba.y, Ta.y), F2.sub(Ba.x, Ta.x)); const cp = rnd(), cm = rnd();
  const r = show(measureKernel(k, [...envAff(), Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1, cp, cm], [F, Fm, Ta.x.c0, Ta.x.c1, Ta.y.c0, Ta.y.c1, lam.c0, lam.c1], {iters: ITERS, label: 'B affine add + line + c-mul, witnessed slope'}));
  const o = r.outputs.map(md); assert.ok(o[6] === 0n && o[7] === 0n && (o[8] !== 0n || o[9] !== 0n));
  const S = Tpt.add(Bpt).toAffine(); assert.ok(o[2] === S.x.c0 && o[5] === S.y.c1, 'affine addition');
  const L = lineAffPoly(A.x, A.y, lam, F2.sub(F2.mul(lam, Ta.x), Ta.y));
  assert.equal(o[0], md(F * ev(L, z) % P * cp)); assert.equal(o[1], md(Fm * ev(L, md(-z)) % P * cm));
  return r;
}
// ---------- B projective doubling (homogeneous) + line (B - E, -3X^2, H) + F^2; b3 = 3b' = 12 + 12u ----------
//   L(+-z) = [(l00 + t l01) + (xz2 l20 + xz2t l21)] +- [yz3 H0 + yz3t H1]
const projDblVals = () => {
  const b3 = F2.mul(B_TWIST, f2(3n, 0n)); const B = F2.sqr(TY), C = F2.sqr(Zr), Ev = F2.mul(b3, C), Fv = F2.mul(Ev, f2(3n, 0n)), H = F2.sub(F2.sub(F2.sqr(F2.add(TY, Zr)), B), C);
  return {l: [F2.sub(B, Ev), F2.neg(F2.mul(f2(3n, 0n), F2.sqr(TX))), H], X3: F2.mul(F2.mul(f2(2n, 0n), F2.mul(TX, TY)), F2.sub(B, Fv)), Y3: F2.sub(F2.sqr(F2.add(B, Fv)), F2.mul(f2(12n, 0n), F2.sqr(Ev))), Z3: F2.mul(f2(4n, 0n), F2.mul(B, H))};
};
function bProjDbl() {
  const k = new Kernel(['p', 't', 'xz2', 'xz2t', 'yz3', 'yz3t'], ['Fp', 'Fm', 'X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1']);
  const E = k.E.bind(k), I = k.I.bind(k), m = k.mod.bind(k), mul = k.mul.bind(k), add = k.add.bind(k), sub = k.sub.bind(k);
  const [X0, X1, Y0, Y1, Z0, Z1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'].map(I);
  const B0 = m(mul(add(Y0, Y1), sub(Y0, Y1))), B1 = m(k.small(mul(Y0, Y1), 2));
  const C0 = m(mul(add(Z0, Z1), sub(Z0, Z1))), C1 = m(k.small(mul(Z0, Z1), 2));
  const E0 = m(k.small(sub(C0, C1), 12)), E1 = m(k.small(add(C0, C1), 12)); // (12 + 12u)(C0 + C1 u)
  const F0 = k.small(E0, 3), F1 = k.small(E1, 3);
  const [xy0, xy1] = kar(k, X0, X1, Y0, Y1); const XY0 = m(xy0), XY1 = m(xy1);
  const D0 = k.small(sub(B0, F0), 2), D1 = k.small(sub(B1, F1), 2);
  const [x30, x31] = sch(k, XY0, XY1, D0, D1); const X30 = m(x30), X31 = m(x31);
  const G0 = add(B0, F0), G1 = add(B1, F1);
  const Y30 = m(sub(mul(add(G0, G1), sub(G0, G1)), k.small(mul(add(E0, E1), sub(E0, E1)), 12)));
  const Y31 = m(sub(k.small(mul(G0, G1), 2), k.small(mul(E0, E1), 24)));
  const S0 = add(Y0, Z0), S1 = add(Y1, Z1);
  const H0 = m(sub(sub(mul(add(S0, S1), sub(S0, S1)), B0), C0)), H1 = m(sub(sub(k.small(mul(S0, S1), 2), B1), C1));
  const B40 = k.small(B0, 4), B41 = k.small(B1, 4);
  const [z30, z31] = sch(k, B40, B41, H0, H1); const Z30 = m(z30), Z31 = m(z31);
  const X20 = mul(add(X0, X1), sub(X0, X1)), X21 = k.small(mul(X0, X1), 2);
  const e = m(k.sum(sub(B0, E0), mul(E('t'), sub(B1, E1)), k.neg(k.small(m(k.sum(mul(E('xz2'), X20), mul(E('xz2t'), X21))), 3))));
  const o = m(add(mul(E('yz3'), H0), mul(E('yz3t'), H1)));
  k.output([m(mul(mul(I('Fp'), I('Fp')), add(e, o))), m(mul(mul(I('Fm'), I('Fm')), sub(e, o))), X30, X31, Y30, Y31, Z30, Z31]);
  const r = show(measureKernel(k, [P, t, md(A.x * z2), md(A.x * z2 * t), md(A.y * z3), md(A.y * z3 * t)], [F, Fm, TX.c0, TX.c1, TY.c0, TY.c1, Zr.c0, Zr.c1], {iters: ITERS, label: 'B projective dbl + line + F^2'}));
  const o2 = r.outputs.map(md); const v = projDblVals();
  assert.ok(o2[2] === v.X3.c0 && o2[3] === v.X3.c1 && o2[4] === v.Y3.c0 && o2[7] === v.Z3.c1, 'projective doubling formulas');
  const Dd = Tpt.double().toAffine(); assert.ok(F2.eql(F2.mul(Dd.x, v.Z3), v.X3) && F2.eql(F2.mul(Dd.y, v.Z3), v.Y3), 'projective doubling = 2T');
  const L = lineGenPoly(A.x, A.y, ...v.l); assert.equal(o2[0], md(F * F % P * ev(L, z))); assert.equal(o2[1], md(Fm * Fm % P * ev(L, md(-z))));
  return r;
}
// ---------- B projective mixed addition with B + line (th xq - la yq, -th, la) + c-multiply ----------
function bProjAdd() {
  const k = new Kernel(['p', 't', 'xz2', 'xz2t', 'yz3', 'yz3t', 'xq0', 'xq1', 'yq0', 'yq1', 'cp', 'cm'], ['Fp', 'Fm', 'X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1']);
  const E = k.E.bind(k), I = k.I.bind(k), m = k.mod.bind(k), mul = k.mul.bind(k), add = k.add.bind(k), sub = k.sub.bind(k);
  const [X0, X1, Y0, Y1, Z0, Z1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'].map(I);
  const [xq0, xq1, yq0, yq1] = ['xq0', 'xq1', 'yq0', 'yq1'].map(E);
  const [qz0, qz1] = sch(k, yq0, yq1, Z0, Z1); const th0 = m(sub(Y0, qz0)), th1 = m(sub(Y1, qz1));
  const [xz0, xz1] = sch(k, xq0, xq1, Z0, Z1); const la0 = m(sub(X0, xz0)), la1 = m(sub(X1, xz1));
  const Cc0 = m(mul(add(th0, th1), sub(th0, th1))), Cc1 = m(k.small(mul(th0, th1), 2));
  const D0 = m(mul(add(la0, la1), sub(la0, la1))), D1 = m(k.small(mul(la0, la1), 2));
  const [e0, e1] = kar(k, la0, la1, D0, D1); const E0 = m(e0), E1 = m(e1);
  const [f0, f1] = kar(k, Z0, Z1, Cc0, Cc1); const F0 = m(f0), F1 = m(f1);
  const [g0, g1] = kar(k, X0, X1, D0, D1); const G0 = m(g0), G1 = m(g1);
  const H0 = sub(add(E0, F0), k.small(G0, 2)), H1 = sub(add(E1, F1), k.small(G1, 2));
  const [x30, x31] = kar(k, la0, la1, H0, H1);
  const [a0, a1] = sch(k, th0, th1, sub(G0, H0), sub(G1, H1)), [b0, b1] = sch(k, Y0, Y1, E0, E1);
  const [z30, z31] = kar(k, Z0, Z1, E0, E1);
  const [tx0, tx1] = sch(k, th0, th1, xq0, xq1), [ly0, ly1] = sch(k, la0, la1, yq0, yq1);
  const e = m(k.sum(sub(tx0, ly0), mul(E('t'), m(sub(tx1, ly1))), k.neg(mul(E('xz2'), th0)), k.neg(mul(E('xz2t'), th1))));
  const o = m(add(mul(E('yz3'), la0), mul(E('yz3t'), la1)));
  k.output([m(mul(mul(I('Fp'), add(e, o)), E('cp'))), m(mul(mul(I('Fm'), sub(e, o)), E('cm'))), m(x30), m(x31), m(sub(a0, b0)), m(sub(a1, b1)), m(z30), m(z31)]);
  const cp = rnd(), cm = rnd();
  const r = show(measureKernel(k, [P, t, md(A.x * z2), md(A.x * z2 * t), md(A.y * z3), md(A.y * z3 * t), Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1, cp, cm], [F, Fm, TX.c0, TX.c1, TY.c0, TY.c1, Zr.c0, Zr.c1], {iters: ITERS, label: 'B projective mixed add + line + c-mul'}));
  const o2 = r.outputs.map(md); const X3 = f2(o2[2], o2[3]), Y3 = f2(o2[4], o2[5]), Z3 = f2(o2[6], o2[7]);
  const S = Tpt.add(Bpt).toAffine(); assert.ok(F2.eql(F2.mul(S.x, Z3), X3) && F2.eql(F2.mul(S.y, Z3), Y3), 'projective addition');
  const la = F2.sub(TX, F2.mul(Ba.x, Zr)), th = F2.sub(TY, F2.mul(Ba.y, Zr));
  const L = lineGenPoly(A.x, A.y, F2.sub(F2.mul(th, Ba.x), F2.mul(la, Ba.y)), F2.neg(th), la);
  assert.equal(o2[0], md(F * ev(L, z) % P * cp)); assert.equal(o2[1], md(Fm * ev(L, md(-z)) % P * cm));
  return r;
}
// ---------- delta step: baked lambda_j (n), state (x_j, c_{j-1}, lambda_{j-1}); c_j = (l + n) x_j - c_{j-1};
// line (c_j, -n, 1) at C: e = c_j0 + t c_j1 - xCz2 n0 - xCz2t n1, L(+-z) = e +- oC; x_{j+1} = n^2 - x_j - s ----------
function deltaStep(isAdd) {
  const k = new Kernel(['p', 't', 'xz2', 'xz2t', 'oC', 'xd0', 'xd1'], ['Fp', 'Fm', 'x0', 'x1', 'c0', 'c1', 'l0', 'l1', 'n0', 'n1']);
  const E = k.E.bind(k), I = k.I.bind(k), m = k.mod.bind(k), mul = k.mul.bind(k), add = k.add.bind(k), sub = k.sub.bind(k);
  const [x0, x1, c0, c1, l0, l1, n0, n1] = ['x0', 'x1', 'c0', 'c1', 'l0', 'l1', 'n0', 'n1'].map(I);
  const [u0, u1] = kar(k, add(l0, n0), add(l1, n1), x0, x1); const nc0 = m(sub(u0, c0)), nc1 = m(sub(u1, c1));
  const e = m(k.sum(nc0, mul(E('t'), nc1), k.neg(mul(E('xz2'), n0)), k.neg(mul(E('xz2t'), n1))));
  const s0 = isAdd ? E('xd0') : x0, s1 = isAdd ? E('xd1') : x1;
  const nx0 = m(sub(sub(mul(add(n0, n1), sub(n0, n1)), x0), s0)), nx1 = m(sub(sub(k.small(mul(n0, n1), 2), x1), s1));
  k.output([m(mul(I('Fp'), add(e, E('oC')))), m(mul(I('Fm'), sub(e, E('oC')))), nx0, nx1, nc0, nc1, n0, n1]);
  // data: delta trajectory T -> 2T (or T + delta); state at step j: x_j = x(T), c_{j-1}, lambda_{j-1} from the previous step
  const del = G2.BASE.multiply(11n), da = del.toAffine(); const Tp = Tpt, T0 = Tp.toAffine();
  const lamPrev = rnd() % P; const prevC = rnd() % P; // c_{j-1} consistent: c_j = (l + n) x_j - c_{j-1} must equal n x_j - y_j
  const lam = isAdd ? F2.div(F2.sub(da.y, T0.y), F2.sub(da.x, T0.x)) : F2.div(F2.mul(f2(3n, 0n), F2.sqr(T0.x)), F2.add(T0.y, T0.y));
  const lP = f2(lamPrev, rnd()); const cPrev = F2.sub(F2.mul(F2.add(lP, lam), T0.x), F2.sub(F2.mul(lam, T0.x), T0.y)); // so that c_j = lam x - y
  const C = G1.BASE.multiply(rnd() % (1n << 200n)).toAffine();
  const r = show(measureKernel(k, [P, t, md(C.x * z2), md(C.x * z2 * t), md(C.y * z3), da.x.c0, da.x.c1], [F, Fm, T0.x.c0, T0.x.c1, cPrev.c0, cPrev.c1, lP.c0, lP.c1, lam.c0, lam.c1], {iters: ITERS, label: `delta step, baked slope (${isAdd ? 'add' : 'dbl'})`}));
  const o = r.outputs.map(md); const T1 = (isAdd ? Tp.add(del) : Tp.double()).toAffine();
  const cj = F2.sub(F2.mul(lam, T0.x), T0.y); assert.ok(o[4] === cj.c0 && o[5] === cj.c1 && o[2] === T1.x.c0 && o[3] === T1.x.c1, 'delta recursion');
  const L = lineAffPoly(C.x, C.y, lam, cj); assert.equal(o[0], md(F * ev(L, z))); assert.equal(o[1], md(Fm * ev(L, md(-z))));
  void prevC; return r;
}
// ---------- state boundary: S'(+-z) from 6 words, residual F+ S'(-z) - F- S'(z), R <- R rho + residual, F+- <- S'(+-z) ----------
function stateStep(final = false) {
  const k = new Kernel(['p', 'rho', 'z', 'z2', 'z4', 'z6', 'z3', 'z5'], ['R', 'Fp', 'Fm', 's0', 's1', 's2', 's3', 's4', 's5']);
  const E = k.E.bind(k), I = k.I.bind(k), m = k.mod.bind(k), mul = k.mul.bind(k), add = k.add.bind(k), sub = k.sub.bind(k);
  const evn = m(k.sum(I('s0'), mul(I('s2'), E('z2')), mul(I('s4'), E('z4')), E('z6')));
  const od = m(k.sum(mul(I('s1'), E('z')), mul(I('s3'), E('z3')), mul(I('s5'), E('z5'))));
  const Sp = add(evn, od), Sm = sub(evn, od);
  const Rn = m(add(mul(I('R'), E('rho')), sub(mul(I('Fp'), Sm), mul(I('Fm'), Sp))));
  k.output(final ? [Rn] : [Rn, Sp, Sm]);
  const zz = (e) => md(z ** BigInt(e));
  return show(measureKernel(k, [P, rnd(), z, zz(2), zz(4), zz(6), zz(3), zz(5)], [rnd(), F, Fm, ...Array.from({length: 6}, rnd)], {iters: ITERS, label: 'state eval + residual + rho fold'}));
}
function horner4() {
  const k = new Kernel(['p', 'z2', 'z4', 'z6', 'z8'], ['acc', 'q3', 'q2', 'q1', 'q0']);
  const E = k.E.bind(k), I = k.I.bind(k), mul = k.mul.bind(k);
  k.output([k.mod(k.sum(mul(I('acc'), E('z8')), mul(I('q3'), E('z6')), mul(I('q2'), E('z4')), mul(I('q1'), E('z2')), I('q0')))]);
  return show(measureKernel(k, [P, rnd(), rnd(), rnd(), rnd()], Array.from({length: 5}, rnd), {iters: ITERS, label: 'Horner x4 words'}));
}
function repEval() { // monic degree-6 at +-x from 6 coefficients (constants pushed by the caller)
  const k = new Kernel(['p', 'x', 'x2', 'x3', 'x4', 'x5', 'x6'], ['c0', 'c1', 'c2', 'c3', 'c4', 'c5']);
  const E = k.E.bind(k), I = k.I.bind(k), mul = k.mul.bind(k);
  const evn = k.mod(k.sum(I('c0'), mul(I('c2'), E('x2')), mul(I('c4'), E('x4')), E('x6')));
  const od = k.mod(k.sum(mul(I('c1'), E('x')), mul(I('c3'), E('x3')), mul(I('c5'), E('x5'))));
  k.output([k.add(evn, od), k.sub(evn, od)]);
  return show(measureKernel(k, [P, ...Array.from({length: 6}, rnd)], Array.from({length: 6}, rnd), {iters: ITERS, label: 'monic deg-6 eval at +-x'}));
}
function frobSc() { // Fr1(x) = (s0 + 2 - x^6) + sum_j s_j x^j (alpha_j + beta_j x^6), at +-x
  const k = new Kernel(['p', 'x', 'x2', 'x3', 'x4', 'x5', 'x6', 'a1', 'a2', 'a3', 'a4', 'a5', 'b1', 'b2', 'b3', 'b4', 'b5'], ['s0', 's1', 's2', 's3', 's4', 's5']);
  const E = k.E.bind(k), I = k.I.bind(k), mul = k.mul.bind(k), m = k.mod.bind(k), add = k.add.bind(k);
  const kap = (j) => m(mul(E(j === 1 ? 'x' : 'x' + j), add(E('a' + j), mul(E('b' + j), E('x6')))));
  const evn = m(k.sum(I('s0'), k.c(2n), k.neg(E('x6')), mul(I('s2'), kap(2)), mul(I('s4'), kap(4))));
  const od = m(k.sum(mul(I('s1'), kap(1)), mul(I('s3'), kap(3)), mul(I('s5'), kap(5))));
  k.output([k.add(evn, od), k.sub(evn, od)]);
  const x = rnd(); const xs = [1, 2, 3, 4, 5, 6].map((e) => md(x ** BigInt(e))); const s = Array.from({length: 6}, rnd);
  const r = show(measureKernel(k, [P, ...xs, ...[1, 2, 3, 4, 5].map((j) => FROB.alpha[j]), ...[1, 2, 3, 4, 5].map((j) => FROB.beta[j])], s, {iters: 4000, label: 'Frob(S_c) at +-x'}));
  return r;
}
function fp2Const() {
  const k = new Kernel(['p', 'k0', 'k1'], ['a0', 'a1']);
  const E = k.E.bind(k), I = k.I.bind(k), mul = k.mul.bind(k), m = k.mod.bind(k);
  k.output([m(k.sub(mul(I('a0'), E('k0')), mul(I('a1'), E('k1')))), m(k.add(mul(I('a0'), E('k1')), mul(I('a1'), E('k0'))))]);
  return show(measureKernel(k, [P, rnd(), rnd()], [rnd(), rnd()], {iters: 2000, label: 'Fp2 x const'}));
}
function glsTable() { // 16 entries from 4 values (11 products)
  const k = new Kernel(['p'], ['v0', 'v1', 'v2', 'v3']);
  const v = ['v0', 'v1', 'v2', 'v3'].map((n) => k.I(n)); const ent = Array(16);
  ent[0] = k.c(1n); for (let n = 1; n < 16; n++) { const lo = n & -n; ent[n] = n === lo ? v[Math.log2(lo)] : k.mm(ent[n ^ lo], v[Math.log2(lo)]); }
  k.output(ent.slice().reverse());
  return show(measureKernel(k, [P], [rnd(), rnd(), rnd(), rnd()], {iters: 3000, label: 'GLS table (16 entries, one sign, one group)'}));
}

// ---------- GLS event loop (64 lookups after the init byte), grouped 16-entry tables, binding Horner over exact integers ----------
function glsLoop() {
  const out = {};
  const TP = [0, 1].map(() => Array.from({length: 16}, rnd)), TM = [0, 1].map(() => Array.from({length: 16}, rnd));
  const axp = [1n, AX, AX ** 2n, AX ** 3n];
  const TB = [0, 1].map(() => Array.from({length: 16}, (_, n) => [0, 1, 2, 3].reduce((s, i) => s + ((n >> i) & 1 ? axp[i] : 0n), 0n)));
  const NEV = 63; const nib = [0, 1].map(() => Uint8Array.from(Array.from({length: NEV}, () => Number(rnd() % 16n))));
  const names = ['p']; for (const kk of [0, 1]) for (const T of ['TB', 'TM', 'TP']) for (let n = 15; n >= 0; n--) names.push(`${T}${kk}[${n}]`);
  names.push('acc0', 'acc1', 'ns0', 'ns1', 'Fp', 'Fm');
  const vals = [P]; for (const kk of [0, 1]) for (const T of [TB, TM, TP]) for (let n = 15; n >= 0; n--) vals.push(T[kk][n]);
  vals.push(0n, 0n, nib[0], nib[1], rnd(), rnd());
  function event(a) {
    for (const kk of [0, 1]) { a.roll(`ns${kk}`).push(1n, 'one').op(OP.SPLIT, 2, `b${kk}`, `ns${kk}`).roll(`b${kk}`).op(OP.BIN2NUM, 1, `i${kk}`); }
    for (const [Fn, T] of [['Fp', 'TP'], ['Fm', 'TM']]) a.pick('i0', 'x').lookup(`${T}0`, 'u').pick('i1', 'x').lookup(`${T}1`, 'v').bin(OP.MUL, 'uv').roll(Fn).bin(OP.MUL, 'w').pick('p').bin(OP.MOD, Fn);
    for (const kk of [0, 1]) a.roll(`acc${kk}`).pick(`acc${kk}`, 'dup').bin(OP.ADD, 'a2').roll(`i${kk}`).lookup(`TB${kk}`, 'tb').bin(OP.ADD, `acc${kk}`);
    a.arrange(['acc0', 'acc1', 'ns0', 'ns1', 'Fp', 'Fm']);
  }
  const evBytes = (() => { const a = new Asm(names); event(a); return a.code.length; })();
  let [Fp_, Fm_] = vals.slice(-2); let acc0 = 0n, acc1 = 0n;
  for (let e = 0; e < NEV; e++) { const i0 = nib[0][e], i1 = nib[1][e]; Fp_ = md(Fp_ * TP[0][i0] * TP[1][i1]); Fm_ = md(Fm_ * TM[0][i0] * TM[1][i1]); acc0 = 2n * acc0 + TB[0][i0]; acc1 = 2n * acc1 + TB[1][i1]; }
  const loop = (tail) => { const b = new Asm(names); for (let e = 0; e < NEV; e++) event(b); b.roll('ns0').drop().roll('ns1').drop(); tail(b); return b.bytes(); };
  const op = runBody(loop((b) => b.arrange(['acc0', 'acc1', 'Fp', 'Fm'])), vals, [acc0, acc1, Fp_, Fm_], {remain: names.length - 6});
  runBody(loop((b) => { b.roll('Fp').drop().roll('Fm').drop(); b.arrange(['acc0', 'acc1']); }), vals, [acc0, acc1], {remain: names.length - 6, exact: true});
  out.opCost = op; out.perEvent = Math.round(op / NEV); out.bytesPerEventUnrolled = evBytes;
  console.log('GLS event loop, 63 events:'.padEnd(56), 'op', op, '(per event', Math.round(op / NEV) + ') per-event code', evBytes, 'B');
  return out;
}
// ---------- witness word decode: next 48-byte LE word of a blob -> canonical unsigned number < p ----------
function decodeWord() {
  const words = Array.from({length: 6}, rnd); const le = (x) => { const b = Buffer.alloc(48); let v = x; for (let i = 0; i < 48; i++) { b[i] = Number(v & 255n); v >>= 8n; } return b; };
  const blob = Buffer.concat(words.map(le));
  const a = new Asm(['p', 'S']);
  for (let j = 0; j < 6; j++) {
    if (j < 5) a.roll('S').push(48n).op(OP.SPLIT, 2, `w${j}`, 'S').roll(`w${j}`); else a.roll('S', `w${j}`);
    a.pushBytes(Buffer.from([0]), 'zb', (b) => [...encodeDataPush(b)]).bin(OP.CAT).op(OP.BIN2NUM, 1, `s${j}`).pick(`s${j}`, 'd').pick('p').bin(OP.LESSTHAN, 'lt').op(OP.VERIFY, 1);
  }
  a.roll('p');
  const op = runBody(a.bytes(), [P, blob], [...words, P], {exact: true});
  console.log('decode 6 x 48-byte words (unsigned, < p checked):'.padEnd(56), 'op', op, 'per word', Math.round(op / 6), ';', a.code.length, 'B unrolled');
  return {opCost: op, perWord: Math.round(op / 6), bytes: a.code.length};
}
// ---------- challenge: BIN2NUM(SHA256(h0 || tag) || 0x00) (256 bits < p: no reduction needed) ----------
function challenge() {
  const a = new Asm(['h0']);
  a.pick('h0').pushBytes(Buffer.from('rho'), 'tag', (b) => [...encodeDataPush(b)]).bin(OP.CAT).op(OP.SHA256, 1, 'd').pushBytes(Buffer.from([0]), 'zb', (b) => [...encodeDataPush(b)]).bin(OP.CAT).op(OP.BIN2NUM, 1, 'rho');
  const h0 = createHash('sha256').update('h0').digest(); const d = createHash('sha256').update(Buffer.concat([h0, Buffer.from('rho')])).digest();
  let v = 0n; for (let i = 31; i >= 0; i--) v = v * 256n + BigInt(d[i]);
  const op = runBody(a.bytes(), [h0], [v], {exact: true, remain: 1});
  console.log('challenge derivation:'.padEnd(56), 'op', op, a.code.length, 'B'); return {opCost: op, bytes: a.code.length};
}

for (const f of [bAffDbl, bAffAdd, bProjDbl, bProjAdd, () => deltaStep(false), () => deltaStep(true), () => stateStep(), horner4, repEval, frobSc, fp2Const, glsTable]) f();
results.glsLoop = glsLoop(); results.decodeWord = decodeWord(); results.challenge = challenge();
writeFileSync(new URL('./kernels.json', import.meta.url), JSON.stringify(results, null, 1));
