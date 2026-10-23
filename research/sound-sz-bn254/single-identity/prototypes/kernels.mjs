// Hand-structured (lazy-reduction) kernels of SI-GLS, scheduled by dsl.mjs's local search and measured
// on the libauth bch-spec VM (standard). Every kernel's outputs are checked in the VM against the
// BigInt simulation, and the simulation is checked against independent math (noble twist point ops,
// affine lines) so that the kernel computes what the protocol says.
//   node kernels.mjs [iters]   (writes kernels.json, read by total.mjs)
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {bn254} from '@noble/curves/bn254.js';
import {Kernel, measureKernel, P} from './dsl.mjs';
const ITERS = Number(process.argv[2] ?? 20000);
const {Fp2: F2} = bn254.fields;
const md = (x) => ((x % P) + P) % P;
let ctr = 0; const rnd = () => BigInt('0x' + createHash('sha256').update('k2:' + ctr++).digest('hex')) % P;
const inv = (x) => bn254.fields.Fp.inv(md(x));
const f2 = (a, b) => F2.fromBigTuple([md(a), md(b)]);
const bTw = F2.div(f2(3n, 0n), f2(9n, 1n)); const b3 = F2.mul(bTw, f2(3n, 0n));
// sample data: P0 = -A (G1), B (G2), T = k*B projective with random Z; z, t = z^6 - 9
const A = bn254.G1.Point.BASE.multiply(rnd() % (1n << 200n)).negate().toAffine();
const Bpt = bn254.G2.Point.BASE.multiply(rnd() % (1n << 200n));
const Tpt = Bpt.multiply(rnd() % (1n << 200n));
const z = rnd(), t = md(z ** 6n - 9n), z3 = md(z ** 3n);
const Ta = Tpt.toAffine(), Ba = Bpt.toAffine();
const Zr = f2(rnd(), rnd());
const TX = F2.mul(Ta.x, Zr), TY = F2.mul(Ta.y, Zr);
const phi = (a) => md(a.c0 + a.c1 * t); // Phi(a)(z)
// line polynomial y Phi(l0) + x X Phi(l1) + X^3 Phi(l3) as a coefficient array, and mod-M reduction
const Phi = (a) => { const o = Array(7).fill(0n); o[0] = md(a.c0 - 9n * a.c1); o[6] = a.c1; return o; };
const lineP = (yP_, xP_, l0, l1, l3) => { const o = Array(10).fill(0n); const [a, b, c] = [Phi(l0), Phi(l1), Phi(l3)];
  for (let i = 0; i < 7; i++) { o[i] = md(o[i] + yP_ * a[i]); o[i + 1] = md(o[i + 1] + xP_ * b[i]); o[i + 3] = md(o[i + 3] + c[i]); } return o; };
const pmul = (a, b) => { const o = Array(a.length + b.length - 1).fill(0n); a.forEach((x, i) => b.forEach((y, j) => (o[i + j] = md(o[i + j] + x * y)))); return o; };
const pmodM = (a) => { const r0 = a.slice(); for (let i = r0.length - 1; i >= 12; i--) { const v = r0[i]; r0[i] = 0n; r0[i - 6] = md(r0[i - 6] + 18n * v); r0[i - 12] = md(r0[i - 12] - 82n * v); } return [...r0.slice(0, 12), ...Array(Math.max(0, 12 - r0.length)).fill(0n)].slice(0, 12); };
const pev = (a, x) => a.reduceRight((acc, c) => md(acc * x + c), 0n);
const sameClassLine = (Lp, s, La) => assert.deepEqual(pmodM(Lp), pmodM(pmul(Phi(s), La)), 'projective line == Phi(scale) * affine line mod M');
const results = {};
const show = (m) => { results[m.label] = {opCost: m.opCost, bytes: m.bytes, naiveSim: m.naiveSim, breakdown: m.breakdown}; console.log(m.label.padEnd(50), 'op', String(m.opCost).padStart(7), ' (sched-sim', m.simCost, 'naive', m.naiveSim + ')  code', m.bytes, 'B'); return m; };
const F = rnd(), Fm = rnd();

// ---------- B projective doubling + line + F^2 accumulate ----------
// line (scaled by +2YZ relative to the affine tangent line 1, -lambda w, c w^3): (H, -3X^2, B-E) in slots (0,1,3)
// e = yP*phi(H), o = xP z phi(3X^2) + z^3 phi(E-B);  L(+z) = e - o, L(-z) = e + o.
function bDbl(noSq = false) {
  const env = ['p', 'yP', 'yPt', 'xz3', 'xz3t', 'z3', 'z3t', 'b0', 'b1', 'bs'];
  const k = new Kernel(env, ['Fp', 'Fm', 'X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1']);
  const E = k.E.bind(k), I = k.I.bind(k), m = k.mod.bind(k), mul = k.mul.bind(k), add = k.add.bind(k), sub = k.sub.bind(k);
  const [X0, X1, Y0, Y1, Z0, Z1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'].map(I);
  const B0 = m(mul(add(Y0, Y1), sub(Y0, Y1))), B1 = m(mul(add(Y0, Y0), Y1));
  const C0 = m(mul(add(Z0, Z1), sub(Z0, Z1))), C1 = m(mul(add(Z0, Z0), Z1));
  // schoolbook Fp2 products (Karatsuba variants measured within +-0.5%)
  const sch = (a0, a1, b0, b1) => [sub(mul(a0, b0), mul(a1, b1)), add(mul(a0, b1), mul(a1, b0))];
  const [e0_, e1_] = sch(E('b0'), E('b1'), C0, C1);
  const E0 = m(e0_), E1 = m(e1_);
  const F0 = k.small(E0, 3), F1 = k.small(E1, 3);
  const t0 = mul(X0, Y0), t1 = mul(X1, Y1), t2 = mul(add(X0, X1), add(Y0, Y1));
  const XY0 = m(sub(t0, t1)), XY1 = m(sub(sub(t2, t0), t1));
  const D0 = k.small(sub(B0, F0), 2), D1 = k.small(sub(B1, F1), 2);
  const [x30_, x31_] = sch(XY0, XY1, D0, D1); const X30 = m(x30_), X31 = m(x31_);
  const G0 = add(B0, F0), G1 = add(B1, F1);
  const Y30 = m(sub(mul(add(G0, G1), sub(G0, G1)), k.small(mul(add(E0, E1), sub(E0, E1)), 12)));
  const Y31 = m(sub(k.small(mul(G0, G1), 2), k.small(mul(E0, E1), 24)));
  const S0 = add(Y0, Z0), S1 = add(Y1, Z1);
  const H0 = m(sub(sub(mul(add(S0, S1), sub(S0, S1)), B0), C0)), H1 = m(sub(sub(mul(add(S0, S0), S1), B1), C1));
  const B40 = k.small(B0, 4), B41 = k.small(B1, 4);
  const [z30_, z31_] = sch(B40, B41, H0, H1); const Z30 = m(z30_), Z31 = m(z31_);
  const X20 = mul(add(X0, X1), sub(X0, X1)), X21 = mul(add(X0, X0), X1);
  const o = m(k.sum(mul(E('xz3'), X20), mul(E('xz3t'), X21), mul(E('z3'), sub(E0, B0)), mul(E('z3t'), sub(E1, B1))));
  const e = m(add(mul(E('yP'), H0), mul(E('yPt'), H1)));
  const sqF = (x) => (noSq ? x : mul(x, x));
  const Fp2 = m(mul(sqF(I('Fp')), sub(e, o))), Fm2 = m(mul(sqF(I('Fm')), add(e, o)));
  k.output([Fp2, Fm2, X30, X31, Y30, Y31, Z30, Z31]);
  const envV = [P, A.y, md(A.y * t), md(3n * A.x * z), md(3n * A.x * z * t), z3, md(z3 * t), b3.c0, b3.c1, md(b3.c0 + b3.c1)];
  const inV = [F, Fm, TX.c0, TX.c1, TY.c0, TY.c1, Zr.c0, Zr.c1];
  const r = show(measureKernel(k, envV, inV, {iters: ITERS, label: noSq ? 'proj dbl + line, no square (delta tail)' : 'B proj dbl + line + F^2 accum (hand)'}));
  // semantic check
  const [nFp, nFm, ...pt] = r.outputs.map(md);
  const X3 = f2(pt[0], pt[1]), Y3 = f2(pt[2], pt[3]), Z3 = f2(pt[4], pt[5]);
  const D = Tpt.double().toAffine();
  assert(F2.eql(F2.mul(D.x, Z3), X3) && F2.eql(F2.mul(D.y, Z3), Y3), 'dbl point');
  const lam = F2.div(F2.mul(f2(3n, 0n), F2.sqr(Ta.x)), F2.mul(f2(2n, 0n), Ta.y)), c = F2.sub(F2.mul(lam, Ta.x), Ta.y);
  const s2 = F2.mul(f2(2n, 0n), F2.mul(TY, Zr)); // scale 2YZ
  const Bq = F2.sqr(TY), Eq = F2.mul(b3, F2.sqr(Zr));
  const Lp = lineP(A.y, A.x, s2, F2.neg(F2.mul(f2(3n, 0n), F2.sqr(TX))), F2.sub(Bq, Eq)), La = lineP(A.y, A.x, f2(1n, 0n), F2.neg(lam), c);
  sameClassLine(Lp, s2, La);
  assert.equal(md(nFp), md((noSq ? F : F * F) % P * pev(Lp, z)), 'dbl line +z');
  assert.equal(md(nFm), md((noSq ? Fm : Fm * Fm) % P * pev(Lp, md(-z))), 'dbl line -z');
  // Z = 0 absorbing / zero-line facts are algebraic: Z3 = 4BH = 8 Y^3 Z; nonzero Z3 => Y,Z != 0 => l0 = 2YZ != 0.
  return r;
}

// ---------- B projective mixed addition T + Q (Q = +-B affine) + line + accumulate (+ optional c-mul) ----------
// line scaled by lambda' = X - xq Z: (lambda', -theta, theta xq - lambda' yq), theta = Y - yq Z.
function bAdd(withC) {
  const env = ['p', 'yP', 'yPt', 'xz', 'xzt', 'z3', 'z3t', 'xq0', 'xq1', 'yq0', 'yq1', 'cp', 'cm'];
  const k = new Kernel(env, ['Fp', 'Fm', 'X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1']);
  const E = k.E.bind(k), I = k.I.bind(k), m = k.mod.bind(k), mul = k.mul.bind(k), add = k.add.bind(k), sub = k.sub.bind(k);
  const [X0, X1, Y0, Y1, Z0, Z1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'].map(I);
  const [xq0, xq1, yq0, yq1] = ['xq0', 'xq1', 'yq0', 'yq1'].map(E);
  const fmul = (a0, a1, b0, b1) => { const u0 = mul(a0, b0), u1 = mul(a1, b1), u2 = mul(add(a0, a1), add(b0, b1)); return [sub(u0, u1), sub(sub(u2, u0), u1)]; };
  const fmulS = (a0, a1, b0, b1) => [sub(mul(a0, b0), mul(a1, b1)), add(mul(a0, b1), mul(a1, b0))];
  const fm = fmul; // Karatsuba where it is cheaper; schoolbook (fmulS) elsewhere
  const [qz0, qz1] = fmulS(yq0, yq1, Z0, Z1); const th0 = m(sub(Y0, qz0)), th1 = m(sub(Y1, qz1));
  const [xz0, xz1] = fmulS(xq0, xq1, Z0, Z1); const la0 = m(sub(X0, xz0)), la1 = m(sub(X1, xz1));
  const Cc0 = m(mul(add(th0, th1), sub(th0, th1))), Cc1 = m(mul(add(th0, th0), th1));
  const D0 = m(mul(add(la0, la1), sub(la0, la1))), D1 = m(mul(add(la0, la0), la1));
  const [e0, e1] = fm(la0, la1, D0, D1); const E0 = m(e0), E1 = m(e1);
  const [f0, f1] = fm(Z0, Z1, Cc0, Cc1); const F0 = m(f0), F1 = m(f1);
  const [g0, g1] = fm(X0, X1, D0, D1); const G0 = m(g0), G1 = m(g1);
  const H0 = sub(add(E0, F0), k.small(G0, 2)), H1 = sub(add(E1, F1), k.small(G1, 2));
  const [x30, x31] = fm(la0, la1, H0, H1); const X30 = m(x30), X31 = m(x31);
  const [a0, a1] = fmulS(th0, th1, sub(G0, H0), sub(G1, H1)), [b0, b1] = fmulS(Y0, Y1, E0, E1);
  const Y30 = m(sub(a0, b0)), Y31 = m(sub(a1, b1));
  const [z30, z31] = fm(Z0, Z1, E0, E1); const Z30 = m(z30), Z31 = m(z31);
  const [tx0, tx1] = fmulS(th0, th1, xq0, xq1), [ly0, ly1] = fmulS(la0, la1, yq0, yq1);
  const l30 = sub(tx0, ly0), l31 = sub(tx1, ly1);
  const o = m(sub(add(mul(E('z3'), l30), mul(E('z3t'), l31)), add(mul(E('xz'), th0), mul(E('xzt'), th1))));
  const e = m(add(mul(E('yP'), la0), mul(E('yPt'), la1)));
  let nFp = mul(I('Fp'), add(e, o)), nFm = mul(I('Fm'), sub(e, o));
  if (withC) { nFp = mul(nFp, E('cp')); nFm = mul(nFm, E('cm')); }
  k.output([m(nFp), m(nFm), X30, X31, Y30, Y31, Z30, Z31]);
  const cp = rnd(), cm = rnd();
  const envV = [P, A.y, md(A.y * t), md(A.x * z), md(A.x * z * t), z3, md(z3 * t), Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1, cp, cm];
  const inV = [F, Fm, TX.c0, TX.c1, TY.c0, TY.c1, Zr.c0, Zr.c1];
  const r = show(measureKernel(k, envV, inV, {iters: ITERS, label: `B proj mixed add + line + accum${withC ? ' + c-mul' : ''} (hand)`}));
  const [oFp, oFm, ...pt] = r.outputs.map(md);
  const X3 = f2(pt[0], pt[1]), Y3 = f2(pt[2], pt[3]), Z3 = f2(pt[4], pt[5]);
  const S = Tpt.add(Bpt).toAffine();
  assert(F2.eql(F2.mul(S.x, Z3), X3) && F2.eql(F2.mul(S.y, Z3), Y3), 'add point');
  const lam = F2.div(F2.sub(Ta.y, Ba.y), F2.sub(Ta.x, Ba.x)), c = F2.sub(F2.mul(lam, Ba.x), Ba.y);
  const la = F2.sub(TX, F2.mul(Ba.x, Zr)), th = F2.sub(TY, F2.mul(Ba.y, Zr));
  const Lp = lineP(A.y, A.x, la, F2.neg(th), F2.sub(F2.mul(th, Ba.x), F2.mul(la, Ba.y))), La = lineP(A.y, A.x, f2(1n, 0n), F2.neg(lam), c);
  sameClassLine(Lp, la, La);
  const cc = withC ? [cp, cm] : [1n, 1n];
  assert.equal(oFp, md(F * pev(Lp, z) % P * cc[0]), 'add line +z');
  assert.equal(oFm, md(Fm * pev(Lp, md(-z)) % P * cc[1]), 'add line -z');
  return r;
}

// ---------- B affine with witness slope (doubling), c-trick free version (tracks x, y) ----------
function bAffDbl() {
  const env = ['p', 'yP', 'xz', 'xzt', 'z3', 'z3t'];
  const k = new Kernel(env, ['Fp', 'Fm', 'x0', 'x1', 'y0', 'y1', 'l0', 'l1']);
  const E = k.E.bind(k), I = k.I.bind(k), m = k.mod.bind(k), mul = k.mul.bind(k), add = k.add.bind(k), sub = k.sub.bind(k);
  const [x0, x1, y0, y1, l0, l1] = ['x0', 'x1', 'y0', 'y1', 'l0', 'l1'].map(I);
  // check lambda * 2y == 3 x^2  (both components == 0 mod p, verified by caller via NOT/VERIFY: outputs d0, d1 here)
  const d0 = m(sub(k.small(sub(mul(l0, y0), mul(l1, y1)), 2), k.small(mul(add(x0, x1), sub(x0, x1)), 3)));
  const d1 = m(sub(k.small(add(mul(l0, y1), mul(l1, y0)), 2), k.small(mul(x0, x1), 6)));
  const nx0 = m(sub(mul(add(l0, l1), sub(l0, l1)), k.small(x0, 2))), nx1 = m(sub(mul(add(l0, l0), l1), k.small(x1, 2)));
  const dx0 = sub(x0, nx0), dx1 = sub(x1, nx1);
  const ny0 = m(sub(sub(mul(l0, dx0), mul(l1, dx1)), y0)), ny1 = m(sub(add(mul(l0, dx1), mul(l1, dx0)), y1));
  // c = lambda x - y ; o = -(xz l0 + xzt l1) + z3 c0 + z3t c1
  const c0 = sub(sub(mul(l0, x0), mul(l1, x1)), y0), c1 = sub(add(mul(l0, x1), mul(l1, x0)), y1);
  const o = m(sub(add(mul(E('z3'), c0), mul(E('z3t'), c1)), add(mul(E('xz'), l0), mul(E('xzt'), l1))));
  const nFp = m(mul(mul(I('Fp'), I('Fp')), add(E('yP'), o))), nFm = m(mul(mul(I('Fm'), I('Fm')), sub(E('yP'), o)));
  k.output([nFp, nFm, nx0, nx1, ny0, ny1, d0, d1]);
  const lam = F2.div(F2.mul(f2(3n, 0n), F2.sqr(Ta.x)), F2.mul(f2(2n, 0n), Ta.y));
  const envV = [P, A.y, md(A.x * z), md(A.x * z * t), z3, md(z3 * t)];
  const inV = [F, Fm, Ta.x.c0, Ta.x.c1, Ta.y.c0, Ta.y.c1, lam.c0, lam.c1];
  const r = show(measureKernel(k, envV, inV, {iters: ITERS, label: 'B affine dbl, witness slope (hand) [+2 VERIFY ~400]'}));
  assert(r.outputs.slice(6).every((x) => md(x) === 0n), 'slope check');
  const D = Tpt.double().toAffine(); assert(md(r.outputs[2]) === D.x.c0 && md(r.outputs[5]) === D.y.c1, 'aff dbl');
  return r;
}
function bAffAdd() {
  const env = ['p', 'yP', 'xz', 'xzt', 'z3', 'z3t', 'xq0', 'xq1', 'yq0', 'yq1', 'cp', 'cm'];
  const k = new Kernel(env, ['Fp', 'Fm', 'x0', 'x1', 'y0', 'y1', 'l0', 'l1']);
  const E = k.E.bind(k), I = k.I.bind(k), m = k.mod.bind(k), mul = k.mul.bind(k), add = k.add.bind(k), sub = k.sub.bind(k);
  const [x0, x1, y0, y1, l0, l1] = ['x0', 'x1', 'y0', 'y1', 'l0', 'l1'].map(I);
  const [xq0, xq1, yq0, yq1] = ['xq0', 'xq1', 'yq0', 'yq1'].map(E);
  const ex0 = sub(xq0, x0), ex1 = sub(xq1, x1);
  const d0 = m(sub(sub(mul(l0, ex0), mul(l1, ex1)), sub(yq0, y0))), d1 = m(sub(add(mul(l0, ex1), mul(l1, ex0)), sub(yq1, y1)));
  const nx0 = m(sub(sub(mul(add(l0, l1), sub(l0, l1)), x0), xq0)), nx1 = m(sub(sub(mul(add(l0, l0), l1), x1), xq1));
  const dx0 = sub(x0, nx0), dx1 = sub(x1, nx1);
  const ny0 = m(sub(sub(mul(l0, dx0), mul(l1, dx1)), y0)), ny1 = m(sub(add(mul(l0, dx1), mul(l1, dx0)), y1));
  const c0 = sub(sub(mul(l0, x0), mul(l1, x1)), y0), c1 = sub(add(mul(l0, x1), mul(l1, x0)), y1);
  const o = m(sub(add(mul(E('z3'), c0), mul(E('z3t'), c1)), add(mul(E('xz'), l0), mul(E('xzt'), l1))));
  const nFp = m(mul(mul(I('Fp'), add(E('yP'), o)), E('cp'))), nFm = m(mul(mul(I('Fm'), sub(E('yP'), o)), E('cm')));
  k.output([nFp, nFm, nx0, nx1, ny0, ny1, d0, d1]);
  const lam = F2.div(F2.sub(Ta.y, Ba.y), F2.sub(Ta.x, Ba.x));
  const envV = [P, A.y, md(A.x * z), md(A.x * z * t), z3, md(z3 * t), Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1, rnd(), rnd()];
  const inV = [F, Fm, Ta.x.c0, Ta.x.c1, Ta.y.c0, Ta.y.c1, lam.c0, lam.c1];
  const r = show(measureKernel(k, envV, inV, {iters: ITERS, label: 'B affine add + c-mul, witness slope (hand) [+2 VERIFY]'}));
  assert(r.outputs.slice(6).every((x) => md(x) === 0n), 'slope check add');
  return r;
}

// ---------- delta fixed-line step: baked lambda_j (pushed by the unrolled schedule), on-chain x, c ----------
// state (x, c, lambda_j); schedule pushes lambda_{j+1}. line_j: (1, -lambda_j, c_j) at P1 = C.
// x_{j+1} = lambda_j^2 - x_j - s (s = x_j for doubling, x_delta for addition); c_{j+1} = (lambda_j + lambda_{j+1}) x_{j+1} - c_j.
function deltaStep(isAdd) {
  const env = ['p', 'yC', 'xz', 'xzt', 'z3', 'z3t', 'xd0', 'xd1'];
  const k = new Kernel(env, ['Fp', 'Fm', 'x0', 'x1', 'c0', 'c1', 'l0', 'l1', 'n0', 'n1']);
  const E = k.E.bind(k), I = k.I.bind(k), m = k.mod.bind(k), mul = k.mul.bind(k), add = k.add.bind(k), sub = k.sub.bind(k);
  const [x0, x1, c0, c1, l0, l1, n0, n1] = ['x0', 'x1', 'c0', 'c1', 'l0', 'l1', 'n0', 'n1'].map(I);
  const o = m(sub(add(mul(E('z3'), c0), mul(E('z3t'), c1)), add(mul(E('xz'), l0), mul(E('xzt'), l1))));
  const nFp = m(mul(I('Fp'), add(E('yC'), o))), nFm = m(mul(I('Fm'), sub(E('yC'), o)));
  const s0 = isAdd ? E('xd0') : x0, s1 = isAdd ? E('xd1') : x1;
  const nx0 = m(sub(sub(mul(add(l0, l1), sub(l0, l1)), x0), s0)), nx1 = m(sub(sub(mul(add(l0, l0), l1), x1), s1));
  const s0_ = add(l0, n0), s1_ = add(l1, n1);
  const u0 = mul(s0_, nx0), u1 = mul(s1_, nx1), u2 = mul(add(s0_, s1_), add(nx0, nx1));
  const nc0 = m(sub(sub(u0, u1), c0)), nc1 = m(sub(sub(sub(u2, u0), u1), c1));
  k.output([nFp, nFm, nx0, nx1, nc0, nc1, n0, n1]);
  // data: delta trajectory T -> 2T (or T + delta)
  const del = bn254.G2.Point.BASE.multiply(rnd() % (1n << 200n));
  const T0 = Tpt.toAffine(), da = del.toAffine();
  const lam = isAdd ? F2.div(F2.sub(T0.y, da.y), F2.sub(T0.x, da.x)) : F2.div(F2.mul(f2(3n, 0n), F2.sqr(T0.x)), F2.mul(f2(2n, 0n), T0.y));
  const T1 = (isAdd ? Tpt.add(del) : Tpt.double()).toAffine();
  const lam1 = F2.div(F2.mul(f2(3n, 0n), F2.sqr(T1.x)), F2.mul(f2(2n, 0n), T1.y));
  const cA = F2.sub(F2.mul(lam, T0.x), T0.y), c1A = F2.sub(F2.mul(lam1, T1.x), T1.y);
  const C = bn254.G1.Point.BASE.multiply(rnd() % (1n << 200n)).toAffine();
  const envV = [P, C.y, md(C.x * z), md(C.x * z * t), z3, md(z3 * t), da.x.c0, da.x.c1];
  const inV = [F, Fm, T0.x.c0, T0.x.c1, cA.c0, cA.c1, lam.c0, lam.c1, lam1.c0, lam1.c1];
  const r = show(measureKernel(k, envV, inV, {iters: ITERS, label: `delta step, baked lambda, ${isAdd ? 'add' : 'dbl'} (hand)`}));
  const out = r.outputs.map(md);
  assert(out[2] === T1.x.c0 && out[3] === T1.x.c1 && out[4] === c1A.c0 && out[5] === c1A.c1, 'delta c-trick');
  const La = lineP(C.y, C.x, f2(1n, 0n), F2.neg(lam), cA);
  assert.equal(out[0], md(F * pev(La, z))); assert.equal(out[1], md(Fm * pev(La, md(-z))));
  return r;
}
// delta line from 4 baked pre-mapped words: o = k0 xz + k1 xzt + k2 z3 + k3 z3t (constants pushed by schedule)
function deltaBake4() {
  const env = ['p', 'yC', 'xz', 'xzt', 'z3', 'z3t'];
  const k = new Kernel(env, ['Fp', 'Fm', 'k0', 'k1', 'k2', 'k3']);
  const E = k.E.bind(k), I = k.I.bind(k), m = k.mod.bind(k), mul = k.mul.bind(k), add = k.add.bind(k), sub = k.sub.bind(k);
  const o = m(k.sum(mul(E('xz'), I('k0')), mul(E('xzt'), I('k1')), mul(E('z3'), I('k2')), mul(E('z3t'), I('k3'))));
  k.output([m(mul(I('Fp'), add(E('yC'), o))), m(mul(I('Fm'), sub(E('yC'), o)))]);
  return show(measureKernel(k, [P, rnd(), rnd(), rnd(), rnd(), rnd()], [F, Fm, rnd(), rnd(), rnd(), rnd()], {iters: ITERS, label: 'delta line, 4 baked words (hand)'}));
}
// state boundary: S'(+-z) from 6 words, residual F+ S'(-z) - F- S'(z), R <- R rho + residual, F+- <- S'(+-z)
function stateStep() {
  const env = ['p', 'rho', 'z', 'z2', 'z4', 'z6', 'z3', 'z5'];
  const k = new Kernel(env, ['R', 'Fp', 'Fm', 's0', 's1', 's2', 's3', 's4', 's5']);
  const E = k.E.bind(k), I = k.I.bind(k), m = k.mod.bind(k), mul = k.mul.bind(k), add = k.add.bind(k), sub = k.sub.bind(k);
  const ev = m(k.sum(I('s0'), mul(I('s2'), E('z2')), mul(I('s4'), E('z4')), E('z6')));
  const od = m(k.sum(mul(I('s1'), E('z')), mul(I('s3'), E('z3')), mul(I('s5'), E('z5'))));
  const Sp = add(ev, od), Sm = sub(ev, od);
  const res = sub(mul(I('Fp'), Sm), mul(I('Fm'), Sp));
  const Rn = m(add(mul(I('R'), E('rho')), res));
  k.output([Rn, Sp, Sm]);
  const zz = (e) => md(z ** BigInt(e));
  return show(measureKernel(k, [P, rnd(), z, zz(2), zz(4), zz(6), zz(3), zz(5)], [rnd(), F, Fm, ...Array.from({length: 6}, rnd)], {iters: ITERS, label: 'state eval + residual + rho fold (hand)'}));
}
// Horner over Q, 4 words per reduction: acc <- acc z^8 + q3 z^6 + q2 z^4 + q1 z^2 + q0
function horner4() {
  const env = ['p', 'z2', 'z4', 'z6', 'z8'];
  const k = new Kernel(env, ['acc', 'q3', 'q2', 'q1', 'q0']);
  const E = k.E.bind(k), I = k.I.bind(k), mul = k.mul.bind(k);
  k.output([k.mod(k.sum(mul(I('acc'), E('z8')), mul(I('q3'), E('z6')), mul(I('q2'), E('z4')), mul(I('q1'), E('z2')), I('q0')))]);
  return show(measureKernel(k, [P, rnd(), rnd(), rnd(), rnd()], Array.from({length: 5}, rnd), {iters: ITERS, label: 'Horner x4 words (hand)'}));
}
// GLS table entry products are plain mulmods; measured inside gls.mjs.

for (const k of [() => bDbl(), () => bDbl(true), () => bAdd(false), () => bAdd(true), bAffDbl, bAffAdd, () => deltaStep(false), () => deltaStep(true), deltaBake4, stateStep, horner4]) k();
writeFileSync(new URL('./kernels.json', import.meta.url), JSON.stringify(results, null, 1));
