// Per-kernel differential test for the T2 rolled residue singleton (review item: "tested, not proved").
//   node kerneltest.mjs [trials]          (default 8 random trials per kernel; T2_SQR does not matter, every kernel is tested)
//
// Every arithmetic kernel of the redeem is a fixed integer polynomial map followed by reductions mod p, with no
// data-dependent branches. This test compiles each kernel ALONE with the same assembler and scheduler as the redeem,
// runs it on the BCH 2026 VM (density budget loosened) at independent uniform random inputs in [0, p), and compares the
// outputs mod p with a reference computed independently of the kernel DAG (noble's Fp2 / Fp12 arithmetic in the SI-GLS
// polynomial basis, noble's curve arithmetic, or the textbook EFD formula):
//   kSqr, kMulSparse (MULL lines, MULC monic), kGlue (full, odd-only)  vs noble Fp12 products (the reduction mod M
//                                                                        reduceM is inside each of them);
//   kDbl, kAdd (G2 step + the 6 line-polynomial coefficients)          vs projDbl / projAdd + linePoly (noble Fp2), and on
//                                                                        curve points vs noble's G2 double / add, with the
//                                                                        line equal to l0 times the affine line;
//   kPsi                                                                vs conj(a) * g over noble Fp2;
//   kJDbl, kJAdd (vk_x Jacobian G1)                                     vs EFD dbl-2009-l / madd-2007-bl (literal forms), and
//                                                                        on curve points vs noble's G1 double / add;
//   kConsts (psi / Frobenius / eta constants)                           vs GAMMA1 powers, FROB (asserted against noble's
//                                                                        Frobenius in ../sigls-dproj/math.mjs) and ETA;
//   kCfold, kScEta, kResidueAB (c-fold and terminal coefficient kernels) vs psubst / pneg / frob1Monic of S_c (kCfold is
//                                                                        tested as its degree-1 map in d, and as S_c(-d X)
//                                                                        at the digits d = +-1).
// Soundness of the argument does not rest on this test (BCH arithmetic is exact, see README); it upgrades "the
// kernels compute the intended maps" from whole-run agreement to a stated probabilistic guarantee: if a kernel's
// output polynomial differed from the reference map mod p, one agreement at a uniform random point happens with
// probability at most deg/p < 2^-245 per output (Schwartz-Zippel; every kernel has total degree < 2^8), and the
// test requires agreement at every trial.
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {bigIntToVmNumber, vmNumberToBigInt} from '@bitauth/libauth';
import {bn254} from '@noble/curves/bn254.js';
import {Asm} from '../sigls-dproj/asm.mjs';
import {p, mod, F2, F12, f2, B3, PSI, GAMMA1, ETA, FROB, projDbl, projAdd, linePoly, fromPoly, toPoly, psubst, pneg, frob1Monic} from './math.mjs';
import {kSqr, kMulSparse, kGlue, kDbl, kAdd, kPsi, kJDbl, kJAdd, kConsts, CONSTS_OUT, kCfold, kScEta, kResidueAB, RESIDUE_OUT, G6} from './script.mjs';
import {bare} from './vm.mjs';

const TRIALS = Number(process.argv[2] ?? 8);
const rnd = () => mod(BigInt('0x' + randomBytes(48).toString('hex')));
const rnd2 = () => f2(rnd(), rnd());
const rndPoly = (n) => Array.from({length: n}, rnd);

// compile kernel K with every referenced name (and p) on the stack, run it on the VM, return its outputs mod p
function runKernel(K, vals) {
  const names = [...K.refs.keys()]; for (const n of names) assert.ok(n in vals, 'no value for ' + n);
  const a = new Asm([...names, 'p']); const outs = K.outs.map((_, i) => 'out' + i); a.kernel(K, outs, {iters: 200});
  const res = bare(Uint8Array.from(a.code), [...names.map((n) => vals[n]), p].map((v) => bigIntToVmNumber(BigInt(v))));
  // the kernel runs to the end; the only error allowed is the final clean-stack rule (the outputs are left on the stack)
  assert.ok(res.error === undefined || /unexpected number of items on the stack/.test(res.error), 'kernel VM error: ' + res.error);
  return res.stack.slice(-outs.length).map((b) => mod(vmNumberToBigInt(b, {requireMinimalEncoding: false})));
}
const X6 = fromPoly([0n, 0n, 0n, 0n, 0n, 0n, 1n]);
const named = (prefix, arr) => Object.fromEntries(arr.map((v, i) => [prefix + i, v]));
const same = (got, want, what) => assert.deepEqual(got, want.map((x) => mod(x)), what);
const counts = {};
const tick = (name) => { counts[name] = (counts[name] ?? 0) + 1; };

for (let t = 0; t < TRIALS; t++) {
  // ---- Fp12 kernels (polynomial basis Fp[X]/M, M = X^12 - 18 X^6 + 82) ----
  const F = rndPoly(12), Fe = fromPoly(F);
  same(runKernel(kSqr(), named('F', F)), toPoly(F12.sqr(Fe)), 'kSqr'); tick('kSqr');
  { const L = rndPoly(6), js = [0, 1, 3, 6, 7, 9], G = Array(12).fill(0n); js.forEach((j, i) => (G[j] = L[i]));
    same(runKernel(kMulSparse(js, 'L', false), {...named('F', F), ...Object.fromEntries(js.map((j, i) => ['L' + j, L[i]]))}), toPoly(F12.mul(Fe, fromPoly(G))), 'MULL'); tick('kMulSparse MULL'); }
  { const G = rndPoly(6);
    same(runKernel(kMulSparse([0, 1, 2, 3, 4, 5], 'G', true), {...named('F', F), ...named('G', G)}), toPoly(F12.mul(Fe, fromPoly([...G, 1n]))), 'MULC'); tick('kMulSparse MULC'); }
  { // GLUE as a map of independent U, V, F: U + X^6 (V - F) - X^12 F  (which is F * (A + X^6 B) when U = F (A + X^6), V = F (B + X^6))
    const U = rndPoly(12), V = rndPoly(12); const want = toPoly(F12.sub(F12.add(fromPoly(U), F12.mul(X6, F12.sub(fromPoly(V), Fe))), F12.mul(F12.mul(X6, X6), Fe)));
    const vals = {...named('U', U), ...named('V', V), ...named('F', F)};
    same(runKernel(kGlue(false), vals), want, 'kGlue'); same(runKernel(kGlue(true), vals), want.filter((_, i) => i % 2), 'kGlue odd'); tick('kGlue'); tick('kGlue odd');
    // and the intended use: two MULC products + GLUE give the general product F * G
    const A = rndPoly(6), Bc = rndPoly(6); const Uu = toPoly(F12.mul(Fe, fromPoly([...A, 1n]))), Vv = toPoly(F12.mul(Fe, fromPoly([...Bc, 1n])));
    same(runKernel(kGlue(false), {...named('U', Uu), ...named('V', Vv), ...named('F', F)}), toPoly(F12.mul(Fe, fromPoly([...A, ...Bc]))), 'MULC+GLUE = F*G'); }

  // ---- G2 step kernels: projective point + line polynomial coefficients at X^0,1,3,6,7,9 ----
  const T = [rnd2(), rnd2(), rnd2()], xP = rnd(), yP = rnd();
  const pt = {X0: T[0].c0, X1: T[0].c1, Y0: T[1].c0, Y1: T[1].c1, Z0: T[2].c0, Z1: T[2].c1};
  const stepWant = (o) => { const lp = linePoly(xP, yP, ...o.line); return [...o.T.flatMap((c) => [c.c0, c.c1]), ...[0, 1, 3, 6, 7, 9].map((d) => lp[d])]; };
  same(runKernel(kDbl(), {...pt, xP3: mod(-3n * xP), yP, b30: B3.c0, b31: B3.c1}), stepWant(projDbl(T)), 'kDbl'); tick('kDbl');
  { const q = [rnd2(), rnd2()];
    same(runKernel(kAdd(), {...pt, xq0: q[0].c0, xq1: q[0].c1, yq0: q[1].c0, yq1: q[1].c1, mxP: mod(-xP), yP}), stepWant(projAdd(T, q)), 'kAdd'); tick('kAdd'); }
  { // on curve: the step equals noble's group law, and the line is l0 * (affine line), l0 != 0
    const k1 = rnd() % bn254.fields.Fr.ORDER, k2 = rnd() % bn254.fields.Fr.ORDER;
    const Q1 = bn254.G2.Point.BASE.multiply(k1), Q2 = bn254.G2.Point.BASE.multiply(k2), a1 = Q1.toAffine(), a2 = Q2.toAffine(), Z = rnd2();
    const P = bn254.G1.Point.BASE.multiply(k2).toAffine(); const T1 = [F2.mul(a1.x, Z), F2.mul(a1.y, Z), Z], ptc = {X0: T1[0].c0, X1: T1[0].c1, Y0: T1[1].c0, Y1: T1[1].c1, Z0: T1[2].c0, Z1: T1[2].c1};
    const aff = (o) => { const zi = F2.inv(f2(o[4], o[5])); return [F2.mul(f2(o[0], o[1]), zi), F2.mul(f2(o[2], o[3]), zi)]; };
    for (const [K, vals, R, lam] of [
      [kDbl(), {...ptc, xP3: mod(-3n * P.x), yP: P.y, b30: B3.c0, b31: B3.c1}, Q1.double(), F2.div(F2.mul(f2(3n, 0n), F2.sqr(a1.x)), F2.add(a1.y, a1.y))],
      [kAdd(), {...ptc, xq0: a2.x.c0, xq1: a2.x.c1, yq0: a2.y.c0, yq1: a2.y.c1, mxP: mod(-P.x), yP: P.y}, Q1.add(Q2), F2.div(F2.sub(a2.y, a1.y), F2.sub(a2.x, a1.x))]]) {
      const o = runKernel(K, vals); const [x, y] = aff(o), ra = R.toAffine(); assert.ok(F2.eql(x, ra.x) && F2.eql(y, ra.y), 'on-curve G2 step = noble');
      // line coefficients: (l0, l1, l3) recovered from the polynomial coefficients must be l0 * (1, -lam, lam x_T - y_T), l0 != 0
      const want = linePoly(P.x, P.y, F2.ONE, F2.neg(lam), F2.sub(F2.mul(lam, a1.x), a1.y)); const got = [0, 1, 3, 6, 7, 9].map((d, i) => o[6 + i]);
      // got = l0 * want (as polynomials in X, l0 in Fp2 acting through Phi): compare the two lines' Fp12 elements up to the Fp2 factor
      const ge = fromPoly([got[0], got[1], 0n, got[2], 0n, 0n, got[3], got[4], 0n, got[5]]), we = fromPoly(want);
      const ratio = F12.mul(ge, F12.inv(we)); const rp = toPoly(ratio);
      assert.ok(rp.every((c, i) => c === 0n || i === 0 || i === 6) && !(rp[0] === 0n && rp[6] === 0n), 'projective line = (nonzero Fp2 scalar) * affine line');
    }
    tick('kDbl/kAdd on curve'); }
  { const x = rnd2(), y = rnd2(), gx = rnd2(), gy = rnd2(); const conj = (a) => f2(a.c0, -a.c1);
    same(runKernel(kPsi(), {x0: x.c0, x1: x.c1, y0: y.c0, y1: y.c1, g20: gx.c0, g21: gx.c1, g30: gy.c0, g31: gy.c1}), [F2.mul(conj(x), gx), F2.mul(conj(y), gy)].flatMap((c) => [c.c0, c.c1]), 'kPsi'); tick('kPsi'); }

  // ---- G1 Jacobian kernels (vk_x) ----
  { const [X1, Y1, Z1, x2, y2] = [rnd(), rnd(), rnd(), rnd(), rnd()];
    // EFD dbl-2009-l: A=X1^2, B=Y1^2, C=B^2, D=2((X1+B)^2-A-C), E=3A, F=E^2, X3=F-2D, Y3=E(D-X3)-8C, Z3=2Y1Z1
    { const A = X1 * X1, B = Y1 * Y1, C = B * B, D = 2n * ((X1 + B) ** 2n - A - C), E = 3n * A, Fv = E * E, X3 = Fv - 2n * D;
      same(runKernel(kJDbl(), {VX: X1, VY: Y1, VZ: Z1}), [X3, E * (D - X3) - 8n * C, 2n * Y1 * Z1], 'kJDbl'); tick('kJDbl'); }
    // EFD madd-2007-bl: Z1Z1=Z1^2, U2=X2 Z1Z1, S2=Y2 Z1 Z1Z1, H=U2-X1, HH=H^2, I=4HH, J=H I, r=2(S2-Y1), V=X1 I,
    // X3=r^2-J-2V, Y3=r(V-X3)-2Y1 J, Z3=(Z1+H)^2-Z1Z1-HH
    { const Z1Z1 = Z1 * Z1, U2 = x2 * Z1Z1, S2 = y2 * Z1 * Z1Z1, H = U2 - X1, HH = H * H, I = 4n * HH, J = H * I, rr = 2n * (S2 - Y1), V = X1 * I, X3 = rr * rr - J - 2n * V;
      same(runKernel(kJAdd(), {VX: X1, VY: Y1, VZ: Z1, xq: x2, yq: y2}), [X3, rr * (V - X3) - 2n * Y1 * J, (Z1 + H) ** 2n - Z1Z1 - HH], 'kJAdd'); tick('kJAdd'); }
    // on curve vs noble
    const P1 = bn254.G1.Point.BASE.multiply(rnd() % bn254.fields.Fr.ORDER), P2 = bn254.G1.Point.BASE.multiply(rnd() % bn254.fields.Fr.ORDER), a1 = P1.toAffine(), a2 = P2.toAffine(), Z = rnd();
    const jac = {VX: mod(a1.x * Z * Z), VY: mod(a1.y * Z ** 3n), VZ: Z};
    const aff = ([X, Y, Zz]) => { const zi = bn254.fields.Fp.inv(Zz); return [mod(X * zi * zi), mod(Y * zi ** 3n)]; };
    for (const [K, vals, R] of [[kJDbl(), jac, P1.double()], [kJAdd(), {...jac, xq: a2.x, yq: a2.y}, P1.add(P2)]]) {
      const ra = R.toAffine(); assert.deepEqual(aff(runKernel(K, vals)), [ra.x, ra.y], 'on-curve G1 step = noble'); }
    tick('kJDbl/kJAdd on curve'); }

  // ---- c-fold and terminal coefficient kernels ----
  { const sc = rndPoly(6), dg = t % 3 === 0 ? 1n : t % 3 === 1 ? p - 1n : rnd(); const env = named('sc', sc);
    // the map is G_j = (-d)^(j mod 2) s_j (degree 1 in d); for the digits d = +-1 it is S_c(-d X) without X^6
    same(runKernel(kCfold(), {...env, dg}), sc.map((x, j) => (j % 2 ? -dg * x : x)), 'kCfold map');
    if (dg === 1n || dg === p - 1n) same(runKernel(kCfold(), {...env, dg: dg === 1n ? 1n : -1n}), psubst(sc, mod(-dg)), 'kCfold: S_c(-d X)');
    tick('kCfold');
    const om = mod(ETA - 1n);
    same(runKernel(kScEta(), {...env, eta: ETA, om}), psubst(sc, ETA), 'kScEta: S_c(eta X)'); tick('kScEta');
    const cst = {eta: ETA, om, g21: FROB.beta[2], g31: FROB.beta[3], ...Object.fromEntries([1, 2, 3, 4, 5].map((j) => ['al' + j, FROB.alpha[j]])), be1: FROB.beta[1], be4: FROB.beta[4], be5: FROB.beta[5]};
    const Fr1 = frob1Monic(sc), s1 = pneg(Fr1), s2 = psubst(Fr1, mod(-ETA)); // sigma(Fr1)(X) = Fr1(-X); sigma(Fr1(eta X)) = Fr1(-eta X)
    const out = runKernel(kResidueAB(), {...env, ...cst}); const at = (n) => out[RESIDUE_OUT.indexOf(n)];
    for (let j = 0; j < 6; j++) { assert.equal(at('A' + j), s1[j], 'residue A' + j); assert.equal(at('B' + j), s1[j + 6], 'residue B' + j); }
    for (let j = 1; j < 6; j++) { assert.equal(at('a' + j), s2[j], 'residue a' + j); assert.equal(at('b' + j), s2[j + 6], 'residue b' + j); }
    assert.equal(s1[0], s2[0]); assert.equal(s1[6], s2[6]); // the shared j = 0 coefficients the caller copies
    tick('kResidueAB'); }
}
// constants (no inputs): psi = (gamma1^2, gamma1^3), alpha_j / beta_j = Phi(gamma1^j), eta, omega
{ const out = runKernel(kConsts(), {}); const at = (n) => out[CONSTS_OUT.indexOf(n)];
  const g = [null, GAMMA1]; for (let j = 2; j <= 5; j++) g.push(F2.mul(g[j - 1], GAMMA1));
  assert.ok(F2.eql(f2(at('g20'), at('g21')), PSI[0].x) && F2.eql(f2(at('g30'), at('g31')), PSI[0].y), 'psi constants');
  for (let j = 1; j <= 5; j++) { assert.equal(at('al' + j), FROB.alpha[j], 'alpha' + j); assert.equal(at({1: 'be1', 2: 'g21', 3: 'g31', 4: 'be4', 5: 'be5'}[j]), FROB.beta[j], 'beta' + j); }
  assert.equal(at('eta'), ETA); assert.equal(at('om'), mod(ETA - 1n)); assert.equal(G6.length, 6); tick('kConsts'); }
console.log('per-kernel differential test: all outputs equal the references mod p');
console.log(Object.entries(counts).map(([k, v]) => `${k} ${v}`).join(', '));
