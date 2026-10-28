// SI-GLS math: field / polynomial helpers, the tower <-> polynomial map, and every baked constant
// of the verifier, each one recomputed from first principles and asserted against noble here (at
// import time, so every build, prover and test run re-checks them).
//
//   Fp12 = Fp[X]/M(X), M = X^12 - 18 X^6 + 82, X = w (noble tower: u^2 = -1, v = w^2, v^3 = 9 + u),
//   u = X^6 - 9; an Fp2 element a0 + a1 u maps to Phi(a) = (a0 - 9 a1) + a1 X^6.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {bn254} from '@noble/curves/bn254.js';
import {psiFrobenius} from '@noble/curves/abstract/tower.js';

export const {Fp, Fp2: F2, Fp6, Fp12: F12} = bn254.fields;
export const p = Fp.ORDER, r = bn254.fields.Fr.ORDER, BN_X = 4965661367192848881n;
export const mod = (x, m = p) => ((x % m) + m) % m;
export const inv = (x) => Fp.inv(mod(x));

// ---------------- fixtures / VK (same as the densless entries) ----------------
export const FIXTURES = JSON.parse(readFileSync(new URL('../../../../chunked/bn254/densless-recovered/public-fixtures.json', import.meta.url)));
export const g1 = (x) => bn254.G1.Point.fromAffine({x: BigInt(x.x), y: BigInt(x.y)});
export const g2 = (x) => bn254.G2.Point.fromAffine({x: {c0: BigInt(x.x.c0), c1: BigInt(x.x.c1)}, y: {c0: BigInt(x.y.c0), c1: BigInt(x.y.c1)}});
export const VK = FIXTURES.vk;

// ---------------- polynomials over Fp (coefficient arrays, low degree first) ----------------
export const trim = (a) => { a = a.slice(); while (a.length > 1 && a.at(-1) === 0n) a.pop(); return a; };
export const pmul = (a, b) => { const o = Array(a.length + b.length - 1).fill(0n); for (let i = 0; i < a.length; i++) if (a[i]) for (let j = 0; j < b.length; j++) o[i + j] += a[i] * b[j]; return o.map((x) => mod(x)); };
export const padd = (a, b) => Array.from({length: Math.max(a.length, b.length)}, (_, i) => mod((a[i] ?? 0n) + (b[i] ?? 0n)));
export const psub = (a, b) => Array.from({length: Math.max(a.length, b.length)}, (_, i) => mod((a[i] ?? 0n) - (b[i] ?? 0n)));
export const pscale = (a, s) => a.map((c) => mod(c * s));
export const psubst = (a, s) => { let k = 1n; return a.map((c) => { const v = mod(c * k); k = mod(k * s); return v; }); }; // a(sX)
export const pneg = (a) => psubst(a, p - 1n); // a(-X): the conjugation sigma = Frob^6
export const peval = (a, x) => { let acc = 0n; for (let i = a.length - 1; i >= 0; i--) acc = mod(acc * x + a[i]); return acc; };
export const M = [82n, 0n, 0n, 0n, 0n, 0n, mod(-18n), 0n, 0n, 0n, 0n, 0n, 1n];
export const pdivM = (a) => { // exact long division by the monic M
  const rem = a.slice(); const q = Array(Math.max(1, a.length - 12)).fill(0n);
  for (let i = rem.length - 1; i >= 12; i--) { const v = rem[i]; q[i - 12] = v; rem[i] = 0n; rem[i - 6] = mod(rem[i - 6] + 18n * v); rem[i - 12] = mod(rem[i - 12] - 82n * v); }
  return {q, r: rem.slice(0, 12).concat(Array(Math.max(0, 12 - rem.length)).fill(0n))};
};
export const pmodM = (a) => pdivM(a).r;
export const isZero = (a) => a.every((x) => x === 0n);

// ---------------- tower <-> polynomial ----------------
const flat = (x) => [x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1, x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1];
// tower slot order (c0.c0, c0.c1, c0.c2, c1.c0, c1.c1, c1.c2) = w^(0,2,4,1,3,5)
const SLOT_DEG = [0, 2, 4, 1, 3, 5];
export const toPoly = (x) => { const c = flat(x), out = Array(12).fill(0n); SLOT_DEG.forEach((d, i) => { out[d] = mod(c[2 * i] - 9n * c[2 * i + 1]); out[d + 6] = c[2 * i + 1]; }); return out; };
export const fromPoly = (a) => {
  const c = pmodM(a); const s = SLOT_DEG.map((d) => ({c0: mod(c[d] + 9n * c[d + 6]), c1: c[d + 6]}));
  return F12.create({c0: Fp6.create({c0: s[0], c1: s[1], c2: s[2]}), c1: Fp6.create({c0: s[3], c1: s[4], c2: s[5]})});
};
export const Phi = (a) => { const o = Array(7).fill(0n); o[0] = mod(a.c0 - 9n * a.c1); o[6] = mod(a.c1); return o; };
export const f2 = (a, b) => F2.fromBigTuple([mod(a), mod(b)]);

// monic degree-6 class representative of f in Fp12*/Fp6*: S = X^6 + s5 X^5 + ... + s0 with [S] = [f]
const solveMod = (A, b) => {
  const n = A.length, Mx = A.map((row, i) => [...row, b[i]].map((x) => mod(x)));
  for (let c = 0; c < n; c++) {
    let piv = c; while (piv < n && Mx[piv][c] === 0n) piv++; if (piv === n) throw new Error('monic representative does not exist (singular)');
    [Mx[c], Mx[piv]] = [Mx[piv], Mx[c]]; const iv = inv(Mx[c][c]); Mx[c] = Mx[c].map((x) => mod(x * iv));
    for (let i = 0; i < n; i++) if (i !== c && Mx[i][c]) { const m = Mx[i][c]; Mx[i] = Mx[i].map((x, k) => mod(x - m * Mx[c][k])); }
  }
  return Mx.map((row) => row[n]);
};
export const monicRep = (f) => {
  const fp = toPoly(f); const cols = [0, 2, 4, 6, 8, 10].map((d) => pmodM(pmul([...Array(d).fill(0n), 1n], fp)));
  const s = solveMod([6, 7, 8, 9, 10, 11].map((row) => cols.map((c) => c[row])), [1n, 0n, 0n, 0n, 0n, 0n]);
  const out = Array(12).fill(0n); cols.forEach((c, j) => c.forEach((x, i) => (out[i] = mod(out[i] + s[j] * x))));
  assert.ok(out.slice(7).every((x) => x === 0n) && out[6] === 1n);
  const rep = out.slice(0, 7); assert.ok(sameClass(fromPoly(rep), f)); return rep; // [s0..s5, 1]
};
export const sameClass = (a, b) => isZero(toPoly(F12.sub(F12.mul(a, F12.conjugate(b)), F12.conjugate(F12.mul(a, F12.conjugate(b)))))); // a/b in Fp6 <=> a conj(b) even

// ---------------- curve, twist, psi ----------------
export const B_TWIST = F2.div(f2(3n, 0n), f2(9n, 1n)); // b' = 3/(9+u)
export const B3 = F2.mul(B_TWIST, f2(3n, 0n));          // 3b' (projective doubling)
const {psi} = psiFrobenius(Fp, F2, F2.NONRESIDUE);
export const psiAff = (x, y) => { const [a, b] = psi(x, y); return [a, b]; };
// psi^k(x, y) = (conj^k(x) * PX[k], conj^k(y) * PY[k])  (k = 1, 2, 3), constants checked against noble's psi
const conj2 = (a) => ({c0: a.c0, c1: mod(-a.c1)});
export const conjK = (a, k) => (k % 2 ? conj2(a) : a);
export const PSI = [1, 2, 3].map((k) => {
  const one = F2.ONE; let x = one, y = one; for (let i = 0; i < k; i++) [x, y] = psi(x, y); // psi^k(1,1) = (PX, PY)  (psi is semilinear)
  return {k, x, y};
});
export const psiK = (k, x, y) => [F2.mul(conjK(x, k), PSI[k - 1].x), F2.mul(conjK(y, k), PSI[k - 1].y)];
for (let t = 0; t < 4; t++) { // check against noble on random twist points
  const Q = bn254.G2.Point.BASE.multiply(BigInt(1000 + 7919 * t)).toAffine(); let [x, y] = [Q.x, Q.y];
  for (let k = 1; k <= 3; k++) { [x, y] = psi(x, y); const [a, b] = psiK(k, Q.x, Q.y); assert.ok(F2.eql(a, x) && F2.eql(b, y), 'psi^' + k + ' constants'); }
}

// ---------------- eta (Frob^2 = X -> eta X) and Frobenius of polynomials ----------------
const randF12 = (seed) => F12.fromBigTwelve(Array.from({length: 12}, (_, i) => mod(BigInt(seed * 1000003 + i * 7919 + 1) ** 37n)));
export const ETA = (() => {
  const g = (() => { for (let a = 2n; ; a++) { const e = Fp.pow(a, (p - 1n) / 6n); if (Fp.pow(e, 2n) !== 1n && Fp.pow(e, 3n) !== 1n) return e; } })();
  const ok = [g, Fp.pow(g, 5n)].filter((eta) => [1, 2, 3].every((s) => { const el = randF12(s); return pmodM(psubst(toPoly(el), eta)).join() === toPoly(F12.frobeniusMap(el, 2)).join(); }));
  assert.equal(ok.length, 1, 'exactly one primitive 6th root realizes Frob^2'); return ok[0];
})();
assert.equal(Fp.pow(ETA, 6n), 1n); assert.equal(Fp.pow(ETA, 3n), p - 1n);
for (let s = 4; s < 8; s++) { const el = randF12(s); assert.equal(toPoly(F12.frobeniusMap(el, 6)).join(), pmodM(pneg(toPoly(el))).join(), 'Frob^6 = X -> -X'); }
// Frob(X^j) = alpha_j X^j + beta_j X^(j+6) for j = 1..5, Frob(1) = 1, Frob(X^6) = 18 - X^6 (mod M)
export const FROB = (() => {
  const mono = (j) => fromPoly([...Array(j).fill(0n), 1n]);
  const out = {alpha: [], beta: []};
  for (let j = 1; j <= 5; j++) {
    const fp = toPoly(F12.frobeniusMap(mono(j), 1));
    fp.forEach((c, i) => assert.ok(c === 0n || i === j || i === j + 6, 'Frob(X^j) support'));
    out.alpha[j] = fp[j]; out.beta[j] = fp[j + 6];
  }
  assert.equal(toPoly(F12.frobeniusMap(mono(0), 1)).join(), [1n, ...Array(11).fill(0n)].join());
  assert.equal(toPoly(F12.frobeniusMap(mono(6), 1)).join(), [18n, 0n, 0n, 0n, 0n, 0n, p - 1n, 0n, 0n, 0n, 0n, 0n].join());
  return out;
})();
// GAMMA1 = xi^((p-1)/6), xi = 9 + u: Frob(X^j) = Phi(GAMMA1^j) X^j, psi = (conj(x) GAMMA1^2, conj(y) GAMMA1^3), so the
// script bakes only GAMMA1 (and eta) and derives the rest; the derivations are asserted against noble here.
export const GAMMA1 = F2.pow(f2(9n, 1n), (p - 1n) / 6n);
{ let g = F2.ONE; for (let j = 1; j <= 5; j++) { g = F2.mul(g, GAMMA1); assert.equal(mod(g.c0 - 9n * g.c1), FROB.alpha[j]); assert.equal(g.c1, FROB.beta[j]); }
  assert.ok(F2.eql(PSI[0].x, F2.pow(GAMMA1, 2n)) && F2.eql(PSI[0].y, F2.pow(GAMMA1, 3n)), 'psi = (gamma^2, gamma^3)');
  assert.equal(mod(ETA * ETA), ETA - 1n, 'eta^2 = eta - 1'); }
// Frob of a monic degree-6 polynomial given by s0..s5 (the on-chain formula), as a polynomial
export const frob1Monic = (s) => { const o = Array(12).fill(0n); o[0] = mod(s[0] + 18n); o[6] = p - 1n; for (let j = 1; j <= 5; j++) { o[j] = mod(o[j] + s[j] * FROB.alpha[j]); o[j + 6] = mod(o[j + 6] + s[j] * FROB.beta[j]); } return o; };
for (let t = 0; t < 3; t++) { const s = Array.from({length: 6}, (_, i) => mod(BigInt(t * 31 + i + 5) ** 41n)); assert.equal(pmodM(frob1Monic(s)).join(), toPoly(F12.frobeniusMap(fromPoly([...s, 1n]), 1)).join(), 'Frob(S) formula'); }

// ---------------- Miller loop schedule, residue exponent, G2 endpoint facts ----------------
export const DIGITS = (() => { const d = []; for (let n = 6n * BN_X + 2n; n > 1n; n >>= 1n) { if (!(n & 1n)) d.unshift(0); else if ((n & 3n) === 3n) { d.unshift(-1); n++; } else d.unshift(1); } return d; })();
export const NE = DIGITS.length; assert.equal(NE, 65);
assert.equal(DIGITS.reduce((acc, d) => 2n * acc + BigInt(d), 1n), 6n * BN_X + 2n, 'NAF of 6x+2');
for (let e = 1; e < NE; e++) assert.ok(!(DIGITS[e] && DIGITS[e - 1]), 'NAF: no adjacent nonzero digits');
export const NADD = DIGITS.filter((d) => d).length;
export const LAMBDA = 6n * BN_X + 2n + p - p ** 2n + p ** 3n;
export const N6R = (p ** 6n + 1n) / r;
const gcd = (a, b) => { a = a < 0n ? -a : a; b = b < 0n ? -b : b; while (b) [a, b] = [b, a % b]; return a; };
export const FACTS = (() => {
  assert.equal((p ** 6n + 1n) % r, 0n); assert.equal(LAMBDA % r, 0n, 'lambda = m r');
  assert.equal(gcd(LAMBDA, N6R), 1n, 'gcd(lambda, (p^6+1)/r) = 1: the residue root exists');
  assert.equal(gcd(3n, p ** 6n + 1n), 1n);
  const t = p + 1n - r, h2 = 2n * p - r; // #E'(Fp2) = r (2p - r)
  const a = 6n * BN_X + 2n + p - t * p, b = 1n - t + t * t - p; // lambda(psi) = a + b psi on E'(Fp2), psi^2 = t psi - p
  const norm = a * a + a * b * t + b * b * p;
  assert.equal(gcd(norm, h2), 1n, 'lambda(psi) is injective on the G2 cofactor part');
  assert.equal(h2 % 2n, 1n, 'E\'(Fp2) has odd order: no 2-torsion');
  return {g2Cofactor: h2.toString(), gcdNormCofactor: '1', lambdaOverR: (LAMBDA / r).toString()};
})();

// ---------------- GT-GLS lattice (Frobenius on GT has eigenvalue p mod r) ----------------
export const PI = [1n, p % r, (p * p) % r, (p ** 3n) % r];
assert.equal(PI[1], p - r); assert.equal(PI[2], mod(PI[1] * PI[1], r)); assert.equal(PI[3], mod(PI[1] * PI[2], r)); // derived on-chain from p, r
export const LATTICE = (() => {
  const x = BN_X;
  const L = [[2n * x + 1n, 0n, 2n * x, 1n], [2n * x, x + 1n, -x, x], [x + 1n, x, x, -2n * x], [2n * x + 1n, -x, -(x + 1n), -x]];
  L.forEach((b) => assert.equal(mod(b.reduce((s, v, i) => s + v * PI[i], 0n), r), 0n, 'lattice vector'));
  return L;
})();
const det = (m) => (m.length === 1 ? m[0][0] : m[0].reduce((s, v, j) => s + (j % 2 ? -1n : 1n) * v * det(m.slice(1).map((row) => row.filter((_, k) => k !== j))), 0n));
const DET = det(LATTICE); assert.equal(DET < 0n ? -DET : DET, r, 'lattice has index r');
const COF = [0, 1, 2, 3].map((j) => (j % 2 ? -1n : 1n) * det(LATTICE.filter((_, a) => a !== j).map((row) => row.slice(1))));
const roundDiv = (a, b) => { if (b < 0n) { a = -a; b = -b; } const q = a / b, rm = a % b; if (2n * (rm < 0n ? -rm : rm) >= b) return a < 0n ? q - 1n : q + 1n; return q; };
export const glsDecompose = (n) => { // Babai rounding of (n,0,0,0) against the reduced basis
  const c = COF.map((cj) => roundDiv(n * cj, DET));
  const e = [n, 0n, 0n, 0n].map((v, i) => v - c.reduce((s, cj, j) => s + cj * LATTICE[j][i], 0n));
  assert.equal(mod(e.reduce((s, v, i) => s + v * PI[i], 0n), r), mod(n, r)); return e;
};
// offset encoding: u_{k,i} = e_{k,i} + 2^64 in [0, 2^65), read MSB-first over the 65 events (bit 64 - e at event e).
// Babai gives |e_{k,i}| <= (1/2) max_i sum_j |b_j[i]| < 2^64 (asserted below), so u always fits; the constant
// offset contributes prod_{k,i} Frob^i(m_{IC_{k+1}})^(-2^64) (folded into Rconst) and -2^64 sum_i pi_i to the binding.
export const GLS_BITS = 65, GLS_OFFSET = 1n << 64n;
export const PI_SUM_OFFSET = mod(GLS_OFFSET * PI.reduce((a, b) => a + b, 0n), r);
{ const colSum = [0, 1, 2, 3].map((i) => LATTICE.reduce((s, b) => s + (b[i] < 0n ? -b[i] : b[i]), 0n)); assert.ok(colSum.every((c) => c < 2n * GLS_OFFSET), 'Babai bound |e| < 2^64'); }

// ---------------- VK-derived constants ----------------
export const vkPoints = () => ({alpha: g1(VK.alpha), beta: g2(VK.beta), gamma: g2(VK.gamma), delta: g2(VK.delta), ic: VK.ic.map(g1)});
// unit-free affine line through twist point Ta with slope lam, as an Fp12 element at P = (xP, yP):
//   yP + (-lam xP) w + (lam xT - yT) w^3
export const affineLine = (xP, yP, lam, c) => F12.create({c0: Fp6.create({c0: {c0: mod(yP), c1: 0n}, c1: F2.ZERO, c2: F2.ZERO}), c1: Fp6.create({c0: F2.mul(F2.neg(lam), {c0: mod(xP), c1: 0n}), c1: c, c2: F2.ZERO})});
// polynomial of the line l0 yP + l1 xP X + l3 X^3 (l's in Fp2, Phi-mapped)
export const linePoly = (xP, yP, l0, l1, l3) => { const o = Array(10).fill(0n); const [a, b, c] = [Phi(l0), Phi(l1), Phi(l3)];
  for (let i = 0; i < 7; i++) { o[i] = mod(o[i] + yP * a[i]); o[i + 1] = mod(o[i + 1] + xP * b[i]); o[i + 3] = mod(o[i + 3] + c[i]); } return o; };
// ---------------- on-chain G2 formulas (B and, in dproj, delta) (homogeneous projective over Fp2) ----------------
// doubling (scaled CLN): B=Y^2, C=Z^2, E=3b'C, F=3E, H=2YZ; X3=2XY(B-F), Y3=(B+F)^2-12E^2, Z3=4BH
// line (H, -3X^2, B-E) = 2YZ * (affine tangent line); Z3 = 8Y^3 Z (Z = 0 absorbing; Z3 != 0 => H != 0)
export const projDbl = ([X, Y, Z]) => {
  const B = F2.sqr(Y), C = F2.sqr(Z), E = F2.mul(B3, C), Fv = F2.mul(E, f2(3n, 0n)), H = F2.mul(F2.mul(Y, Z), f2(2n, 0n));
  const X3 = F2.mul(F2.mul(F2.mul(X, Y), f2(2n, 0n)), F2.sub(B, Fv));
  const Y3 = F2.sub(F2.sqr(F2.add(B, Fv)), F2.mul(F2.sqr(E), f2(12n, 0n)));
  const Z3 = F2.mul(F2.mul(B, H), f2(4n, 0n));
  return {T: [X3, Y3, Z3], line: [H, F2.neg(F2.mul(F2.sqr(X), f2(3n, 0n))), F2.sub(B, E)]};
};
// mixed addition with affine Q: theta=Y-yq Z, lam=X-xq Z, D=lam^2, E=lam D, Fv=Z theta^2, G=X D, H=E+Fv-2G;
// X3=lam H, Y3=theta(G-H)-Y E, Z3=Z E; line (lam, -theta, theta xq - lam yq) = lam * (affine chord line); Z3 = Z lam^3
export const projAdd = ([X, Y, Z], [xq, yq]) => {
  const th = F2.sub(Y, F2.mul(yq, Z)), la = F2.sub(X, F2.mul(xq, Z));
  const D = F2.sqr(la), E = F2.mul(la, D), Fv = F2.mul(Z, F2.sqr(th)), G = F2.mul(X, D), H = F2.sub(F2.add(E, Fv), F2.add(G, G));
  return {T: [F2.mul(la, H), F2.sub(F2.mul(th, F2.sub(G, H)), F2.mul(Y, E)), F2.mul(Z, E)],
    line: [la, F2.neg(th), F2.sub(F2.mul(th, xq), F2.mul(la, yq))]};
};

export const VKC = (() => {
  const V = vkPoints();
  // delta trajectory (dproj): computed ON-CHAIN as a homogeneous projective walk with the same doubling and
  // mixed-addition formulas as B (projDbl/projAdd below). delta is a baked VK constant, so the whole trajectory
  // is deterministic; this build-time check replaces the old slope-pile assertion. For all 88 steps (65 doublings,
  // 21 additions with +-delta, the two Frobenius additions with psi(delta) and -psi^2(delta)) it asserts against
  // noble: (X/Z, Y/Z) is the true point, Z != 0, the line's leading coefficient (H = 2YZ, resp. lambda') is
  // nonzero, and the projective line equals that coefficient times the affine tangent/chord line (1, -lam, lam xT - yT).
  const d = V.delta.toAffine();
  const [p1x, p1y] = psiK(1, d.x, d.y), [p2x, p2y] = psiK(2, d.x, d.y);
  const Q1 = bn254.G2.Point.fromAffine({x: p1x, y: p1y}), Q2 = bn254.G2.Point.fromAffine({x: p2x, y: F2.neg(p2y)});
  { let T = [d.x, d.y, F2.ONE], Tt = V.delta, steps = 0;
    const aff = ([X, Y, Z]) => { assert.ok(!F2.is0(Z), 'delta walk: Z = 0'); const zi = F2.inv(Z); return [F2.mul(X, zi), F2.mul(Y, zi)]; };
    const chk = (o, Tprev, lam) => { const [l0, l1, l3] = o.line; const ta = Tprev.toAffine();
      assert.ok(!F2.is0(l0), 'delta line: leading coefficient 0');
      assert.ok(F2.eql(l1, F2.mul(l0, F2.neg(lam))) && F2.eql(l3, F2.mul(l0, F2.sub(F2.mul(lam, ta.x), ta.y))), 'delta line != l0 * affine line'); steps++; };
    const slopeDbl = (Ta) => F2.div(F2.mul(f2(3n, 0n), F2.sqr(Ta.x)), F2.add(Ta.y, Ta.y));
    const slopeAdd = (Ta, Qa) => { assert.ok(!F2.eql(Ta.x, Qa.x)); return F2.div(F2.sub(Qa.y, Ta.y), F2.sub(Qa.x, Ta.x)); };
    const dbl = () => { const o = projDbl(T); chk(o, Tt, slopeDbl(Tt.toAffine())); T = o.T; Tt = Tt.double(); const [x, y] = aff(T), ta = Tt.toAffine(); assert.ok(F2.eql(x, ta.x) && F2.eql(y, ta.y), 'delta walk dbl'); };
    const add = (Qp, q) => { const o = projAdd(T, q); chk(o, Tt, slopeAdd(Tt.toAffine(), Qp.toAffine())); T = o.T; Tt = Tt.add(Qp); const [x, y] = aff(T), ta = Tt.toAffine(); assert.ok(F2.eql(x, ta.x) && F2.eql(y, ta.y), 'delta walk add'); };
    for (let e = 0; e < NE; e++) { dbl(); if (DIGITS[e]) add(DIGITS[e] < 0 ? V.delta.negate() : V.delta, [d.x, DIGITS[e] < 0 ? F2.neg(d.y) : d.y]); }
    add(Q1, [p1x, p1y]); add(Q2, [p2x, F2.neg(p2y)]); assert.equal(steps, 88);
    // the Miller-loop endpoint (6x+2)delta + psi(delta) - psi^2(delta) == -psi^3(delta) (delta in G2)
    const [p3x, p3y] = psiK(3, d.x, d.y); const [x, y] = aff(T); assert.ok(F2.eql(x, p3x) && F2.eql(y, F2.neg(p3y)), 'delta endpoint'); }
  // pairing Miller values used as GT-GLS factors and the constant
  const m = (P, Q) => bn254.pairing(P, Q, false);
  const mIC = V.ic.map((P) => m(P, V.gamma));
  const mConst = F12.mul(m(V.alpha, V.beta), mIC[0]);
  const R = [1, 2].map((k) => [monicRep(mIC[k]), monicRep(F12.frobeniusMap(mIC[k], 1))]); // R[k][0], R[k][1] (degree-6 monic, 7 coeffs)
  // review fix (eta shortcut): R_{k,2} := R_{k,0}(eta X), R_{k,3} := R_{k,1}(eta X) are monic reps of Frob^2, Frob^3
  R.forEach((Rk, k) => [0, 1].forEach((i) => { const el = F12.frobeniusMap(mIC[k + 1], i + 2); const sh = psubst(Rk[i], ETA); assert.equal(sh[6], 1n); assert.ok(sameClass(fromPoly(sh), el), 'R_{k,i+2} via eta X'); }));
  // GLS offset correction: prod_{k,i} Frob^i(m_{IC_{k+1}})^(-2^64)
  let corr = F12.ONE; for (const k of [1, 2]) for (let i = 0; i < 4; i++) corr = F12.mul(corr, F12.frobeniusMap(mIC[k], i));
  corr = F12.conjugate(F12.pow(corr, GLS_OFFSET)); // conj = inverse up to Fp6 (same class); exponent -2^64
  const Rconst = monicRep(F12.mul(mConst, corr));
  return {deltaAff: d, deltaPsi: {x: p1x, y: p1y}, deltaPsi2neg: {x: p2x, y: F2.neg(p2y)}, mIC, mConst, R, Rconst};
})();
// polynomial of the GLS factor (k, i) with sign s (0: +, 1: -): R_{k,i}(+-X), R_{k,2/3} = R_{k,0/1}(eta X)
export const glsFactorPoly = (k, i) => { let f = VKC.R[k][i % 2]; if (i >= 2) f = psubst(f, ETA); return f; };
