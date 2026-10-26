// BLS12-381 SI-GLS math (design prototype): the tower <-> polynomial map, M-type lines, Frobenius,
// the GT-GLS lattice and the number-theoretic facts the soundness argument uses. Every constant is
// recomputed and asserted against noble at import time.
//
//   Fp12 = Fp[X]/M(X), M = X^12 - 2 X^6 + 2, X = w (noble tower: u^2 = -1, v^3 = 1 + u, w^2 = v),
//   u = X^6 - 1; an Fp2 element a0 + a1 u maps to Phi(a) = (a0 - a1) + a1 X^6.
//   M-type line (noble mul014): o0 + o1 v + o4 v w = Phi(c0) + xP Phi(c1) X^2 + yP Phi(c2) X^3.
import assert from 'node:assert/strict';
import {bls12_381} from '@noble/curves/bls12-381.js';

export const {Fp, Fp2: F2, Fp6, Fp12: F12} = bls12_381.fields;
export const p = Fp.ORDER, r = bls12_381.fields.Fr.ORDER;
export const BLS_X = -0xd201000000010000n, AX = 0xd201000000010000n; // x < 0, |x|
export const mod = (x, m = p) => ((x % m) + m) % m;
export const inv = (x) => Fp.inv(mod(x));
export const f2 = (a, b) => F2.fromBigTuple([mod(a), mod(b)]);
const gcd = (a, b) => { a = a < 0n ? -a : a; b = b < 0n ? -b : b; while (b) [a, b] = [b, a % b]; return a; };

// ---------------- polynomials ----------------
export const pmul = (a, b) => { const o = Array(a.length + b.length - 1).fill(0n); for (let i = 0; i < a.length; i++) if (a[i]) for (let j = 0; j < b.length; j++) o[i + j] += a[i] * b[j]; return o.map((x) => mod(x)); };
export const psub = (a, b) => Array.from({length: Math.max(a.length, b.length)}, (_, i) => mod((a[i] ?? 0n) - (b[i] ?? 0n)));
export const psubst = (a, s) => { let k = 1n; return a.map((c) => { const v = mod(c * k); k = mod(k * s); return v; }); };
export const pneg = (a) => psubst(a, p - 1n);
export const peval = (a, x) => { let acc = 0n; for (let i = a.length - 1; i >= 0; i--) acc = mod(acc * x + a[i]); return acc; };
export const M = [2n, 0n, 0n, 0n, 0n, 0n, mod(-2n), 0n, 0n, 0n, 0n, 0n, 1n];
export const pdivM = (a) => {
  const rem = a.slice(); const q = Array(Math.max(1, a.length - 12)).fill(0n);
  for (let i = rem.length - 1; i >= 12; i--) { const v = rem[i]; q[i - 12] = v; rem[i] = 0n; rem[i - 6] = mod(rem[i - 6] + 2n * v); rem[i - 12] = mod(rem[i - 12] - 2n * v); }
  return {q, r: rem.slice(0, 12).concat(Array(Math.max(0, 12 - rem.length)).fill(0n))};
};
export const pmodM = (a) => pdivM(a).r;
export const isZero = (a) => a.every((x) => x === 0n);

// ---------------- tower <-> polynomial ----------------
const flat = (x) => [x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1, x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1];
const SLOT_DEG = [0, 2, 4, 1, 3, 5];
export const toPoly = (x) => { const c = flat(x), out = Array(12).fill(0n); SLOT_DEG.forEach((d, i) => { out[d] = mod(c[2 * i] - c[2 * i + 1]); out[d + 6] = c[2 * i + 1]; }); return out; };
export const fromPoly = (a) => {
  const c = pmodM(a); const s = SLOT_DEG.map((d) => ({c0: mod(c[d] + c[d + 6]), c1: c[d + 6]}));
  return F12.create({c0: Fp6.create({c0: s[0], c1: s[1], c2: s[2]}), c1: Fp6.create({c0: s[3], c1: s[4], c2: s[5]})});
};
export const Phi = (a) => { const o = Array(7).fill(0n); o[0] = mod(a.c0 - a.c1); o[6] = mod(a.c1); return o; };
const randF12 = (seed) => F12.fromBigTwelve(Array.from({length: 12}, (_, i) => mod(BigInt(seed * 1000003 + i * 7919 + 1) ** 37n)));
for (let s = 1; s < 4; s++) { // the map is a ring isomorphism
  const a = randF12(s), b = randF12(s + 10);
  assert.ok(F12.eql(fromPoly(toPoly(a)), a));
  assert.equal(pmodM(pmul(toPoly(a), toPoly(b))).join(), toPoly(F12.mul(a, b)).join(), 'X-representation is multiplicative');
}
export const sameClass = (a, b) => isZero(toPoly(F12.sub(F12.mul(a, F12.conjugate(b)), F12.conjugate(F12.mul(a, F12.conjugate(b))))));
for (let s = 4; s < 7; s++) { const el = randF12(s); assert.equal(toPoly(F12.frobeniusMap(el, 6)).join(), pmodM(pneg(toPoly(el))).join(), 'Frob^6 = X -> -X'); }

// monic degree-6 class representative (as in the BN SI-GLS)
const solveMod = (A, b) => {
  const n = A.length, Mx = A.map((row, i) => [...row, b[i]].map((x) => mod(x)));
  for (let c = 0; c < n; c++) {
    let piv = c; while (piv < n && Mx[piv][c] === 0n) piv++; if (piv === n) throw new Error('monic representative does not exist');
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
  const rep = out.slice(0, 7); assert.ok(sameClass(fromPoly(rep), f)); return rep;
};

// ---------------- eta: Frob^2 = X -> eta X ----------------
export const ETA = (() => {
  assert.equal(p % 6n, 1n);
  const cands = []; for (let a = 2n; cands.length < 2; a++) { const e = Fp.pow(a, (p - 1n) / 6n); if (Fp.pow(e, 2n) !== 1n && Fp.pow(e, 3n) !== 1n && !cands.includes(e)) cands.push(e); }
  const ok = cands.filter((eta) => [1, 2, 3].every((s) => { const el = randF12(s); return pmodM(psubst(toPoly(el), eta)).join() === toPoly(F12.frobeniusMap(el, 2)).join(); }));
  assert.equal(ok.length, 1, 'exactly one primitive 6th root realizes Frob^2'); return ok[0];
})();
assert.equal(Fp.pow(ETA, 6n), 1n); assert.equal(mod(ETA * ETA), ETA - 1n, 'eta^2 = eta - 1');
// Frob(X^j) = alpha_j X^j + beta_j X^(j+6) (j = 1..5), Frob(1) = 1, Frob(X^6) = X^6 rewritten: (1+u)^p = 1 + u^p = 1 - u => X^6 -> 2 - X^6
export const FROB = (() => {
  const mono = (j) => fromPoly([...Array(j).fill(0n), 1n]); const out = {alpha: [], beta: []};
  for (let j = 1; j <= 5; j++) { const fp = toPoly(F12.frobeniusMap(mono(j), 1)); fp.forEach((c, i) => assert.ok(c === 0n || i === j || i === j + 6)); out.alpha[j] = fp[j]; out.beta[j] = fp[j + 6]; }
  assert.equal(toPoly(F12.frobeniusMap(mono(6), 1)).join(), [2n, 0n, 0n, 0n, 0n, 0n, p - 1n, 0n, 0n, 0n, 0n, 0n].join());
  return out;
})();
export const GAMMA1 = F2.pow(f2(1n, 1n), (p - 1n) / 6n); // (1+u)^((p-1)/6): Frob(X^j) = Phi(GAMMA1^j) X^j
{ let g = F2.ONE; for (let j = 1; j <= 5; j++) { g = F2.mul(g, GAMMA1); assert.equal(mod(g.c0 - g.c1), FROB.alpha[j]); assert.equal(g.c1, FROB.beta[j]); } }
export const frob1Monic = (s) => { const o = Array(12).fill(0n); o[0] = mod(s[0] + 2n); o[6] = p - 1n; for (let j = 1; j <= 5; j++) { o[j] = mod(o[j] + s[j] * FROB.alpha[j]); o[j + 6] = mod(o[j + 6] + s[j] * FROB.beta[j]); } return o; };
for (let t = 0; t < 3; t++) { const s = Array.from({length: 6}, (_, i) => mod(BigInt(t * 31 + i + 5) ** 41n)); assert.equal(pmodM(frob1Monic(s)).join(), toPoly(F12.frobeniusMap(fromPoly([...s, 1n]), 1)).join(), 'Frob(S)'); }

// ---------------- curve, twist, psi, lines ----------------
export const B_TWIST = f2(4n, 4n); // E': y^2 = x^3 + 4(1+u)
// psi(x, y) = (conj(x) PX, conj(y) PY); check against noble's G2 psi via the subgroup criterion psi(Q) = [x]Q on G2
export const PSI = (() => {
  // psi = untwist-Frobenius-twist; with w-coordinates: x' = x w^2, y' = y w^3 -> Frob -> divide: PX = gamma^2.., derive from GAMMA1
  const PX = F2.inv(F2.pow(GAMMA1, 2n)), PY = F2.inv(F2.pow(GAMMA1, 3n));
  return {PX, PY};
})();
const conj2 = (a) => ({c0: a.c0, c1: mod(-a.c1)});
export const psiAff = (x, y) => [F2.mul(conj2(x), PSI.PX), F2.mul(conj2(y), PSI.PY)];
{ // psi(Q) == [x]Q for Q in G2 (Scott), with these constants (or with their inverses: pick the right pair)
  const Q = bls12_381.G2.Point.BASE.multiply(12345n); const a = Q.toAffine(); const [px, py] = psiAff(a.x, a.y);
  const xQ = Q.multiply(AX).negate().toAffine();
  assert.ok(F2.eql(px, xQ.x) && F2.eql(py, xQ.y), 'psi(Q) = [x]Q on G2 with PX = gamma^-2, PY = gamma^-3');
}
// polynomial of the M-type line Phi(c0) + xP Phi(c1) X^2 + yP Phi(c2) X^3
export const linePoly = (xP, yP, c0, c1, c2) => { const o = Array(10).fill(0n); const [a, b, c] = [Phi(c0), Phi(c1), Phi(c2)];
  for (let i = 0; i < 7; i++) { o[i] = mod(o[i] + a[i]); o[i + 2] = mod(o[i + 2] + xP * b[i]); o[i + 3] = mod(o[i + 3] + yP * c[i]); } return o; };
// homogeneous projective B formulas (scaled): doubling X3 = 2XY(B-F), Y3 = (B+F)^2 - 12E^2, Z3 = 4BH; line (E-B, 3X^2, -H)
export const B3 = F2.mul(B_TWIST, f2(3n, 0n)); // 3b' = 12 + 12u
export const projDbl = ([X, Y, Z]) => {
  const B = F2.sqr(Y), C = F2.sqr(Z), E = F2.mul(B3, C), Fv = F2.mul(E, f2(3n, 0n)), H = F2.mul(F2.mul(Y, Z), f2(2n, 0n));
  return {T: [F2.mul(F2.mul(F2.mul(X, Y), f2(2n, 0n)), F2.sub(B, Fv)), F2.sub(F2.sqr(F2.add(B, Fv)), F2.mul(F2.sqr(E), f2(12n, 0n))), F2.mul(F2.mul(B, H), f2(4n, 0n))],
    line: [F2.sub(E, B), F2.mul(F2.sqr(X), f2(3n, 0n)), F2.neg(H)]};
};
// mixed addition with affine Q: theta = Y - yq Z, la = X - xq Z; line (theta xq - la yq, -theta, la)
export const projAdd = ([X, Y, Z], [xq, yq]) => {
  const th = F2.sub(Y, F2.mul(yq, Z)), la = F2.sub(X, F2.mul(xq, Z));
  const D = F2.sqr(la), E = F2.mul(la, D), Fv = F2.mul(Z, F2.sqr(th)), G = F2.mul(X, D), H = F2.sub(F2.add(E, Fv), F2.add(G, G));
  return {T: [F2.mul(la, H), F2.sub(F2.mul(th, F2.sub(G, H)), F2.mul(Y, E)), F2.mul(Z, E)], line: [F2.sub(F2.mul(th, xq), F2.mul(la, yq)), F2.neg(th), la]};
};
// affine witnessed-slope steps (alternative B walk): doubling slope lam: 2 y lam = 3 x^2; addition: lam (xq - x) = yq - y
export const affDbl = ([x, y], lam) => { const nx = F2.sub(F2.sqr(lam), F2.add(x, x)); return {T: [nx, F2.sub(F2.mul(lam, F2.sub(x, nx)), y)], line: [F2.sub(F2.mul(lam, x), y), F2.neg(lam), F2.ONE]}; };
export const affAdd = ([x, y], [xq, yq], lam) => { const nx = F2.sub(F2.sub(F2.sqr(lam), x), xq); return {T: [nx, F2.sub(F2.mul(lam, F2.sub(x, nx)), y)], line: [F2.sub(F2.mul(lam, x), y), F2.neg(lam), F2.ONE]}; };

// ---------------- Miller schedule: binary |x|, 63 doubling events, 5 additions ----------------
export const BITS = AX.toString(2).split('').map(Number); assert.equal(BITS.length, 64); assert.equal(BITS[0], 1);
export const EVENTS = BITS.slice(1); // event e = 1..63 -> EVENTS[e-1]: double, then add iff bit
export const NEV = EVENTS.length; assert.equal(NEV, 63);
export const ADD_EVENTS = EVENTS.map((b, i) => (b ? i + 1 : 0)).filter(Boolean); assert.deepEqual(ADD_EVENTS, [1, 3, 6, 15, 47]);
// check: line products with this schedule give noble's Miller value up to Fp6 (same class)
export function millerClass(P, Q) { // P in G1 (affine), Q in G2 (affine); f_{|x|,Q}(P) via our formulas
  let T = [Q.x, Q.y, F2.ONE], f = F12.ONE;
  for (const b of EVENTS) { f = F12.sqr(f); let o = projDbl(T); f = F12.mul(f, fromPoly(linePoly(P.x, P.y, ...o.line))); T = o.T; if (b) { o = projAdd(T, [Q.x, Q.y]); f = F12.mul(f, fromPoly(linePoly(P.x, P.y, ...o.line))); T = o.T; } }
  return {f, T};
}
{ const P = bls12_381.G1.Point.BASE.multiply(777n).toAffine(), Q = bls12_381.G2.Point.BASE.multiply(999n).toAffine();
  const {f} = millerClass(P, Q); const nob = bls12_381.pairing(bls12_381.G1.Point.fromAffine(P), bls12_381.G2.Point.fromAffine(Q), false); // conj(f_|x|)
  assert.ok(sameClass(F12.conjugate(f), nob), 'our Miller class = noble Miller value (x < 0: conjugate)');
  assert.ok(F12.eql(F12.finalExponentiate(F12.conjugate(f)), bls12_381.pairing(bls12_381.G1.Point.fromAffine(P), bls12_381.G2.Point.fromAffine(Q))), 'pairing value'); }

// ---------------- residue exponent and G2 facts ----------------
export const LAMBDA = p + AX; // = p - x
export const N6R = (p ** 6n + 1n) / r;
export const FACTS = (() => {
  assert.equal((p ** 6n + 1n) % r, 0n); assert.equal(LAMBDA % r, 0n, 'lambda = p - x = m r');
  assert.equal(gcd(LAMBDA / r, N6R), 1n, 'gcd(lambda/r, (p^6+1)/r) = 1: residue roots exist');
  assert.notEqual(N6R % r, 0n, 'r does not divide (p^6+1)/r');
  // #E'(Fp2) for the sextic twist: t2 = t^2 - 2p, t2^2 - 4p^2 = -3 f^2, #E' = p^2 + 1 - (t2 - 3f)/2 (asserted = noble's h * r)
  const t = BLS_X + 1n, t2 = t * t - 2n * p, f2sq = (4n * p * p - t2 * t2) / 3n;
  let f = 1n << 400n; for (;;) { const g = (f + f2sq / f) / 2n; if (g >= f) break; f = g; } assert.equal(f * f, f2sq);
  const n2 = p * p + 1n - (t2 - 3n * f) / 2n, h2 = n2 / r; assert.equal(n2 % r, 0n, '#E\'(Fp2) divisible by r');
  assert.equal(h2, bls12_381.G2.Point.CURVE().h, 'G2 cofactor = noble');
  assert.notEqual(h2 % r, 0n, 'r^2 does not divide #E\'(Fp2)');
  assert.equal(gcd(p - BLS_X, h2), 1n, 'deg(psi - [x]) = p - x is coprime to the G2 cofactor: psi(Q) = [x]Q => Q in G2');
  const h1 = (BLS_X - 1n) ** 2n / 3n; assert.equal(h1 % 2n, 1n, 'E(Fp) has odd order: y != 0 on G1-side points');
  // irreducibility of M is implied by the ring isomorphism above (Fp12 is a field)
  return {h2, h1};
})();

// ---------------- GT-GLS lattice: Frob acts on mu_r as p = x (mod r) ----------------
export const PI = [1n, p % r, (p * p) % r, (p ** 3n) % r];
assert.equal(PI[1], mod(BLS_X, r), 'p = x (mod r)');
export const LATTICE = (() => {
  const x = BLS_X; const L = [[-x, 1n, 0n, 0n], [0n, -x, 1n, 0n], [0n, 0n, -x, 1n], [-1n, 0n, 1n, -x]];
  L.forEach((b) => assert.equal(mod(b.reduce((s, v, i) => s + v * PI[i], 0n), r), 0n, 'lattice vector'));
  return L;
})();
const det = (m) => (m.length === 1 ? m[0][0] : m[0].reduce((s, v, j) => s + (j % 2 ? -1n : 1n) * v * det(m.slice(1).map((row) => row.filter((_, k) => k !== j))), 0n));
const DET = det(LATTICE); assert.equal(DET < 0n ? -DET : DET, r, 'lattice has index r');
const COF = [0, 1, 2, 3].map((j) => (j % 2 ? -1n : 1n) * det(LATTICE.filter((_, a) => a !== j).map((row) => row.slice(1))));
const roundDiv = (a, b) => { if (b < 0n) { a = -a; b = -b; } const q = a / b, rm = a % b; if (2n * (rm < 0n ? -rm : rm) >= b) return a < 0n ? q - 1n : q + 1n; return q; };
export const glsDecompose = (n) => {
  const c = COF.map((cj) => roundDiv(n * cj, DET));
  const e = [n, 0n, 0n, 0n].map((v, i) => v - c.reduce((s, cj, j) => s + cj * LATTICE[j][i], 0n));
  assert.equal(mod(e.reduce((s, v, i) => s + v * PI[i], 0n), r), mod(n, r)); return e;
};
export const GLS_BITS = 64, GLS_OFFSET = 1n << 63n; // u = e + 2^63 in [0, 2^64): bit 63 - e at GLS event e (0..63)
{ const colSum = [0, 1, 2, 3].map((i) => LATTICE.reduce((s, b) => s + (b[i] < 0n ? -b[i] : b[i]), 0n)); assert.ok(colSum.every((c) => c < 2n * GLS_OFFSET), 'Babai bound |e| < 2^63'); }
export const PI_SUM_OFFSET = mod(GLS_OFFSET * PI.reduce((a, b) => a + b, 0n), r);
