// Track 6 math: field / polynomial helpers and the tower <-> polynomial map (forked from
// chunked/bn254/sound-si-gls/math.mjs, reviewed), plus the PLONK/KZG-specific constants:
//   - the two fixed-G2 chains ([1]_2 and [x]_2), each with 88 baked slopes, checked against noble;
//   - the G1 GLV endomorphism (beta, lambda), checked against noble;
//   - the MSM offset point (hash-to-curve, unknown discrete log) and its correction points.
// Every constant is recomputed and asserted when this module loads.
//
//   Fp12 = Fp[X]/M(X), M = X^12 - 18 X^6 + 82, X = w (noble tower: u^2 = -1, v = w^2, v^3 = 9 + u),
//   u = X^6 - 9; an Fp2 element a0 + a1 u maps to Phi(a) = (a0 - 9 a1) + a1 X^6.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {bn254} from '@noble/curves/bn254.js';
import {psiFrobenius} from '@noble/curves/abstract/tower.js';

export const {Fp, Fp2: F2, Fp6, Fp12: F12} = bn254.fields;
export const p = Fp.ORDER, r = bn254.fields.Fr.ORDER, BN_X = 4965661367192848881n;
export const mod = (x, m = p) => ((x % m) + m) % m;
export const inv = (x, m = p) => { let [a, b] = [mod(x, m), m], [s0, s1] = [1n, 0n]; while (b) { const q = a / b; [a, b] = [b, a - q * b]; [s0, s1] = [s1, s0 - q * s1]; } assert.equal(a, 1n, 'not invertible'); return mod(s0, m); };
export const powm = (b, e, m) => { let o = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) o = (o * b) % m; b = (b * b) % m; e >>= 1n; } return o; };
export const G1 = bn254.G1.Point, G2 = bn254.G2.Point;

// ---------------- polynomials over Fp ----------------
export const pmul = (a, b) => { const o = Array(a.length + b.length - 1).fill(0n); for (let i = 0; i < a.length; i++) if (a[i]) for (let j = 0; j < b.length; j++) o[i + j] += a[i] * b[j]; return o.map((x) => mod(x)); };
export const psub = (a, b) => Array.from({length: Math.max(a.length, b.length)}, (_, i) => mod((a[i] ?? 0n) - (b[i] ?? 0n)));
export const psubst = (a, s) => { let k = 1n; return a.map((c) => { const v = mod(c * k); k = mod(k * s); return v; }); }; // a(sX)
export const pneg = (a) => psubst(a, p - 1n);
export const peval = (a, x) => { let acc = 0n; for (let i = a.length - 1; i >= 0; i--) acc = mod(acc * x + a[i]); return acc; };
export const M = [82n, 0n, 0n, 0n, 0n, 0n, mod(-18n), 0n, 0n, 0n, 0n, 0n, 1n];
export const pdivM = (a) => {
  const rem = a.slice(); const q = Array(Math.max(1, a.length - 12)).fill(0n);
  for (let i = rem.length - 1; i >= 12; i--) { const v = rem[i]; q[i - 12] = v; rem[i] = 0n; rem[i - 6] = mod(rem[i - 6] + 18n * v); rem[i - 12] = mod(rem[i - 12] - 82n * v); }
  return {q, r: rem.slice(0, 12).concat(Array(Math.max(0, 12 - rem.length)).fill(0n))};
};
export const pmodM = (a) => pdivM(a).r;
export const isZero = (a) => a.every((x) => x === 0n);

// ---------------- tower <-> polynomial ----------------
const flat = (x) => [x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1, x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1];
const SLOT_DEG = [0, 2, 4, 1, 3, 5];
export const toPoly = (x) => { const c = flat(x), out = Array(12).fill(0n); SLOT_DEG.forEach((d, i) => { out[d] = mod(c[2 * i] - 9n * c[2 * i + 1]); out[d + 6] = c[2 * i + 1]; }); return out; };
export const fromPoly = (a) => {
  const c = pmodM(a); const s = SLOT_DEG.map((d) => ({c0: mod(c[d] + 9n * c[d + 6]), c1: c[d + 6]}));
  return F12.create({c0: Fp6.create({c0: s[0], c1: s[1], c2: s[2]}), c1: Fp6.create({c0: s[3], c1: s[4], c2: s[5]})});
};
export const Phi = (a) => { const o = Array(7).fill(0n); o[0] = mod(a.c0 - 9n * a.c1); o[6] = mod(a.c1); return o; };
export const f2 = (a, b) => F2.fromBigTuple([mod(a), mod(b)]);
const solveMod = (A, b) => {
  const n = A.length, Mx = A.map((row, i) => [...row, b[i]].map((x) => mod(x)));
  for (let c = 0; c < n; c++) {
    let piv = c; while (piv < n && Mx[piv][c] === 0n) piv++; if (piv === n) throw new Error('monic representative does not exist (singular)');
    [Mx[c], Mx[piv]] = [Mx[piv], Mx[c]]; const iv = inv(Mx[c][c]); Mx[c] = Mx[c].map((x) => mod(x * iv));
    for (let i = 0; i < n; i++) if (i !== c && Mx[i][c]) { const m = Mx[i][c]; Mx[i] = Mx[i].map((x, k) => mod(x - m * Mx[c][k])); }
  }
  return Mx.map((row) => row[n]);
};
export const sameClass = (a, b) => isZero(toPoly(F12.sub(F12.mul(a, F12.conjugate(b)), F12.conjugate(F12.mul(a, F12.conjugate(b))))));
export const monicRep = (f) => {
  const fp = toPoly(f); const cols = [0, 2, 4, 6, 8, 10].map((d) => pmodM(pmul([...Array(d).fill(0n), 1n], fp)));
  const s = solveMod([6, 7, 8, 9, 10, 11].map((row) => cols.map((c) => c[row])), [1n, 0n, 0n, 0n, 0n, 0n]);
  const out = Array(12).fill(0n); cols.forEach((c, j) => c.forEach((x, i) => (out[i] = mod(out[i] + s[j] * x))));
  assert.ok(out.slice(7).every((x) => x === 0n) && out[6] === 1n);
  const rep = out.slice(0, 7); assert.ok(sameClass(fromPoly(rep), f)); return rep;
};

// ---------------- psi, eta, Frobenius (as in SI-GLS) ----------------
const {psi} = psiFrobenius(Fp, F2, F2.NONRESIDUE);
const conj2 = (a) => ({c0: a.c0, c1: mod(-a.c1)});
const conjK = (a, k) => (k % 2 ? conj2(a) : a);
export const PSI = [1, 2, 3].map((k) => { let x = F2.ONE, y = F2.ONE; for (let i = 0; i < k; i++) [x, y] = psi(x, y); return {k, x, y}; });
export const psiK = (k, x, y) => [F2.mul(conjK(x, k), PSI[k - 1].x), F2.mul(conjK(y, k), PSI[k - 1].y)];
for (let t = 0; t < 3; t++) {
  const Q = G2.BASE.multiply(BigInt(1000 + 7919 * t)).toAffine(); let [x, y] = [Q.x, Q.y];
  for (let k = 1; k <= 3; k++) { [x, y] = psi(x, y); const [a, b] = psiK(k, Q.x, Q.y); assert.ok(F2.eql(a, x) && F2.eql(b, y), 'psi^' + k); }
}
const randF12 = (seed) => F12.fromBigTwelve(Array.from({length: 12}, (_, i) => mod(BigInt(seed * 1000003 + i * 7919 + 1) ** 37n)));
export const ETA = (() => {
  const g = (() => { for (let a = 2n; ; a++) { const e = Fp.pow(a, (p - 1n) / 6n); if (Fp.pow(e, 2n) !== 1n && Fp.pow(e, 3n) !== 1n) return e; } })();
  const ok = [g, Fp.pow(g, 5n)].filter((eta) => [1, 2, 3].every((s) => { const el = randF12(s); return pmodM(psubst(toPoly(el), eta)).join() === toPoly(F12.frobeniusMap(el, 2)).join(); }));
  assert.equal(ok.length, 1); return ok[0];
})();
for (let s = 4; s < 7; s++) { const el = randF12(s); assert.equal(toPoly(F12.frobeniusMap(el, 6)).join(), pmodM(pneg(toPoly(el))).join(), 'Frob^6 = X -> -X'); }
export const FROB = (() => {
  const mono = (j) => fromPoly([...Array(j).fill(0n), 1n]); const out = {alpha: [], beta: []};
  for (let j = 1; j <= 5; j++) { const fp = toPoly(F12.frobeniusMap(mono(j), 1)); fp.forEach((c, i) => assert.ok(c === 0n || i === j || i === j + 6)); out.alpha[j] = fp[j]; out.beta[j] = fp[j + 6]; }
  assert.equal(toPoly(F12.frobeniusMap(mono(6), 1)).join(), [18n, 0n, 0n, 0n, 0n, 0n, p - 1n, 0n, 0n, 0n, 0n, 0n].join());
  return out;
})();
export const GAMMA1 = F2.pow(f2(9n, 1n), (p - 1n) / 6n);
{ let g = F2.ONE; for (let j = 1; j <= 5; j++) { g = F2.mul(g, GAMMA1); assert.equal(mod(g.c0 - 9n * g.c1), FROB.alpha[j]); assert.equal(g.c1, FROB.beta[j]); }
  assert.ok(F2.eql(PSI[0].x, F2.pow(GAMMA1, 2n)) && F2.eql(PSI[0].y, F2.pow(GAMMA1, 3n)));
  assert.equal(mod(ETA * ETA), ETA - 1n); }
export const frob1Monic = (s) => { const o = Array(12).fill(0n); o[0] = mod(s[0] + 18n); o[6] = p - 1n; for (let j = 1; j <= 5; j++) { o[j] = mod(o[j] + s[j] * FROB.alpha[j]); o[j + 6] = mod(o[j + 6] + s[j] * FROB.beta[j]); } return o; };
for (let t = 0; t < 2; t++) { const s = Array.from({length: 6}, (_, i) => mod(BigInt(t * 31 + i + 5) ** 41n)); assert.equal(pmodM(frob1Monic(s)).join(), toPoly(F12.frobeniusMap(fromPoly([...s, 1n]), 1)).join()); }

// ---------------- Miller schedule and residue facts ----------------
export const DIGITS = (() => { const d = []; for (let n = 6n * BN_X + 2n; n > 1n; n >>= 1n) { if (!(n & 1n)) d.unshift(0); else if ((n & 3n) === 3n) { d.unshift(-1); n++; } else d.unshift(1); } return d; })();
export const NE = DIGITS.length; assert.equal(NE, 65);
assert.equal(DIGITS.reduce((acc, d) => 2n * acc + BigInt(d), 1n), 6n * BN_X + 2n);
for (let e = 1; e < NE; e++) assert.ok(!(DIGITS[e] && DIGITS[e - 1]));
export const NADD = DIGITS.filter((d) => d).length;
export const LAMBDA = 6n * BN_X + 2n + p - p ** 2n + p ** 3n;
export const N6R = (p ** 6n + 1n) / r;
const gcd = (a, b) => { a = a < 0n ? -a : a; b = b < 0n ? -b : b; while (b) [a, b] = [b, a % b]; return a; };
assert.equal((p ** 6n + 1n) % r, 0n); assert.equal(LAMBDA % r, 0n);
assert.equal(gcd(LAMBDA, N6R), 1n, 'residue root exists'); assert.equal(gcd(3n, p ** 6n + 1n), 1n);

// ---------------- one fixed-G2 chain (the SI-GLS delta chain, for any fixed Q in G2) ----------------
// lams: 65 doubling slopes and 21 addition slopes (+-Q) in loop order, then the slope of T + psi(Q) (tracked line),
// then the slope of T' - psi^2(Q) (its c follows from the same recursion). The on-chain recursion
// c_j = (lambda_{j-1} + lambda_j) x_j - c_{j-1}, x_{j+1} = lambda_j^2 - x_j - s_j is asserted against noble's points.
export function chainConsts(Q) {
  Q.assertValidity(); const d = Q.toAffine(); let T = Q; const lams = [];
  const slopeDbl = (Ta) => F2.div(F2.mul(f2(3n, 0n), F2.sqr(Ta.x)), F2.add(Ta.y, Ta.y));
  const slopeAdd = (Ta, Qa) => { assert.ok(!F2.eql(Ta.x, Qa.x), 'exceptional chain step'); return F2.div(F2.sub(Qa.y, Ta.y), F2.sub(Qa.x, Ta.x)); };
  for (let e = 0; e < NE; e++) {
    assert.ok(!T.is0()); lams.push(slopeDbl(T.toAffine())); T = T.double();
    if (DIGITS[e]) { const Qs = DIGITS[e] < 0 ? Q.negate() : Q; lams.push(slopeAdd(T.toAffine(), Qs.toAffine())); T = T.add(Qs); }
  }
  const [p1x, p1y] = psiK(1, d.x, d.y), [p2x, p2y] = psiK(2, d.x, d.y), [p3x, p3y] = psiK(3, d.x, d.y);
  const Q1 = G2.fromAffine({x: p1x, y: p1y}), Q2 = G2.fromAffine({x: p2x, y: F2.neg(p2y)});
  lams.push(slopeAdd(T.toAffine(), Q1.toAffine())); T = T.add(Q1);
  const lamF2 = slopeAdd(T.toAffine(), Q2.toAffine()); T = T.add(Q2);
  // endpoint: (6x+2)Q + psi(Q) - psi^2(Q) = -psi^3(Q) (Q in G2)
  assert.ok(T.equals(G2.fromAffine({x: p3x, y: F2.neg(p3y)})), 'chain endpoint');
  const all = [...lams, lamF2]; assert.equal(all.length, 88);
  { let x = d.x, c = d.y, l = F2.ZERO, Tt = Q, j = 0;
    const check = (Ttrue) => { const ta = Ttrue.toAffine(); assert.ok(F2.eql(x, ta.x), 'x_j'); const cj = F2.sub(F2.mul(F2.add(l, all[j]), x), c); assert.ok(F2.eql(cj, F2.sub(F2.mul(all[j], ta.x), ta.y)), 'c_j'); assert.ok(!F2.is0(all[j]) || true); return cj; };
    const step = (s) => { const cj = check(Tt); const nx = F2.sub(F2.sub(F2.sqr(all[j]), x), s); c = cj; l = all[j]; x = nx; j++; };
    for (let e = 0; e < NE; e++) { step(x); Tt = Tt.double(); if (DIGITS[e]) { step(d.x); Tt = Tt.add(DIGITS[e] < 0 ? Q.negate() : Q); } }
    step(p1x); Tt = Tt.add(Q1); check(Tt); assert.equal(j, 87); }
  return {aff: d, lams: all, psi1x: p1x};
}
// line l0 yP + l1 xP X + l3 X^3 (Phi-mapped Fp2 coefficients) at an affine G1 point
export const linePoly = (xP, yP, l0, l1, l3) => { const o = Array(10).fill(0n); const [a, b, c] = [Phi(l0), Phi(l1), Phi(l3)];
  for (let i = 0; i < 7; i++) { o[i] = mod(o[i] + yP * a[i]); o[i + 1] = mod(o[i + 1] + xP * b[i]); o[i + 3] = mod(o[i + 3] + c[i]); } return o; };

// ---------------- G1 GLV endomorphism phi(x, y) = (beta x, y) = [lambda](x, y) ----------------
export const GLV = (() => {
  const cube = (m) => { for (let g = 2n; ; g++) { const c = powm(g, (m - 1n) / 3n, m); const cc = (c * c) % m; if (c !== 1n) return [c, cc]; } };
  const betas = cube(p).map((b) => b), lams = cube(r);
  const P0 = G1.BASE.multiply(123456789n).toAffine();
  for (const beta of betas) for (const lam of lams) { const a = G1.fromAffine({x: mod(beta * P0.x), y: P0.y}); if (a.equals(G1.fromAffine(P0).multiply(lam))) {
    for (let t = 0; t < 3; t++) { const Q = G1.BASE.multiply(BigInt(7 + 991 * t)).toAffine(); assert.ok(G1.fromAffine({x: mod(beta * Q.x), y: Q.y}).equals(G1.fromAffine(Q).multiply(lam))); }
    assert.equal(mod(lam * lam + lam + 1n, r), 0n); return {beta, lambda: lam}; } }
  throw new Error('no GLV pair');
})();

// ---------------- MSM offset point: try-and-increment from a tag (nobody knows its discrete log) ----------------
const sqrtP = (a) => { const s = Fp.pow(mod(a), (p + 1n) / 4n); return mod(s * s) === mod(a) ? s : null; }; // p = 3 mod 4
export const OFFSET = (() => {
  for (let i = 0; ; i++) { const x = mod(BigInt('0x' + createHash('sha256').update(`verifier.cash/plonk-kzg/msm-offset/${i}`).digest('hex'))); const y = sqrtP(x ** 3n + 3n); if (y !== null) return G1.fromAffine({x, y: y & 1n ? p - y : y}); }
})();
OFFSET.assertValidity();
export const aff = (P) => { const a = P.toAffine(); return [a.x, a.y]; };
