// BLS12-381 SI-GLS design prototype: field / polynomial helpers, the tower <-> polynomial map, the
// number-theoretic facts the soundness argument uses, and every baked constant, each one recomputed
// from first principles and asserted against noble at import time.
//
//   Fp12 = Fp[X]/M(X),  M = X^12 - 2 X^6 + 2,  X = w   (noble tower: u^2 = -1, v^3 = xi = 1 + u, w^2 = v)
//   u = X^6 - 1; an Fp2 element a0 + a1 u maps to Phi(a) = (a0 - a1) + a1 X^6, so Phi(a)(z) = a0 + a1 (z^6 - 1).
import assert from 'node:assert/strict';
import {bls12_381} from '@noble/curves/bls12-381.js';
import {psiFrobenius} from '@noble/curves/abstract/tower.js';

export const {Fp, Fp2: F2, Fp6, Fp12: F12} = bls12_381.fields;
export const p = Fp.ORDER, r = bls12_381.fields.Fr.ORDER;
export const T = 0xd201000000010000n;         // |x|, x = -T
export const X_SEED = -T;
export const mod = (x, m = p) => ((x % m) + m) % m;
export const inv = (x) => Fp.inv(mod(x));
const gcd = (a, b) => { a = a < 0n ? -a : a; b = b < 0n ? -b : b; while (b) [a, b] = [b, a % b]; return a; };
export const G1P = bls12_381.G1.Point, G2P = bls12_381.G2.Point;
assert.equal(bls12_381.params.ateLoopSize, T); assert.equal(bls12_381.params.twistType, 'multiplicative');

// ---------------- fixture VK (bench: singleton/bls12-381/bls_instance.mjs, gen-multiproof-bls12381.mjs) ----------------
export const VK_SCALARS = {alpha: 3n, beta: 5n, gamma: 7n, delta: 11n, ic: [2n, 4n, 6n]};
export const VK = {alpha: G1P.BASE.multiply(3n), beta: G2P.BASE.multiply(5n), gamma: G2P.BASE.multiply(7n), delta: G2P.BASE.multiply(11n),
  ic: [2n, 4n, 6n].map((k) => G1P.BASE.multiply(k))};
// a proof for public inputs n (B = b G2, C = c G1, A solved in the exponent), the bench's construction
export function modInv(a, m) { let [x, y] = [mod(a, m), m], [s0, s1] = [1n, 0n]; while (y) { const q = x / y; [x, y] = [y, x - q * y]; [s0, s1] = [s1, s0 - q * s1]; } assert.equal(x, 1n); return mod(s0, m); }
export function mintProof(ns, {b = 1n, c = 13n} = {}) {
  const S = VK_SCALARS; const vx = mod(S.ic[0] + ns[0] * S.ic[1] + ns[1] * S.ic[2], r);
  const a = mod((S.alpha * S.beta + vx * S.gamma + c * S.delta) * modInv(b, r), r);
  return {A: G1P.BASE.multiply(a), B: G2P.BASE.multiply(b), C: G1P.BASE.multiply(c), ns};
}
const smul = (P, k) => (mod(k, r) === 0n ? P.multiply(1n).subtract(P) : P.multiply(mod(k, r)));
export const groth16Holds = ({A, B, C, ns}) => {
  const vkx = VK.ic[0].add(smul(VK.ic[1], ns[0])).add(smul(VK.ic[2], ns[1]));
  const prod = bls12_381.pairingBatch([{g1: A.negate(), g2: B}, {g1: VK.alpha, g2: VK.beta}, {g1: vkx, g2: VK.gamma}, {g1: C, g2: VK.delta}], true);
  return F12.eql(prod, F12.ONE);
};

// ---------------- polynomials over Fp (coefficient arrays, low degree first) ----------------
export const trim = (a) => { a = a.slice(); while (a.length > 1 && a.at(-1) === 0n) a.pop(); return a; };
export const pmul = (a, b) => { const o = Array(a.length + b.length - 1).fill(0n); for (let i = 0; i < a.length; i++) if (a[i]) for (let j = 0; j < b.length; j++) o[i + j] += a[i] * b[j]; return o.map((x) => mod(x)); };
export const padd = (a, b) => Array.from({length: Math.max(a.length, b.length)}, (_, i) => mod((a[i] ?? 0n) + (b[i] ?? 0n)));
export const psub = (a, b) => Array.from({length: Math.max(a.length, b.length)}, (_, i) => mod((a[i] ?? 0n) - (b[i] ?? 0n)));
export const pscale = (a, s) => a.map((c) => mod(c * s));
export const psubst = (a, s) => { let k = 1n; return a.map((c) => { const v = mod(c * k); k = mod(k * s); return v; }); }; // a(sX)
export const pneg = (a) => psubst(a, p - 1n); // a(-X): conjugation sigma = Frob^6
export const peval = (a, x) => { let acc = 0n; for (let i = a.length - 1; i >= 0; i--) acc = mod(acc * x + a[i]); return acc; };
export const pdeg = (a) => trim(a).length - 1;
export const M = [2n, 0n, 0n, 0n, 0n, 0n, p - 2n, 0n, 0n, 0n, 0n, 0n, 1n];          // X^12 - 2X^6 + 2
export const pdivM = (a) => { // exact long division by the monic M: X^12 = 2X^6 - 2
  const rem = a.slice(); const q = Array(Math.max(1, a.length - 12)).fill(0n);
  for (let i = rem.length - 1; i >= 12; i--) { const v = rem[i]; q[i - 12] = v; rem[i] = 0n; rem[i - 6] = mod(rem[i - 6] + 2n * v); rem[i - 12] = mod(rem[i - 12] - 2n * v); }
  return {q, r: rem.slice(0, 12).concat(Array(Math.max(0, 12 - rem.length)).fill(0n))};
};
export const pmodM = (a) => pdivM(a).r;
export const isZero = (a) => a.every((x) => x === 0n);

// ---------------- tower <-> polynomial ----------------
const flat = (x) => [x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1, x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1];
const SLOT_DEG = [0, 2, 4, 1, 3, 5]; // c0.c0, c0.c1, c0.c2, c1.c0, c1.c1, c1.c2 = w^(0,2,4,1,3,5)
export const toPoly = (x) => { const c = flat(x), out = Array(12).fill(0n); SLOT_DEG.forEach((d, i) => { out[d] = mod(c[2 * i] - c[2 * i + 1]); out[d + 6] = c[2 * i + 1]; }); return out; };
export const fromPoly = (a) => {
  const c = pmodM(a); const s = SLOT_DEG.map((d) => ({c0: mod(c[d] + c[d + 6]), c1: c[d + 6]}));
  return F12.create({c0: Fp6.create({c0: s[0], c1: s[1], c2: s[2]}), c1: Fp6.create({c0: s[3], c1: s[4], c2: s[5]})});
};
export const Phi = (a) => { const o = Array(7).fill(0n); o[0] = mod(a.c0 - a.c1); o[6] = mod(a.c1); return o; };
export const f2 = (a, b) => F2.fromBigTuple([mod(a), mod(b)]);
const randF12 = (seed) => F12.fromBigTwelve(Array.from({length: 12}, (_, i) => mod(BigInt(seed * 1000003 + i * 7919 + 1) ** 37n)));
// the map is a ring isomorphism: checked on random products, and M(w) = 0
for (let s = 1; s <= 4; s++) { const a = randF12(s), b = randF12(s + 10); assert.equal(pmodM(pmul(toPoly(a), toPoly(b))).join(), toPoly(F12.mul(a, b)).join(), 'toPoly is multiplicative'); assert.ok(F12.eql(fromPoly(toPoly(a)), a)); }
{ const w = fromPoly([0n, 1n]); const w6 = F12.pow(w, 6n), w12 = F12.pow(w, 12n); assert.ok(F12.eql(F12.add(F12.sub(w12, F12.mul(w6, F12.fromBigTwelve([2n, ...Array(11).fill(0n)]))), F12.fromBigTwelve([2n, ...Array(11).fill(0n)])), F12.ZERO), 'M(w) = 0'); }

// ---------------- irreducibility of M (Ben-Or: gcd(X^(p^k) - X, M) = 1 for k = 1..6) ----------------
const polyMulMod = (a, b) => pmodM(pmul(a, b));
const polyPowMod = (a, e) => { let res = [1n], b = a; while (e > 0n) { if (e & 1n) res = polyMulMod(res, b); b = polyMulMod(b, b); e >>= 1n; } return res; };
const pgcd = (a, b) => { a = trim(a); b = trim(b); while (!(b.length === 1 && b[0] === 0n)) { // remainder a mod b over Fp
  let rem = a.slice(); const lb = b.at(-1), il = inv(lb);
  while (rem.length >= b.length && !(rem.length === 1 && rem[0] === 0n)) { const c = mod(rem.at(-1) * il), sh = rem.length - b.length; for (let i = 0; i < b.length; i++) rem[sh + i] = mod(rem[sh + i] - c * b[i]); rem = trim(rem); if (rem.length === 1 && rem[0] === 0n) break; if (rem.length < b.length) break; }
  [a, b] = [b, rem]; } return a; };
export const IRREDUCIBLE = (() => {
  let xp = [0n, 1n];
  for (let k = 1; k <= 6; k++) { xp = polyPowMod(xp, p); const g = pgcd(M, psub(xp, [0n, 1n])); assert.equal(trim(g).length, 1, `gcd(X^(p^${k}) - X, M) = 1`); }
  return true;
})();

// ---------------- class representatives in G = Fp12*/Fp6* ----------------
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
// monic degree-6 representative S = X^6 + s5 X^5 + ... + s0 with [S] = [f]: S = f * e with e in Fp6 (even)
export const monicRep = (f) => {
  const fp = toPoly(f); const cols = [0, 2, 4, 6, 8, 10].map((d) => pmodM(pmul([...Array(d).fill(0n), 1n], fp)));
  const s = solveMod([6, 7, 8, 9, 10, 11].map((row) => cols.map((c) => c[row])), [1n, 0n, 0n, 0n, 0n, 0n]);
  const out = Array(12).fill(0n); cols.forEach((c, j) => c.forEach((x, i) => (out[i] = mod(out[i] + s[j] * x))));
  assert.ok(out.slice(7).every((x) => x === 0n) && out[6] === 1n);
  const rep = out.slice(0, 7); assert.ok(sameClass(fromPoly(rep), f)); return rep; // [s0..s5, 1]
};
// conjugation = X -> -X (Frob^6)
for (let s = 4; s < 7; s++) { const el = randF12(s); assert.equal(toPoly(F12.frobeniusMap(el, 6)).join(), pmodM(pneg(toPoly(el))).join(), 'Frob^6 = X -> -X'); assert.ok(F12.eql(F12.conjugate(el), F12.frobeniusMap(el, 6))); }

// ---------------- Frobenius: Frob^2 = X -> eta X (eta in Fp), Frob(X^j) = Phi(gamma1^j) X^j ----------------
export const XI = f2(1n, 1n);
export const ETA = (() => {
  const g = (() => { for (let a = 2n; ; a++) { const e = Fp.pow(a, (p - 1n) / 6n); if (Fp.pow(e, 2n) !== 1n && Fp.pow(e, 3n) !== 1n) return e; } })();
  const ok = [g, Fp.pow(g, 5n)].filter((eta) => [1, 2, 3].every((s) => { const el = randF12(s); return pmodM(psubst(toPoly(el), eta)).join() === toPoly(F12.frobeniusMap(el, 2)).join(); }));
  assert.equal(ok.length, 1, 'exactly one primitive 6th root realizes Frob^2'); return ok[0];
})();
assert.equal(Fp.pow(ETA, 6n), 1n); assert.equal(Fp.pow(ETA, 3n), p - 1n); assert.equal(mod(ETA * ETA), mod(ETA - 1n), 'eta^2 = eta - 1');
export const GAMMA1 = F2.pow(XI, (p - 1n) / 6n);
{ // Frob(X^j) = Phi(gamma1^j) X^j for j = 1..5 (mod M); Frob(1) = 1; Frob(X^6) = Frob(1 + u) = 2 - X^6
  const mono = (j) => fromPoly([...Array(j).fill(0n), 1n]); let g = F2.ONE;
  for (let j = 1; j <= 5; j++) { g = F2.mul(g, GAMMA1); const want = pmodM(pmul(Phi(g), [...Array(j).fill(0n), 1n])); assert.equal(toPoly(F12.frobeniusMap(mono(j), 1)).join(), want.join(), 'Frob(X^' + j + ')'); }
  assert.equal(toPoly(F12.frobeniusMap(mono(6), 1)).join(), [2n, 0n, 0n, 0n, 0n, 0n, p - 1n, 0n, 0n, 0n, 0n, 0n].join(), 'Frob(X^6) = 2 - X^6');
}
// gamma1^j (j = 1..5), the coefficients the script uses: cj(z) = Phi(gamma1^j)(z) = g0 + g1 (z^6 - 1)
export const GAMMA_POW = (() => { const o = [F2.ONE]; for (let j = 1; j <= 6; j++) o.push(F2.mul(o[j - 1], GAMMA1)); return o; })();
// Frob(S) for a monic S = X^6 + sum_{j<6} s_j X^j, as a polynomial (degree <= 11, not reduced): the on-chain formula
export const frob1Monic = (s) => { let o = [2n, 0n, 0n, 0n, 0n, 0n, p - 1n]; o[0] = mod(o[0] + s[0]); for (let j = 1; j <= 5; j++) o = padd(o, pscale(pmul(Phi(GAMMA_POW[j]), [...Array(j).fill(0n), 1n]), s[j])); return o; };
for (let t = 0; t < 3; t++) { const s = Array.from({length: 6}, (_, i) => mod(BigInt(t * 31 + i + 5) ** 41n)); assert.equal(pmodM(frob1Monic(s)).join(), toPoly(F12.frobeniusMap(fromPoly([...s, 1n]), 1)).join(), 'Frob(S) formula'); }

// ---------------- twist, psi ----------------
export const B_TWIST = f2(4n, 4n);              // E': y^2 = x^3 + 4(1 + u)
export const B3 = F2.mul(B_TWIST, f2(3n, 0n));  // 3b' (projective doubling)
assert.ok(F2.eql(B_TWIST, bls12_381.G2.Point.CURVE().b));
const {psi} = psiFrobenius(Fp, F2, F2.div(F2.ONE, F2.NONRESIDUE));
const conj2 = (a) => ({c0: a.c0, c1: mod(-a.c1)});
export const PSI = (() => { const [x, y] = psi(F2.ONE, F2.ONE); return {x, y}; })(); // psi(x, y) = (conj(x) PX, conj(y) PY)
export const psiAff = (x, y) => [F2.mul(conj2(x), PSI.x), F2.mul(conj2(y), PSI.y)];
for (let t = 0; t < 4; t++) { const Q = G2P.BASE.multiply(BigInt(1000 + 7919 * t)).toAffine(); const [a, b] = psi(Q.x, Q.y); const [c, d] = psiAff(Q.x, Q.y); assert.ok(F2.eql(a, c) && F2.eql(b, d), 'psi constants'); }
// psi on G2 is [p] = [x] (mod r), so psi(Q) = -[T]Q for Q in G2: the endpoint of the T-walk is -psi(B)
{ const Q = G2P.BASE.multiply(123456789n); const [a, b] = psiAff(Q.toAffine().x, Q.toAffine().y); const TQ = Q.multiply(T).negate().toAffine(); assert.ok(F2.eql(TQ.x, a) && F2.eql(TQ.y, b), 'psi(Q) = [x]Q on G2'); }

// ---------------- number-theoretic facts ----------------
export const H1 = bls12_381.G1.Point.CURVE().h, H2 = bls12_381.G2.Point.CURVE().h;
export const LAMBDA = p + T;                    // = p - x
export const N6R = (p ** 6n + 1n) / r;
export const FACTS = (() => {
  const t = X_SEED + 1n;                        // trace of Frobenius of E/Fp
  assert.equal(mod(p, r), mod(X_SEED, r), 'p = x (mod r)');
  assert.equal(r, X_SEED ** 4n - X_SEED ** 2n + 1n, 'r = x^4 - x^2 + 1');
  assert.equal((p ** 6n + 1n) % r, 0n, 'r | p^6 + 1');
  assert.equal(LAMBDA % r, 0n, 'lambda = p + |x| = m r');
  assert.equal(gcd(LAMBDA, p ** 6n + 1n), r, 'gcd(lambda, p^6+1) = r: every class with FE = 1 is a lambda-th power (completeness)');
  assert.equal(gcd(LAMBDA / r, N6R), 1n); assert.notEqual(N6R % r, 0n, 'r^2 does not divide p^6+1');
  assert.equal(gcd(3n, p ** 6n + 1n), 1n, '3 does not divide p^6 + 1 (no cubic-residue witness in G)');
  // G1: #E(Fp) = r h1; the reduced pairing kills the h1-part (gcd(h1, r) = 1)
  assert.equal(p + 1n - t, r * H1, '#E(Fp) = r h1'); assert.equal(gcd(H1, r), 1n);
  // G2 membership via psi(B) = [x]B: psi^2 - t psi + p = 0 on E'(Fp2); N(psi - x) = x^2 - t x + p = p - x = lambda
  const norm = X_SEED * X_SEED - t * X_SEED + p; assert.equal(norm, LAMBDA);
  assert.equal(gcd(norm, H2), 1n, 'psi - [x] is injective on the cofactor part of E\'(Fp2)'); assert.equal(gcd(H2, r), 1n, 'r does not divide h2');
  assert.equal(H2 % 2n, 1n, 'E\'(Fp2) has odd order (no 2-torsion)'); assert.equal(H1 % 2n, 1n, 'E(Fp) has odd order');
  // #E'(Fp2) = r h2 cross-check with the twist order formula: p^2 + 1 - t2' where E(Fp2) trace t2 = t^2 - 2p and the sextic twist trace (t2 + 3 f2)/2
  return {lambdaOverR: (LAMBDA / r).toString(), h1: H1.toString(), h2: H2.toString(), gcd_lambda_p6p1: r.toString()};
})();
export const HASH_CHALLENGE_SPACE = 1n << 256n;  // SHA-256 output as an unsigned integer is < 2^256 < p: no reduction, no bias
assert.ok(HASH_CHALLENGE_SPACE < p);

// ---------------- the loop schedule: bits of T below its top bit ----------------
export const BITS = (() => { const b = []; for (let i = 62; i >= 0; i--) b.push(Number((T >> BigInt(i)) & 1n)); return b; })(); // event e <-> bit 62 - e
export const NE = BITS.length; assert.equal(NE, 63); assert.equal((T >> 63n), 1n);
export const NADD = BITS.filter((b) => b).length; assert.equal(NADD, 5);
export const ADD_EVENTS = BITS.map((b, e) => (b ? e : -1)).filter((e) => e >= 0); // [0, 2, 5, 14, 46]
assert.equal(BITS.reduce((acc, b) => 2n * acc + BigInt(b), 1n), T);

// ---------------- GT-GLS: n = sum_i d_i T^i, 0 <= d_i < T (base-|x| digits; canonical, no lattice) ----------------
// T^i = (-x)^i = (-p)^i (mod r), so FE(m)^(T^i) = FE(sigma^i Frob^i (m)): factor_i = Frob^(7i mod 12)(m)
export const TPOW = [1n, T, T * T, T * T * T];
assert.ok(T ** 4n > r, 'n < r < T^4: four base-T digits suffice');
TPOW.forEach((tp, i) => assert.equal(mod(tp, r), mod((i % 2 ? -1n : 1n) * p ** BigInt(i), r), 'T^i = (-1)^i p^i (mod r)'));
export const glsDigits = (n) => { assert.ok(n >= 0n && n < r); const d = []; let v = n; for (let i = 0; i < 4; i++) { d.push(v % T); v /= T; } assert.equal(v, 0n); return d; };
export const GLS_BITS = 64; // digits < T < 2^64; bit 63 is read at the loop's initial step

// ---------------- Miller values (the unconjugated f_{T,Q}(P), noble's loop before its xNegative conjugation) ----------------
export const millerT = (P, Q) => F12.conjugate(bls12_381.pairing(P, Q, false));
export const eT = (P, Q) => F12.finalExponentiate(millerT(P, Q)); // = e(P, Q)^(-1), a non-degenerate bilinear pairing
{ const a = eT(G1P.BASE, G2P.BASE), b = F12.finalExponentiate(bls12_381.pairing(G1P.BASE, G2P.BASE, false)); assert.ok(F12.eql(F12.mul(a, b), F12.ONE), 'FE(f_T) = e^-1'); }

// ---------------- VK-derived constants ----------------
export const VKC = (() => {
  // delta trajectory: lambda_j for the 68 loop lines (63 doublings, 5 additions with +delta)
  const d = VK.delta.toAffine(); let Tt = VK.delta; const lams = [];
  const slopeDbl = (Ta) => F2.div(F2.mul(f2(3n, 0n), F2.sqr(Ta.x)), F2.add(Ta.y, Ta.y));
  const slopeAdd = (Ta, Qa) => { assert.ok(!F2.eql(Ta.x, Qa.x)); return F2.div(F2.sub(Qa.y, Ta.y), F2.sub(Qa.x, Ta.x)); };
  for (let e = 0; e < NE; e++) { lams.push(slopeDbl(Tt.toAffine())); Tt = Tt.double(); if (BITS[e]) { lams.push(slopeAdd(Tt.toAffine(), d)); Tt = Tt.add(VK.delta); } }
  assert.equal(lams.length, NE + NADD);
  assert.ok(Tt.equals(VK.delta.multiply(T)));
  const c0 = F2.sub(F2.mul(lams[0], d.x), d.y);
  // the script's delta recursion: state (x_j, c_{j-1}, lambda_{j-1}), start (x_delta, y_delta, 0);
  // c_j = (lambda_{j-1} + lambda_j) x_j - c_{j-1}; x_{j+1} = lambda_j^2 - x_j - s_j. Assert every line equals the true chord/tangent.
  { let x = d.x, c = d.y, l = F2.ZERO, Tc = VK.delta, j = 0;
    const step = (s) => { const ta = Tc.toAffine(); assert.ok(F2.eql(x, ta.x), 'delta x_j'); const cj = F2.sub(F2.mul(F2.add(l, lams[j]), x), c); assert.ok(F2.eql(cj, F2.sub(F2.mul(lams[j], ta.x), ta.y)), 'delta c_j');
      const nx = F2.sub(F2.sub(F2.sqr(lams[j]), x), s); c = cj; l = lams[j]; x = nx; j++; };
    for (let e = 0; e < NE; e++) { step(x); Tc = Tc.double(); if (BITS[e]) { step(d.x); Tc = Tc.add(VK.delta); } }
    assert.equal(j, 68); }
  const mIC = VK.ic.map((P) => millerT(P, VK.gamma));
  const mConst = F12.mul(millerT(VK.alpha, VK.beta), mIC[0]);
  // GLS factor reps: R_{k,0} = rep[m], R_{k,1} = rep[sigma Frob(m)] = rep[Frob m](-X); R_{k,2}, R_{k,3} = R_{k,0}, R_{k,1} at eta X
  const R = [1, 2].map((k) => [monicRep(mIC[k]), monicRep(F12.conjugate(F12.frobeniusMap(mIC[k], 1)))]);
  R.forEach((Rk, k) => { const m = mIC[k + 1];
    assert.ok(sameClass(fromPoly(psubst(Rk[0], ETA)), F12.frobeniusMap(m, 2)), 'R_{k,2} = R_{k,0}(eta X) is Frob^2');
    assert.ok(sameClass(fromPoly(psubst(Rk[1], ETA)), F12.conjugate(F12.frobeniusMap(m, 3))), 'R_{k,3} = R_{k,1}(eta X) is sigma Frob^3');
    // exponent check on GT: FE(factor_i) = FE(m)^(T^i)
    const g = F12.finalExponentiate(m);
    [Rk[0], Rk[1], psubst(Rk[0], ETA), psubst(Rk[1], ETA)].forEach((f, i) => assert.ok(F12.eql(F12.finalExponentiate(fromPoly(f)), F12.pow(g, TPOW[i])), 'FE(R_{k,' + i + '}) = FE(m)^(T^' + i + ')'));
  });
  const Rconst = monicRep(mConst);
  return {deltaAff: d, lams, deltaStart: {x: d.x, c: c0}, mIC, mConst, R, Rconst};
})();
export const glsFactorPoly = (k, i) => { let f = VKC.R[k][i % 2]; if (i >= 2) f = psubst(f, ETA); return f; };

// ---------------- line polynomials (M-twist, noble's 014 slots: c0 * 1 + (c1 xP) * v + (c2 yP) * v w) ----------------
// L(X) = Phi(c0) + xP X^2 Phi(c1) + yP X^3 Phi(c2); affine line through T with slope lam: (lam xT - yT, -lam, 1)
export const linePoly = (xP, yP, c0, c1, c2) => { const o = Array(10).fill(0n); const [a, b, c] = [Phi(c0), Phi(c1), Phi(c2)];
  for (let i = 0; i < 7; i++) { o[i] = mod(o[i] + a[i]); o[i + 2] = mod(o[i + 2] + xP * b[i]); o[i + 3] = mod(o[i + 3] + yP * c[i]); } return trim(o); };
// projective (homogeneous) formulas over Fp2, as in the BN SI-GLS (Z = 0 absorbing; lines are Fp2 multiples of the affine line)
export const projDbl = ([X, Y, Z]) => {
  const B = F2.sqr(Y), C = F2.sqr(Z), E = F2.mul(B3, C), Fv = F2.mul(E, f2(3n, 0n)), H = F2.mul(F2.mul(Y, Z), f2(2n, 0n));
  const X3 = F2.mul(F2.mul(F2.mul(X, Y), f2(2n, 0n)), F2.sub(B, Fv));
  const Y3 = F2.sub(F2.sqr(F2.add(B, Fv)), F2.mul(F2.sqr(E), f2(12n, 0n)));
  const Z3 = F2.mul(F2.mul(B, H), f2(4n, 0n));
  // 2YZ * (lam x - y, -lam, 1) with lam = 3x^2/2y: (Y^2 - 3b'Z^2, -3X^2, 2YZ)
  return {T: [X3, Y3, Z3], line: [F2.sub(B, E), F2.neg(F2.mul(F2.sqr(X), f2(3n, 0n))), H]};
};
export const projAdd = ([X, Y, Z], [xq, yq]) => {
  const th = F2.sub(Y, F2.mul(yq, Z)), la = F2.sub(X, F2.mul(xq, Z));
  const D = F2.sqr(la), E = F2.mul(la, D), Fv = F2.mul(Z, F2.sqr(th)), G = F2.mul(X, D), H = F2.sub(F2.add(E, Fv), F2.add(G, G));
  // lam' * (lam xq - yq, -lam, 1), lam = theta / lam': (theta xq - lam' yq, -theta, lam')
  return {T: [F2.mul(la, H), F2.sub(F2.mul(th, F2.sub(G, H)), F2.mul(Y, E)), F2.mul(Z, E)], line: [F2.sub(F2.mul(th, xq), F2.mul(la, yq)), F2.neg(th), la]};
};
// sanity: the projective lines are Fp2 multiples of the affine lines, and the walk matches noble
{ const Bq = G2P.BASE.multiply(77n), Ba = Bq.toAffine(), P = G1P.BASE.multiply(5n).toAffine();
  const o = projDbl([Ba.x, Ba.y, F2.ONE]); const lam = F2.div(F2.mul(f2(3n, 0n), F2.sqr(Ba.x)), F2.add(Ba.y, Ba.y));
  const aff = linePoly(P.x, P.y, F2.sub(F2.mul(lam, Ba.x), Ba.y), F2.neg(lam), F2.ONE);
  assert.ok(sameClass(fromPoly(linePoly(P.x, P.y, ...o.line)), fromPoly(aff)), 'projective doubling line ~ affine');
  const D = Bq.double().toAffine(); assert.ok(F2.eql(F2.mul(D.x, o.T[2]), o.T[0]) && F2.eql(F2.mul(D.y, o.T[2]), o.T[1]), 'projective doubling');
  const Q2 = G2P.BASE.multiply(1234n).toAffine(); const o2 = projAdd(o.T, [Q2.x, Q2.y]); const S = Bq.double().add(G2P.BASE.multiply(1234n)).toAffine();
  assert.ok(F2.eql(F2.mul(S.x, o2.T[2]), o2.T[0]) && F2.eql(F2.mul(S.y, o2.T[2]), o2.T[1]), 'projective mixed addition');
  const lam2 = F2.div(F2.sub(Q2.y, D.y), F2.sub(Q2.x, D.x));
  assert.ok(sameClass(fromPoly(linePoly(P.x, P.y, ...o2.line)), fromPoly(linePoly(P.x, P.y, F2.sub(F2.mul(lam2, D.x), D.y), F2.neg(lam2), F2.ONE))), 'projective addition line ~ affine');
}
