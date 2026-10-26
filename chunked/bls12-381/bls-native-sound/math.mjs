// BLS12-381 SI-GLS math: field / polynomial helpers, the tower <-> polynomial map, the Miller loop in the
// verifier's own line convention, every structural fact the construction relies on, and every baked VK
// constant, each recomputed from first principles and asserted (against noble where noble has the object)
// at import time, so every build, prover and test run re-checks them. (Ported from the design record
// research/sound-sz-bls12381/si-gls-spec/blsmath.mjs; test.mjs cross-checks it against the second design's
// independent math module research/sound-si-gls-bls12381-d2/math.mjs.)
//
//   Fp12 = Fp[X]/M(X), M = X^12 - 2 X^6 + 2, X = w (noble tower: u^2 = -1, v^3 = 1 + u = xi, w^2 = v),
//   u = X^6 - 1; an Fp2 element a0 + a1 u maps to Phi(a) = (a0 - a1) + a1 X^6.
import assert from 'node:assert/strict';
import {bls12_381} from '@noble/curves/bls12-381.js';

export const {Fp, Fp2: F2, Fp6, Fp12: F12, Fr} = bls12_381.fields;
export const p = Fp.ORDER, r = Fr.ORDER;
export const BLS_X = -0xd201000000010000n, AX = -BLS_X; // x < 0; AX = |x|
export const mod = (x, m = p) => ((x % m) + m) % m;
export const inv = (x) => Fp.inv(mod(x));
export const gcd = (a, b) => { a = a < 0n ? -a : a; b = b < 0n ? -b : b; while (b) [a, b] = [b, a % b]; return a; };
export const G1 = bls12_381.G1.Point, G2 = bls12_381.G2.Point;
assert.equal(bls12_381.params.ateLoopSize, AX);
assert.equal(r, AX ** 4n - AX ** 2n + 1n, 'r = x^4 - x^2 + 1');
assert.equal(p, ((BLS_X - 1n) ** 2n * r) / 3n + BLS_X, 'p = (x-1)^2 r / 3 + x');

// ---------------- polynomials over Fp (coefficient arrays, low degree first) ----------------
export const trim = (a) => { a = a.slice(); while (a.length > 1 && a.at(-1) === 0n) a.pop(); return a; };
export const deg = (a) => trim(a).length - 1;
export const pmul = (a, b) => { const o = Array(a.length + b.length - 1).fill(0n); for (let i = 0; i < a.length; i++) if (a[i]) for (let j = 0; j < b.length; j++) o[i + j] += a[i] * b[j]; return o.map((x) => mod(x)); };
export const padd = (a, b) => Array.from({length: Math.max(a.length, b.length)}, (_, i) => mod((a[i] ?? 0n) + (b[i] ?? 0n)));
export const psub = (a, b) => Array.from({length: Math.max(a.length, b.length)}, (_, i) => mod((a[i] ?? 0n) - (b[i] ?? 0n)));
export const pscale = (a, s) => a.map((c) => mod(c * s));
export const psubst = (a, s) => { let k = 1n; return a.map((c) => { const v = mod(c * k); k = mod(k * s); return v; }); }; // a(sX)
export const pneg = (a) => psubst(a, p - 1n); // a(-X): sigma = Frob^6
export const peval = (a, x) => { let acc = 0n; for (let i = a.length - 1; i >= 0; i--) acc = mod(acc * x + a[i]); return acc; };
export const ppow = (a, e) => { let out = [1n], b = a; while (e) { if (e & 1n) out = pmul(out, b); b = pmul(b, b); e >>= 1n; } return out; };
export const M = [2n, 0n, 0n, 0n, 0n, 0n, mod(-2n), 0n, 0n, 0n, 0n, 0n, 1n];
export const pdivM = (a) => { // exact long division by the monic, even M: X^12 = 2 X^6 - 2
  const rem = a.slice(); const q = Array(Math.max(1, a.length - 12)).fill(0n);
  for (let i = rem.length - 1; i >= 12; i--) { const v = rem[i]; q[i - 12] = v; rem[i] = 0n; rem[i - 6] = mod(rem[i - 6] + 2n * v); rem[i - 12] = mod(rem[i - 12] - 2n * v); }
  return {q, r: rem.slice(0, 12).concat(Array(Math.max(0, 12 - rem.length)).fill(0n))};
};
export const pmodM = (a) => pdivM(a).r;
export const isZero = (a) => a.every((x) => x === 0n);
const mulM = (a, b) => pmodM(pmul(a, b));
const powM = (a, e) => { let out = [1n], b = a; while (e) { if (e & 1n) out = mulM(out, b); b = mulM(b, b); e >>= 1n; } return out; };
// polynomial gcd over Fp (for the Rabin irreducibility test)
const pdivmod = (a, b) => { a = trim(a); b = trim(b); const ib = inv(b.at(-1)); const q = Array(Math.max(1, a.length - b.length + 1)).fill(0n); const rem = a.slice();
  for (let i = rem.length - b.length; i >= 0; i--) { const c = mod(rem[i + b.length - 1] * ib); q[i] = c; if (c) for (let j = 0; j < b.length; j++) rem[i + j] = mod(rem[i + j] - c * b[j]); }
  return {q, r: trim(rem.slice(0, Math.max(1, b.length - 1)))}; };
const pgcd = (a, b) => { a = trim(a); b = trim(b); while (!(b.length === 1 && b[0] === 0n)) { const {r: rr} = pdivmod(a, b); [a, b] = [b, rr]; } return a; };

// ---------------- tower <-> polynomial ----------------
const flat = (x) => [x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1, x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1];
const SLOT_DEG = [0, 2, 4, 1, 3, 5]; // tower slots (c0.c0, c0.c1, c0.c2, c1.c0, c1.c1, c1.c2) = w^(0,2,4,1,3,5)
export const toPoly = (x) => { const c = flat(x), out = Array(12).fill(0n); SLOT_DEG.forEach((d, i) => { out[d] = mod(c[2 * i] - c[2 * i + 1]); out[d + 6] = c[2 * i + 1]; }); return out; };
export const fromPoly = (a) => {
  const c = pmodM(a); const s = SLOT_DEG.map((d) => ({c0: mod(c[d] + c[d + 6]), c1: c[d + 6]}));
  return F12.create({c0: Fp6.create({c0: s[0], c1: s[1], c2: s[2]}), c1: Fp6.create({c0: s[3], c1: s[4], c2: s[5]})});
};
export const Phi = (a) => { const o = Array(7).fill(0n); o[0] = mod(a.c0 - a.c1); o[6] = mod(a.c1); return o; };
export const f2 = (a, b) => F2.fromBigTuple([mod(a), mod(b)]);
export const XI = f2(1n, 1n);
assert.ok(F2.eql(F2.NONRESIDUE, XI), 'noble xi = 1 + u');
const randF12 = (seed) => F12.fromBigTwelve(Array.from({length: 12}, (_, i) => mod(BigInt(seed * 1000003 + i * 7919 + 1) ** 37n)));
for (let s = 1; s <= 4; s++) { // ring isomorphism: toPoly(a b) = toPoly(a) toPoly(b) mod M, fromPoly(toPoly(a)) = a
  const a = randF12(s), b = randF12(s + 50);
  assert.equal(toPoly(F12.mul(a, b)).join(), mulM(toPoly(a), toPoly(b)).join(), 'tower <-> Fp[X]/M is multiplicative');
  assert.ok(F12.eql(fromPoly(toPoly(a)), a));
}
{ const w = fromPoly([0n, 1n]); assert.ok(F12.eql(F12.add(F12.sub(F12.pow(w, 12n), F12.mul(F12.pow(w, 6n), F12.fromBigTwelve([2n, ...Array(11).fill(0n)]))), F12.fromBigTwelve([2n, ...Array(11).fill(0n)])), F12.ZERO), 'M(w) = 0'); }

// ---------------- M is irreducible over Fp (Rabin): M | X^(p^12) - X, gcd(X^(p^6) - X, M) = gcd(X^(p^4) - X, M) = 1 ----------------
export const IRREDUCIBLE = (() => {
  const Xp = powM([0n, 1n], p); // X^p mod M; X^(p^k) = Xp composed k times: compose via Frobenius-linearity is not available, so iterate powM
  const frobK = (k) => { let a = [0n, 1n]; for (let i = 0; i < k; i++) a = powM(a, p); return a; };
  const x12 = frobK(12); assert.equal(trim(psub(x12, [0n, 1n])).join(), '0', 'X^(p^12) = X mod M');
  for (const k of [6, 4]) { const g = pgcd(M, psub(frobK(k), [0n, 1n])); assert.equal(g.length, 1, `gcd(X^(p^${k}) - X, M) = 1`); }
  return {Xp};
})();

// ---------------- Frobenius: Frob(X) = Phi(gamma1) X, gamma1 = xi^((p-1)/6); Frob^2 = X -> eta X; Frob^6 = X -> -X ----------------
export const GAMMA1 = F2.pow(XI, (p - 1n) / 6n);
export const ETA = Fp.pow(2n, (p - 1n) / 6n); // xi^((p^2-1)/6) = N(xi)^((p-1)/6) = 2^((p-1)/6)
assert.ok(F2.eql(F2.pow(XI, (p * p - 1n) / 6n), f2(ETA, 0n)), 'eta = xi^((p^2-1)/6) is in Fp');
assert.equal(Fp.pow(ETA, 6n), 1n); assert.notEqual(Fp.pow(ETA, 2n), 1n); assert.notEqual(Fp.pow(ETA, 3n), 1n); // primitive 6th root
assert.equal(mod(ETA * ETA), mod(ETA - 1n), 'eta^2 = eta - 1');
for (let s = 4; s < 8; s++) {
  const el = randF12(s);
  assert.equal(toPoly(F12.frobeniusMap(el, 2)).join(), pmodM(psubst(toPoly(el), ETA)).join(), 'Frob^2 = X -> eta X');
  assert.equal(toPoly(F12.frobeniusMap(el, 6)).join(), pmodM(pneg(toPoly(el))).join(), 'Frob^6 = X -> -X');
}
export const FROB = (() => { // Frob(X^j) = alpha_j X^j + beta_j X^(j+6) (j = 1..5), Frob(1) = 1, Frob(X^6) = 2 - X^6
  const out = {alpha: [], beta: []}; let g = F2.ONE;
  for (let j = 1; j <= 5; j++) {
    g = F2.mul(g, GAMMA1); const fp = toPoly(F12.frobeniusMap(fromPoly([...Array(j).fill(0n), 1n]), 1));
    fp.forEach((c, i) => assert.ok(c === 0n || i === j || i === j + 6, 'Frob(X^j) support'));
    assert.equal(fp[j], mod(g.c0 - g.c1)); assert.equal(fp[j + 6], g.c1); // = Phi(gamma1^j) X^j
    out.alpha[j] = fp[j]; out.beta[j] = fp[j + 6];
  }
  assert.equal(toPoly(F12.frobeniusMap(fromPoly([...Array(6).fill(0n), 1n]), 1)).join(), [2n, 0n, 0n, 0n, 0n, 0n, p - 1n, 0n, 0n, 0n, 0n, 0n].join(), 'Frob(X^6) = 2 - X^6');
  return out;
})();
// Frob of a monic degree-6 polynomial s0..s5 (the on-chain formula, degree 11)
export const frob1Monic = (s) => { const o = Array(12).fill(0n); o[0] = mod(s[0] + 2n); o[6] = p - 1n; for (let j = 1; j <= 5; j++) { o[j] = mod(o[j] + s[j] * FROB.alpha[j]); o[j + 6] = mod(o[j + 6] + s[j] * FROB.beta[j]); } return o; };
for (let t = 0; t < 3; t++) { const s = Array.from({length: 6}, (_, i) => mod(BigInt(t * 31 + i + 5) ** 41n)); assert.equal(pmodM(frob1Monic(s)).join(), toPoly(F12.frobeniusMap(fromPoly([...s, 1n]), 1)).join(), 'Frob(S) formula'); }

// ---------------- classes in G = Fp12*/Fp6* (order p^6 + 1); monic degree-6 representatives ----------------
export const sameClass = (a, b) => { const q = F12.mul(a, F12.conjugate(b)); return isZero(toPoly(F12.sub(q, F12.conjugate(q)))); }; // a/b in Fp6 <=> a conj(b) even
const solveMod = (A, b) => {
  const n = A.length, Mx = A.map((row, i) => [...row, b[i]].map((x) => mod(x)));
  for (let c = 0; c < n; c++) {
    let piv = c; while (piv < n && Mx[piv][c] === 0n) piv++; if (piv === n) throw new Error('monic representative does not exist (singular)');
    [Mx[c], Mx[piv]] = [Mx[piv], Mx[c]]; const iv = inv(Mx[c][c]); Mx[c] = Mx[c].map((x) => mod(x * iv));
    for (let i = 0; i < n; i++) if (i !== c && Mx[i][c]) { const m = Mx[i][c]; Mx[i] = Mx[i].map((x, k) => mod(x - m * Mx[c][k])); }
  }
  return Mx.map((row) => row[n]);
};
export const monicRep = (f) => { // S = X^6 + s5 X^5 + ... + s0 with [S] = [f]: S = f * (even g), solve for g's 6 coefficients
  const fp = toPoly(f); const cols = [0, 2, 4, 6, 8, 10].map((d) => pmodM(pmul([...Array(d).fill(0n), 1n], fp)));
  const s = solveMod([6, 7, 8, 9, 10, 11].map((row) => cols.map((c) => c[row])), [1n, 0n, 0n, 0n, 0n, 0n]);
  const out = Array(12).fill(0n); cols.forEach((c, j) => c.forEach((x, i) => (out[i] = mod(out[i] + s[j] * x))));
  assert.ok(out.slice(7).every((x) => x === 0n) && out[6] === 1n);
  const rep = out.slice(0, 7); assert.ok(sameClass(fromPoly(rep), f)); return rep; // [s0..s5, 1]
};

// ---------------- curve, twist (M-type), psi ----------------
export const B_TWIST = F2.mul(f2(4n, 0n), XI); // b' = 4 xi = 4 + 4u
assert.ok(F2.eql(G2.CURVE ? G2.CURVE().b : B_TWIST, B_TWIST), 'twist b');
const sqrtF2 = (a) => F2.sqrt(a);
// psi(x, y) = (conj(x) * PX, conj(y) * PY): untwist-Frobenius-twist for the M-type twist (x', y') -> (x'/w^2, y'/w^3)
// psi(x', y') = (conj(x') * xi^(-(p-1)/3), conj(y') * xi^(-(p-1)/2)) = (conj(x') / gamma1^2, conj(y') / gamma1^3)
export const PSI_X = F2.inv(F2.pow(GAMMA1, 2n)), PSI_Y = F2.inv(F2.pow(GAMMA1, 3n));
export const conj2 = (a) => f2(a.c0, -a.c1);
export const psiAff = (x, y) => [F2.mul(conj2(x), PSI_X), F2.mul(conj2(y), PSI_Y)];
// scalar multiplication for any scalar (noble's multiplyUnsafe requires k < r)
export const smul = (P, k) => { let R = P.multiplyUnsafe(0n), A = P; if (k < 0n) { k = -k; A = P.negate(); } while (k) { if (k & 1n) R = R.add(A); A = A.double(); k >>= 1n; } return R; };
const onTwist = (x, y) => F2.eql(F2.sqr(y), F2.add(F2.mul(F2.sqr(x), x), B_TWIST));
// check psi against the untwist-Frobenius-twist definition in Fp12 directly
const untwist = (x, y) => { const w = fromPoly([0n, 1n]); const e = (a) => F12.fromBigTwelve([a.c0, a.c1, ...Array(10).fill(0n)]);
  return [F12.div(e(x), F12.mul(w, w)), F12.div(e(y), F12.pow(w, 3n))]; };
{ const Q = G2.BASE.multiply(12345n).toAffine(); const [ux, uy] = untwist(Q.x, Q.y); const [px, py] = psiAff(Q.x, Q.y);
  const [ux2, uy2] = untwist(px, py); assert.ok(F12.eql(F12.frobeniusMap(ux, 1), ux2) && F12.eql(F12.frobeniusMap(uy, 1), uy2), 'psi = untwist^-1 Frob untwist');
  // untwisted point lies on E: y^2 = x^3 + 4
  assert.ok(F12.eql(F12.sqr(uy), F12.add(F12.pow(ux, 3n), F12.fromBigTwelve([4n, ...Array(11).fill(0n)]))), 'M-type untwist (x/w^2, y/w^3)'); }
// a twist point outside G2 (random x with x^3 + b' a square)
export const randomTwistPoint = (seed) => { for (let k = BigInt(seed); ; k++) { const x = f2(k * 7919n + 3n, k * 104729n + 5n); const rhs = F2.add(F2.mul(F2.sqr(x), x), B_TWIST); try { const y = sqrtF2(rhs); if (y && F2.eql(F2.sqr(y), rhs)) return {x, y}; } catch { /* non-square */ } } };

// ---------------- the verifier's line convention and Miller loop (|x|, affine twist lines, scaled by w^3) ----------------
//   line through twist point T' with slope lam' (twist coordinates), evaluated at P = (xP, yP) in E(Fp), times w^3:
//   L(X) = Phi(lam' xT - yT) - xP X^2 Phi(lam') + yP X^3            (degree 8; even part + odd part yP X^3)
export const lineAffPoly = (xP, yP, lam, c) => { const o = Array(9).fill(0n); const A = Phi(c), Bc = Phi(F2.neg(lam));
  for (let i = 0; i < 7; i++) { o[i] = mod(o[i] + A[i]); o[i + 2] = mod(o[i + 2] + xP * Bc[i]); } o[3] = mod(o[3] + yP); return o; };
// generic sparse line (l0, l2, l3) in Fp2: Phi(l0) + xP X^2 Phi(l2) + yP X^3 Phi(l3)   (projective lines; degree 9)
export const lineGenPoly = (xP, yP, l0, l2, l3) => { const o = Array(10).fill(0n); const [a, b, c] = [Phi(l0), Phi(l2), Phi(l3)];
  for (let i = 0; i < 7; i++) { o[i] = mod(o[i] + a[i]); o[i + 2] = mod(o[i + 2] + xP * b[i]); o[i + 3] = mod(o[i + 3] + yP * c[i]); } return o; };
export const BITS = (() => { const b = []; for (let i = 62; i >= 0; i--) b.push(Number((AX >> BigInt(i)) & 1n)); return b; })(); // event e <-> bit 62 - e
export const NE = BITS.length; assert.equal(NE, 63); assert.equal(AX >> 63n, 1n);
export const ADD_EVENTS = BITS.map((b, e) => (b ? e : -1)).filter((e) => e >= 0);
assert.deepEqual(ADD_EVENTS, [0, 2, 5, 14, 46], 'additions after the doublings of events 0, 2, 5, 14, 46 (bits 62, 60, 57, 48, 16)');
export const slopeDbl = (Ta) => F2.div(F2.mul(f2(3n, 0n), F2.sqr(Ta.x)), F2.add(Ta.y, Ta.y));
export const slopeAdd = (Ta, Qa) => { assert.ok(!F2.eql(Ta.x, Qa.x)); return F2.div(F2.sub(Qa.y, Ta.y), F2.sub(Qa.x, Ta.x)); };
// Miller loop with the per-event structure: returns the Fp12 value and the list of (event, kind, slope, T) records
export const millerTrace = (P, Q) => {
  const Pa = P.toAffine(); let T = Q; let f = F12.ONE; const lines = [];
  const mulLine = (lam, Ta) => { const c = F2.sub(F2.mul(lam, Ta.x), Ta.y); f = F12.mul(f, fromPoly(lineAffPoly(Pa.x, Pa.y, lam, c))); return c; };
  for (let e = 0; e < NE; e++) {
    f = F12.sqr(f); const Ta = T.toAffine(); const lam = slopeDbl(Ta); lines.push({e, kind: 'dbl', lam, x: Ta.x, y: Ta.y, c: mulLine(lam, Ta)}); T = T.double();
    if (BITS[e]) { const Tb = T.toAffine(), Qa = Q.toAffine(); const lam2 = slopeAdd(Tb, Qa); lines.push({e, kind: 'add', lam: lam2, x: Tb.x, y: Tb.y, c: mulLine(lam2, Tb)}); T = T.add(Q); }
  }
  return {f, lines, T};
};
export const miller = (P, Q) => millerTrace(P, Q).f;
export const FE = (f) => F12.finalExponentiate(f);
// our pairing is e_hat(P, Q) = FE(f_{|x|,Q}(P) * w^(3n)) = e(P, Q)^(-1) (noble conjugates f_{|x|} for x < 0; w^3 classes die in FE)
{ const P1 = G1.BASE.multiply(77n), Q1 = G2.BASE.multiply(99n); const {f, T} = millerTrace(P1, Q1);
  assert.ok(T.equals(Q1.multiply(AX)), 'loop endpoint T = [|x|] Q');
  assert.ok(F12.eql(F12.mul(FE(f), bls12_381.pairing(P1, Q1)), F12.ONE), 'FE(our Miller value) = e(P, Q)^-1');
  const w3 = fromPoly([0n, 0n, 0n, 1n]); assert.ok(F12.eql(FE(w3), F12.ONE), 'FE(w^3) = 1'); }

// ---------------- residue exponent: lambda = p - x = p + |x| = m r, m = (x-1)^2/3 ----------------
export const LAMBDA = p + AX, MRES = LAMBDA / r;
export const N6 = p ** 6n + 1n, N6R = N6 / r;
export const FACTS = (() => {
  assert.equal(LAMBDA % r, 0n, 'lambda = m r'); assert.equal(MRES, (BLS_X - 1n) ** 2n / 3n, 'm = (x-1)^2/3 = h1 (G1 cofactor)');
  assert.equal(N6 % r, 0n, 'r | p^6 + 1'); assert.notEqual(N6R % r, 0n, 'r^2 does not divide p^6 + 1');
  assert.equal(gcd(LAMBDA, N6R), 1n, 'gcd(lambda, (p^6+1)/r) = 1: residue roots exist and are unique in the order-(p^6+1)/r subgroup');
  assert.equal(p % 3n, 1n); assert.equal(gcd(3n, N6), 1n, '3 does not divide p^6 + 1 (no cubic-residue witness)');
  assert.equal(mod(p, r), mod(BLS_X, r), 'p = x (mod r): Frobenius on GT = x-power');
  // G1: #E(Fp) = h1 r, h1 odd (no 2-torsion: yP != 0)
  const h1 = MRES; assert.equal(G1.CURVE().h ?? h1, h1); assert.equal(h1 % 2n, 1n);
  // G2: #E'(Fp2) = h2 r; psi^2 - t psi + p = 0 (t = x + 1); endpoint check [|x|]B = -psi(B) <=> (psi - [x]) B = O
  const t = BLS_X + 1n; const h2 = (BLS_X ** 8n - 4n * BLS_X ** 7n + 5n * BLS_X ** 6n - 4n * BLS_X ** 4n + 6n * BLS_X ** 3n - 4n * BLS_X ** 2n - 4n * BLS_X + 13n) / 9n;
  const nE2 = p * p + 1n - (t * t - 2n * p); // #E(Fp2) of the base curve; the M-twist order is h2 r
  assert.equal(h2 % 2n, 1n, 'E\'(Fp2) has odd order'); assert.equal(gcd(h2, r), 1n, 'gcd(h2, r) = 1');
  // N(psi - x) = x^2 - x t + p = p - x = m r
  const normPsiMinusX = BLS_X * BLS_X - BLS_X * t + p; assert.equal(normPsiMinusX, LAMBDA);
  const g = gcd(normPsiMinusX, h2);
  // the twist order: check a random twist point is killed by h2 r
  const R0 = randomTwistPoint(1); const Rp = G2.fromAffine({x: R0.x, y: R0.y});
  assert.ok(smul(smul(Rp, r), h2).is0(), '#E\'(Fp2) | h2 r'); assert.ok(!smul(Rp, r).is0(), 'random point is not in G2');
  // psi^2 - t psi + p = 0 on E'(Fp2)
  const psiP = (Pt) => { const a = Pt.toAffine(); const [x, y] = psiAff(a.x, a.y); return G2.fromAffine({x, y}); };
  assert.ok(psiP(psiP(Rp)).add(smul(psiP(Rp), -t)).add(smul(Rp, p)).is0(), 'psi^2 - t psi + p = 0');
  assert.ok(psiP(G2.BASE.multiply(5n)).equals(G2.BASE.multiply(5n).multiply(mod(BLS_X, r))), 'psi = [x] on G2');
  assert.ok(!psiP(Rp).equals(smul(Rp, BLS_X)), 'psi != [x] on a non-G2 point');
  return {h1: h1.toString(), h2: h2.toString(), gcdNormH2: g.toString(), lambdaOverR: MRES.toString(), nE2: nE2.toString()};
})();
assert.equal(FACTS.gcdNormH2, '1', 'gcd(N(psi - x), h2) = 1: psi(B) = [x]B implies B in G2');

// ---------------- GT-GLS: n = sum_i a_i |x|^i (base |x|, 0 <= a_i < |x| < 2^64), factors Frob^i(m)^((-1)^i a_i) ----------------
export const GLS_BITS = 64;
export const AXPOW = [1n, AX, AX ** 2n, AX ** 3n];
assert.ok(r < AX ** 4n && AX < 1n << 64n && AX >= 1n << 63n);
export const glsDigits = (n) => { assert.ok(n >= 0n && n < r); const a = []; let m = n; for (let i = 0; i < 4; i++) { a.push(m % AX); m /= AX; } assert.equal(m, 0n); assert.equal(a.reduce((s, v, i) => s + v * AXPOW[i], 0n), n); return a; };
{ const m0 = miller(G1.BASE.multiply(4n), G2.BASE.multiply(7n)); const gt = FE(m0); const n = 0x1234567890abcdef1234567890abcdefn % r; const a = glsDigits(n);
  let prod = F12.ONE; a.forEach((ai, i) => { let fi = F12.frobeniusMap(m0, i); if (i % 2) fi = F12.conjugate(fi); prod = F12.mul(prod, F12.pow(fi, ai)); });
  assert.ok(F12.eql(FE(prod), F12.pow(gt, n)), 'GT-GLS: prod_i FE(Frob^i(m))^((-1)^i a_i) = FE(m)^n'); }
// factor polynomial (k, i): R_k0 = rep[m_k], R_k1 = rep[Frob(m_k)]; factor_i(X) = R_{k,i%2}((-1)^i eta^(i>=2) X):
//   i = 0: R0(X), i = 1: R1(-X) (= conj Frob), i = 2: R0(eta X) (= Frob^2), i = 3: R1(-eta X) (= conj Frob^3)
export const glsFactorPoly = (R, i) => psubst(R[i % 2], mod((i % 2 ? -1n : 1n) * (i >= 2 ? ETA : 1n)));

// ---------------- G1 cofactor: our pairing ignores the cofactor component of a curve point P in E(Fp) ----------------
export const G1_COFACTOR_FACT = (() => {
  // a random point of E(Fp) has components in every cofactor subgroup (h1 = 3 * 11^2 * 10177^2 * 859267^2 * 52437899^2);
  // e_hat(P, Q) = e_hat(P_r, Q) with P_r = [h1 (h1^-1 mod r)] P its G1 component, and e_hat(P - P_r, Q) = 1
  const h1 = MRES; assert.equal(h1, 3n * 11n ** 2n * 10177n ** 2n * 859267n ** 2n * 52437899n ** 2n);
  // pick a point whose cofactor part T has order divisible by every prime factor of h1
  let P = null, Pr = null, Tc = null;
  for (let xx = 2n; !P; xx++) { const rhs = mod(xx ** 3n + 4n); let y; try { y = Fp.sqrt(rhs); } catch { continue; } if (mod(y * y) !== rhs) continue;
    const Pt = G1.fromAffine({x: xx, y}); const Prt = smul(Pt, h1 * Fr.inv(h1 % r)), T = Pt.subtract(Prt);
    if ([[3n, 1n], [11n, 2n], [10177n, 2n], [859267n, 2n], [52437899n, 2n]].every(([q, v]) => !smul(T, h1 / q ** v).is0())) [P, Pr, Tc] = [Pt, Prt, T]; }
  assert.ok(smul(Tc, h1).is0() && smul(Pr, r).is0());
  const Q = G2.BASE.multiply(31n);
  assert.ok(F12.eql(FE(miller(Tc, Q)), F12.ONE), 'e_hat(T, Q) = 1 for the cofactor part T');
  assert.ok(F12.eql(FE(miller(P, Q)), FE(miller(Pr, Q))), 'e_hat(P, Q) = e_hat(P_r, Q)');
  return 'e_hat kills the E(Fp) cofactor component (checked on a point with components of every prime order dividing h1); a curve-checked A or C off G1 only re-encodes a valid proof';
})();

// ---------------- the fixed VK and the bench fixtures (singleton/bls12-381/bls_instance.mjs, measure_fs_singleton.mjs) ----------------
// alpha = 3 G1, beta = 5 G2, gamma = 7 G2, delta = 11 G2, IC = (2, 4, 6) G1. A proof for public inputs (n0, n1):
// B = b G2, C = c G1, A = (alpha beta + vx gamma + c delta) / b G1 with vx = 2 + 4 n0 + 6 n1 (mod r).
export const VK_SCALARS = {alpha: 3n, beta: 5n, gamma: 7n, delta: 11n, ic: [2n, 4n, 6n]};
export const VK = {alpha: G1.BASE.multiply(3n), beta: G2.BASE.multiply(5n), gamma: G2.BASE.multiply(7n), delta: G2.BASE.multiply(11n), ic: [2n, 4n, 6n].map((k) => G1.BASE.multiply(k))};
export const synthetic = (inputs, b, c, a) => {
  const ns = inputs.map(BigInt); const S = VK_SCALARS; const vx = mod(S.ic[0] + S.ic[1] * ns[0] + S.ic[2] * ns[1], r);
  const rhs = mod(S.alpha * S.beta + vx * S.gamma + BigInt(c) * S.delta, r);
  const as = a === undefined ? mod(rhs * Fr.inv(mod(BigInt(b), r)), r) : mod(BigInt(a), r);
  const pt = (G, k) => (k === 0n ? G.ZERO : G.BASE.multiply(k));
  return {inputs: ns, proof: {a: pt(G1, as), b: pt(G2, mod(BigInt(b), r)), c: pt(G1, mod(BigInt(c), r))}, scalars: {a: as, b: BigInt(b), c: BigInt(c), vx}};
};
const fxSpec = () => { const p1 = [135208n, 67633n]; const vx = mod(2n + 4n * p1[0] + 6n * p1[1], r); const zc = mod(-(15n + 7n * vx) * Fr.inv(11n), r);
  return {
    committed: synthetic([123n, 456n], 1n, 13n), proof1: synthetic(p1, 17n, 19n),
    dense: synthetic([40792793307691160132937706698213704133054528069427933762012433436987942497952n, 20976222017425405296340351928930328963278634447870202382235661951061637561134n], 23n, 29n),
    zero: synthetic([0n, 0n], 31n, 37n), max: synthetic([r - 1n, r - 1n], 41n, 43n), 'msm-identity': synthetic([3n, r - 2n], 47n, 53n),
    // identity fixtures (A, B or C = O): not representable in this verifier's affine encoding, rejected (see README)
    'b-identity': synthetic(p1, 0n, zc, 59n), 'a-identity': synthetic(p1, 17n, zc, 0n), 'c-identity': synthetic(p1, 17n, 0n),
    'all-identity': synthetic([0n, mod(-29n * Fr.inv(42n), r)], 0n, 0n, 0n),
  }; };
export const FIXTURES = fxSpec();
export const FIXTURE_NAMES = ['committed', 'proof1', 'dense', 'zero', 'max', 'msm-identity'];
export const IDENTITY_FIXTURES = ['b-identity', 'a-identity', 'c-identity', 'all-identity'];
export const groth16Holds = ({inputs, proof}) => {
  const vkx = VK.ic[0].add(VK.ic[1].multiplyUnsafe(mod(inputs[0], r))).add(VK.ic[2].multiplyUnsafe(mod(inputs[1], r)));
  const terms = [{g1: proof.a.negate(), g2: proof.b}, {g1: VK.alpha, g2: VK.beta}, {g1: vkx, g2: VK.gamma}, {g1: proof.c, g2: VK.delta}].filter((t) => !t.g1.is0() && !t.g2.is0());
  return F12.eql(terms.length ? bls12_381.pairingBatch(terms, true) : F12.ONE, F12.ONE);
};
for (const n of [...FIXTURE_NAMES, ...IDENTITY_FIXTURES]) assert.ok(groth16Holds(FIXTURES[n]), 'fixture ' + n);
// the fixture used by the BLS singleton and FS-PIT entries (committed)
{ const c = FIXTURES.committed.proof; assert.ok(c.a.equals(G1.BASE.multiply(mod(15n + mod(2n + 4n * 123n + 6n * 456n, r) * 7n + 13n * 11n, r))) && c.b.equals(G2.BASE) && c.c.equals(G1.BASE.multiply(13n))); }
// a proof for any statement under the fixed VK (liveness sweeps): B = b G2, C = c G1
export const mint = (ns, b = 1n + mod(ns[0], 97n), c = 13n + mod(ns[1], 89n)) => synthetic(ns, b, c);

// VK encoding (the transcript tag carries its SHA256): alpha, beta, gamma, delta, IC0..IC2 as affine 48-byte LE words
export const le = (x, n) => { assert.ok(x >= 0n && x < 1n << BigInt(8 * n)); const b = Buffer.alloc(n); let v = x; for (let i = 0; i < n; i++) { b[i] = Number(v & 255n); v >>= 8n; } return b; };
export const VK_ENCODING = (() => { const g1e = (P) => { const a = P.toAffine(); return [a.x, a.y]; }; const g2e = (P) => { const a = P.toAffine(); return [a.x.c0, a.x.c1, a.y.c0, a.y.c1]; };
  return Buffer.concat([...g1e(VK.alpha), ...g2e(VK.beta), ...g2e(VK.gamma), ...g2e(VK.delta), ...VK.ic.flatMap(g1e)].map((x) => le(x, 48))); })();
assert.equal(VK_ENCODING.length, 48 * (2 + 4 * 3 + 2 * 3));

// ---------------- VK-derived constants ----------------
export const B3 = F2.mul(B_TWIST, f2(3n, 0n)); // 3b' = 12 + 12u (projective doubling)
// G2 endpoint constants: [|x|]B = -psi(B) <=> X gamma1^2 = conj(xB) Z and Y gamma1^3 = -conj(yB) Z
export const GAMMA2 = F2.pow(GAMMA1, 2n), GAMMA3 = F2.pow(GAMMA1, 3n);
assert.ok(F2.eql(F2.mul(PSI_X, GAMMA2), F2.ONE) && F2.eql(F2.mul(PSI_Y, GAMMA3), F2.ONE));
{ const Q = G2.BASE.multiply(987654321n); const a = Q.toAffine(), Tq = Q.multiply(AX).toAffine();
  assert.ok(F2.eql(F2.mul(Tq.x, GAMMA2), conj2(a.x)) && F2.eql(F2.mul(Tq.y, GAMMA3), F2.neg(conj2(a.y))), 'endpoint equations hold on G2');
  const Rn = randomTwistPoint(7); const Rp = G2.fromAffine({x: Rn.x, y: Rn.y}); const Tr = smul(Rp, AX).toAffine();
  assert.ok(!(F2.eql(F2.mul(Tr.x, GAMMA2), conj2(Rn.x)) && F2.eql(F2.mul(Tr.y, GAMMA3), F2.neg(conj2(Rn.y)))), 'endpoint equations fail off G2'); }
export const VKC = (() => {
  // delta trajectory: lambda_j for the 68 loop lines (63 doublings, 5 additions with +delta)
  const d = VK.delta.toAffine(); let Tt = VK.delta; const lams = [];
  for (let e = 0; e < NE; e++) { lams.push(slopeDbl(Tt.toAffine())); Tt = Tt.double(); if (BITS[e]) { lams.push(slopeAdd(Tt.toAffine(), d)); Tt = Tt.add(VK.delta); } }
  assert.equal(lams.length, NE + ADD_EVENTS.length); assert.equal(lams.length, 68); assert.ok(Tt.equals(VK.delta.multiply(AX)));
  // the script's delta recursion: state (x_j, c_{j-1}, lambda_{j-1}), start (x_delta, y_delta, 0); c_j = (lambda_{j-1} + lambda_j) x_j - c_{j-1};
  // x_{j+1} = lambda_j^2 - x_j - s_j (s = x_j for a doubling, x_delta for an addition). Every line is asserted to be the true tangent/chord.
  { let x = d.x, c = d.y, l = F2.ZERO, Tc = VK.delta, j = 0;
    const step = (s) => { const ta = Tc.toAffine(); assert.ok(F2.eql(x, ta.x), 'delta x_j'); const cj = F2.sub(F2.mul(F2.add(l, lams[j]), x), c); assert.ok(F2.eql(cj, F2.sub(F2.mul(lams[j], ta.x), ta.y)), 'delta c_j');
      const nx = F2.sub(F2.sub(F2.sqr(lams[j]), x), s); c = cj; l = lams[j]; x = nx; j++; };
    for (let e = 0; e < NE; e++) { step(x); Tc = Tc.double(); if (BITS[e]) { step(d.x); Tc = Tc.add(VK.delta); } }
    assert.equal(j, 68); }
  // the delta Miller value through the recursion's lines equals the reference loop (millerTrace) on a test point
  { const P = G1.BASE.multiply(1234567n); const ref = millerTrace(P, VK.delta); assert.equal(ref.lines.length, 68);
    ref.lines.forEach((ln, j) => assert.ok(F2.eql(ln.lam, lams[j]), 'delta slope ' + j)); }
  const mIC = VK.ic.map((P) => miller(P, VK.gamma));
  const mConst = F12.mul(miller(VK.alpha, VK.beta), mIC[0]);
  // GLS factor reps: R_{k,0} = rep[m_k], R_{k,1} = rep[Frob(m_k)]; factor_i = R_{k,i%2}((-1)^i eta^[i>=2] X), FE(factor_i) = FE(m_k)^(T^i)
  const R = [1, 2].map((k) => [monicRep(mIC[k]), monicRep(F12.frobeniusMap(mIC[k], 1))]);
  R.forEach((Rk, k) => { const g = FE(mIC[k + 1]);
    [0, 1, 2, 3].forEach((i) => { let t = F12.frobeniusMap(mIC[k + 1], i); if (i % 2) t = F12.conjugate(t);
      const f = glsFactorPoly(Rk, i); assert.equal(f[6], 1n); assert.ok(sameClass(fromPoly(f), t), 'GLS factor class ' + k + i);
      assert.ok(F12.eql(FE(fromPoly(f)), F12.pow(g, AXPOW[i])), `FE(R_{${k},${i}}) = FE(m)^(T^${i})`); }); });
  // Rconst' sits in the loop's initial value and is squared 63 times: Rconst' = rep[(m_ab m_IC0)^(2^-63 mod r)]
  const RC_SQUARINGS = NE;
  const Rconst = monicRep(F12.pow(mConst, Fr.pow(Fr.inv(2n), BigInt(RC_SQUARINGS))));
  assert.ok(F12.eql(FE(F12.pow(fromPoly(Rconst), 1n << BigInt(RC_SQUARINGS))), FE(mConst)), "FE(Rconst'^(2^63)) = FE(m_ab m_IC0)");
  return {deltaAff: d, lams, mIC, mConst, R, Rconst, RC_SQUARINGS};
})();
export const glsFactor = (k, i) => glsFactorPoly(VKC.R[k], i);
