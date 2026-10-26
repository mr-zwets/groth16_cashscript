// BLS12-381 SI-GLS math (design prototype): the tower <-> polynomial map, Frobenius / eta / psi constants,
// line polynomials, the residue facts and the base-|x| GT-GLS, each asserted against noble at import time.
//
//   Fp12 = Fp[X]/M(X), M = X^12 - 2 X^6 + 2, X = w (noble tower: u^2 = -1, v^3 = 1 + u, w^2 = v),
//   u = X^6 - 1; an Fp2 element a0 + a1 u maps to Phi(a) = (a0 - a1) + a1 X^6.
//   G = Fp12* / Fp6* (cyclic, order p^6 + 1); conjugation sigma = Frob^6 is X -> -X; Frob^2 is X -> eta X.
import assert from 'node:assert/strict';
import {bls12_381} from '@noble/curves/bls12-381.js';

export const {Fp, Fp2: F2, Fp6, Fp12: F12} = bls12_381.fields;
export const p = Fp.ORDER, r = bls12_381.fields.Fr.ORDER;
export const X_ABS = 0xd201000000010000n;          // |x|, x = -|x|
export const mod = (a, m = p) => ((a % m) + m) % m;
export const inv = (a) => Fp.inv(mod(a));
export const G1 = bls12_381.G1.Point, G2 = bls12_381.G2.Point;
export const f2 = (a, b) => F2.fromBigTuple([mod(a), mod(b)]);
const gcd = (a, b) => { a = a < 0n ? -a : a; b = b < 0n ? -b : b; while (b) [a, b] = [b, a % b]; return a; };
export const minv = (a, m) => { let [x, y] = [mod(a, m), m], [s0, s1] = [1n, 0n]; while (y) { const q = x / y; [x, y] = [y, x - q * y]; [s0, s1] = [s1, s0 - q * s1]; } assert.equal(x, 1n); return mod(s0, m); };

// ---------------- polynomials over Fp ----------------
export const pmul = (a, b) => { const o = Array(a.length + b.length - 1).fill(0n); for (let i = 0; i < a.length; i++) if (a[i]) for (let j = 0; j < b.length; j++) o[i + j] += a[i] * b[j]; return o.map((x) => mod(x)); };
export const padd = (a, b) => Array.from({length: Math.max(a.length, b.length)}, (_, i) => mod((a[i] ?? 0n) + (b[i] ?? 0n)));
export const psub = (a, b) => Array.from({length: Math.max(a.length, b.length)}, (_, i) => mod((a[i] ?? 0n) - (b[i] ?? 0n)));
export const psubst = (a, s) => { let k = 1n; return a.map((c) => { const v = mod(c * k); k = mod(k * s); return v; }); }; // a(sX)
export const pneg = (a) => psubst(a, p - 1n);
export const peval = (a, x) => { let acc = 0n; for (let i = a.length - 1; i >= 0; i--) acc = mod(acc * x + a[i]); return acc; };
export const deg = (a) => { let d = a.length - 1; while (d > 0 && a[d] === 0n) d--; return d; };
export const M = [2n, 0n, 0n, 0n, 0n, 0n, p - 2n, 0n, 0n, 0n, 0n, 0n, 1n];
export const pdivM = (a) => { // exact long division by the monic M: X^12 = 2 X^6 - 2
  const rem = a.slice(); const q = Array(Math.max(1, a.length - 12)).fill(0n);
  for (let i = rem.length - 1; i >= 12; i--) { const v = rem[i]; q[i - 12] = v; rem[i] = 0n; rem[i - 6] = mod(rem[i - 6] + 2n * v); rem[i - 12] = mod(rem[i - 12] - 2n * v); }
  return {q, r: rem.slice(0, 12).concat(Array(Math.max(0, 12 - rem.length)).fill(0n))};
};
export const pmodM = (a) => pdivM(a).r;
export const isZero = (a) => a.every((x) => x === 0n);

// ---------------- tower <-> polynomial ----------------
const flat = (x) => [x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1, x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1];
const SLOT_DEG = [0, 2, 4, 1, 3, 5]; // c0.c0, c0.c1 (v = w^2), c0.c2 (v^2), c1.c0 (w), c1.c1 (vw), c1.c2 (v^2 w)
export const toPoly = (x) => { const c = flat(x), out = Array(12).fill(0n); SLOT_DEG.forEach((d, i) => { out[d] = mod(c[2 * i] - c[2 * i + 1]); out[d + 6] = c[2 * i + 1]; }); return out; };
export const fromPoly = (a) => {
  const c = pmodM(a); const s = SLOT_DEG.map((d) => ({c0: mod(c[d] + c[d + 6]), c1: c[d + 6]}));
  return F12.create({c0: Fp6.create({c0: s[0], c1: s[1], c2: s[2]}), c1: Fp6.create({c0: s[3], c1: s[4], c2: s[5]})});
};
export const Phi = (a) => { const o = Array(7).fill(0n); o[0] = mod(a.c0 - a.c1); o[6] = mod(a.c1); return o; };
const randF12 = (seed) => F12.fromBigTwelve(Array.from({length: 12}, (_, i) => mod(BigInt(seed * 1000003 + i * 7919 + 1) ** 37n)));
for (let s = 1; s < 5; s++) { // the map is a ring isomorphism
  const a = randF12(s), b = randF12(s + 10);
  assert.equal(pmodM(pmul(toPoly(a), toPoly(b))).join(), toPoly(F12.mul(a, b)).join(), 'toPoly multiplicative');
  assert.ok(F12.eql(fromPoly(toPoly(a)), a), 'fromPoly o toPoly');
}

// monic degree-6 class representative S = X^6 + s5 X^5 + ... + s0 with [S] = [f] in G
const solveMod = (A, b) => {
  const n = A.length, Mx = A.map((row, i) => [...row, b[i]].map((x) => mod(x)));
  for (let c = 0; c < n; c++) {
    let piv = c; while (piv < n && Mx[piv][c] === 0n) piv++; if (piv === n) throw new Error('monic representative does not exist (singular)');
    [Mx[c], Mx[piv]] = [Mx[piv], Mx[c]]; const iv = inv(Mx[c][c]); Mx[c] = Mx[c].map((x) => mod(x * iv));
    for (let i = 0; i < n; i++) if (i !== c && Mx[i][c]) { const m = Mx[i][c]; Mx[i] = Mx[i].map((x, k) => mod(x - m * Mx[c][k])); }
  }
  return Mx.map((row) => row[n]);
};
// a / b in Fp6 <=> a conj(b) is even
export const sameClass = (a, b) => { const t = toPoly(F12.mul(a, F12.conjugate(b))); return t.every((x, i) => i % 2 === 0 || x === 0n); };
export const monicRep = (f) => {
  const fp = toPoly(f); const cols = [0, 2, 4, 6, 8, 10].map((d) => pmodM(pmul([...Array(d).fill(0n), 1n], fp)));
  const s = solveMod([6, 7, 8, 9, 10, 11].map((row) => cols.map((c) => c[row])), [1n, 0n, 0n, 0n, 0n, 0n]);
  const out = Array(12).fill(0n); cols.forEach((c, j) => c.forEach((x, i) => (out[i] = mod(out[i] + s[j] * x))));
  assert.ok(out.slice(7).every((x) => x === 0n) && out[6] === 1n);
  const rep = out.slice(0, 7); assert.ok(sameClass(fromPoly(rep), f)); return rep; // [s0..s5, 1]
};

// ---------------- Frobenius, eta, sigma ----------------
for (let s = 4; s < 7; s++) { const el = randF12(s); assert.equal(toPoly(F12.frobeniusMap(el, 6)).join(), pmodM(pneg(toPoly(el))).join(), 'Frob^6 = X -> -X'); }
export const ETA = (() => {
  const g = (() => { for (let a = 2n; ; a++) { const e = Fp.pow(a, (p - 1n) / 6n); if (Fp.pow(e, 2n) !== 1n && Fp.pow(e, 3n) !== 1n) return e; } })();
  const ok = [g, Fp.pow(g, 5n)].filter((eta) => [1, 2, 3].every((s) => { const el = randF12(s); return pmodM(psubst(toPoly(el), eta)).join() === toPoly(F12.frobeniusMap(el, 2)).join(); }));
  assert.equal(ok.length, 1, 'exactly one primitive 6th root realizes Frob^2'); return ok[0];
})();
assert.equal(Fp.pow(ETA, 6n), 1n); assert.equal(Fp.pow(ETA, 3n), p - 1n); assert.equal(mod(ETA * ETA), ETA - 1n, 'eta^2 = eta - 1');
// Frob(X^j) = Phi(GAMMA1^j) X^j, GAMMA1 = xi^((p-1)/6), xi = 1 + u; Frob(X^6) = Frob(1 + u) = 1 - u = 2 - X^6
export const GAMMA1 = F2.pow(f2(1n, 1n), (p - 1n) / 6n);
export const FROB = (() => {
  const mono = (j) => fromPoly([...Array(j).fill(0n), 1n]); const out = {alpha: [], beta: []}; let g = F2.ONE;
  for (let j = 1; j <= 5; j++) {
    g = F2.mul(g, GAMMA1); const fp = toPoly(F12.frobeniusMap(mono(j), 1));
    fp.forEach((c, i) => assert.ok(c === 0n || i === j || i === j + 6, 'Frob(X^j) support'));
    out.alpha[j] = fp[j]; out.beta[j] = fp[j + 6];
    assert.equal(mod(g.c0 - g.c1), out.alpha[j]); assert.equal(g.c1, out.beta[j], 'Frob(X^j) = Phi(gamma1^j) X^j');
  }
  assert.equal(toPoly(F12.frobeniusMap(mono(6), 1)).join(), [2n, 0n, 0n, 0n, 0n, 0n, p - 1n, 0n, 0n, 0n, 0n, 0n].join());
  return out;
})();
// Frob of a monic degree-6 polynomial s0..s5 (the on-chain formula): s0 + 2 - X^6 + sum_j s_j Phi(gamma1^j) X^j
export const frob1Monic = (s) => { const o = Array(12).fill(0n); o[0] = mod(s[0] + 2n); o[6] = p - 1n; for (let j = 1; j <= 5; j++) { o[j] = mod(o[j] + s[j] * FROB.alpha[j]); o[j + 6] = mod(o[j + 6] + s[j] * FROB.beta[j]); } return o; };
for (let t = 0; t < 3; t++) { const s = Array.from({length: 6}, (_, i) => mod(BigInt(t * 31 + i + 5) ** 41n)); assert.equal(pmodM(frob1Monic(s)).join(), toPoly(F12.frobeniusMap(fromPoly([...s, 1n]), 1)).join(), 'Frob(S) formula'); }

// ---------------- twist, lines (noble mul014 convention), psi ----------------
// E': y^2 = x^3 + 4(1 + u) (M-type). Line element = c0 + (c1 Px) v + (c2 Py) v w  ->  Phi(c0) + Px Phi(c1) X^2 + Py Phi(c2) X^3
export const B_TWIST = f2(4n, 4n);
export const B3 = F2.mul(B_TWIST, f2(3n, 0n)); // 3b' = 12 + 12u
export const linePoly = (xP, yP, c0, c1, c2) => { const o = Array(10).fill(0n); const [a, b, c] = [Phi(c0), Phi(c1), Phi(c2)];
  for (let i = 0; i < 7; i++) { o[i] = mod(o[i] + a[i]); o[i + 2] = mod(o[i + 2] + xP * b[i]); o[i + 3] = mod(o[i + 3] + yP * c[i]); } return o; };
// projective doubling (noble's formulas scaled by 4: X3 = 2XY(B - F), Y3 = (B + F)^2 - 12 E^2, Z3 = 4 B H), line (E - B, 3X^2, -H)
export const projDbl = ([X, Y, Z]) => {
  const B = F2.sqr(Y), C = F2.sqr(Z), E = F2.mul(B3, C), Fv = F2.mul(E, f2(3n, 0n)), H = F2.mul(F2.mul(Y, Z), f2(2n, 0n));
  return {T: [F2.mul(F2.mul(F2.mul(X, Y), f2(2n, 0n)), F2.sub(B, Fv)), F2.sub(F2.sqr(F2.add(B, Fv)), F2.mul(F2.sqr(E), f2(12n, 0n))), F2.mul(F2.mul(B, H), f2(4n, 0n))],
    line: [F2.sub(E, B), F2.mul(F2.sqr(X), f2(3n, 0n)), F2.neg(H)]};
};
// mixed addition with affine Q (noble's pointAdd): t0 = Y - yq Z, t1 = X - xq Z, line (t0 xq - t1 yq, -t0, t1); Z3 = Z t1^3
export const projAdd = ([X, Y, Z], [xq, yq]) => {
  const t0 = F2.sub(Y, F2.mul(yq, Z)), t1 = F2.sub(X, F2.mul(xq, Z));
  const t2 = F2.sqr(t1), t3 = F2.mul(t2, t1), t4 = F2.mul(t2, X), t5 = F2.add(F2.sub(t3, F2.mul(t4, f2(2n, 0n))), F2.mul(F2.sqr(t0), Z));
  return {T: [F2.mul(t1, t5), F2.sub(F2.mul(F2.sub(t4, t5), t0), F2.mul(t3, Y)), F2.mul(Z, t3)],
    line: [F2.sub(F2.mul(t0, xq), F2.mul(t1, yq)), F2.neg(t0), t1]};
};
// psi(x, y) = (conj(x) PX, conj(y) PY) on E'(Fp2), checked against noble's G2 psi via the subgroup relation below
const conj2 = (a) => ({c0: a.c0, c1: mod(-a.c1)});
export const PSI = {x: F2.inv(F2.pow(f2(1n, 1n), (p - 1n) / 3n)), y: F2.inv(F2.pow(f2(1n, 1n), (p - 1n) / 2n))};
export const psi = (x, y) => [F2.mul(conj2(x), PSI.x), F2.mul(conj2(y), PSI.y)];
for (let t = 1; t < 4; t++) { // psi(Q) = [x]Q = -[|x|]Q on G2 (noble's isTorsionFree test), psi maps E' to E'
  const Q = G2.BASE.multiply(BigInt(1000 + 7919 * t)), a = Q.toAffine(); const [px, py] = psi(a.x, a.y);
  const xQ = Q.multiply(X_ABS).negate().toAffine(); assert.ok(F2.eql(px, xQ.x) && F2.eql(py, xQ.y), 'psi(Q) = [x]Q on G2');
}

// ---------------- Miller schedule (plain binary |x|: 63 doubling events, 5 additions) ----------------
export const BITS = Array.from({length: 64}, (_, i) => Number((X_ABS >> BigInt(63 - i)) & 1n)); // BITS[0] = 1 (top)
export const NE = 63; // events e = 1..63 handle bit 63 - e; event 0 is the initialization (top bit)
export const ADD_EVENTS = BITS.map((b, e) => (e > 0 && b ? e : -1)).filter((e) => e > 0);
assert.equal(BITS[0], 1); assert.deepEqual(ADD_EVENTS, [1, 3, 6, 15, 47]);

// ---------------- residue and G2 facts ----------------
export const LAMBDA = p + X_ABS;           // = p - x = m r
export const N6R = (p ** 6n + 1n) / r;
export const FACTS = (() => {
  assert.equal(mod(p, r), mod(-X_ABS, r), 'p = x (mod r)');
  assert.equal((p ** 6n + 1n) % r, 0n, 'r | p^6 + 1'); assert.equal(LAMBDA % r, 0n, 'lambda = m r');
  assert.equal(gcd(LAMBDA, N6R), 1n, 'gcd(lambda, (p^6+1)/r) = 1: a residue root exists for every FE-trivial class');
  assert.equal(gcd(3n, p ** 6n + 1n), 1n, '3 does not divide p^6 + 1');
  assert.equal(((p ** 6n + 1n) / r) % 2n, 0n, '(p^6+1)/r even: FE(w^3) = 1');
  // E'(Fp2): #E'(Fp2) = (p+1-t2)... computed via the twist trace: t = x + 1, t2 = t^2 - 2p, twist order p^2 + 1 - (3f + t2)/2
  const t = 1n - X_ABS; const t2 = t * t - 2n * p; const f2sq = (4n * p * p - t2 * t2) / 3n; const f = sqrtBig(f2sq); assert.equal(f * f, f2sq);
  const cands = [p * p + 1n - (t2 + 3n * f) / 2n, p * p + 1n - (t2 - 3n * f) / 2n, p * p + 1n - (-t2 + 3n * f) / 2n, p * p + 1n - (-t2 - 3n * f) / 2n].filter((n) => n % r === 0n);
  assert.equal(cands.length, 1, 'the sextic twist with r | #E\'(Fp2)'); const nE2 = cands[0];
  // check #E'(Fp2) against noble: the G2 cofactor h_eff is not the plain cofactor, so test [nE2] kills random twist points
  { const x0 = f2(5n, 7n); let x = x0; let pt = null; for (let i = 0n; !pt; i++) { x = F2.add(x0, f2(i, 0n)); const rhs = F2.add(F2.mul(F2.sqr(x), x), B_TWIST); try { const y = F2.sqrt(rhs); pt = G2.fromAffine({x, y}); } catch {} }
    const mulAny = (P, n) => { let acc = G2.ZERO; for (const b of n.toString(2)) { acc = acc.double(); if (b === '1') acc = acc.add(P); } return acc; };
    assert.ok(!mulAny(pt, nE2 / r).is0() && mulAny(pt, nE2).is0(), '#E\'(Fp2) annihilates a random twist point (not in G2)'); }
  // endpoint: psi(B) = [x]B with B on E'(Fp2) => B in G2: ker(psi - [x]) has order deg = p - x = lambda (separable),
  // so ker cap E'(Fp2) has order dividing gcd(lambda, #E'(Fp2)) = r, the unique order-r subgroup (r || #E'(Fp2))
  assert.equal(gcd(LAMBDA, nE2), r, 'gcd(p - x, #E\'(Fp2)) = r'); assert.ok((nE2 / r) % r !== 0n, 'r || #E\'(Fp2)');
  // G1: cofactor h1 = (x-1)^2/3, gcd(h1, r) = 1 (A, C are only curve-checked; see README "G1 cofactor")
  const h1 = ((X_ABS + 1n) ** 2n) / 3n; assert.equal(h1 * r, p + 1n - t, '#E(Fp) = h1 r'); assert.equal(gcd(h1, r), 1n);
  return {nE2, h2: nE2 / r, h1, lambdaOverR: LAMBDA / r};
})();
function sqrtBig(n) { if (n < 2n) return n; let x = 1n << BigInt(Math.ceil(n.toString(2).length / 2) + 1); for (;;) { const y = (x + n / x) >> 1n; if (y >= x) return x; x = y; } } // Newton from above: floor(sqrt(n))

// ---------------- GT-GLS in base |x| ----------------
// e(IC, gamma)^n = prod_i ((sigma Frob)^i e(IC, gamma))^(d_i), n = sum_i d_i |x|^i, 0 <= d_i < |x| (unique; r < |x|^4)
// because |x| = -x = -p (mod r) and sigma = inversion on mu_r.
export const XPOW = [1n, X_ABS, X_ABS ** 2n, X_ABS ** 3n];
assert.ok(r < X_ABS ** 4n, 'r < |x|^4: base-|x| digits of n in [0, r) have 4 digits');
XPOW.forEach((xp, i) => assert.equal(mod(xp, r), mod((p * (r - 1n)) ** BigInt(i), r), '|x|^i = (-p)^i mod r'));
export const glsDigits = (n) => { assert.ok(n >= 0n && n < r); const d = []; let v = n; for (let i = 0; i < 4; i++) { d.push(v % X_ABS); v /= X_ABS; } assert.equal(v, 0n); return d; };
export const GLS_BITS = 64; // d_i < |x| < 2^64; bit 63 is folded at event 0 (initialization)
