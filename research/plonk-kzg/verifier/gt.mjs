// GT folding of the fixed MSM bases (Track 7; the SI-GLS GT-GLS technique, chunked/bn254/sound-si-gls/math.mjs).
//
// Every fixed base B_i (Ql, Qr, Qm, Qo, Qk, S3, S1, S2, [1]_1) is paired with the fixed [1]_2, so
//   e(sum_i s_i B_i, [1]_2) = prod_i e(B_i, [1]_2)^{s_i},
// and FE(Frob^j(m_i)) = e(B_i, [1]_2)^{pi_j} with m_i = Miller(B_i, [1]_2) and pi_j = p^j mod r. The scalar s_i is
// split as s_i = sum_j e_{i,j} pi_j (mod r) with |e_{i,j}| < 2^64 (Babai rounding on the 4-dim GLS lattice), and
// u_{i,j} = e_{i,j} + 2^64 in [0, 2^65) is applied bit by bit in the 65 Miller events: at event e the factor
// prod_{j : bit (64 - e) of u_{i,j} set} R_{i,j}(X) multiplies F, where R_{i,j} is a baked monic degree-6
// representative of the class of Frob^j(m_i) in Fp12*/Fp6* (R_{i,2}, R_{i,3} are R_{i,0}, R_{i,1} at eta X).
// The constant offset 2^64 is cancelled by the terminal factor Rconst (a monic representative of
// prod_{i,j} Frob^j(m_i)^{-2^64}) and by the binding  (sum_j u_{i,j} pi_j - 2^64 sum_j pi_j - s_i) mod r == 0.
// The per-event nibble of base i is byte e of N_i: bit j = bit (64 - e) of u_{i,j}.
import assert from 'node:assert/strict';
import {bn254} from '@noble/curves/bn254.js';
import {p, r, mod, F12, ETA, BN_X, G1, G2, monicRep, sameClass, fromPoly, psubst, peval} from './math.mjs';

export const FIXED_NAMES = ['Ql', 'Qr', 'Qm', 'Qo', 'Qk', 'S3', 'S1', 'S2', 'G'];
export const PI = [1n, p % r, (p * p) % r, (p ** 3n) % r];
assert.equal(PI[1], p - r); assert.equal(PI[2], mod(PI[1] * PI[1], r)); assert.equal(PI[3], mod(PI[1] * PI[2], r));
const LATTICE = (() => { const x = BN_X;
  const L = [[2n * x + 1n, 0n, 2n * x, 1n], [2n * x, x + 1n, -x, x], [x + 1n, x, x, -2n * x], [2n * x + 1n, -x, -(x + 1n), -x]];
  L.forEach((b) => assert.equal(mod(b.reduce((s, v, i) => s + v * PI[i], 0n), r), 0n, 'lattice vector')); return L; })();
const det = (m) => (m.length === 1 ? m[0][0] : m[0].reduce((s, v, j) => s + (j % 2 ? -1n : 1n) * v * det(m.slice(1).map((row) => row.filter((_, k) => k !== j))), 0n));
const DET = det(LATTICE); assert.equal(DET < 0n ? -DET : DET, r, 'lattice has index r');
const COF = [0, 1, 2, 3].map((j) => (j % 2 ? -1n : 1n) * det(LATTICE.filter((_, a) => a !== j).map((row) => row.slice(1))));
const roundDiv = (a, b) => { if (b < 0n) { a = -a; b = -b; } const q = a / b, rm = a % b; if (2n * (rm < 0n ? -rm : rm) >= b) return a < 0n ? q - 1n : q + 1n; return q; };
export const GLS_BITS = 65, GLS_OFFSET = 1n << 64n;
{ const colSum = [0, 1, 2, 3].map((i) => LATTICE.reduce((s, b) => s + (b[i] < 0n ? -b[i] : b[i]), 0n)); assert.ok(colSum.every((c) => c < 2n * GLS_OFFSET), 'Babai bound |e| < 2^64'); }
export const glsDecompose = (n) => {
  const c = COF.map((cj) => roundDiv(n * cj, DET));
  const e = [n, 0n, 0n, 0n].map((v, i) => v - c.reduce((s, cj, j) => s + cj * LATTICE[j][i], 0n));
  assert.equal(mod(e.reduce((s, v, i) => s + v * PI[i], 0n), r), mod(n, r)); e.forEach((v) => assert.ok(v > -GLS_OFFSET && v < GLS_OFFSET)); return e;
};
export const PI_SUM_OFFSET = mod(GLS_OFFSET * PI.reduce((a, b) => a + b, 0n), r);
// TB[n] = sum_{j in n} pi_j (exact integers); the on-chain accumulator acc <- 2 acc + TB[n] ends at sum_j u_j pi_j
export const TB = Array.from({length: 16}, (_, n) => [0, 1, 2, 3].reduce((s, j) => s + ((n >> j) & 1 ? PI[j] : 0n), 0n));

// per-VK constants: R_{i,0}, R_{i,1} (7 coefficients each, monic) and Rconst. Cached per VK.
const cache = new Map();
export function gtConsts(vk, names) {
  const key = vk.rawAll.toString('hex') + names.join(); if (cache.has(key)) return cache.get(key);
  const pt = (nm) => (nm === 'G' ? G1.BASE : vk.pt[nm]);
  const m = names.map((nm) => bn254.pairing(pt(nm), G2.BASE, false));
  for (const [i, nm] of names.entries()) assert.ok(F12.eql(F12.finalExponentiate(m[i]), bn254.pairing(pt(nm), G2.BASE)), 'Miller value of ' + nm);
  const R = m.map((mi) => [monicRep(mi), monicRep(F12.frobeniusMap(mi, 1))]);
  R.forEach((Ri, i) => [0, 1].forEach((j) => { const sh = psubst(Ri[j], ETA); assert.equal(sh[6], 1n); assert.ok(sameClass(fromPoly(sh), F12.frobeniusMap(m[i], j + 2)), 'R_{i,j+2} via eta X'); }));
  let corr = F12.ONE; for (const mi of m) for (let j = 0; j < 4; j++) corr = F12.mul(corr, F12.frobeniusMap(mi, j));
  corr = F12.conjugate(F12.pow(corr, GLS_OFFSET)); // class of prod Frob^j(m_i)^(-2^64)
  const Rconst = monicRep(corr);
  const out = {names, m, R, Rconst}; cache.set(key, out); return out;
}
// polynomial of factor (i, j)
export const factorPoly = (G, i, j) => (j >= 2 ? psubst(G.R[i][j - 2], ETA) : G.R[i][j]);
// nibbles: N[i][e] for the scalars s_i; the transposed string (event-major: byte e*m + i) is the witness
export function nibbles(scal) {
  const U = scal.map((s) => glsDecompose(mod(s, r)).map((e) => e + GLS_OFFSET));
  const N = U.map((u) => Array.from({length: GLS_BITS}, (_, e) => u.reduce((nb, uj, j) => nb | (Number((uj >> BigInt(64 - e)) & 1n) << j), 0)));
  for (const [i, u] of U.entries()) { let acc = 0n; for (let e = 0; e < GLS_BITS; e++) acc = 2n * acc + TB[N[i][e]]; assert.equal(acc, u.reduce((s, uj, j) => s + uj * PI[j], 0n));
    assert.equal(mod(acc - PI_SUM_OFFSET - scal[i], r), 0n, 'binding'); }
  const NB = Buffer.alloc(GLS_BITS * scal.length); for (let e = 0; e < GLS_BITS; e++) for (let i = 0; i < scal.length; i++) NB[e * scal.length + i] = N[i][e];
  return {U, N, NB};
}
// event factor polynomials for event e (list of R_{i,j} for the set bits)
export const eventFactors = (G, N, e) => { const fs = []; N.forEach((Ni, i) => { for (let j = 0; j < 4; j++) if ((Ni[e] >> j) & 1) fs.push(factorPoly(G, i, j)); }); return fs; };
// value check: FE(prod_e prod factors^(2^(64-e)) * Rconst) == prod_i e(B_i, [1]_2)^{s_i}
export function checkFold(vk, G, scal, N) {
  let f = F12.ONE;
  for (let e = 0; e < GLS_BITS; e++) { f = F12.sqr(f); for (const fp of eventFactors(G, N, e)) f = F12.mul(f, fromPoly(fp)); }
  f = F12.mul(f, fromPoly(G.Rconst));
  const pt = (nm) => (nm === 'G' ? G1.BASE : vk.pt[nm]);
  let want = bn254.fields.Fp12.ONE; G.names.forEach((nm, i) => { want = F12.mul(want, bn254.pairing(pt(nm).multiply(mod(scal[i], r) || r), G2.BASE)); });
  return F12.eql(F12.finalExponentiate(f), want);
}
export {peval};
