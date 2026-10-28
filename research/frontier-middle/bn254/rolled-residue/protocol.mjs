// T2 witness layout and honest prover. W = xA yA xB0 xB1 yB0 yB1 xC yC n0 n1 sc0..sc5 zInv (17 x 32-byte LE words).
// The prover computes the raw Miller product exactly as the script's line polynomials define it, the residue root c
// with [c]^lambda = [raw] (as SI-GLS), its monic class representative S_c, and zInv for the script's Jacobian vk_x.
import assert from 'node:assert/strict';
import {bn254} from '@noble/curves/bn254.js';
import {p, r, mod, F2, F12, DIGITS, NE, LAMBDA, N6R, psiK, projDbl, projAdd, linePoly, fromPoly, monicRep, VK, VKC, NBITS, g1, g2} from './math.mjs';
export const W_SIZE = 17 * 32;
export const WL = {n0: 256, n1: 288, sc: 320, zInv: 512};
export const le32 = (x) => { assert.ok(x >= 0n && x < 1n << 256n); const b = Buffer.alloc(32); let v = x; for (let i = 0; i < 32; i++) { b[i] = Number(v & 255n); v >>= 8n; } return b; };
// the script's Jacobian vk_x (same formulas): returns the projective (X, Y, Z)
export function vkxJacobian(n0, n1) {
  const m = (x) => mod(x); let [X, Y, Z] = [VKC.Q0.x, VKC.Q0.y, 1n]; const T = [null, VKC.T1, VKC.T2, VKC.T3];
  for (let i = NBITS - 1; i >= 0; i--) {
    { const A = m(X * X), B = m(Y * Y), C = m(B * B), D = m(2n * ((X + B) ** 2n - A - C)), E = 3n * A; const X3 = m(E * E - 2n * D); [X, Y, Z] = [X3, m(E * (D - X3) - 8n * C), m(2n * Y * Z)]; }
    const j = Number((n0 >> BigInt(i)) & 1n) + 2 * Number((n1 >> BigInt(i)) & 1n);
    if (j) { const {x: x2, y: y2} = T[j]; const ZZ = m(Z * Z), U2 = x2 * ZZ, S2 = y2 * m(Z * ZZ), H = m(U2 - X), HH = m(H * H), I = 4n * HH, J = m(H * I), R = m(2n * (S2 - Y)), V = m(X * I);
      const X3 = m(R * R - J - 2n * V); [X, Y, Z] = [X3, m(R * (V - X3) - 2n * Y * J), m(2n * Z * H)]; }
  }
  return [X, Y, Z];
}
// raw Miller product of the three pairs as the script's polynomials (no c), times the baked m_alpha_beta
export function rawMiller(Aa, Ba, Ca, V) {
  const Q = {B: [Ba.x, Ba.y], G: [VKC.gamma.x, VKC.gamma.y], D: [VKC.delta.x, VKC.delta.y]};
  const P = {B: [Aa.x, mod(-Aa.y)], G: [V.x, V.y], D: [Ca.x, Ca.y]};
  const T = Object.fromEntries(Object.entries(Q).map(([w, [x, y]]) => [w, [x, y, F2.ONE]]));
  let f = F12.ONE; const mulL = (w, o) => { f = F12.mul(f, fromPoly(linePoly(P[w][0], P[w][1], ...o.line))); T[w] = o.T; };
  for (let e = 0; e < NE; e++) {
    f = F12.sqr(f);
    for (const w of ['B', 'G', 'D']) mulL(w, projDbl(T[w]));
    if (DIGITS[e]) for (const w of ['B', 'G', 'D']) mulL(w, projAdd(T[w], [Q[w][0], DIGITS[e] < 0 ? F2.neg(Q[w][1]) : Q[w][1]]));
  }
  for (const w of ['B', 'G', 'D']) { const [x, y] = Q[w]; const [p1x, p1y] = psiK(1, x, y), [p2x, p2y] = psiK(2, x, y);
    mulL(w, projAdd(T[w], [p1x, p1y])); mulL(w, projAdd(T[w], [p2x, F2.neg(p2y)])); }
  f = F12.mul(f, fromPoly(VKC.MAB));
  const [p3x, p3y] = psiK(3, Ba.x, Ba.y); const [X, Y, Z] = T.B;
  const endpoint = !F2.is0(Z) && F2.eql(X, F2.mul(p3x, Z)) && F2.eql(Y, F2.mul(F2.neg(p3y), Z));
  return {f, endpoint};
}
const minv = (a, m) => { let [x, y] = [mod(a, m), m], [s0, s1] = [1n, 0n]; while (y) { const q = x / y; [x, y] = [y, x - q * y]; [s0, s1] = [s1, s0 - q * s1]; } assert.equal(x, 1n); return mod(s0, m); };
export function prove({proof, publicInputs}, {forge = false} = {}) {
  const A = g1(proof.a), B = g2(proof.b), C = g1(proof.c);
  const ns = publicInputs.map(BigInt);
  const Aa = A.toAffine(), Ba = B.toAffine(), Ca = C.toAffine();
  const [X, Y, Z] = vkxJacobian(ns[0], ns[1]); const zInv = Z === 0n ? 0n : bn254.fields.Fp.inv(Z);
  const V = {x: mod(X * zInv * zInv), y: mod(Y * zInv ** 3n)};
  if (!forge) { let vk = VK.ic[0]; ns.forEach((n, i) => { if (n) vk = vk.add(VK.ic[i + 1].multiply(n)); }); const va = vk.toAffine(); assert.ok(va.x === V.x && va.y === V.y, 'Jacobian vk_x'); }
  const {f, endpoint} = rawMiller(Aa, Ba, Ca, V);
  if (!forge) { assert.ok(endpoint, 'B endpoint'); assert.ok(F12.eql(F12.finalExponentiate(f), F12.ONE), 'Groth16 equation fails'); }
  let Sc;
  if (F12.eql(F12.finalExponentiate(f), F12.ONE)) {
    const u = F12.mul(F12.conjugate(f), F12.inv(f)), v = F12.pow(u, minv(LAMBDA, N6R)), c = F12.add(F12.ONE, F12.conjugate(v)); Sc = monicRep(c);
  } else Sc = monicRep(F12.add(F12.ONE, f)); // forge (red-team / invalid vectors only): some class; the identity must fail
  const W = Buffer.concat([Aa.x, Aa.y, Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1, Ca.x, Ca.y, ns[0], ns[1], ...Sc.slice(0, 6), zInv].map((x) => le32(mod(x, 1n << 256n))));
  assert.equal(W.length, W_SIZE);
  return {W, Sc, zInv, V};
}
