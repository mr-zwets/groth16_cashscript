// T2 rolled residue singleton (BN254): constants for the bench's singleton VK (src/checkpoints/pairing-vectors.json,
// the VK of the BN plain / opcode-optimized / minop singletons), asserted against noble. The generic field, tower,
// Frobenius, psi, NAF and residue facts are the reviewed SI-GLS ones (../sigls-dproj/math.mjs, asserted there).
import assert from 'node:assert/strict';
import {existsSync, readFileSync} from 'node:fs';
import {bn254} from '@noble/curves/bn254.js';
import {p, r, mod, F2, F12, f2, DIGITS, NE, ETA, GAMMA1, PSI, psiK, projDbl, projAdd, monicRep, linePoly, fromPoly, B_TWIST} from '../sigls-dproj/math.mjs';
export * from '../sigls-dproj/math.mjs';

// VERIFIER_DIR: a zk-verifier-bench checkout. Default: the sibling of this repository's checkout, as zk-verifier-bench/
// (side-by-side clones) or bench/ (the work/<task>/{src,bench} worktree layout), whichever has the vectors.
const REPO_PARENT = new URL('../../../../../', import.meta.url).pathname;
export const VDIR = process.env.VERIFIER_DIR ?? (['zk-verifier-bench', 'bench'].map((d) => REPO_PARENT + d).find((d) => existsSync(d + '/src/checkpoints/pairing-vectors.json')) ?? REPO_PARENT + 'zk-verifier-bench');
export const VEC = JSON.parse(readFileSync(VDIR + '/src/checkpoints/pairing-vectors.json', 'utf8'));
export const g1 = (x) => bn254.G1.Point.fromAffine({x: BigInt(x.x), y: BigInt(x.y)});
export const g2 = (x) => bn254.G2.Point.fromAffine({x: {c0: BigInt(x.x.c0), c1: BigInt(x.x.c1)}, y: {c0: BigInt(x.y.c0), c1: BigInt(x.y.c1)}});
export const VK = {alpha: g1(VEC.vk.alpha), beta: g2(VEC.vk.beta), gamma: g2(VEC.vk.gamma), delta: g2(VEC.vk.delta), ic: VEC.vk.ic.map(g1)};
assert.equal(VK.ic.length, 3, 'two public inputs');
export const NBITS = 254; assert.ok(r < 1n << 254n);

// projective walk of a baked G2 point (gamma, delta): deterministic; assert every step against noble, Z != 0,
// nonzero leading line coefficient, and projective line = l0 * affine line. Returns the 88 projective lines.
export function assertWalk(Q, name) {
  const d = Q.toAffine(); const [p1x, p1y] = psiK(1, d.x, d.y), [p2x, p2y] = psiK(2, d.x, d.y);
  const Q1 = bn254.G2.Point.fromAffine({x: p1x, y: p1y}), Q2 = bn254.G2.Point.fromAffine({x: p2x, y: F2.neg(p2y)});
  let T = [d.x, d.y, F2.ONE], Tt = Q; const lines = [];
  const aff = ([X, Y, Z]) => { assert.ok(!F2.is0(Z), name + ' walk: Z = 0'); const zi = F2.inv(Z); return [F2.mul(X, zi), F2.mul(Y, zi)]; };
  const chk = (o, lam) => { const [l0, l1, l3] = o.line; const ta = Tt.toAffine(); assert.ok(!F2.is0(l0), name + ' line: l0 = 0');
    assert.ok(F2.eql(l1, F2.mul(l0, F2.neg(lam))) && F2.eql(l3, F2.mul(l0, F2.sub(F2.mul(lam, ta.x), ta.y))), name + ' line != l0 * affine line'); lines.push(o.line); };
  const slopeDbl = (Ta) => F2.div(F2.mul(f2(3n, 0n), F2.sqr(Ta.x)), F2.add(Ta.y, Ta.y));
  const slopeAdd = (Ta, Qa) => { assert.ok(!F2.eql(Ta.x, Qa.x)); return F2.div(F2.sub(Qa.y, Ta.y), F2.sub(Qa.x, Ta.x)); };
  const step = (o, Tn, lam) => { chk(o, lam); T = o.T; Tt = Tn; const [x, y] = aff(T), ta = Tt.toAffine(); assert.ok(F2.eql(x, ta.x) && F2.eql(y, ta.y), name + ' walk'); };
  for (let e = 0; e < NE; e++) { step(projDbl(T), Tt.double(), slopeDbl(Tt.toAffine()));
    if (DIGITS[e]) { const Qs = DIGITS[e] < 0 ? Q.negate() : Q; step(projAdd(T, [d.x, DIGITS[e] < 0 ? F2.neg(d.y) : d.y]), Tt.add(Qs), slopeAdd(Tt.toAffine(), Qs.toAffine())); } }
  step(projAdd(T, [p1x, p1y]), Tt.add(Q1), slopeAdd(Tt.toAffine(), Q1.toAffine()));
  step(projAdd(T, [p2x, F2.neg(p2y)]), Tt.add(Q2), slopeAdd(Tt.toAffine(), Q2.toAffine()));
  assert.equal(lines.length, 88);
  const [p3x, p3y] = psiK(3, d.x, d.y); const [x, y] = aff(T); assert.ok(F2.eql(x, p3x) && F2.eql(y, F2.neg(p3y)), name + ' endpoint');
  return lines;
}
export const VKC = (() => {
  const gA = VK.gamma.toAffine(), dA = VK.delta.toAffine();
  assertWalk(VK.gamma, 'gamma'); assertWalk(VK.delta, 'delta');
  // e(alpha, beta) as a baked monic class representative of the Miller value (FE(m) = e(alpha, beta))
  const mAB = bn254.pairing(VK.alpha, VK.beta, false); const MAB = monicRep(mAB);
  assert.ok(F12.eql(F12.finalExponentiate(mAB), bn254.pairing(VK.alpha, VK.beta)));
  // the BAKED representative itself: FE(MAB) = e(alpha, beta) (review item; MAB and mAB differ by an Fp6* factor, which
  // the final exponentiation kills since (p^6 - 1) | (p^12 - 1)/r). e(alpha, beta) != 1, so honest acceptance (prove()
  // asserts FE(f) = 1 for every honest proof, f built with MAB and the script-mirror lines) pins the script's pairing
  // exponent to 1 (README, T2 soundness item 1).
  assert.ok(F12.eql(F12.finalExponentiate(fromPoly(MAB)), bn254.pairing(VK.alpha, VK.beta)), 'FE(MAB) = e(alpha, beta)');
  assert.ok(!F12.eql(bn254.pairing(VK.alpha, VK.beta), F12.ONE), 'e(alpha, beta) != 1');
  // vk_x start point: Q0 = 2^-254 IC0, so 254 doublings of the Straus accumulator land on IC0
  const inv2k = bn254.fields.Fr.inv(bn254.fields.Fr.pow(2n, BigInt(NBITS)));
  const Q0 = VK.ic[0].multiply(inv2k); assert.ok(Q0.multiply(bn254.fields.Fr.pow(2n, BigInt(NBITS))).equals(VK.ic[0]));
  const T3 = VK.ic[1].add(VK.ic[2]);
  const A = (P) => P.toAffine();
  return {gamma: gA, delta: dA, MAB, Q0: A(Q0), T1: A(VK.ic[1]), T2: A(VK.ic[2]), T3: A(T3)};
})();
