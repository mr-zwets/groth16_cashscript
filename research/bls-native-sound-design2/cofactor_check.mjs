// G1 cofactor: the verifier only curve-checks A and C (BLS12-381 G1 has cofactor h1 = (x-1)^2/3). This checks numerically
// that the Miller loop + final exponentiation the protocol relies on, FE(f_{|x|,Q}(P)), is unchanged when P gets an
// h1-torsion component: FE(f(P + T)) = FE(f(P)) for T in E(Fp)[h1]. (Ate pairing = power of the reduced Tate pairing
// t(Q, P) for every P in E(Fp), and t(Q, .) kills E(Fp)[h1] since it lies in r E(Fp).) Not a substitute for the proof
// in the README; a regression check of the claim on this curve with the protocol's own line polynomials.
import assert from 'node:assert/strict';
import {p, r, mod, F2, F12, G1, G2, X_ABS, BITS, NE, projDbl, projAdd, linePoly, fromPoly, FACTS} from './blsmath.mjs';
const Fp = (await import('@noble/curves/bls12-381.js')).bls12_381.fields.Fp;
const mulAny = (P, n) => { let acc = G1.ZERO; for (const b of n.toString(2)) { acc = acc.double(); if (b === '1') acc = acc.add(P); } return acc; };
// a point of E(Fp) outside G1, and T = [r]R in E(Fp)[h1]
let R = null; for (let x = 3n; !R; x++) { const rhs = mod(x ** 3n + 4n); try { const y = Fp.sqrt(rhs); if (mod(y * y) === rhs) R = G1.fromAffine({x, y}); } catch {} }
const T = mulAny(R, r); assert.ok(!T.is0()); assert.ok(mulAny(T, FACTS.h1).is0(), 'T has order dividing h1');
const millerFE = (Q, P) => { // the protocol's B-line Miller loop over |x| at P, then the final exponentiation
  const Qa = Q.toAffine(), Pa = P.toAffine(); let Tq = [Qa.x, Qa.y, F2.ONE], f = F12.ONE;
  for (let e = 1; e <= NE; e++) { f = F12.sqr(f); let o = projDbl(Tq); f = F12.mul(f, fromPoly(linePoly(Pa.x, Pa.y, ...o.line))); Tq = o.T;
    if (BITS[e]) { o = projAdd(Tq, [Qa.x, Qa.y]); f = F12.mul(f, fromPoly(linePoly(Pa.x, Pa.y, ...o.line))); Tq = o.T; } }
  return F12.finalExponentiate(f); };
const Q = G2.BASE.multiply(987654321n);
for (const k of [1n, 5n, 123456789n]) {
  const P = G1.BASE.multiply(k); const PT = P.add(T); assert.ok(!PT.is0());
  const a = millerFE(Q, P), b = millerFE(Q, PT);
  assert.ok(F12.eql(a, b), 'FE(f(P + T)) = FE(f(P))');
  assert.ok(!F12.eql(a, F12.ONE));
}
console.log('ok: FE(f_{|x|,Q}(P + T)) = FE(f_{|x|,Q}(P)) for T of order', 'dividing h1', '(3 points, T nontrivial)');
