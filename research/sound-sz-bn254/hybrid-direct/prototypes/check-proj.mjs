// Checks witness.mjs's projective doubling / mixed addition (the formulas the hot loop compiles)
// and the psi, psi^2 maps against noble, plus the two facts the zero-line argument needs:
//   doubling:  Z3 = 8 Y^2 (Y Z), so Z = 0 stays 0, and Z3 != 0 implies c_y = 2YZ != 0;
//   mixed add: Z3 = Z la^3 with la = X - xq Z, so Z = 0 stays 0, and Z3 != 0 implies c_y = la != 0.
// Usage: node check-proj.mjs
import assert from 'node:assert/strict';
import {bn254} from '@noble/curves/bn254.js';
import {psiFrobenius} from '@noble/curves/abstract/tower.js';
import {f2, projDbl, projAdd, psiA, psi2A, BTW} from './witness.mjs';
const {Fp, Fp2} = bn254.fields;
const G = bn254.G2.Point.BASE;
const a2 = (Q) => { const a = Q.toAffine(); return [f2.of(a.x), f2.of(a.y)]; };
const toA = ([X, Y, Z]) => { const zi = f2.inv(Z); return [f2.mul(X, zi), f2.mul(Y, zi)]; };
const eqP = (a, b) => f2.eq(a[0], b[0]) && f2.eq(a[1], b[1]);
const {psi} = psiFrobenius(Fp, Fp2, Fp2.NONRESIDUE);
for (const [t, q] of [[5n, 7n], [1000n, 77n], [123456789n, 987654321n]]) {
  const T = a2(G.multiply(t)), Q = a2(G.multiply(q));
  assert.ok(f2.eq(f2.sqr(T[1]), f2.add(f2.mul(f2.sqr(T[0]), T[0]), BTW)), 'on twist');
  const Zr = [3n + t, 11n]; // random projective scaling
  const Tp = [f2.mul(T[0], Zr), f2.mul(T[1], Zr), Zr];
  const d = projDbl(Tp);
  assert.ok(eqP(toA(d.T), a2(G.multiply(2n * t))), 'projective doubling');
  assert.ok(f2.eq(d.T[2], f2.sc(f2.mul(f2.sqr(Tp[1]), f2.mul(Tp[1], Tp[2])), 8n)), 'dbl: Z3 = 8 Y^2 YZ');
  assert.ok(f2.eq(d.cy, f2.sc(f2.mul(Tp[1], Tp[2]), 2n)), 'dbl: c_y = 2YZ');
  const s = projAdd(Tp, Q);
  assert.ok(eqP(toA(s.T), a2(G.multiply(t + q))), 'projective mixed addition');
  const la = f2.sub(Tp[0], f2.mul(Q[0], Tp[2]));
  assert.ok(f2.eq(s.T[2], f2.mul(Tp[2], f2.mul(la, f2.sqr(la)))), 'add: Z3 = Z la^3');
  assert.ok(f2.eq(s.cy, la), 'add: c_y = la');
  const r1 = psi(Fp2.fromBigTuple(T[0]), Fp2.fromBigTuple(T[1])), r2 = psi(r1[0], r1[1]);
  assert.ok(eqP(psiA(T), [f2.of(r1[0]), f2.of(r1[1])]), 'psi');
  assert.ok(eqP(psi2A(T), [f2.of(r2[0]), f2.of(r2[1])]), 'psi^2');
}
// Z = 0 is absorbing for both formulas (any X, Y)
const Z0 = projDbl([[5n, 6n], [7n, 8n], [0n, 0n]]), A0 = projAdd([[5n, 6n], [7n, 8n], [0n, 0n]], a2(G));
assert.ok(f2.eq(Z0.T[2], [0n, 0n]) && f2.eq(A0.T[2], [0n, 0n]), 'Z = 0 absorbing');
console.log('projective dbl/add vs noble, Z3 factorisations (Z absorbing, Z3 != 0 => c_y != 0), psi, psi^2: OK');
