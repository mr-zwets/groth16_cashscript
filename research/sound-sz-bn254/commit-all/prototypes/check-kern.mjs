// Math check of kern.mjs against noble (BigInt evaluator): projective doubling/mixed-add points and
// their lines (= Fp2 scale * affine unit line), affine steps, psi. Usage: node check-kern.mjs
import assert from 'node:assert/strict';
import {bn254} from '@noble/curves/bn254.js';
import {psiFrobenius} from '@noble/curves/abstract/tower.js';
import {evaluator, mod, P} from './lib.mjs';
import {projDbl, projAdd, affStep, psiK} from './kern.mjs';
const F2 = bn254.fields.Fp2, Fp = bn254.fields.Fp;
const {psi} = psiFrobenius(Fp, F2, F2.NONRESIDUE);
const k = evaluator();
const f2 = (a) => [a.c0, a.c1], F = ([a, b]) => ({c0: mod(a), c1: mod(b)});
const z = 0x1234567890abcdefn * 99991n % P, u = mod(z ** 6n - 9n), eps = (a) => mod(a.c0 + a.c1 * u);
const xP = 1234567n, yP = 7654321n;
const c = {yP, yPu: mod(yP * u), xz: mod(xP * z), xzu: mod(xP * z * u), xz3: mod(3n * xP * z), xz6u: mod(6n * xP * z * u), z3: mod(z ** 3n), z3u: mod(z ** 3n * u)};
const lineAt = (s, lam, b) => { // s * (1, -lam, b) at +-z
  const e0 = mod(eps(s) * yP), T = mod(eps(F2.neg(F2.mul(s, lam))) * xP * z + eps(F2.mul(s, b)) * z ** 3n);
  return [mod(e0 + T), mod(e0 - T)];
};
for (let t = 1n; t < 4n; t++) {
  const Ta = bn254.G2.Point.BASE.multiply(1000n + t).toAffine(), Qa = bn254.G2.Point.BASE.multiply(77n + t).toAffine();
  const Zs = {c0: 77n * t + 3n, c1: 5n + t};
  const X = F2.mul(Ta.x, Zs), Y = F2.mul(Ta.y, Zs);
  // doubling
  const d = projDbl(k, {X: f2(X), Y: f2(Y), Z: f2(Zs)}, c);
  const D = bn254.G2.Point.BASE.multiply(2n * (1000n + t)).toAffine();
  assert(F2.eql(F2.div(F(d.X), F(d.Z)), D.x) && F2.eql(F2.div(F(d.Y), F(d.Z)), D.y), 'proj dbl point');
  const lam = F2.div(F2.mul(F2.sqr(Ta.x), {c0: 3n, c1: 0n}), F2.add(Ta.y, Ta.y)), b = F2.sub(F2.mul(lam, Ta.x), Ta.y);
  const H = F2.mul(F2.add(Y, Y), Zs); // scale 2YZ
  assert.deepEqual([mod(d.lp), mod(d.lm)], lineAt(H, lam, b), 'proj dbl line');
  // mixed add
  const a = projAdd(k, {X: f2(X), Y: f2(Y), Z: f2(Zs)}, {x: f2(Qa.x), y: f2(Qa.y)}, c);
  const S = bn254.G2.Point.BASE.multiply(1000n + t + 77n + t).toAffine();
  assert(F2.eql(F2.div(F(a.X), F(a.Z)), S.x) && F2.eql(F2.div(F(a.Y), F(a.Z)), S.y), 'proj add point');
  const m = F2.div(F2.sub(Qa.y, Ta.y), F2.sub(Qa.x, Ta.x)), bm = F2.sub(F2.mul(m, Ta.x), Ta.y);
  const la = F2.sub(X, F2.mul(Qa.x, Zs));
  assert.deepEqual([mod(a.lp), mod(a.lm)], lineAt(la, m, bm), 'proj add line');
  // affine dbl / add with checks
  const s1 = affStep(k, {x: f2(Ta.x), y: f2(Ta.y)}, f2(lam), c, {check: 'dbl'});
  assert(F2.eql(F(s1.x), D.x) && F2.eql(F(s1.y), D.y)); assert.deepEqual([mod(s1.lp), mod(s1.lm)], lineAt(F2.ONE, lam, b));
  const s2 = affStep(k, {x: f2(Ta.x), y: f2(Ta.y)}, f2(m), c, {check: 'add', Q: {x: f2(Qa.x), y: f2(Qa.y)}});
  assert(F2.eql(F(s2.x), S.x) && F2.eql(F(s2.y), S.y)); assert.deepEqual([mod(s2.lp), mod(s2.lm)], lineAt(F2.ONE, m, bm));
  // psi
  const q = psi(Ta.x, Ta.y);
  const PX = F2.div(q[0], F2.conjugate ? F2.conjugate(Ta.x) : {c0: Ta.x.c0, c1: mod(-Ta.x.c1)}), PY = F2.div(q[1], {c0: Ta.y.c0, c1: mod(-Ta.y.c1)});
  if (t === 1n) globalThis.PSI = {PX, PY};
  const ps = psiK(k, {x: f2(Qa.x), y: f2(Qa.y)}, globalThis.PSI.PX, globalThis.PSI.PY), q2 = psi(Qa.x, Qa.y);
  assert(F2.eql(F(ps.x), q2[0]) && F2.eql(F(ps.y), q2[1]), 'psi');
}
console.log('kern.mjs formulas: projective dbl/add points and lines (Fp2-scaled), affine steps, psi: OK');
