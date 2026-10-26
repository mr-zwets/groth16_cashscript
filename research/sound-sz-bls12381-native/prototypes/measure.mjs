// Measure every BLS kernel in the libauth VM: op cost and bytes, outputs checked against the DAG simulation
// (and, for the curve kernels, against the reference formulas in math.mjs on real curve points).
//   node measure.mjs            -> prints a table and writes kernels.json
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {bls12_381} from '@noble/curves/bls12-381.js';
import {Asm} from './asm.mjs';
import {runBare} from './vm.mjs';
import * as K from './kernels.mjs';
import {p, mod, F2, projDbl, projAdd, affDbl, affAdd, B3} from './math.mjs';

const ITERS = Number(process.env.SCHED_ITERS ?? 4000);
let seed = 12345n; const rnd = () => (seed = (seed * 6364136223846793005n + 1442695040888963407n) % (1n << 64n), mod(seed ** 7n + seed));
// measure kernel K with env names E (read-only) and input names I (consumed); values from `vals` (name -> bigint)
function measure(name, Kfn, env, ins, vals, check) {
  const Kd = Kfn(); const stack = ['p', ...env, ...ins];
  const a = new Asm(stack); const nOut = Kd.outs.length; const outs = Array.from({length: nOut}, (_, i) => 'o' + i);
  a.kernel(Kd, outs, {iters: ITERS});
  const items = stack.map((n) => (n === 'p' ? p : vals[n]));
  const r = runBare(a.code, items);
  assert.equal(r.error, undefined, name + ': ' + r.error);
  const got = r.stack.slice(-nOut);
  // DAG simulation (exact integers, mods as in the script)
  const sim = Kd.simulate((n) => vals[n.name], p); const want = Kd.outs.map((id) => sim[id]);
  assert.deepEqual(got.map((x) => mod(x)), want.map((x) => mod(x)), name + ': VM vs DAG');
  if (check) check(want.map((x) => mod(x)));
  return {name, op: r.op, bytes: a.code.length};
}
// ---- realistic values: a G2 point, A, C, z ----
const Bp = bls12_381.G2.Point.BASE.multiply(0x1234567n), Ba = Bp.toAffine();
const A = bls12_381.G1.Point.BASE.multiply(99n).toAffine(), C = bls12_381.G1.Point.BASE.multiply(77n).toAffine();
const z = rnd(), z2 = mod(z * z), z3 = mod(z2 * z), z6 = mod(z3 * z3), t = mod(z6 - 1n);
const env = {t, xz2: mod(A.x * z2), xz2t: mod(A.x * z2 * t), yz3: mod(A.y * z3), yz3t: mod(A.y * z3 * t), nyz3: mod(-A.y * z3),
  cz2: mod(C.x * z2), cz2t: mod(C.x * z2 * t), cy3: mod(C.y * z3), rho: rnd()};
const lineAt = (xP, yP, [c0, c1, c2], sgn) => { const e = mod(c0.c0 + c0.c1 * t + xP * z2 * (c1.c0 + c1.c1 * t)); const o = mod(yP * z3 * (c2.c0 + c2.c1 * t)); return mod(e + sgn * o); };
const Fp_ = rnd(), Fm_ = rnd();
const T = Bp.multiply(5n).toAffine(); const Zs = f2r(); function f2r() { return {c0: rnd(), c1: rnd()}; }
const TP = [F2.mul(T.x, Zs), F2.mul(T.y, Zs), Zs]; // projective T with a random Z
const results = [];
// projective doubling
results.push(measure('BDbl (projective dbl + line + F^2)', K.kBDbl, ['t', 'xz2', 'xz2t', 'yz3', 'yz3t'], ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'],
  {...env, X0: TP[0].c0, X1: TP[0].c1, Y0: TP[1].c0, Y1: TP[1].c1, Z0: TP[2].c0, Z1: TP[2].c1, Fp: Fp_, Fm: Fm_},
  (o) => { const r = projDbl(TP); assert.deepEqual(o.slice(0, 6), r.T.flatMap((v) => [v.c0, v.c1]));
    assert.equal(o[6], mod(Fp_ * Fp_ * lineAt(A.x, mod(-A.y), r.line, 1n))); assert.equal(o[7], mod(Fm_ * Fm_ * lineAt(A.x, mod(-A.y), r.line, -1n))); }));
// projective mixed addition
const cp = rnd(), cm = rnd();
results.push(measure('BAdd (projective mixed add + line * c)', K.kBAdd, ['t', 'xz2', 'xz2t', 'yz3', 'yz3t'], ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'xq0', 'xq1', 'yq0', 'yq1', 'Fp', 'Fm', 'cp', 'cm'],
  {...env, X0: TP[0].c0, X1: TP[0].c1, Y0: TP[1].c0, Y1: TP[1].c1, Z0: TP[2].c0, Z1: TP[2].c1, xq0: Ba.x.c0, xq1: Ba.x.c1, yq0: Ba.y.c0, yq1: Ba.y.c1, Fp: Fp_, Fm: Fm_, cp, cm},
  (o) => { const r = projAdd(TP, [Ba.x, Ba.y]); assert.deepEqual(o.slice(0, 6), r.T.flatMap((v) => [v.c0, v.c1]));
    assert.equal(o[6], mod(Fp_ * lineAt(A.x, mod(-A.y), r.line, 1n) * cp)); }));
// affine doubling with a witnessed slope
const lamD = F2.div(F2.mul(F2.sqr(T.x), {c0: 3n, c1: 0n}), F2.add(T.y, T.y));
results.push(measure('ADbl (affine dbl, witnessed slope, checks)', K.kADbl, ['t', 'xz2', 'xz2t', 'nyz3'], ['x0', 'x1', 'y0', 'y1', 'l0', 'l1', 'Fp', 'Fm'],
  {...env, x0: T.x.c0, x1: T.x.c1, y0: T.y.c0, y1: T.y.c1, l0: lamD.c0, l1: lamD.c1, Fp: Fp_, Fm: Fm_},
  (o) => { assert.equal(o[0], 0n); assert.equal(o[1], 0n); const r = affDbl([T.x, T.y], lamD); const d = Bp.multiply(10n).toAffine();
    assert.ok(F2.eql({c0: o[2], c1: o[3]}, d.x) && F2.eql({c0: o[4], c1: o[5]}, d.y), 'affine doubling = 2T');
    assert.equal(o[6], mod(Fp_ * Fp_ * lineAt(A.x, mod(-A.y), r.line, 1n))); }));
const lamA = F2.div(F2.sub(Ba.y, T.y), F2.sub(Ba.x, T.x));
results.push(measure('AAdd (affine add, witnessed slope, checks)', K.kAAdd, ['t', 'xz2', 'xz2t', 'nyz3'], ['x0', 'x1', 'y0', 'y1', 'l0', 'l1', 'xq0', 'xq1', 'yq0', 'yq1', 'Fp', 'Fm', 'cp', 'cm'],
  {...env, x0: T.x.c0, x1: T.x.c1, y0: T.y.c0, y1: T.y.c1, l0: lamA.c0, l1: lamA.c1, xq0: Ba.x.c0, xq1: Ba.x.c1, yq0: Ba.y.c0, yq1: Ba.y.c1, Fp: Fp_, Fm: Fm_, cp, cm},
  (o) => { assert.equal(o[0], 0n); assert.equal(o[1], 0n); const s = Bp.multiply(6n).toAffine(); assert.ok(F2.eql({c0: o[4], c1: o[5]}, s.x) && F2.eql({c0: o[6], c1: o[7]}, s.y), 'affine add = T + B'); }));
// delta step (recursion) and baked-line variant
const nl = f2r(), dl = f2r(), dx = f2r(), dc = f2r();
results.push(measure('DStep (delta line, slope-only bake, recursion)', K.kDStep, ['t', 'cz2', 'cz2t', 'cy3'], ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'n0', 'n1', 's0', 's1', 'Fp', 'Fm'],
  {...env, dx0: dx.c0, dx1: dx.c1, dc0: dc.c0, dc1: dc.c1, dl0: dl.c0, dl1: dl.c1, n0: nl.c0, n1: nl.c1, s0: dx.c0, s1: dx.c1, Fp: Fp_, Fm: Fm_}));
results.push(measure('DLine (delta line fully baked)', K.kDLine, ['t', 'cz2', 'cz2t', 'cy3'], ['n0', 'n1', 'cc0', 'cc1', 'Fp', 'Fm'],
  {...env, n0: nl.c0, n1: nl.c1, cc0: dc.c0, cc1: dc.c1, Fp: Fp_, Fm: Fm_}));
// evaluation, tables, boundary
const ev = {}; for (let i = 0; i < 12; i++) ev['in' + i] = rnd();
results.push(measure('EV (monic deg-6 at +-x)', K.kEval, [], Array.from({length: 12}, (_, i) => 'in' + i), ev));
results.push(measure('TM (16-entry product table)', () => K.kTable(true), [], ['in0', 'in1', 'in2', 'in3'], ev));
results.push(measure('TA (16-entry sum table, < r)', () => K.kTable(false), [], ['in0', 'in1', 'in2', 'in3'], ev));
results.push(measure('Bound (R update)', K.kBound, ['rho'], ['R', 'Fp', 'Fm', 'Sp', 'Sm'], {...env, R: rnd(), Fp: Fp_, Fm: Fm_, Sp: rnd(), Sm: rnd()}));
for (const r of results) console.log(r.name.padEnd(48), String(r.op).padStart(9), String(r.bytes).padStart(6), 'B');
writeFileSync(new URL('./kernels.json', import.meta.url), JSON.stringify(Object.fromEntries(results.map((r) => [r.name.split(' ')[0], {op: r.op, bytes: r.bytes, desc: r.name}])), null, 1));
