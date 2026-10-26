// Kernel prototypes for the bch-2026 multi-input design, scheduled with the SI-GLS kernel compiler
// (chunked/bn254/sound-si-gls/asm.mjs) and run in the libauth BCH_2026 VM on real values.
//
//   node research/sound-bn254-native/prototypes/kernels.mjs
//
// Compares the SI-GLS projective B kernels (kBDbl, kBAdd) with affine kernels that read a witnessed
// slope lambda and check it by the exact tangent / chord equation, and the delta step (kDStep), alone
// and merged with the B kernels (one F^2 * L_B * L_delta update per event).
import assert from 'node:assert/strict';
import {bn254} from '@noble/curves/bn254.js';
import {Asm, Kernel, OP} from '../../../chunked/bn254/sound-si-gls/asm.mjs';
import {kBDbl, kBAdd, kDStep} from '../../../chunked/bn254/sound-si-gls/script.mjs';
import {p, mod, F2, f2, B3, Fp} from '../../../chunked/bn254/sound-si-gls/math.mjs';
import {runBare, numPush, num} from './vm26.mjs';

const ITERS = Number(process.env.SCHED_ITERS ?? 4000);
const ops = (k) => ({I: (n) => k.in(n), E: (n) => k.env(n), m: (x) => k.mod(x), mul: (a, b) => k.mul(a, b), add: (a, b) => k.add(a, b), sub: (a, b) => k.sub(a, b)});

// ---- affine doubling with witnessed slope l = (l0, l1): check 2 y l = 3 x^2; x' = l^2 - 2x; c = l x - y; y' = c - l x'
// line (1, -l, c) at P = (xP, yP): L(+-z) = yP +- o, o = z3 c0 + z3t c1 - (xz l0 + xzt l1)
// opts.delta: also apply the delta line of this event (merged F update): F <- F^2 * L_B * L_delta
export function kADbl({delta = false, karatsuba = false} = {}) {
  const k = new Kernel(); const {I, E, m, mul, add, sub} = ops(k);
  const [x0, x1, y0, y1, l0, l1] = ['X0', 'X1', 'Y0', 'Y1', 'l0', 'l1'].map(I);
  const fm = (a0, a1, b0, b1) => { if (!karatsuba) return [sub(mul(a0, b0), mul(a1, b1)), add(mul(a0, b1), mul(a1, b0))];
    const u0 = mul(a0, b0), u1 = mul(a1, b1), u2 = mul(add(a0, a1), add(b0, b1)); return [sub(u0, u1), sub(sub(u2, u0), u1)]; };
  const [yl0, yl1] = fm(y0, y1, l0, l1);
  const xx0 = mul(add(x0, x1), sub(x0, x1)), xx1 = mul(add(x0, x0), x1);
  const ch0 = m(sub(k.small(yl0, 2), k.small(xx0, 3))), ch1 = m(sub(k.small(yl1, 2), k.small(xx1, 3)));
  const nx0 = m(sub(mul(add(l0, l1), sub(l0, l1)), add(x0, x0))), nx1 = m(sub(mul(add(l0, l0), l1), add(x1, x1)));
  const [lx0, lx1] = fm(l0, l1, x0, x1); const c0 = m(sub(lx0, y0)), c1 = m(sub(lx1, y1));
  const [ln0, ln1] = fm(l0, l1, nx0, nx1); const ny0 = m(sub(c0, ln0)), ny1 = m(sub(c1, ln1));
  const o = m(sub(add(mul(E('z3'), c0), mul(E('z3t'), c1)), add(mul(E('xz'), l0), mul(E('xzt'), l1))));
  const Fp = I('Fp'), Fm = I('Fm'); let Lp = add(E('yP'), o), Lm = sub(E('yP'), o);
  const outs = [nx0, nx1, ny0, ny1];
  if (delta) { const d = deltaPart(k); outs.push(...d.state); Lp = m(mul(Lp, d.Lp)); Lm = m(mul(Lm, d.Lm)); }
  k.output(...outs, m(mul(mul(Fp, Fp), Lp)), m(mul(mul(Fm, Fm), Lm)), ch0, ch1);
  return k;
}
// the delta step's line (kDStep) as a sub-DAG: returns the new delta state and L_delta(+-z)
function deltaPart(k) {
  const {I, E, m, mul, add, sub} = ops(k);
  const [x0, x1, c0, c1, l0, l1, n0, n1, s0, s1] = ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'n0', 'n1', 's0', 's1'].map(I);
  const a0 = add(l0, n0), a1 = add(l1, n1);
  const u0 = mul(a0, x0), u1 = mul(a1, x1), u2 = mul(add(a0, a1), add(x0, x1));
  const nc0 = m(sub(sub(u0, u1), c0)), nc1 = m(sub(sub(sub(u2, u0), u1), c1));
  const o = m(sub(add(mul(E('z3'), nc0), mul(E('z3t'), nc1)), add(mul(E('cz'), n0), mul(E('czt'), n1))));
  const nx0 = m(sub(sub(mul(add(n0, n1), sub(n0, n1)), x0), s0)), nx1 = m(sub(sub(mul(add(n0, n0), n1), x1), s1));
  return {state: [nx0, nx1, nc0, nc1, n0, n1], Lp: add(E('yC'), o), Lm: sub(E('yC'), o)};
}
// ---- affine addition T + Q, Q = (xq, yq) (env), witnessed slope: check l x - y = l xq - yq and x != xq;
// x' = l^2 - x - xq; c = l x - y; y' = c - l x'; F <- F * L * cp
export function kAAdd({delta = false, karatsuba = false} = {}) {
  const k = new Kernel(); const {I, E, m, mul, add, sub} = ops(k);
  const [x0, x1, y0, y1, l0, l1] = ['X0', 'X1', 'Y0', 'Y1', 'l0', 'l1'].map(I);
  const [q0, q1, r0, r1] = ['xq0', 'xq1', 'yq0', 'yq1'].map(E);
  const fm = (a0, a1, b0, b1) => { if (!karatsuba) return [sub(mul(a0, b0), mul(a1, b1)), add(mul(a0, b1), mul(a1, b0))];
    const u0 = mul(a0, b0), u1 = mul(a1, b1), u2 = mul(add(a0, a1), add(b0, b1)); return [sub(u0, u1), sub(sub(u2, u0), u1)]; };
  // chord check: l (x - xq) = y - yq, as one Fp2 product
  const [d0, d1] = fm(l0, l1, sub(x0, q0), sub(x1, q1));
  const ch0 = m(sub(d0, sub(y0, r0))), ch1 = m(sub(d1, sub(y1, r1)));
  const ex0 = m(sub(x0, q0)), ex1 = m(sub(x1, q1)); // x != xq (non-exceptional)
  const nx0 = m(sub(sub(mul(add(l0, l1), sub(l0, l1)), x0), q0)), nx1 = m(sub(sub(mul(add(l0, l0), l1), x1), q1));
  const [lx0, lx1] = fm(l0, l1, x0, x1); const c0 = m(sub(lx0, y0)), c1 = m(sub(lx1, y1));
  const [ln0, ln1] = fm(l0, l1, nx0, nx1); const ny0 = m(sub(c0, ln0)), ny1 = m(sub(c1, ln1));
  const o = m(sub(add(mul(E('z3'), c0), mul(E('z3t'), c1)), add(mul(E('xz'), l0), mul(E('xzt'), l1))));
  let Lp = add(E('yP'), o), Lm = sub(E('yP'), o);
  const outs = [nx0, nx1, ny0, ny1];
  if (delta) { const d = deltaPart(k); outs.push(...d.state); Lp = m(mul(Lp, d.Lp)); Lm = m(mul(Lm, d.Lm)); }
  k.output(...outs, m(mul(mul(I('Fp'), Lp), I('cp'))), m(mul(mul(I('Fm'), Lm), I('cm'))), ch0, ch1, ex0, ex1);
  return k;
}
// ---- projective T = (X:Y:Z) plus affine Q with a witnessed affine slope l: check l (X - xq Z) = Y - yq Z and
// X != xq Z; Z3 = Z, X3 = l^2 Z - X - xq Z, Y3 = l (xq Z - X3) - yq Z; line (1, -l, l xq - yq) (Q is affine)
export function kPWAdd({karatsuba = false} = {}) {
  const k = new Kernel(); const {I, E, m, mul, add, sub} = ops(k);
  const [X0, X1, Y0, Y1, Z0, Z1, l0, l1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'l0', 'l1'].map(I);
  const [q0, q1, r0, r1] = ['xq0', 'xq1', 'yq0', 'yq1'].map(E);
  const fm = (a0, a1, b0, b1) => { if (!karatsuba) return [sub(mul(a0, b0), mul(a1, b1)), add(mul(a0, b1), mul(a1, b0))];
    const u0 = mul(a0, b0), u1 = mul(a1, b1), u2 = mul(add(a0, a1), add(b0, b1)); return [sub(u0, u1), sub(sub(u2, u0), u1)]; };
  const [xz0_, xz1_] = fm(q0, q1, Z0, Z1); const xz0 = m(xz0_), xz1 = m(xz1_);
  const [yz0_, yz1_] = fm(r0, r1, Z0, Z1); const yz0 = m(yz0_), yz1 = m(yz1_);
  const dx0 = sub(X0, xz0), dx1 = sub(X1, xz1);
  const [d0, d1] = fm(l0, l1, dx0, dx1);
  const ch0 = m(sub(d0, sub(Y0, yz0))), ch1 = m(sub(d1, sub(Y1, yz1)));
  const ex0 = m(dx0), ex1 = m(dx1);
  const ll0 = m(mul(add(l0, l1), sub(l0, l1))), ll1 = m(mul(add(l0, l0), l1));
  const [lz0, lz1] = fm(ll0, ll1, Z0, Z1);
  const X30 = m(sub(sub(lz0, X0), xz0)), X31 = m(sub(sub(lz1, X1), xz1));
  const [w0, w1] = fm(l0, l1, sub(xz0, X30), sub(xz1, X31));
  const Y30 = m(sub(w0, yz0)), Y31 = m(sub(w1, yz1));
  const [lq0, lq1] = fm(l0, l1, q0, q1); const c0 = m(sub(lq0, r0)), c1 = m(sub(lq1, r1));
  const o = m(sub(add(mul(E('z3'), c0), mul(E('z3t'), c1)), add(mul(E('xz'), l0), mul(E('xzt'), l1))));
  k.output(X30, X31, Y30, Y31, Z0, Z1, m(mul(mul(I('Fp'), add(E('yP'), o)), I('cp'))), m(mul(mul(I('Fm'), sub(E('yP'), o)), I('cm'))), ch0, ch1, ex0, ex1);
  return k;
}
// ---- affine with a witnessed inverse NORM (32 B instead of a 64-byte slope): the slope is computed on-chain as
// lambda = num * conj(den) * t with t = 1 / (2 N(den)) for the doubling (den = y, num = 3x^2) or t = 1 / N(den)
// for the addition (den = x - xq, num = y - yq), and the check t * (scaled norm) == 1 fixes t uniquely (and
// implies den != 0: the Fp2 norm vanishes only at 0). Everything after lambda is as in kADbl / kAAdd.
function affineTail(k, x0, x1, y0, y1, l0, l1, q, outs, cpcm) {
  const {I, E, m, mul, add, sub} = ops(k);
  const fm = (a0, a1, b0, b1) => [sub(mul(a0, b0), mul(a1, b1)), add(mul(a0, b1), mul(a1, b0))];
  const nx0 = q ? m(sub(sub(mul(add(l0, l1), sub(l0, l1)), x0), q[0])) : m(sub(mul(add(l0, l1), sub(l0, l1)), add(x0, x0)));
  const nx1 = q ? m(sub(sub(mul(add(l0, l0), l1), x1), q[1])) : m(sub(mul(add(l0, l0), l1), add(x1, x1)));
  const [lx0, lx1] = fm(l0, l1, x0, x1); const c0 = m(sub(lx0, y0)), c1 = m(sub(lx1, y1));
  const [ln0, ln1] = fm(l0, l1, nx0, nx1); const ny0 = m(sub(c0, ln0)), ny1 = m(sub(c1, ln1));
  const o = m(sub(add(mul(E('z3'), c0), mul(E('z3t'), c1)), add(mul(E('xz'), l0), mul(E('xzt'), l1))));
  const Lp = add(E('yP'), o), Lm = sub(E('yP'), o);
  const Fp = I('Fp'), Fm = I('Fm');
  const fp = cpcm ? m(mul(mul(Fp, Lp), I('cp'))) : m(mul(mul(Fp, Fp), Lp));
  const fmm = cpcm ? m(mul(mul(Fm, Lm), I('cm'))) : m(mul(mul(Fm, Fm), Lm));
  return [nx0, nx1, ny0, ny1, fp, fmm, ...outs];
}
export function kADblN() {
  const k = new Kernel(); const {I, m, mul, add, sub} = ops(k);
  const [x0, x1, y0, y1, t] = ['X0', 'X1', 'Y0', 'Y1', 't'].map(I);
  const A0 = m(k.small(mul(add(x0, x1), sub(x0, x1)), 3)), A1 = m(k.small(mul(add(x0, x0), x1), 3)); // 3 x^2
  const w0 = m(add(mul(A0, y0), mul(A1, y1))), w1 = m(sub(mul(A1, y0), mul(A0, y1)));                  // 3x^2 conj(y)
  const l0 = m(mul(w0, t)), l1 = m(mul(w1, t));
  const chk = m(sub(mul(t, k.small(add(mul(y0, y0), mul(y1, y1)), 2)), k.c(1n)));                     // t * 2 N(y) - 1
  return k.output(...affineTail(k, x0, x1, y0, y1, l0, l1, null, [chk], false));
}
export function kAAddN() {
  const k = new Kernel(); const {I, E, m, mul, add, sub} = ops(k);
  const [x0, x1, y0, y1, t] = ['X0', 'X1', 'Y0', 'Y1', 't'].map(I);
  const [q0, q1, r0, r1] = ['xq0', 'xq1', 'yq0', 'yq1'].map(E);
  const d0 = sub(x0, q0), d1 = sub(x1, q1), e0 = sub(y0, r0), e1 = sub(y1, r1);
  const w0 = m(add(mul(e0, d0), mul(e1, d1))), w1 = m(sub(mul(e1, d0), mul(e0, d1)));                  // (y - yq) conj(x - xq)
  const l0 = m(mul(w0, t)), l1 = m(mul(w1, t));
  const chk = m(sub(mul(t, add(mul(d0, d0), mul(d1, d1))), k.c(1n)));                                // t * N(x - xq) - 1
  return k.output(...affineTail(k, x0, x1, y0, y1, l0, l1, [q0, q1], [chk], true));
}
// SI projective doubling merged with the delta step
export function kBDblDelta() {
  const base = kBDbl(); // rebuild: take kBDbl's DAG and multiply its F outputs by L_delta
  const outs = base.outs.slice(); const [fp, fm] = outs.slice(6, 8);
  // fp = mod(mul(mul(Fp,Fp), L)): reach inside to get the unreduced product and multiply by L_delta
  const k = base; const d = deltaPart(k);
  const inner = (id) => k.nodes[id].args[0]; // mod -> mul
  k.output(...outs.slice(0, 6), ...d.state, k.mod(k.mul(inner(fp), d.Lp)), k.mod(k.mul(inner(fm), d.Lm)));
  return k;
}

import {writeFileSync} from 'node:fs';
if (import.meta.url === `file://${process.argv[1]}`) main();
function main() {
// ---------------- measurement ----------------
const rnd = (s) => mod(BigInt(s) ** 37n + 12345n);
function measure(name, K, ins, env, outs, values, check) {
  const stack = ['p', ...env, ...ins];
  const a = new Asm(stack); const res = a.kernel(K, outs, {iters: ITERS});
  const pushes = stack.map((n) => numPush(n === 'p' ? p : values[n]));
  const run = runBare(a.code, pushes, 'standard');
  assert.equal(run.error, undefined, name + ': ' + run.error);
  const got = run.stack.slice(-outs.length).map((b) => mod(num(b)));
  if (check) check(Object.fromEntries(outs.map((o, i) => [o, got[i]])));
  return {name, est: res.cost, vm: run.opCost, bytes: a.code.length};
}

const Q = bn254.G2.Point.BASE.multiply(123456789n).toAffine();
const Bpt = bn254.G2.Point.BASE.multiply(987654321n).toAffine();
const z = rnd(77), t = mod(z ** 6n - 9n), z3 = mod(z ** 3n), xA = rnd(5), yP = rnd(6), xC = rnd(8), yC = rnd(9);
const env0 = {z3, z3t: mod(z3 * t), xz: mod(xA * z), xzt: mod(xA * z * t), yP, yPt: mod(yP * t), xz3: mod(3n * xA * z), xz3t: mod(3n * xA * z * t),
  b30: B3.c0, b31: B3.c1, cz: mod(xC * z), czt: mod(xC * z * t), yC, cp: rnd(10), cm: rnd(11)};
const F = {Fp: rnd(12), Fm: rnd(13)};
const PhiAt = (a) => mod(a.c0 + a.c1 * t);
const lineAt = (lam, c, xz_, sgn) => mod(yP + sgn * (z3 * PhiAt(c) - xz_ * PhiAt(lam)));
const results = [];

// affine doubling
{ const lam = F2.div(F2.mul(f2(3n, 0n), F2.sqr(Q.x)), F2.add(Q.y, Q.y)); const c = F2.sub(F2.mul(lam, Q.x), Q.y);
  const D = bn254.G2.Point.fromAffine(Q).double().toAffine();
  const vals = {...env0, ...F, X0: Q.x.c0, X1: Q.x.c1, Y0: Q.y.c0, Y1: Q.y.c1, l0: lam.c0, l1: lam.c1};
  const chk = (o) => { assert.deepEqual([o.nx0, o.nx1, o.ny0, o.ny1], [D.x.c0, D.x.c1, D.y.c0, D.y.c1]); assert.equal(o.ch0, 0n); assert.equal(o.ch1, 0n);
    assert.equal(o.Fp, mod(F.Fp ** 2n * lineAt(lam, c, env0.xz, 1n))); assert.equal(o.Fm, mod(F.Fm ** 2n * lineAt(lam, c, env0.xz, -1n))); };
  for (const kar of [false, true]) results.push(measure('affine dbl' + (kar ? ' (karatsuba)' : ''), kADbl({karatsuba: kar}), ['X0', 'X1', 'Y0', 'Y1', 'l0', 'l1', 'Fp', 'Fm'],
    ['yP', 'xz', 'xzt', 'z3', 'z3t'], ['nx0', 'nx1', 'ny0', 'ny1', 'Fp', 'Fm', 'ch0', 'ch1'], vals, chk)); }
// affine addition
{ const lam = F2.div(F2.sub(Bpt.y, Q.y), F2.sub(Bpt.x, Q.x)); const c = F2.sub(F2.mul(lam, Q.x), Q.y);
  const S = bn254.G2.Point.fromAffine(Q).add(bn254.G2.Point.fromAffine(Bpt)).toAffine();
  const vals = {...env0, ...F, X0: Q.x.c0, X1: Q.x.c1, Y0: Q.y.c0, Y1: Q.y.c1, l0: lam.c0, l1: lam.c1, xq0: Bpt.x.c0, xq1: Bpt.x.c1, yq0: Bpt.y.c0, yq1: Bpt.y.c1};
  const chk = (o) => { assert.deepEqual([o.nx0, o.nx1, o.ny0, o.ny1], [S.x.c0, S.x.c1, S.y.c0, S.y.c1]); assert.equal(o.ch0, 0n); assert.equal(o.ch1, 0n); assert.ok(o.ex0 || o.ex1);
    assert.equal(o.Fp, mod(F.Fp * lineAt(lam, c, env0.xz, 1n) * env0.cp)); assert.equal(o.Fm, mod(F.Fm * lineAt(lam, c, env0.xz, -1n) * env0.cm)); };
  for (const kar of [false, true]) results.push(measure('affine add' + (kar ? ' (karatsuba)' : ''), kAAdd({karatsuba: kar}), ['X0', 'X1', 'Y0', 'Y1', 'l0', 'l1', 'Fp', 'Fm', 'cp', 'cm'],
    ['xq0', 'xq1', 'yq0', 'yq1', 'yP', 'xz', 'xzt', 'z3', 'z3t'], ['nx0', 'nx1', 'ny0', 'ny1', 'Fp', 'Fm', 'ch0', 'ch1', 'ex0', 'ex1'], vals, chk)); }
// SI projective kernels (reference, same harness)
{ const vals = {...env0, ...F, X0: Q.x.c0, X1: Q.x.c1, Y0: Q.y.c0, Y1: Q.y.c1, Z0: 1n, Z1: 0n};
  results.push(measure('SI projective dbl (kBDbl)', kBDbl(), ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'], ['yP', 'yPt', 'xz3', 'xz3t', 'z3', 'z3t', 'b30', 'b31'],
    ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'], vals));
  const v2 = {...vals, xq0: Bpt.x.c0, xq1: Bpt.x.c1, yq0: Bpt.y.c0, yq1: Bpt.y.c1};
  results.push(measure('SI projective add (kBAdd)', kBAdd(), ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'xq0', 'xq1', 'yq0', 'yq1', 'Fp', 'Fm', 'cp', 'cm'], ['yP', 'yPt', 'xz', 'xzt', 'z3', 'z3t'],
    ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'], v2)); }
// delta step alone and merged
{ const dvals = {dx0: rnd(20), dx1: rnd(21), dc0: rnd(22), dc1: rnd(23), dl0: rnd(24), dl1: rnd(25), n0: rnd(26), n1: rnd(27), s0: rnd(28), s1: rnd(29)};
  results.push(measure('SI delta step (kDStep)', kDStep(), ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'n0', 'n1', 's0', 's1', 'Fp', 'Fm'], ['yC', 'cz', 'czt', 'z3', 'z3t'],
    ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm'], {...env0, ...F, ...dvals}));
  const lam = F2.div(F2.mul(f2(3n, 0n), F2.sqr(Q.x)), F2.add(Q.y, Q.y));
  const vals = {...env0, ...F, ...dvals, X0: Q.x.c0, X1: Q.x.c1, Y0: Q.y.c0, Y1: Q.y.c1, l0: lam.c0, l1: lam.c1};
  results.push(measure('affine dbl + delta (merged)', kADbl({delta: true}), ['X0', 'X1', 'Y0', 'Y1', 'l0', 'l1', 'dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'n0', 'n1', 's0', 's1', 'Fp', 'Fm'],
    ['yP', 'xz', 'xzt', 'z3', 'z3t', 'yC', 'cz', 'czt'], ['nx0', 'nx1', 'ny0', 'ny1', 'dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm', 'ch0', 'ch1'], vals));
  const lamA = F2.div(F2.sub(Bpt.y, Q.y), F2.sub(Bpt.x, Q.x));
  const v3 = {...vals, l0: lamA.c0, l1: lamA.c1, xq0: Bpt.x.c0, xq1: Bpt.x.c1, yq0: Bpt.y.c0, yq1: Bpt.y.c1};
  results.push(measure('affine add + delta (merged)', kAAdd({delta: true}), ['X0', 'X1', 'Y0', 'Y1', 'l0', 'l1', 'dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'n0', 'n1', 's0', 's1', 'Fp', 'Fm', 'cp', 'cm'],
    ['xq0', 'xq1', 'yq0', 'yq1', 'yP', 'xz', 'xzt', 'z3', 'z3t', 'yC', 'cz', 'czt'], ['nx0', 'nx1', 'ny0', 'ny1', 'dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm', 'ch0', 'ch1', 'ex0', 'ex1'], v3));
  const pv = {...env0, ...F, ...dvals, X0: Q.x.c0, X1: Q.x.c1, Y0: Q.y.c0, Y1: Q.y.c1, Z0: 1n, Z1: 0n};
  results.push(measure('SI projective dbl + delta (merged)', kBDblDelta(), ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'n0', 'n1', 's0', 's1', 'Fp', 'Fm'],
    ['yP', 'yPt', 'xz3', 'xz3t', 'z3', 'z3t', 'b30', 'b31', 'yC', 'cz', 'czt'], ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm'], pv)); }

{ const Zr = f2(rnd(40), rnd(41)); const Xp = F2.mul(Q.x, Zr), Yp = F2.mul(Q.y, Zr);
  const lam = F2.div(F2.sub(Bpt.y, Q.y), F2.sub(Bpt.x, Q.x)); const c = F2.sub(F2.mul(lam, Bpt.x), Bpt.y);
  const S = bn254.G2.Point.fromAffine(Q).add(bn254.G2.Point.fromAffine(Bpt)).toAffine();
  const vals = {...env0, ...F, X0: Xp.c0, X1: Xp.c1, Y0: Yp.c0, Y1: Yp.c1, Z0: Zr.c0, Z1: Zr.c1, l0: lam.c0, l1: lam.c1, xq0: Bpt.x.c0, xq1: Bpt.x.c1, yq0: Bpt.y.c0, yq1: Bpt.y.c1};
  const chk = (o) => { const Z = f2(o.Z0, o.Z1); const x = F2.div(f2(o.X0, o.X1), Z), y = F2.div(f2(o.Y0, o.Y1), Z);
    assert.ok(F2.eql(x, S.x) && F2.eql(y, S.y), 'PW add point'); assert.equal(o.ch0, 0n); assert.equal(o.ch1, 0n); assert.ok(o.ex0 || o.ex1);
    assert.equal(o.Fp, mod(F.Fp * lineAt(lam, c, env0.xz, 1n) * env0.cp)); assert.equal(o.Fm, mod(F.Fm * lineAt(lam, c, env0.xz, -1n) * env0.cm)); };
  for (const kar of [false, true]) results.push(measure('projective + witnessed-slope add' + (kar ? ' (karatsuba)' : ''), kPWAdd({karatsuba: kar}), ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'l0', 'l1', 'Fp', 'Fm', 'cp', 'cm'],
    ['xq0', 'xq1', 'yq0', 'yq1', 'yP', 'xz', 'xzt', 'z3', 'z3t'], ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm', 'ch0', 'ch1', 'ex0', 'ex1'], vals, chk)); }

{ const N = (a) => mod(a.c0 * a.c0 + a.c1 * a.c1);
  const lam = F2.div(F2.mul(f2(3n, 0n), F2.sqr(Q.x)), F2.add(Q.y, Q.y)); const c = F2.sub(F2.mul(lam, Q.x), Q.y);
  const D = bn254.G2.Point.fromAffine(Q).double().toAffine(); const t = Fp.inv(mod(2n * N(Q.y)));
  const vals = {...env0, ...F, X0: Q.x.c0, X1: Q.x.c1, Y0: Q.y.c0, Y1: Q.y.c1, t};
  const chk = (o) => { assert.deepEqual([o.nx0, o.nx1, o.ny0, o.ny1], [D.x.c0, D.x.c1, D.y.c0, D.y.c1]); assert.equal(o.chk, 0n);
    assert.equal(o.Fp, mod(F.Fp ** 2n * lineAt(lam, c, env0.xz, 1n))); assert.equal(o.Fm, mod(F.Fm ** 2n * lineAt(lam, c, env0.xz, -1n))); };
  results.push(measure('affine dbl, inverse-norm witness', kADblN(), ['X0', 'X1', 'Y0', 'Y1', 't', 'Fp', 'Fm'], ['yP', 'xz', 'xzt', 'z3', 'z3t'], ['nx0', 'nx1', 'ny0', 'ny1', 'Fp', 'Fm', 'chk'], vals, chk));
  const lamA = F2.div(F2.sub(Bpt.y, Q.y), F2.sub(Bpt.x, Q.x)); const cA = F2.sub(F2.mul(lamA, Q.x), Q.y);
  const S = bn254.G2.Point.fromAffine(Q).add(bn254.G2.Point.fromAffine(Bpt)).toAffine(); const tA = Fp.inv(N(F2.sub(Q.x, Bpt.x)));
  const v2 = {...env0, ...F, X0: Q.x.c0, X1: Q.x.c1, Y0: Q.y.c0, Y1: Q.y.c1, t: tA, xq0: Bpt.x.c0, xq1: Bpt.x.c1, yq0: Bpt.y.c0, yq1: Bpt.y.c1};
  const chk2 = (o) => { assert.deepEqual([o.nx0, o.nx1, o.ny0, o.ny1], [S.x.c0, S.x.c1, S.y.c0, S.y.c1]); assert.equal(o.chk, 0n);
    assert.equal(o.Fp, mod(F.Fp * lineAt(lamA, cA, env0.xz, 1n) * env0.cp)); assert.equal(o.Fm, mod(F.Fm * lineAt(lamA, cA, env0.xz, -1n) * env0.cm)); };
  results.push(measure('affine add, inverse-norm witness', kAAddN(), ['X0', 'X1', 'Y0', 'Y1', 't', 'Fp', 'Fm', 'cp', 'cm'], ['xq0', 'xq1', 'yq0', 'yq1', 'yP', 'xz', 'xzt', 'z3', 'z3t'],
    ['nx0', 'nx1', 'ny0', 'ny1', 'Fp', 'Fm', 'chk'], v2, chk2)); }

console.table(results);
if (process.env.OUT) writeFileSync(process.env.OUT, JSON.stringify(results, null, 1));
}
