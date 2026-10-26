// Measure the BLS12-381 kernels in the libauth VM (BCH 2026 instruction set, op-cost accounting identical to bch-spec):
// each kernel runs on random field inputs, its outputs are checked against the blsmath reference, and its op cost
// (the kernel alone: total minus the cost of the input pushes) and code size are recorded.
//   node measure.mjs [out.json]
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {createVirtualMachineBch2026, createVirtualMachineBchSpec, encodeDataPush, bigIntToVmNumber, vmNumberToBigInt} from '@bitauth/libauth';
import {Asm, OP, pushNum} from './asm.mjs';
import {p, mod, F2, f2, G2, projDbl, projAdd, linePoly, peval, pneg, Phi} from './blsmath.mjs';
import * as K from './kernels.mjs';

const VM = {spec: createVirtualMachineBchSpec(false), v2026: createVirtualMachineBch2026(false), v2026s: createVirtualMachineBch2026(true)};
const enc = (pushes) => Uint8Array.from(pushes.flatMap((b) => [...encodeDataPush(b)]));
const program = (locking, unlocking) => ({inputIndex: 0, sourceOutputs: [{lockingBytecode: locking, valueSatoshis: 1000n}],
  transaction: {version: 2, locktime: 0, inputs: [{outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: unlocking}], outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n}]}});
let seed = 0; const rnd = () => mod(BigInt('0x' + createHash('sha512').update('m' + seed++).digest('hex')));
const num = (b) => vmNumberToBigInt(b, {requireMinimalEncoding: false});

// run `code` on a stack of named values; returns {outs, op, bytes}
export function runCode(code, stackVals, nOut, vm = 'spec') {
  const unl = enc(stackVals.map((v) => bigIntToVmNumber(v)));
  const base = VM[vm].evaluate(program(Uint8Array.of(), unl)); const st = VM[vm].evaluate(program(Uint8Array.from(code), unl));
  const okErr = (e) => e === undefined || /unexpected number of items on the stack/.test(e); assert.ok(okErr(st.error), 'VM error: ' + st.error);
  return {outs: st.stack.slice(-nOut).map(num), op: st.metrics.operationCost - base.metrics.operationCost, bytes: code.length};
}
// assemble kernel K over a stack [p, ...names]; values from vals
export function measure(name, kern, vals, outNames, ref, {iters = 4000} = {}) {
  const names = ['p', ...Object.keys(vals)];
  const a = new Asm(names); a.kernel(kern, outNames, {iters});
  const r = runCode(a.bytes(), [p, ...Object.values(vals)], outNames.length);
  const exp = ref(vals).map((x) => mod(x)); const got = r.outs.map((x) => mod(x));
  assert.deepEqual(got, exp, name + ': output mismatch');
  // sanity: the same code costs the same on the BCH 2026 VM (consensus and standard)
  for (const vm of ['v2026', 'v2026s']) { const r2 = runCode(a.bytes(), [p, ...Object.values(vals)], outNames.length, vm); assert.equal(r2.op, r.op, name + ' op differs on ' + vm); }
  return {name, op: r.op, bytes: r.bytes};
}

const results = [];
const rec = (x) => { results.push(x); console.log(x.name.padEnd(14), String(x.op).padStart(8), 'op', String(x.bytes).padStart(5), 'B'); };
const z = rnd(), t = mod(z ** 6n - 1n), xA = rnd(), yA = rnd(), xC = rnd(), yC = rnd();
const env = {t, xz2: mod(xA * z * z), yz3: mod(yA * z ** 3n), cz2: mod(xC * z * z), ycz3: mod(yC * z ** 3n)};
env.xz2t = mod(env.xz2 * t); env.yz3t = mod(env.yz3 * t); env.cz2t = mod(env.cz2 * t); env.xz23 = mod(3n * env.xz2); env.xz23t = mod(env.xz23 * t);
const Q = G2.BASE.multiply(123456789n); const Zr = f2(rnd(), rnd()); const Qa = Q.toAffine();
const T = [F2.mul(Qa.x, Zr), F2.mul(Qa.y, Zr), Zr]; // a projective point with a random Z
const tv = (Tp) => ({X0: Tp[0].c0, X1: Tp[0].c1, Y0: Tp[1].c0, Y1: Tp[1].c1, Z0: Tp[2].c0, Z1: Tp[2].c1});
const Fp0 = rnd(), Fm0 = rnd();
// line poly at P = -A evaluated at +-z
const lineAt = (ln) => { const L = linePoly(xA, mod(-yA), ...ln); return [peval(L, z), peval(L, mod(-z))]; };

// B doubling
rec(measure('BDbl', K.kBDbl(), {t: env.t, xz23: env.xz23, xz23t: env.xz23t, yz3: env.yz3, yz3t: env.yz3t, ...tv(T), Fp: Fp0, Fm: Fm0},
  ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'], () => { const o = projDbl(T); const [a, b] = lineAt(o.line); return [o.T[0].c0, o.T[0].c1, o.T[1].c0, o.T[1].c1, o.T[2].c0, o.T[2].c1, Fp0 * Fp0 * a, Fm0 * Fm0 * b]; }));
// B mixed addition with Bq = some affine point, times c^-1 at +-z
{ const Bq = G2.BASE.multiply(987654321n).toAffine(); const cp = rnd(), cm = rnd();
  rec(measure('BAdd', K.kBAdd(), {xq0: Bq.x.c0, xq1: Bq.x.c1, yq0: Bq.y.c0, yq1: Bq.y.c1, t: env.t, xz2: env.xz2, xz2t: env.xz2t, yz3: env.yz3, yz3t: env.yz3t, cp, cm, ...tv(T), Fp: Fp0, Fm: Fm0},
    ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'], () => { const o = projAdd(T, [Bq.x, Bq.y]); const [a, b] = lineAt(o.line); return [o.T[0].c0, o.T[0].c1, o.T[1].c0, o.T[1].c1, o.T[2].c0, o.T[2].c1, Fp0 * a * cp, Fm0 * b * cm]; })); }
// delta step (slope recursion)
{ const dx = f2(rnd(), rnd()), dc = f2(rnd(), rnd()), dl = f2(rnd(), rnd()), n = f2(rnd(), rnd()), s = f2(rnd(), rnd());
  rec(measure('DStep', K.kDStep(), {t: env.t, cz2: env.cz2, cz2t: env.cz2t, ycz3: env.ycz3, dx0: dx.c0, dx1: dx.c1, dc0: dc.c0, dc1: dc.c1, dl0: dl.c0, dl1: dl.c1, n0: n.c0, n1: n.c1, s0: s.c0, s1: s.c1, Fp: Fp0, Fm: Fm0},
    ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm'], () => {
      const cj = F2.sub(F2.mul(F2.add(dl, n), dx), dc); const nx = F2.sub(F2.sub(F2.sqr(n), dx), s);
      const L = linePoly(xC, yC, cj, F2.neg(n), F2.ONE); return [nx.c0, nx.c1, cj.c0, cj.c1, n.c0, n.c1, Fp0 * peval(L, z), Fm0 * peval(L, mod(-z))]; })); }
// delta line fully baked
{ const c = f2(rnd(), rnd()), l = f2(rnd(), rnd());
  rec(measure('DBaked', K.kDBaked(), {t: env.t, cz2: env.cz2, cz2t: env.cz2t, ycz3: env.ycz3, c0: c.c0, c1: c.c1, l0: l.c0, l1: l.c1, Fp: Fp0, Fm: Fm0}, ['Fp', 'Fm'],
    () => { const L = linePoly(xC, yC, c, F2.neg(l), F2.ONE); return [Fp0 * peval(L, z), Fm0 * peval(L, mod(-z))]; })); }
// monic evaluation at +-x
{ const s = Array.from({length: 6}, rnd); const x = rnd(); const xs = [1, 2, 3, 4, 5, 6].map((i) => mod(x ** BigInt(i)));
  const vals = {}; s.forEach((v, i) => (vals['in' + i] = v)); xs.forEach((v, i) => (vals['in' + (6 + i)] = v));
  rec(measure('Eval', K.kEval(), vals, ['vp', 'vm'], () => [peval([...s, 1n], x), peval([...s, 1n], mod(-x))])); }
// table
{ const v = Array.from({length: 4}, rnd); const vals = {in0: v[0], in1: v[1], in2: v[2], in3: v[3]};
  rec(measure('Table16', K.kTable(), vals, Array.from({length: 16}, (_, i) => 'T' + (15 - i)), () => Array.from({length: 16}, (_, i) => { const n = 15 - i; let a = 1n; for (let b = 0; b < 4; b++) if ((n >> b) & 1) a = mod(a * v[b]); return a; }))); }
// boundary
{ const R = rnd(), rho = rnd(), Sp = rnd(), Sm = rnd();
  rec(measure('Boundary', K.kBoundary(), {rho, R, Fp: Fp0, Fm: Fm0, Sp, Sm}, ['Fp', 'Fm', 'R'], () => [Sp, Sm, R * rho + Fp0 * Sm - Fm0 * Sp])); }
// GLS fold (one sign)
{ const u = rnd(), v = rnd(); rec(measure('GlsMul', K.kGlsMul(), {u, v, F: Fp0}, ['F'], () => [u * v * Fp0])); }
// Horner
{ const z2 = mod(z * z), z4 = mod(z2 * z2), z6 = mod(z4 * z2), z8 = mod(z4 * z4); const acc = rnd(), q = Array.from({length: 4}, rnd);
  rec(measure('Horner4', K.kHorner4(), {z2, z4, z6, z8, acc, q0: q[0], q1: q[1], q2: q[2], q3: q[3]}, ['acc'], () => [acc * z8 + q[0] * z6 + q[1] * z4 + q[2] * z2 + q[3]])); }
// powers / loop env
{ rec(measure('Powers', K.kPowers(), {z, xA, yA, xC, yC}, ['z2', 'z3', 'z4', 'z5', 'z6', 't', 'xz2', 'xz2t', 'xz23', 'xz23t', 'yz3', 'yz3t', 'cz2', 'cz2t', 'ycz3'], () => {
  const z2 = z * z, z3 = z2 * z, z6 = z3 * z3, tt = z6 - 1n, xz2 = xA * z2, yz3 = yA * z3, cz2 = xC * z2;
  return [z2, z3, z2 * z2, z2 * z3, z6, tt, xz2, xz2 * tt, 3n * xz2, 3n * xz2 * tt, yz3, yz3 * tt, cz2, cz2 * tt, yC * z3]; })); }
// curve checks
{ const P =
  (await import('./blsmath.mjs')).G1.BASE.multiply(77n).toAffine(); rec(measure('G1Check', K.kG1Check(), {x: P.x, y: P.y}, ['d'], () => [0n])); }
{ const P = G2.BASE.multiply(99n).toAffine(); rec(measure('G2Check', K.kG2Check(), {x0: P.x.c0, x1: P.x.c1, y0: P.y.c0, y1: P.y.c1}, ['d0', 'd1'], () => [0n, 0n])); }

// non-kernel snippets (hand assembled like sound-si-gls): RD (48-byte word decode + range check), table lookup + GLS step
{ // RD: [blob] -> [v, rest]; blob of 2 words
  const a = new Asm(['p', 'blob']); a.push(48).op(OP.SPLIT, 2, 'w', 'rest').roll('w').pushBytes([0]).op(OP.CAT, 2, 'w0').op(OP.BIN2NUM, 1, 'v');
  a.pick('v').pick('p').op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1).roll('rest');
  const w = rnd(); const blob = Buffer.concat([Buffer.from(bigIntToVmNumber(w)).subarray(0, 48), Buffer.alloc(48, 7)]);
  const unl = enc([bigIntToVmNumber(p), blob]); const base = VM.spec.evaluate(program(Uint8Array.of(), unl)); const st = VM.spec.evaluate(program(a.bytes(), unl));
  assert.ok(st.error === undefined || /unexpected number of items/.test(st.error), st.error); rec({name: 'RD48', op: st.metrics.operationCost - base.metrics.operationCost, bytes: a.bytes().length}); }
writeFileSync(process.argv[2] ?? 'kernels.json', JSON.stringify(Object.fromEntries(results.map((x) => [x.name, {op: x.op, bytes: x.bytes}])), null, 1));
